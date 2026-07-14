#!/usr/bin/env node
/**
 * Pretense identify + mutate bridge.
 *
 * Feeds the synthetic DLP benchmark corpus through the real `pretense`
 * engine and measures two kinds of coverage per difficulty tier:
 *
 *   IDENTIFY - pretense `scan(text)` (secret/identifier pattern scan) returns >=1 match.
 *   MUTATE   - pretense `mutate(text, "typescript")` rewrites >=1 token.
 *
 * The pretense engine ships as TypeScript whose internal imports use `.js`
 * specifiers that resolve to sibling `.ts` files. Node cannot import those
 * directly, so at runtime we copy the needed source files into a fresh temp
 * dir, rewrite `from "./X.js"` -> `from "./X.ts"`, then dynamic-import the
 * copies under `--experimental-transform-types`.
 *
 * All corpus input is synthetic, fake, and banner-marked. This script only
 * reads the corpus; it never mutates corpus data on disk.
 *
 * Run:
 *   node --experimental-transform-types dlp_benchmark/pretense_bridge/run.mjs
 */

import { copyFileSync, mkdtempSync, existsSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

// Real pretense engine source (a separate local checkout).
const PRETENSE_SRC = "/Users/jimmymalhan/Documents/pretense/packages/cli/src";

// Source files the engine needs to load `mutate` and `scan`.
const ENGINE_FILES = [
  "types.ts",
  "scanner.ts",
  "mutator.ts",
  "reverser.ts",
  "deterministic-id.ts",
  "salt.ts",
  "secrets.ts",
];

// Corpus lives one directory up from this bridge.
const CORPUS_PATH = join(HERE, "..", "corpus", "cases.json");

/**
 * Copy the engine files into a fresh temp dir and rewrite relative `.js`
 * import specifiers to `.ts` so Node's TS loader can resolve them.
 * Returns the temp dir path.
 */
function stageEngine(srcDir) {
  const stageDir = mkdtempSync(join(tmpdir(), "pretense-bridge-"));
  for (const name of ENGINE_FILES) {
    const src = join(srcDir, name);
    const dst = join(stageDir, name);
    copyFileSync(src, dst);
    const rewritten = readFileSync(dst, "utf8").replace(
      /(from\s+["']\.\/[A-Za-z0-9_-]+)\.js(["'])/g,
      "$1.ts$2",
    );
    writeFileSync(dst, rewritten);
  }
  return stageDir;
}

function pct(hits, n) {
  return n === 0 ? "  n/a" : `${((hits / n) * 100).toFixed(1).padStart(5)}%`;
}

async function main() {
  if (!existsSync(PRETENSE_SRC)) {
    console.log(`pretense engine not found at ${PRETENSE_SRC}; skipping`);
    process.exit(0);
  }

  const stageDir = stageEngine(PRETENSE_SRC);
  const { mutate } = await import(pathToFileURL(join(stageDir, "mutator.ts")).href);
  const { scan } = await import(pathToFileURL(join(stageDir, "secrets.ts")).href);

  // Engine modules are loaded; the staged copies are no longer needed.
  rmSync(stageDir, { recursive: true, force: true });

  const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf8"));
  const cases = corpus.cases ?? [];

  // tier -> { n, identify, mutate }
  const tiers = new Map();
  const overall = { n: 0, identify: 0, mutate: 0 };

  for (const c of cases) {
    const text = c.text ?? "";
    const tier = c.difficulty ?? "?";
    if (!tiers.has(tier)) tiers.set(tier, { n: 0, identify: 0, mutate: 0 });
    const t = tiers.get(tier);

    const scanRes = scan(text);
    const identified = (scanRes.matches?.length ?? 0) > 0;

    const mutRes = mutate(text, "typescript");
    const mutated =
      (mutRes.stats?.tokensMutated ?? 0) > 0 || mutRes.mutatedCode !== text;

    t.n += 1;
    overall.n += 1;
    if (identified) {
      t.identify += 1;
      overall.identify += 1;
    }
    if (mutated) {
      t.mutate += 1;
      overall.mutate += 1;
    }
  }

  console.log("Pretense identify + mutate coverage over synthetic DLP corpus");
  console.log(`Cases: ${overall.n}  (all synthetic, fake, banner-marked)\n`);
  console.log("tier |   n | identify | mutate");
  console.log("-----+-----+----------+-------");
  for (const tier of [...tiers.keys()].sort((a, b) => (a > b ? 1 : -1))) {
    const t = tiers.get(tier);
    console.log(
      `${String(tier).padStart(4)} | ${String(t.n).padStart(3)} |   ${pct(
        t.identify,
        t.n,
      )} | ${pct(t.mutate, t.n)}`,
    );
  }
  console.log("-----+-----+----------+-------");
  console.log(
    ` all | ${String(overall.n).padStart(3)} |   ${pct(
      overall.identify,
      overall.n,
    )} | ${pct(overall.mutate, overall.n)}`,
  );

  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
