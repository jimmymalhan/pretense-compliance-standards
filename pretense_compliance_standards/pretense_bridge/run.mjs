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
 *   node --experimental-transform-types pretense_compliance_standards/pretense_bridge/run.mjs
 */

import {
  cpSync,
  readdirSync,
  mkdtempSync,
  existsSync,
  readFileSync,
  writeFileSync,
  rmSync,
  realpathSync,
} from "node:fs";
import { join, dirname, relative, sep } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

// Real pretense engine source (a separate local checkout). Overridable via the
// PRETENSE_SRC env var so the bridge is portable across machines (and so tests /
// CI can point it elsewhere or leave it unset to exercise the graceful-skip path).
// `|| default` (not `?? default`) so an exported-but-empty `PRETENSE_SRC=` — a
// common CI/wrapper accident — falls back to the default instead of becoming "".
// PRETENSE_SRC is the pretense REPO ROOT — the packages are derived from it.
//
// It used to be a directory of loose engine files and defaulted to
// `.../packages/cli/src`. Both parts were wrong:
//
//   1. `packages/cli` is `@pretense/cli-legacy`, a private package that is NOT
//      what ships. Measuring it inflated results by roughly three points, so any
//      figure produced against that default was measuring the wrong engine.
//   2. The flat file list (types/scanner/mutator/reverser/deterministic-id/
//      salt/secrets.ts) describes a layout the engine no longer has. The shipped
//      scanner is `packages/scanner/src` (index/patterns/extended-patterns/
//      level2/lexer/entropy/deobfuscate/…) and the mutator is
//      `packages/mutator/src`. Every one of those seven files was missing, so
//      the bridge could not start at all — meaning the headline compliance
//      number was unreproducible until this was repaired.
const PRETENSE_SRC =
  process.env.PRETENSE_SRC?.trim() ||
  "/Users/jimmymalhan/Documents/Product/pretense";

// The two packages that constitute the SHIPPED engine, staged as a unit.
// NOTE: use `grep -a` when auditing this list. Several engine sources contain
// non-UTF8 bytes, so plain grep reports NOTHING for them — which is exactly how
// `@pretense/compliance-engine` (scanner/src/index.ts:18) was missed twice while
// tracking down a "Cannot find package" error.
const ENGINE_PACKAGES = [
  { name: "scanner", srcDir: join("packages", "scanner", "src") },
  { name: "mutator", srcDir: join("packages", "mutator", "src") },
  { name: "compliance-engine", srcDir: join("packages", "compliance-engine", "src") },
];

// Corpus lives one directory up from this bridge.
const CORPUS_PATH = join(HERE, "..", "corpus", "cases.json");

// Compliance taxonomy (kind -> frameworks) lives alongside the corpus.
const COMPLIANCE_PATH = join(HERE, "..", "compliance_map.json");

/**
 * Copy the engine files into a fresh temp dir and rewrite relative `.js`
 * import specifiers to `.ts` so Node's TS loader can resolve them.
 * Returns the temp dir path.
 */
function stageEngine(repoRoot) {
  const stageDir = mkdtempSync(join(tmpdir(), "pretense-bridge-"));

  for (const pkg of ENGINE_PACKAGES) {
    const from = join(repoRoot, pkg.srcDir);
    if (!existsSync(from)) {
      throw new Error(
        `engine source not found: ${from}\n` +
          `PRETENSE_SRC must be the pretense REPO ROOT (it is "${repoRoot}").`,
      );
    }
    // Recursive, because the packages have subdirectories. __tests__ is excluded:
    // it is not engine code and its fixtures import test-only helpers.
    cpSync(from, join(stageDir, pkg.name), {
      recursive: true,
      filter: (src) => !src.includes(`${sep}__tests__`),
    });
  }

  // Rewrite specifiers so Node's type-stripping loader can resolve them.
  //
  //   ./foo.js            → ./foo.ts        (TS source, not built output)
  //   @pretense/scanner   → ../scanner/index.ts
  //   @pretense/mutator   → ../mutator/index.ts
  //
  // The bare-specifier rewrite is the part the old staging lacked. Four shipped
  // scanner files (extended-patterns, level2, deobfuscate, secret-vocabulary)
  // and two mutator files (rules-engine, salt) import each other by package
  // name, and nothing resolves those outside the pnpm workspace.
  // `relative()` returns "index.ts" for a same-directory target, and Node reads
  // an unprefixed specifier as a BARE package name — which fails with a
  // misleading "Cannot find package" error. Always force a ./ prefix.
  const rel = (fromDir, toFile) => {
    const r = relative(fromDir, toFile).split(sep).join("/");
    return r.startsWith(".") ? r : `./${r}`;
  };

  const rewrite = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, entry.name);
      if (entry.isDirectory()) {
        rewrite(p);
      } else if (entry.name.endsWith(".ts")) {
        const before = readFileSync(p, "utf8");
        const after = before
          .replace(/(from\s+["'](?:\.{1,2}\/)[A-Za-z0-9_./-]+)\.js(["'])/g, "$1.ts$2")
          .replace(
            // Generic over ENGINE_PACKAGES so adding one needs no new rule here.
            // Anchored on the closing quote so `@pretense/scanner-rs` is NOT
            // caught by the `scanner` entry.
            new RegExp(`(["'])@pretense/(${ENGINE_PACKAGES.map((p) => p.name).join("|")})\\1`, "g"),
            (_m, _q, name) => `"${rel(dir, join(stageDir, name, "index.ts"))}"`,
          );
        if (after !== before) writeFileSync(p, after);
      }
    }
  };
  rewrite(stageDir);

  return stageDir;
}

function pct(hits, n) {
  return n === 0 ? "  n/a" : `${((hits / n) * 100).toFixed(1).padStart(5)}%`;
}

/**
 * Parse an optional `--framework <NAME>` flag, scoping the run to one compliance
 * framework's data. Validates against the taxonomy's framework list and exits
 * with a clear message on a missing/unknown name.
 */
export function parseFrameworkArg(argv, frameworks) {
  // Accept both `--framework NAME` and `--framework=NAME`.
  let name = null;
  const eq = argv.find((a) => a.startsWith("--framework="));
  if (eq) {
    name = eq.slice("--framework=".length);
  } else {
    const i = argv.indexOf("--framework");
    if (i === -1) return null;
    name = argv[i + 1];
  }
  if (!name) {
    console.error("--framework requires a name, e.g. --framework HIPAA");
    process.exit(2);
  }
  if (!frameworks.includes(name)) {
    console.error(
      `unknown framework '${name}'.\nValid frameworks: ${frameworks.join(", ")}`,
    );
    process.exit(2);
  }
  return name;
}

/**
 * Pure scoring core: run each case through the engine's `scan` (identify) and
 * `mutate`, tallying per-difficulty-tier and per-framework identify/mutate
 * coverage. Kept free of I/O and engine loading so it is unit-testable with a
 * mock engine (see run.test.mjs). A case counts toward every framework its
 * `kind` maps to (kinds may map to more than one).
 *
 * @param {Array<object>} cases  corpus cases ({ text, difficulty, kind }).
 * @param {object} deps
 * @param {string[]} deps.frameworks  ordered framework list.
 * @param {Record<string,string[]>} deps.kindFrameworks  kind -> frameworks.
 * @param {(text:string)=>{matches?:unknown[]}} deps.scan  identify fn.
 * @param {(text:string,lang:string)=>{stats?:{tokensMutated?:number},mutatedCode?:string}} deps.mutate  mutate fn.
 * @returns {{tiers:Map, overall:{n:number,identify:number,mutate:number}, fw:Map}}
 */
export function scoreCorpus(cases, { frameworks, kindFrameworks, scan, mutate }) {
  const tiers = new Map();
  const overall = { n: 0, identify: 0, mutate: 0 };
  const fw = new Map(
    frameworks.map((name) => [name, { n: 0, identify: 0, mutate: 0 }]),
  );

  for (const c of cases) {
    const text = c.text ?? "";
    const tier = c.difficulty ?? "?";
    if (!tiers.has(tier)) tiers.set(tier, { n: 0, identify: 0, mutate: 0 });
    const t = tiers.get(tier);

    const scanRes = scan(text);
    const identified = (scanRes.matches?.length ?? 0) > 0;

    const mutRes = mutate(text, "typescript");
    const mutated =
      (mutRes.stats?.tokensMutated ?? 0) > 0 ||
      (mutRes.mutatedCode !== undefined && mutRes.mutatedCode !== text);

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

    for (const name of kindFrameworks[c.kind] ?? []) {
      const f = fw.get(name);
      if (!f) continue; // kind maps to a framework not in the ordered list
      f.n += 1;
      if (identified) f.identify += 1;
      if (mutated) f.mutate += 1;
    }
  }

  return { tiers, overall, fw };
}

async function main() {
  // Graceful skip FIRST, before reading any data file, so the no-engine path
  // stays a clean exit 0 even if the corpus / compliance map are not present.
  if (!existsSync(PRETENSE_SRC)) {
    console.log(`pretense engine not found at ${PRETENSE_SRC}; skipping`);
    process.exit(0);
  }

  const stageDir = stageEngine(PRETENSE_SRC);
  // The shipped engine exposes `mutate` from @pretense/mutator and `scan` from
  // @pretense/scanner — not from flat `mutator.ts` / `secrets.ts` files.
  const { mutate } = await import(pathToFileURL(join(stageDir, "mutator", "index.ts")).href);
  const { scan } = await import(pathToFileURL(join(stageDir, "scanner", "index.ts")).href);

  // Engine modules are loaded; the staged copies are no longer needed.
  rmSync(stageDir, { recursive: true, force: true });

  // Compliance taxonomy: ordered framework list + kind -> frameworks map.
  const compliance = JSON.parse(readFileSync(COMPLIANCE_PATH, "utf8"));
  const frameworks = compliance.frameworks ?? [];
  const kindFrameworks = compliance.kind_frameworks ?? {};

  const fwArg = parseFrameworkArg(process.argv, frameworks);

  const corpus = JSON.parse(readFileSync(CORPUS_PATH, "utf8"));
  const allCases = corpus.cases ?? [];
  // With --framework, scan only the cases whose kind maps to that framework.
  const cases = fwArg
    ? allCases.filter((c) => (kindFrameworks[c.kind] ?? []).includes(fwArg))
    : allCases;
  if (fwArg) {
    console.log(
      `Scoped to framework: ${fwArg} (${cases.length} of ${allCases.length} cases)\n`,
    );
  }

  const { tiers, overall, fw } = scoreCorpus(cases, {
    frameworks,
    kindFrameworks,
    scan,
    mutate,
  });

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

  // Per-framework coverage: how well pretense protects each compliance
  // framework's data, over the cases whose `kind` maps to that framework.
  console.log("\nPer-framework coverage (cases whose kind maps to the framework)");
  console.log("framework  |   n | identify | mutate");
  console.log("-----------+-----+----------+-------");
  for (const name of frameworks) {
    const f = fw.get(name);
    console.log(
      `${name.padEnd(10)} | ${String(f.n).padStart(3)} |   ${pct(
        f.identify,
        f.n,
      )} | ${pct(f.mutate, f.n)}`,
    );
  }
  console.log("-----------+-----+----------+-------");

  process.exit(0);
}

// Only run the benchmark when invoked directly (`node run.mjs`), not when this
// module is imported for its exports (scoreCorpus / parseFrameworkArg) by tests.
// argv[1] is realpath-resolved to match the realpath-based import.meta.url, so a
// symlinked invocation (`node /path/to/link-to-run.mjs`) still runs main().
function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    return false; // entry not on disk (e.g. a REPL/eval context)
  }
}

if (invokedDirectly()) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
