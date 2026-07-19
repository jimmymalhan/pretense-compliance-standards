#!/usr/bin/env node
/**
 * Pretense EGRESS-REDACTION benchmark bridge.
 *
 * Drives the synthetic DLP corpus through the REAL, SHIPPED pretense engine and
 * reports what the product actually protects.
 *
 * ─── PRIMARY METRIC: EGRESS REDACTION ────────────────────────────────────────
 * "What fraction of sensitive values actually left the proxy TRANSFORMED."
 * Computed the way `apps/proxy/src/server.ts` really behaves — a case counts
 * ONLY when ALL of the following hold:
 *   1. a match whose detector KIND AGREES with the case's expected kind, AND
 *   2. that match's action is one the proxy acts on — {block, redact, mutate}
 *      (`warn`/`pass` matches are SKIPPED by the proxy: see toSecretFindings),
 *      AND
 *   3. that match has a REAL, NON-ZERO span (end > start) — a zero-span
 *      deobfuscation-only hit can never be spliced and is stripped by
 *      `egressSafe: true`, so it protects NOTHING, AND
 *   4. the REAL redaction path `mutateSecrets(text, findings)` (the exact
 *      function the proxy calls) produced output in which the matched value is
 *      VERIFIABLY GONE.
 *
 * ─── SECONDARY METRIC: IDENTIFY ──────────────────────────────────────────────
 * "The detector recognized this datum for what it IS" — a kind-agreeing match
 * of any action/span. Identify is NOT protection: a `warn` match and a
 * zero-span match both read as identified while the data egresses in plaintext.
 * Never quote identify as a protection or compliance number.
 *
 * ─── WRONG-KIND ──────────────────────────────────────────────────────────────
 * A case with matches but NO kind-agreeing match (e.g. an NPI or a UK NHS
 * number caught by the `phone-us` detector). These are counted and reported in
 * their own column, never silently folded into identify: scoring them as
 * coverage manufactures FALSE COMPLIANCE CREDIT for a framework whose data is,
 * in fact, egressing in plaintext.
 *
 * ─── ANTI-INFLATION RULES (do not "fix" these by relaxing them) ──────────────
 * This harness measures a product. Every ambiguous case resolves AGAINST the
 * product, and every misconfiguration is a LOUD FAILURE, never a silent
 * fallback that yields a good-looking number:
 *   • It measures the SHIPPED engine (`packages/scanner` -> `@pretense/scanner`)
 *     and hard-fails if pointed anywhere else. `packages/cli/src` is a
 *     NON-SHIPPED copy that scores several points higher; measuring it has
 *     burned this project repeatedly.
 *   • It refuses to run against a STALE corpus: the builder is re-run first.
 *   • Every report header names the engine, package, version and git commit
 *     actually measured, plus the case count.
 *
 * All corpus input is synthetic, fake, and banner-marked.
 *
 * Run:
 *   node pretense_compliance_standards/pretense_bridge/run.mjs
 *   node pretense_compliance_standards/pretense_bridge/run.mjs --framework HIPAA
 *   node pretense_compliance_standards/pretense_bridge/run.mjs --json
 */

import { existsSync, readFileSync, realpathSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = join(HERE, "..");
const REPO_ROOT = join(PKG_ROOT, "..");

// ─── The SHIPPED engine ──────────────────────────────────────────────────────

/**
 * The one true engine under test. `pretense`'s shipped CLI/proxy binary builds
 * from `packages/scanner` (published as `@pretense/scanner`). The default is a
 * SIBLING checkout of the product repo.
 *
 * NOTE the deliberate `??` (not `||`): an exported-but-empty `PRETENSE_SRC=` is
 * a MISCONFIGURATION and must surface as one, not silently become the default.
 * Silently defaulting is exactly how a bad config produces a good-looking
 * number.
 */
const DEFAULT_SCANNER_DIR = resolve(REPO_ROOT, "..", "pretense", "packages", "scanner");
const SCANNER_DIR_RAW = process.env.PRETENSE_SRC ?? null;
const SCANNER_DIR = resolve(SCANNER_DIR_RAW ?? DEFAULT_SCANNER_DIR);

const SHIPPED_SCANNER_PKG = "@pretense/scanner";
const SHIPPED_MUTATOR_PKG = "@pretense/mutator";

/**
 * Scanner options the proxy uses on the egress path, copied verbatim from
 * `apps/proxy/src/server.ts`. Measuring with different options measures
 * something the product never does.
 */
const PROXY_SCAN_OPTS = Object.freeze({
  contextAware: true,
  entropyAnalysis: false,
  deobfuscate: false,
  egressSafe: true,
});

/** Actions the proxy actually acts on. `warn`/`pass` are skipped entirely. */
const PROXY_ACTIONS = Object.freeze(new Set(["block", "redact", "mutate"]));

const CORPUS_PATH = join(PKG_ROOT, "corpus", "cases.json");
const COMPLIANCE_PATH = join(PKG_ROOT, "compliance_map.json");
const KIND_DETECTORS_PATH = join(PKG_ROOT, "kind_detectors.json");

function die(msg) {
  console.error(`\n[bridge] FATAL: ${msg}\n`);
  process.exit(2);
}

function readJson(path, what) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    die(`could not read ${what} at ${path}\n  ${err.message}`);
  }
}

function git(cwd, args) {
  try {
    return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}

/**
 * Resolve + VALIDATE the engine under test. Fails loudly on anything that is
 * not the shipped, built `@pretense/scanner` — there is deliberately NO
 * fallback path, because a fallback is how you end up measuring the wrong
 * engine and reporting an inflated number.
 */
function resolveEngine() {
  if (SCANNER_DIR_RAW !== null && SCANNER_DIR_RAW.trim() === "") {
    die(
      "PRETENSE_SRC is set but EMPTY.\n" +
        "  Refusing to guess. Either unset it (to use the default sibling checkout)\n" +
        `  or point it at the shipped scanner package: <pretense>/packages/scanner`,
    );
  }

  if (!existsSync(SCANNER_DIR)) {
    if (SCANNER_DIR_RAW !== null) {
      die(`PRETENSE_SRC points at a path that does not exist:\n  ${SCANNER_DIR}`);
    }
    // Engine genuinely not checked out and nothing was configured: SKIP.
    // A skip prints NO numbers — it can never be mistaken for a passing run.
    console.log(
      `[bridge] SKIPPED — no pretense checkout at ${SCANNER_DIR}\n` +
        "[bridge] No measurement was performed. Clone pretense as a sibling to measure.",
    );
    process.exit(0);
  }

  const pkgPath = join(SCANNER_DIR, "package.json");
  if (!existsSync(pkgPath)) {
    die(
      `${SCANNER_DIR} is not a node package (no package.json).\n` +
        `  Expected the SHIPPED scanner package: <pretense>/packages/scanner\n` +
        `  If you pointed this at packages/cli/src — that is the NON-SHIPPED copy. See below.\n` +
        wrongEngineHelp(),
    );
  }

  const pkg = readJson(pkgPath, "scanner package.json");
  if (pkg.name !== SHIPPED_SCANNER_PKG) {
    die(
      `wrong engine. ${SCANNER_DIR}\n` +
        `  is package '${pkg.name}', but the SHIPPED engine is '${SHIPPED_SCANNER_PKG}'.\n` +
        wrongEngineHelp(),
    );
  }

  const scannerEntry = join(SCANNER_DIR, "dist", "index.js");
  if (!existsSync(scannerEntry)) {
    die(
      `the shipped scanner is not built: ${scannerEntry} missing.\n` +
        "  The harness measures the BUILT artifact (what ships), never loose sources.\n" +
        "  Build it in the pretense checkout:\n" +
        "    pnpm install && pnpm --filter @pretense/compliance-engine --filter @pretense/scanner --filter @pretense/mutator build",
    );
  }

  // The real redaction path lives in the sibling mutator package.
  const mutatorDir = resolve(SCANNER_DIR, "..", "mutator");
  const mutatorPkgPath = join(mutatorDir, "package.json");
  if (!existsSync(mutatorPkgPath)) {
    die(`shipped mutator package not found next to the scanner:\n  ${mutatorDir}`);
  }
  const mutatorPkg = readJson(mutatorPkgPath, "mutator package.json");
  if (mutatorPkg.name !== SHIPPED_MUTATOR_PKG) {
    die(`wrong mutator package: '${mutatorPkg.name}' (expected '${SHIPPED_MUTATOR_PKG}') at ${mutatorDir}`);
  }
  const mutatorEntry = join(mutatorDir, "dist", "index.js");
  if (!existsSync(mutatorEntry)) {
    die(
      `the shipped mutator is not built: ${mutatorEntry} missing.\n` +
        "  Build it: pnpm --filter @pretense/mutator build",
    );
  }

  const productRoot = resolve(SCANNER_DIR, "..", "..");
  return {
    scannerEntry,
    mutatorEntry,
    provenance: {
      scannerPkg: `${pkg.name}@${pkg.version ?? "?"}`,
      mutatorPkg: `${mutatorPkg.name}@${mutatorPkg.version ?? "?"}`,
      scannerDir: SCANNER_DIR,
      productRoot,
      commit: git(productRoot, ["rev-parse", "--short", "HEAD"]) ?? "unknown",
      branch: git(productRoot, ["rev-parse", "--abbrev-ref", "HEAD"]) ?? "unknown",
      dirty: git(productRoot, ["status", "--porcelain"]) ? "DIRTY" : "clean",
      configuredVia: SCANNER_DIR_RAW === null ? "default (sibling checkout)" : "PRETENSE_SRC",
    },
  };
}

function wrongEngineHelp() {
  return (
    "\n  ── THE DUAL-ENGINE TRAP ──────────────────────────────────────────────\n" +
    "  pretense contains TWO scanner implementations:\n" +
    "    packages/scanner   -> @pretense/scanner   ← SHIPPED. The binary builds this.\n" +
    "    packages/cli/src   -> a NON-SHIPPED copy  ← scores HIGHER. Measuring it\n" +
    "                                                 reports a number the product\n" +
    "                                                 does not deliver.\n" +
    "  This harness measures ONLY the shipped engine, by design.\n" +
    "  Set PRETENSE_SRC=<pretense>/packages/scanner or leave it unset.\n"
  );
}

// ─── Corpus freshness ────────────────────────────────────────────────────────

/**
 * ALWAYS regenerate the corpus before measuring. The per-framework and flat
 * `cases.json` files are committed BUILD ARTIFACTS and have been stale before
 * (452 committed vs 648 real), which silently changes every number in the
 * report. If the builder cannot run we HARD-FAIL rather than quietly measuring
 * a stale corpus.
 */
function regenerateCorpus() {
  if (process.argv.includes("--no-regenerate")) {
    if (!existsSync(CORPUS_PATH)) die("--no-regenerate given but no corpus exists.");
    console.error(
      "[bridge] WARNING: --no-regenerate — measuring a possibly STALE committed corpus.\n" +
        "[bridge] The reported case count may not match the builder. Do not publish these numbers.",
    );
    return { regenerated: false };
  }
  const attempts = [
    ["uv", ["run", "python", "-m", "pretense_compliance_standards.corpus_builder"]],
    ["python3", ["-m", "pretense_compliance_standards.corpus_builder"]],
  ];
  const errors = [];
  for (const [cmd, args] of attempts) {
    try {
      execFileSync(cmd, args, { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
      return { regenerated: true, via: cmd };
    } catch (err) {
      errors.push(`${cmd}: ${(err.stderr || err.message || "").toString().trim().split("\n").slice(-3).join(" | ")}`);
    }
  }
  die(
    "could not regenerate the corpus, and refusing to measure a stale one.\n" +
      "  Run `uv sync` in the harness repo, then retry.\n  Attempts:\n    " +
      errors.join("\n    "),
  );
}

// ─── Scoring ─────────────────────────────────────────────────────────────────

function pct(hits, n) {
  return n === 0 ? "   n/a" : `${((hits / n) * 100).toFixed(1).padStart(5)}%`;
}

export function parseFrameworkArg(argv, frameworks) {
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
    console.error(`unknown framework '${name}'.\nValid frameworks: ${frameworks.join(", ")}`);
    process.exit(2);
  }
  return name;
}

const emptyTally = () => ({ n: 0, egress: 0, identify: 0, wrongKind: 0, miss: 0 });

/**
 * Classify ONE case exactly as the proxy would treat it.
 *
 * @returns {{egress:boolean, identify:boolean, wrongKind:boolean, matched:boolean}}
 */
export function classifyCase(c, { kindDetectors, scan, mutateSecrets }) {
  const text = c.text ?? "";
  const allowed = kindDetectors[c.kind];
  if (allowed === undefined) {
    // A corpus kind with no declared detector mapping would otherwise score an
    // arbitrary number. Fail loudly so new kinds must be classified explicitly.
    throw new Error(
      `corpus kind '${c.kind}' has no entry in kind_detectors.json.\n` +
        "  Add it (use [] if the shipped engine genuinely has no detector for it).\n" +
        "  Refusing to score an unclassified kind.",
    );
  }
  const allowedSet = new Set(allowed);

  const matches = scan(text, PROXY_SCAN_OPTS).matches ?? [];
  const matched = matches.length > 0;

  // IDENTIFY (secondary): a kind-agreeing match of ANY action/span.
  const kindAgreeing = matches.filter((m) => allowedSet.has(m.type));
  const identify = kindAgreeing.length > 0;

  // WRONG-KIND: matched something, but nothing that means the right datum.
  const wrongKind = matched && !identify;

  // EGRESS (primary): reproduce the proxy's own filter, then the REAL
  // redaction path, then VERIFY the value is actually gone from the output.
  const actionable = matches.filter((m) => PROXY_ACTIONS.has(m.action) && m.end > m.start);
  let egress = false;
  if (actionable.length > 0) {
    const findings = actionable.map((m) => ({
      value: m.value,
      offset: m.start,
      length: m.end - m.start,
      type: m.type,
    }));
    const { content } = mutateSecrets(text, findings);
    // Only a KIND-AGREEING, actionable, real-span match whose value is
    // verifiably absent from the redacted output counts as protection.
    egress = actionable.some((m) => allowedSet.has(m.type) && m.value.length > 0 && !content.includes(m.value));
  }

  return { egress, identify, wrongKind, matched };
}

/**
 * Score the whole corpus, tallying per difficulty tier and per framework.
 * Pure (no I/O, no engine loading) so it is unit-testable with a mock engine.
 */
export function scoreCorpus(cases, { frameworks, kindFrameworks, kindDetectors, scan, mutateSecrets }) {
  const tiers = new Map();
  const overall = emptyTally();
  const fw = new Map(frameworks.map((name) => [name, emptyTally()]));
  const wrongKindByKind = new Map();

  for (const c of cases) {
    const tier = c.difficulty ?? "?";
    if (!tiers.has(tier)) tiers.set(tier, emptyTally());
    const t = tiers.get(tier);

    const r = classifyCase(c, { kindDetectors, scan, mutateSecrets });

    for (const bucket of [t, overall]) {
      bucket.n += 1;
      if (r.egress) bucket.egress += 1;
      if (r.identify) bucket.identify += 1;
      if (r.wrongKind) bucket.wrongKind += 1;
      if (!r.matched) bucket.miss += 1;
    }
    if (r.wrongKind) wrongKindByKind.set(c.kind, (wrongKindByKind.get(c.kind) ?? 0) + 1);

    for (const name of kindFrameworks[c.kind] ?? []) {
      const f = fw.get(name);
      if (!f) continue;
      f.n += 1;
      if (r.egress) f.egress += 1;
      if (r.identify) f.identify += 1;
      if (r.wrongKind) f.wrongKind += 1;
      if (!r.matched) f.miss += 1;
    }
  }

  return { tiers, overall, fw, wrongKindByKind };
}

// ─── Report ──────────────────────────────────────────────────────────────────

function printHeader(prov, corpusInfo, caseCount) {
  console.log("=".repeat(78));
  console.log("Pretense EGRESS-REDACTION benchmark  (synthetic DLP corpus)");
  console.log("=".repeat(78));
  console.log(`  engine        : ${prov.scannerPkg}   [SHIPPED]`);
  console.log(`  redaction     : ${prov.mutatorPkg}  (mutateSecrets — the proxy's own path)`);
  console.log(`  product repo  : ${prov.productRoot}`);
  console.log(`  commit        : ${prov.commit} (${prov.branch}) [${prov.dirty}]`);
  console.log(`  engine path   : ${prov.scannerDir}`);
  console.log(`  configured via: ${prov.configuredVia}`);
  console.log(`  scan options  : ${JSON.stringify(PROXY_SCAN_OPTS)}`);
  console.log(`  proxy actions : {${[...PROXY_ACTIONS].join(", ")}}  (warn/pass are NOT acted on)`);
  console.log(
    `  corpus        : ${caseCount} cases — ${corpusInfo.regenerated ? `REGENERATED via ${corpusInfo.via}` : "NOT regenerated (STALE RISK)"}`,
  );
  console.log("=".repeat(78));
  console.log("");
  console.log("  PRIMARY   egress = value verifiably left TRANSFORMED (kind-agreeing,");
  console.log("            proxy-actionable, real span, replacement verified).");
  console.log("  SECONDARY ident. = detector recognized the datum. NOT protection:");
  console.log("            warn-action and zero-span hits identify but protect nothing.");
  console.log("  wrong-kind = matched, but as the WRONG datum (no compliance credit).");
  console.log("");
}

function row(label, t, width) {
  return (
    `${String(label).padEnd(width)} | ${String(t.n).padStart(4)} | ${pct(t.egress, t.n)} | ${pct(t.identify, t.n)} | ` +
    `${String(t.wrongKind).padStart(5)} | ${String(t.miss).padStart(4)}`
  );
}

function table(title, labelHdr, width, rows) {
  const bar = `${"-".repeat(width)}-+------+--------+--------+-------+-----`;
  console.log(title);
  console.log(`${labelHdr.padEnd(width)} |    n | egress | ident. | wrong | miss`);
  console.log(bar);
  for (const [label, t] of rows) console.log(row(label, t, width));
  console.log(bar);
}

async function main() {
  const engine = resolveEngine();
  const corpusInfo = regenerateCorpus();

  const { scan } = await import(pathToFileURL(engine.scannerEntry).href);
  const { mutateSecrets } = await import(pathToFileURL(engine.mutatorEntry).href);
  if (typeof scan !== "function") die(`${SHIPPED_SCANNER_PKG} does not export scan()`);
  if (typeof mutateSecrets !== "function") die(`${SHIPPED_MUTATOR_PKG} does not export mutateSecrets()`);

  const compliance = readJson(COMPLIANCE_PATH, "compliance map");
  const frameworks = compliance.frameworks ?? [];
  const kindFrameworks = compliance.kind_frameworks ?? {};
  const kindDetectors = readJson(KIND_DETECTORS_PATH, "kind->detector map").kind_detectors ?? {};

  const fwArg = parseFrameworkArg(process.argv, frameworks);

  const corpus = readJson(CORPUS_PATH, "corpus");
  const allCases = corpus.cases ?? [];
  const cases = fwArg ? allCases.filter((c) => (kindFrameworks[c.kind] ?? []).includes(fwArg)) : allCases;

  const { tiers, overall, fw, wrongKindByKind } = scoreCorpus(cases, {
    frameworks,
    kindFrameworks,
    kindDetectors,
    scan,
    mutateSecrets,
  });

  if (process.argv.includes("--json")) {
    console.log(
      JSON.stringify(
        {
          engine: engine.provenance,
          scanOptions: PROXY_SCAN_OPTS,
          corpus: { ...corpusInfo, cases: overall.n, totalCases: allCases.length },
          framework: fwArg,
          overall,
          tiers: Object.fromEntries(tiers),
          frameworks: Object.fromEntries(fw),
          wrongKindByKind: Object.fromEntries(wrongKindByKind),
        },
        null,
        2,
      ),
    );
    process.exit(0);
  }

  printHeader(engine.provenance, corpusInfo, allCases.length);
  if (fwArg) console.log(`Scoped to framework: ${fwArg} (${cases.length} of ${allCases.length} cases)\n`);

  table(
    "By difficulty tier",
    "tier",
    10,
    [...tiers.keys()].sort((a, b) => (a > b ? 1 : -1)).map((k) => [k, tiers.get(k)]),
  );
  console.log(row("ALL", overall, 10));
  console.log("");

  table(
    "Per-framework coverage (cases whose kind maps to the framework)",
    "framework",
    12,
    frameworks.map((name) => [name, fw.get(name)]),
  );
  console.log("");

  console.log("Wrong-kind matches by data kind (detected as the WRONG datum — no credit)");
  console.log("kind                     | cases");
  console.log("-------------------------+------");
  const wk = [...wrongKindByKind.entries()].sort((a, b) => b[1] - a[1]);
  if (wk.length === 0) console.log("(none)");
  for (const [kind, n] of wk) console.log(`${kind.padEnd(24)} | ${String(n).padStart(5)}`);
  console.log("-------------------------+------");
  console.log(
    `TOTAL wrong-kind: ${overall.wrongKind} of ${overall.n} cases ` +
      `(${((overall.wrongKind / Math.max(overall.n, 1)) * 100).toFixed(1)}%)`,
  );
  console.log("");
  console.log(
    `HEADLINE — egress redaction: ${pct(overall.egress, overall.n).trim()}  ` +
      `(identify, secondary: ${pct(overall.identify, overall.n).trim()})`,
  );

  process.exit(0);
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
