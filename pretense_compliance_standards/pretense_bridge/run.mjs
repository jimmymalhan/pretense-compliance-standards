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
 *   • It reports FALSE POSITIVES on the benign look-alike corpus next to the
 *     headline. Recall alone is trivially gamed by a detector that flags
 *     everything; precision is what stops that.
 *
 * ─── ANTI-STALENESS RULES ────────────────────────────────────────────────────
 * UNDERSTATING the product is as much a bug as inflating it: a benchmark that
 * scores a real fix as a no-op gets the fix reverted. Two hand-maintained copies
 * of product facts did exactly that, so neither is maintained by hand any more:
 *   • The proxy's egress SCAN OPTIONS are DERIVED from `apps/proxy/src/server.ts`
 *     on every run (`deriveProxyScanOpts`). A hardcoded copy went stale when
 *     pretense #524 flipped `deobfuscate` to true, and the harness reported
 *     tiers 3-5 at 0.0% — a 30-point understatement.
 *   • The kind->detector MAP is VALIDATED against the engine's exported
 *     `ALL_PATTERNS` on every run (`validateKindDetectors`). A stale map scored
 *     20 correctly-redacted NPI/NHS cases as wrong-kind after pretense #521
 *     shipped detectors for them — a 4-point understatement.
 * Both fail HARD (exit 2, no numbers printed) rather than measuring an
 * unverified configuration, and every judgment call must carry a written reason.
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
 * Where the proxy's egress scan lives, relative to the product repo root. The
 * options passed at this call site are DERIVED at run time — see
 * `deriveProxyScanOpts`. This harness deliberately keeps NO hardcoded copy.
 */
const PROXY_SERVER_REL = join("apps", "proxy", "src", "server.ts");

/** Actions the proxy actually acts on. `warn`/`pass` are skipped entirely. */
const PROXY_ACTIONS = Object.freeze(new Set(["block", "redact", "mutate"]));

const CORPUS_PATH = join(PKG_ROOT, "corpus", "cases.json");
const NEGATIVES_PATH = join(PKG_ROOT, "corpus", "negatives.json");
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
    // The scanner's own built type declarations — the authority on which scan
    // options exist. Used to validate what the proxy passes.
    scannerDts: join(SCANNER_DIR, "dist", "index.d.ts"),
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

// ─── The proxy's REAL scan options (derived, never copied) ───────────────────

/**
 * Blank out comments, string/template literals and regex literals, replacing
 * each with spaces so that every byte offset (and therefore every line number)
 * is preserved. Newlines survive.
 *
 * String awareness is NOT optional here: `apps/proxy/src/server.ts` contains
 * `app.all("/*", ...)`, and a naive comment stripper reads that `/*` as the
 * start of a block comment and silently erases the rest of the file — including
 * the very call site this harness must read. Erasing it must never look like
 * "the proxy has no scan call"; it looks like a bug in this function, so the
 * function is written to not have one.
 */
export function blankNonCode(src) {
  const out = Array.from(src);
  const blank = (from, to) => {
    for (let k = from; k < to && k < out.length; k += 1) if (out[k] !== "\n") out[k] = " ";
  };
  // A `/` starts a regex literal (rather than division) only where a value
  // cannot legally precede it.
  const REGEX_PRECEDERS = new Set(["(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-", "*", "%", "~", "^", "<", ">", "\n"]);
  let prevMeaningful = "\n";
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    const two = src.slice(i, i + 2);

    if (two === "//") {
      const nl = src.indexOf("\n", i);
      const end = nl === -1 ? src.length : nl;
      blank(i, end);
      i = end;
      continue;
    }
    if (two === "/*") {
      const close = src.indexOf("*/", i + 2);
      const end = close === -1 ? src.length : close + 2;
      blank(i, end);
      i = end;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      let j = i + 1;
      while (j < src.length) {
        if (src[j] === "\\") {
          j += 2;
          continue;
        }
        if (src[j] === ch) break;
        // An unterminated single/double quote would otherwise run to EOF.
        if (ch !== "`" && src[j] === "\n") break;
        j += 1;
      }
      blank(i, Math.min(j + 1, src.length));
      i = Math.min(j + 1, src.length);
      prevMeaningful = "x";
      continue;
    }
    if (ch === "/" && REGEX_PRECEDERS.has(prevMeaningful)) {
      let j = i + 1;
      let inClass = false;
      let closed = false;
      while (j < src.length && src[j] !== "\n") {
        if (src[j] === "\\") {
          j += 2;
          continue;
        }
        if (src[j] === "[") inClass = true;
        else if (src[j] === "]") inClass = false;
        else if (src[j] === "/" && !inClass) {
          closed = true;
          break;
        }
        j += 1;
      }
      if (closed) {
        blank(i, j + 1);
        i = j + 1;
        prevMeaningful = "x";
        continue;
      }
    }
    if (!/\s/.test(ch)) prevMeaningful = ch;
    else if (ch === "\n") prevMeaningful = prevMeaningful === "\n" ? "\n" : prevMeaningful;
    i += 1;
  }
  return out.join("");
}

/**
 * The set of option names the SHIPPED scanner actually understands, read out of
 * its own built type declarations (`dist/index.d.ts`). Any option the proxy
 * passes that is not in here means the harness is reading a scanner and a proxy
 * that do not belong together — a loud failure, never a guess.
 */
export function parseScanOptionKeys(dts) {
  const start = dts.search(/(?:export\s+)?(?:declare\s+)?interface\s+ScanOptions\s*\{/);
  if (start === -1) return null;
  const open = dts.indexOf("{", start);
  let depth = 0;
  let end = -1;
  for (let i = open; i < dts.length; i += 1) {
    if (dts[i] === "{") depth += 1;
    else if (dts[i] === "}") {
      depth -= 1;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end === -1) return null;
  const body = blankNonCode(dts.slice(open + 1, end));
  const keys = new Set();
  // Only top-level members: skip anything nested inside a member's own braces.
  let nest = 0;
  for (const line of body.split("\n")) {
    if (nest === 0) {
      const m = line.match(/^\s*(?:readonly\s+)?([A-Za-z_$][\w$]*)\s*\??\s*:/);
      if (m) keys.add(m[1]);
    }
    nest += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
    if (nest < 0) nest = 0;
  }
  return keys.size > 0 ? keys : null;
}

/**
 * Parse ONE inline object literal of the form `{ key: true, key2: false }`.
 * Returns `{ ok: true, value }` or `{ ok: false, reason }`. Anything that is not
 * a plain `identifier: boolean` pair — a spread, a variable, a ternary, a nested
 * object — is REFUSED rather than approximated: the harness must either know
 * exactly what the proxy passes or say that it does not.
 */
export function parseBooleanObjectLiteral(body) {
  const value = {};
  const parts = body
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (parts.length === 0) return { ok: false, reason: "the option object is empty" };
  for (const part of parts) {
    const m = part.match(/^([A-Za-z_$][\w$]*)\s*:\s*(true|false)$/);
    if (!m) {
      return {
        ok: false,
        reason: `cannot statically evaluate the option \`${part}\` — the harness only understands \`name: true|false\``,
      };
    }
    if (Object.prototype.hasOwnProperty.call(value, m[1])) {
      return { ok: false, reason: `option \`${m[1]}\` is specified twice` };
    }
    value[m[1]] = m[2] === "true";
  }
  return { ok: true, value };
}

/**
 * DERIVE the scan options the proxy actually passes on the egress path, by
 * reading `apps/proxy/src/server.ts` in the product checkout under test.
 *
 * ─── WHY THIS IS NOT A CONSTANT ──────────────────────────────────────────────
 * It used to be one, copied by hand out of the proxy. The proxy then changed
 * (`deobfuscate: false` -> `true`, pretense #524) and the copy did not. The
 * harness went on measuring an egress path the product had stopped running and
 * reported tiers 3-5 at 0.0%, scoring a real 30-point improvement as a no-op.
 * A number that UNDERSTATES the product is exactly as much a bug as one that
 * inflates it: it gets real fixes reverted.
 *
 * So: the proxy source is the single source of truth, and every way this can go
 * wrong is a hard failure with a pointer at the call site —
 *   • proxy file missing              -> die
 *   • no `scan(x, {...})` call        -> die (the egress path was restructured)
 *   • more than one                   -> die (which one is egress? refuse to guess)
 *   • a non-literal option value      -> die (cannot be evaluated statically)
 *   • an option the scanner's own d.ts does not declare -> die (mismatched pair)
 * There is deliberately no default and no fallback: a misconfiguration must
 * never be able to produce a plausible-looking number.
 */
export function deriveProxyScanOpts(productRoot, { readFile = (p) => readFileSync(p, "utf8") } = {}) {
  const proxyPath = join(productRoot, PROXY_SERVER_REL);
  if (!existsSync(proxyPath)) {
    die(
      `cannot derive the proxy's scan options: ${proxyPath} not found.\n` +
        "  The harness reads the egress scan options out of the shipped proxy source\n" +
        "  rather than keeping a copy that can go stale. Point PRETENSE_SRC at a\n" +
        "  FULL pretense checkout (<pretense>/packages/scanner), not a bare package.",
    );
  }

  const raw = readFile(proxyPath);
  const src = blankNonCode(raw);

  const callRe = /\bscan\s*\(([^(),]*),\s*\{([^{}]*)\}\s*\)/g;
  const found = [];
  for (const m of src.matchAll(callRe)) {
    found.push({ index: m.index, arg: m[1].trim(), body: m[2] });
  }

  // Every `scan(` in the file must be one we parsed. A call we cannot read
  // might be THE egress call, and silently ignoring it is how the stale copy
  // survived for so long.
  const allCalls = [...src.matchAll(/\bscan\s*\(/g)].length;
  const lineOf = (idx) => src.slice(0, idx).split("\n").length;

  if (found.length === 0 || allCalls !== found.length) {
    die(
      `could not derive the proxy's egress scan options from ${PROXY_SERVER_REL}.\n` +
        `  Found ${allCalls} \`scan(\` call(s), of which ${found.length} had a parseable inline\n` +
        "  option literal of the form `scan(text, { ... })`.\n" +
        "  The proxy's egress path has been restructured. Update deriveProxyScanOpts()\n" +
        "  to match the new shape — do NOT re-introduce a hardcoded copy of the options.",
    );
  }
  if (found.length > 1) {
    die(
      `${PROXY_SERVER_REL} has ${found.length} \`scan(text, {...})\` call sites ` +
        `(lines ${found.map((f) => lineOf(f.index)).join(", ")}).\n` +
        "  The harness cannot tell which one is the EGRESS path, and refuses to guess.\n" +
        "  Teach deriveProxyScanOpts() how to identify the egress call site.",
    );
  }

  const site = found[0];
  const line = lineOf(site.index);
  const parsed = parseBooleanObjectLiteral(site.body);
  if (!parsed.ok) {
    die(
      `cannot derive the proxy's egress scan options from ${PROXY_SERVER_REL}:${line}\n` +
        `  ${parsed.reason}.\n` +
        "  Refusing to measure with options that may differ from the product's.",
    );
  }

  return { opts: Object.freeze(parsed.value), source: `${PROXY_SERVER_REL}:${line}` };
}

/**
 * Cross-check the derived options against the SHIPPED scanner's own declared
 * option surface. Catches the case where the proxy source and the scanner
 * package come from different checkouts/versions.
 */
export function assertOptionsUnderstoodByScanner(opts, dtsPath, source) {
  if (!existsSync(dtsPath)) {
    die(
      `the shipped scanner has no type declarations at ${dtsPath}.\n` +
        "  The harness validates the proxy's scan options against them. Rebuild:\n" +
        "    pnpm --filter @pretense/scanner build",
    );
  }
  const keys = parseScanOptionKeys(readFileSync(dtsPath, "utf8"));
  if (!keys) {
    die(
      `could not find \`interface ScanOptions\` in ${dtsPath}.\n` +
        "  The harness cannot validate the proxy's scan options against the shipped\n" +
        "  scanner, so it refuses to run rather than measure an unverified config.",
    );
  }
  const unknown = Object.keys(opts).filter((k) => !keys.has(k));
  if (unknown.length > 0) {
    die(
      `the proxy at ${source} passes scan option(s) the SHIPPED scanner does not declare:\n` +
        `    ${unknown.join(", ")}\n` +
        `  Declared options: ${[...keys].sort().join(", ")}\n` +
        "  The proxy source and the scanner package are out of sync — measuring this\n" +
        "  pair would report a number neither one delivers.",
    );
  }
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

// ─── kind -> detector map: validated against the SHIPPED detector list ───────

/** `uk_nhs_number` -> `uk-nhs-number`, so kinds and detector names compare. */
const normalizeKind = (kind) => kind.replace(/_/g, "-");

/**
 * Detectors whose NAME says they detect this kind. `npi` -> `npi-labeled`,
 * `github_token` -> `github-token`, `github-token-split`. Used to force a human
 * decision whenever the engine ships a detector that obviously belongs to a
 * corpus kind.
 */
export function nameMatchedDetectors(kind, shippedNames) {
  const k = normalizeKind(kind);
  return shippedNames.filter((n) => n === k || n.startsWith(`${k}-`));
}

/**
 * Validate the kind->detector map against the detector list the SHIPPED engine
 * ACTUALLY exports (`ALL_PATTERNS`), and fail loudly on every kind of drift.
 *
 * ─── WHY ─────────────────────────────────────────────────────────────────────
 * This map used to be maintained purely by hand. pretense #521 shipped
 * `npi-labeled` and `uk-nhs-number-labeled`; the map still said those kinds had
 * NO detector, so 20 cases the product correctly redacted were scored as
 * wrong-kind. Nothing anywhere failed. Now four rules make that impossible:
 *
 *   1. UNKNOWN DETECTOR — a name in the map that the engine does not export.
 *      Catches renames and deletions (which would otherwise silently drop
 *      coverage to zero for that kind).
 *   2. UNCLASSIFIED DETECTOR — a shipped detector mapped to no kind and not
 *      listed in `unmapped_detectors`. Every new detector must be triaged by a
 *      human; it cannot arrive unnoticed.
 *   3. UNCLAIMED NAME MATCH — the engine ships `<kind>` / `<kind>-*` but the
 *      kind does not list it and `rejected_name_matches` does not explain why.
 *      This is the exact rule that #521 would have tripped.
 *   4. UNDOCUMENTED EMPTY KIND — a kind mapped to `[]` must say, in
 *      `kinds_without_shipped_detector`, that this is a real product gap.
 *
 * Every rule resolves to a HARD FAILURE with a suggested edit. None of them can
 * be satisfied by a default, and all of them require a written reason, so the
 * judgment calls are on the page instead of implied by an empty list.
 */
export function validateKindDetectors(doc, shippedNames) {
  // `_`-prefixed keys are prose (documentation for humans reading the file),
  // never detector or kind names.
  const dropDocs = (o) => Object.fromEntries(Object.entries(o ?? {}).filter(([k]) => !k.startsWith("_")));
  const kindDetectors = dropDocs(doc.kind_detectors);
  const unmapped = dropDocs(doc.unmapped_detectors);
  const emptyKinds = dropDocs(doc.kinds_without_shipped_detector);
  const rejected = dropDocs(doc.rejected_name_matches);
  const shipped = new Set(shippedNames);
  const problems = [];

  const reasonFor = (bag, key) => {
    const r = bag[key];
    return typeof r === "string" && r.trim().length > 0 ? r : null;
  };

  // 1. every mapped detector must exist in the shipped engine
  for (const [kind, list] of Object.entries(kindDetectors)) {
    for (const name of list) {
      if (!shipped.has(name)) {
        problems.push(
          `kind '${kind}' maps to detector '${name}', which the SHIPPED engine does not export.\n` +
            "      It was renamed or removed. Fix the mapping — leaving it silently scores every\n" +
            "      such case as wrong-kind.",
        );
      }
    }
  }

  // 2. every shipped detector must be mapped, or explicitly triaged as unmapped
  const mapped = new Set(Object.values(kindDetectors).flat());
  for (const name of shippedNames) {
    if (mapped.has(name)) continue;
    if (!reasonFor(unmapped, name)) {
      problems.push(
        `the SHIPPED engine exports detector '${name}', which no corpus kind claims.\n` +
          `      Either map it to a kind, or add "${name}": "<why no corpus kind uses it>"\n` +
          "      to `unmapped_detectors`. A new detector must never arrive unnoticed.",
      );
    }
  }
  for (const name of Object.keys(unmapped)) {
    if (!shipped.has(name)) {
      problems.push(
        `'${name}' is listed in \`unmapped_detectors\` but the engine no longer exports it. ` +
          "Remove the stale entry.",
      );
    } else if (mapped.has(name)) {
      problems.push(`'${name}' is BOTH mapped to a kind and listed in \`unmapped_detectors\`. Pick one.`);
    }
  }

  // 3. name matches must be claimed or explicitly rejected, with a reason
  for (const [kind, list] of Object.entries(kindDetectors)) {
    for (const cand of nameMatchedDetectors(kind, shippedNames)) {
      if (list.includes(cand)) continue;
      if (!reasonFor(dropDocs(rejected[kind]), cand)) {
        problems.push(
          `the SHIPPED engine exports '${cand}', whose name means kind '${kind}', but '${kind}'\n` +
            `      does not list it. Add it to kind_detectors['${kind}'], or record\n` +
            `      rejected_name_matches['${kind}']['${cand}'] = "<why it is NOT this kind>".\n` +
            "      Ignoring a real detector scores correctly-redacted cases as wrong-kind.",
        );
      }
    }
  }
  for (const [kind, bag] of Object.entries(rejected)) {
    for (const name of Object.keys(dropDocs(bag))) {
      if (!shipped.has(name)) {
        problems.push(`rejected_name_matches['${kind}'] mentions '${name}', which the engine no longer exports.`);
      } else if ((kindDetectors[kind] ?? []).includes(name)) {
        problems.push(`'${name}' is both listed under kind '${kind}' and rejected for it. Pick one.`);
      }
    }
  }

  // 4. an empty kind is a claim about the product; make it say so out loud
  for (const [kind, list] of Object.entries(kindDetectors)) {
    if (list.length > 0) continue;
    if (!reasonFor(emptyKinds, kind)) {
      problems.push(
        `kind '${kind}' maps to NO detector. If the shipped engine genuinely has none, say so in\n` +
          `      \`kinds_without_shipped_detector['${kind}']\` — an unexplained empty list is\n` +
          "      indistinguishable from a mapping someone forgot to update.",
      );
    }
  }
  for (const kind of Object.keys(emptyKinds)) {
    if ((kindDetectors[kind] ?? []).length > 0) {
      problems.push(
        `kind '${kind}' is documented as having no shipped detector, but now maps to ` +
          `${JSON.stringify(kindDetectors[kind])}. The product shipped one — remove the stale note.`,
      );
    }
  }

  return problems;
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
export function classifyCase(c, { kindDetectors, scan, mutateSecrets, scanOpts }) {
  // `scanOpts` is DERIVED from the proxy source and passed in explicitly. There
  // is no default: a caller that forgets it must fail, not silently measure
  // some other engine configuration.
  if (!scanOpts || typeof scanOpts !== "object" || Object.keys(scanOpts).length === 0) {
    throw new Error("classifyCase requires the proxy's derived scanOpts — refusing to invent a scan configuration.");
  }
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

  const matches = scan(text, scanOpts).matches ?? [];
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
export function scoreCorpus(cases, { frameworks, kindFrameworks, kindDetectors, scan, mutateSecrets, scanOpts }) {
  const tiers = new Map();
  const overall = emptyTally();
  const fw = new Map(frameworks.map((name) => [name, emptyTally()]));
  const wrongKindByKind = new Map();

  for (const c of cases) {
    const tier = c.difficulty ?? "?";
    if (!tiers.has(tier)) tiers.set(tier, emptyTally());
    const t = tiers.get(tier);

    const r = classifyCase(c, { kindDetectors, scan, mutateSecrets, scanOpts });

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

/**
 * FALSE POSITIVES on the benign look-alike corpus — the anti-inflation
 * counterweight to every recall number above.
 *
 * A recall-only benchmark is trivially gamed: a detector that flags everything
 * scores 100% egress. So the same two gates are run over 70 cases a correct
 * detector must flag NONE of, and both counts are printed next to the headline.
 * `fpIdentify` is any match at all; `fpRedaction` is the stricter, more serious
 * one — a benign value the proxy would actually have mangled in flight.
 *
 * Reported, never silently folded into the headline: precision and recall are
 * different claims and must be readable separately.
 */
export function scoreNegatives(cases, { scan, mutateSecrets, scanOpts }) {
  let fpIdentify = 0;
  let fpRedaction = 0;
  const byDetector = new Map();
  for (const c of cases) {
    const text = c.text ?? "";
    const matches = scan(text, scanOpts).matches ?? [];
    if (matches.length === 0) continue;
    fpIdentify += 1;
    for (const m of matches) byDetector.set(m.type, (byDetector.get(m.type) ?? 0) + 1);

    const actionable = matches.filter((m) => PROXY_ACTIONS.has(m.action) && m.end > m.start);
    if (actionable.length === 0) continue;
    const findings = actionable.map((m) => ({ value: m.value, offset: m.start, length: m.end - m.start, type: m.type }));
    const { content } = mutateSecrets(text, findings);
    if (actionable.some((m) => m.value.length > 0 && !content.includes(m.value))) fpRedaction += 1;
  }
  return { n: cases.length, fpIdentify, fpRedaction, byDetector };
}

// ─── Report ──────────────────────────────────────────────────────────────────

function printHeader(prov, corpusInfo, caseCount, scanOpts, scanOptsSource) {
  console.log("=".repeat(78));
  console.log("Pretense EGRESS-REDACTION benchmark  (synthetic DLP corpus)");
  console.log("=".repeat(78));
  console.log(`  engine        : ${prov.scannerPkg}   [SHIPPED]`);
  console.log(`  redaction     : ${prov.mutatorPkg}  (mutateSecrets — the proxy's own path)`);
  console.log(`  product repo  : ${prov.productRoot}`);
  console.log(`  commit        : ${prov.commit} (${prov.branch}) [${prov.dirty}]`);
  console.log(`  engine path   : ${prov.scannerDir}`);
  console.log(`  configured via: ${prov.configuredVia}`);
  console.log(`  scan options  : ${JSON.stringify(scanOpts)}`);
  console.log(`                  ^ DERIVED from ${scanOptsSource} — not a copy`);
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

  // The proxy's egress scan options are READ OUT OF THE PROXY, every run.
  const { opts: scanOpts, source: scanOptsSource } = deriveProxyScanOpts(engine.provenance.productRoot);
  assertOptionsUnderstoodByScanner(scanOpts, engine.scannerDts, scanOptsSource);

  const corpusInfo = regenerateCorpus();

  const scanner = await import(pathToFileURL(engine.scannerEntry).href);
  const { scan, ALL_PATTERNS } = scanner;
  const { mutateSecrets } = await import(pathToFileURL(engine.mutatorEntry).href);
  if (typeof scan !== "function") die(`${SHIPPED_SCANNER_PKG} does not export scan()`);
  if (typeof mutateSecrets !== "function") die(`${SHIPPED_MUTATOR_PKG} does not export mutateSecrets()`);
  if (!Array.isArray(ALL_PATTERNS) || ALL_PATTERNS.length === 0) {
    die(
      `${SHIPPED_SCANNER_PKG} does not export a non-empty ALL_PATTERNS.\n` +
        "  The harness validates kind_detectors.json against the engine's REAL detector\n" +
        "  list; without it the map could go stale unnoticed, so it refuses to run.",
    );
  }
  const shippedDetectorNames = ALL_PATTERNS.map((p) => p?.name).filter((n) => typeof n === "string");

  const compliance = readJson(COMPLIANCE_PATH, "compliance map");
  const frameworks = compliance.frameworks ?? [];
  const kindFrameworks = compliance.kind_frameworks ?? {};
  const kindDetectorsDoc = readJson(KIND_DETECTORS_PATH, "kind->detector map");
  const kindDetectors = kindDetectorsDoc.kind_detectors ?? {};

  const mapProblems = validateKindDetectors(kindDetectorsDoc, shippedDetectorNames);
  if (mapProblems.length > 0) {
    die(
      `kind_detectors.json is OUT OF SYNC with the shipped engine (${shippedDetectorNames.length} detectors).\n` +
        "  Every problem below must be resolved explicitly — the harness will not guess,\n" +
        "  because a silently stale map scores correctly-protected data as a failure.\n\n" +
        mapProblems.map((m, i) => `  ${String(i + 1).padStart(2)}. ${m}`).join("\n\n") +
        `\n\n  File: ${KIND_DETECTORS_PATH}`,
    );
  }

  const fwArg = parseFrameworkArg(process.argv, frameworks);

  const corpus = readJson(CORPUS_PATH, "corpus");
  const allCases = corpus.cases ?? [];
  const cases = fwArg ? allCases.filter((c) => (kindFrameworks[c.kind] ?? []).includes(fwArg)) : allCases;

  const negatives = readJson(NEGATIVES_PATH, "benign look-alike corpus").cases ?? [];
  if (negatives.length === 0) {
    die(
      `the benign look-alike corpus at ${NEGATIVES_PATH} is empty.\n` +
        "  Without it the report would be recall-only — a number a detector that flags\n" +
        "  EVERYTHING would max out. Refusing to publish recall with no precision check.",
    );
  }
  const fp = scoreNegatives(negatives, { scan, mutateSecrets, scanOpts });

  const { tiers, overall, fw, wrongKindByKind } = scoreCorpus(cases, {
    frameworks,
    kindFrameworks,
    kindDetectors,
    scan,
    mutateSecrets,
    scanOpts,
  });

  if (process.argv.includes("--json")) {
    console.log(
      JSON.stringify(
        {
          engine: engine.provenance,
          scanOptions: scanOpts,
          scanOptionsSource: scanOptsSource,
          corpus: { ...corpusInfo, cases: overall.n, totalCases: allCases.length },
          framework: fwArg,
          overall,
          tiers: Object.fromEntries(tiers),
          frameworks: Object.fromEntries(fw),
          wrongKindByKind: Object.fromEntries(wrongKindByKind),
          falsePositives: { ...fp, byDetector: Object.fromEntries(fp.byDetector) },
        },
        null,
        2,
      ),
    );
    process.exit(0);
  }

  printHeader(engine.provenance, corpusInfo, allCases.length, scanOpts, scanOptsSource);
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
  console.log("False positives on the benign look-alike corpus (a correct detector flags NONE)");
  console.log(`  identify   : ${fp.fpIdentify} / ${fp.n} benign cases matched something`);
  console.log(`  redaction  : ${fp.fpRedaction} / ${fp.n} would have been MANGLED in flight`);
  if (fp.byDetector.size > 0) {
    const worst = [...fp.byDetector.entries()].sort((a, b) => b[1] - a[1]);
    console.log(`  detectors  : ${worst.map(([d, n]) => `${d} x${n}`).join(", ")}`);
  }
  console.log("");
  console.log(
    `HEADLINE — egress redaction: ${pct(overall.egress, overall.n).trim()}  ` +
      `(identify, secondary: ${pct(overall.identify, overall.n).trim()})  ` +
      `[false positives: ${fp.fpRedaction}/${fp.n} redaction, ${fp.fpIdentify}/${fp.n} identify]`,
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
