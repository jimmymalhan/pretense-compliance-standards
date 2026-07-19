/**
 * Bridge scoring tests — offline, against a MOCK engine (no pretense checkout).
 *
 * These lock in the ANTI-INFLATION contract of the harness. Every assertion
 * here exists because the un-fixed harness reported a number the product does
 * not deliver. If a change makes one of these fail, the change is almost
 * certainly making the benchmark easier to inflate — fix the change, not the
 * test.
 *
 * Run: node --test pretense_compliance_standards/pretense_bridge/run.test.mjs
 */

import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import {
  scoreCorpus,
  classifyCase,
  parseFrameworkArg,
  blankNonCode,
  parseBooleanObjectLiteral,
  parseScanOptionKeys,
  nameMatchedDetectors,
  validateKindDetectors,
  scoreNegatives,
} from "./run.mjs";

const RUN_MJS = join(dirname(fileURLToPath(import.meta.url)), "run.mjs");

// --- mock engine -------------------------------------------------------------

/** A match shaped like a real ScanMatch. Defaults are the PROTECTIVE case. */
const m = (over = {}) => ({
  type: "ssn",
  action: "redact",
  start: 0,
  end: 11,
  value: "900-55-1234",
  category: "pii",
  ...over,
});

/** scan() that returns a fixed match list. */
const scanOf = (matches) => () => ({ matches });

/** mutateSecrets() that actually removes each finding's value from the text. */
const realMutate = (text, findings) => ({
  content: findings.reduce((acc, f) => acc.split(f.value).join("[TOKEN]"), text),
  mutations: findings.map((f) => ({ original: f.value, replacement: "[TOKEN]" })),
});

/** mutateSecrets() that claims success but leaves the value in place. */
const noopMutate = (text) => ({ content: text, mutations: [] });

const kindDetectors = { ssn: ["ssn"], npi: [], phone: ["phone-us"] };
const CASE = { text: "Member SSN on file: 900-55-1234.", difficulty: 0, kind: "ssn" };

/**
 * Stand-in for the options DERIVED from the proxy source. Tests must pass them
 * explicitly for the same reason production does: there is no default.
 */
const SCAN_OPTS = { contextAware: true, entropyAnalysis: false, deobfuscate: true, egressSafe: true };

const classify = (c, matches, mutateSecrets = realMutate) =>
  classifyCase(c, { kindDetectors, scan: scanOf(matches), mutateSecrets, scanOpts: SCAN_OPTS });

// --- PRIMARY METRIC: egress redaction ----------------------------------------

test("a kind-agreeing, actionable, real-span, verified-replaced match IS egress-protected", () => {
  const r = classify(CASE, [m()]);
  assert.equal(r.egress, true);
  assert.equal(r.identify, true);
  assert.equal(r.wrongKind, false);
});

test("a `warn` match is NOT egress-protected — the proxy skips warn entirely", () => {
  // Identify still true (the detector DID recognize the datum) — which is
  // exactly why identify must never be quoted as a protection number.
  const r = classify(CASE, [m({ action: "warn" })]);
  assert.equal(r.egress, false);
  assert.equal(r.identify, true);
});

test("a `pass` match is NOT egress-protected", () => {
  assert.equal(classify(CASE, [m({ action: "pass" })]).egress, false);
});

test("a ZERO-SPAN match is NOT egress-protected — it can never be spliced", () => {
  // start===end===0 is a deobfuscated-view hit; `egressSafe` strips these and
  // the proxy could not splice one anyway. It protects nothing.
  const r = classify(CASE, [m({ start: 0, end: 0 })]);
  assert.equal(r.egress, false);
  assert.equal(r.identify, true, "still identified — that is the point of the split");
});

test("a match whose value SURVIVES redaction is NOT egress-protected", () => {
  // The replacement must be VERIFIED, not assumed from a non-empty findings list.
  assert.equal(classify(CASE, [m()], noopMutate).egress, false);
});

test("no matches at all: miss on every axis", () => {
  const r = classify(CASE, []);
  assert.deepEqual(r, { egress: false, identify: false, wrongKind: false, matched: false });
});

// --- KIND AGREEMENT ----------------------------------------------------------

test("a WRONG-KIND match scores no egress and no identify", () => {
  // The real bug: NPI (and UK NHS numbers) get matched by the `phone-us`
  // detector. That earned HIPAA "coverage" for data egressing in plaintext.
  const npiCase = { text: "provider npi: 1234567890", difficulty: 0, kind: "npi" };
  const r = classify(npiCase, [m({ type: "phone-us", action: "warn", value: "1234567890", end: 10 })]);
  assert.equal(r.egress, false);
  assert.equal(r.identify, false);
  assert.equal(r.wrongKind, true, "must be VISIBLE as wrong-kind, not silently dropped");
  assert.equal(r.matched, true);
});

test("a wrong-kind match is not laundered into egress even when it IS redacted", () => {
  // Redacting a thing you mis-identified is luck. It must not earn the
  // compliance credit that the correct kind would.
  const npiCase = { text: "npi 1234567890", difficulty: 0, kind: "npi" };
  const r = classify(npiCase, [m({ type: "credit-card", action: "redact", value: "1234567890", end: 10 })]);
  assert.equal(r.egress, false);
  assert.equal(r.wrongKind, true);
});

test("a kind with an EMPTY detector list can never score", () => {
  // [] means "the shipped engine has no detector for this". Every such case is
  // a miss, by construction — that is the honest result, not a gap to paper over.
  const npiCase = { text: "npi 1234567890", difficulty: 0, kind: "npi" };
  assert.equal(classify(npiCase, [m({ type: "ssn" })]).egress, false);
});

test("a right-kind match alongside wrong-kind noise still counts", () => {
  const r = classify(CASE, [m({ type: "phone-us", action: "warn" }), m()]);
  assert.equal(r.egress, true);
  assert.equal(r.wrongKind, false);
});

test("an unmapped corpus kind THROWS rather than scoring arbitrarily", () => {
  assert.throws(
    () => classify({ text: "x", difficulty: 0, kind: "brand_new_kind" }, [m()]),
    /no entry in kind_detectors\.json/,
  );
});

// --- aggregation -------------------------------------------------------------

const frameworks = ["FW_A", "FW_B"];
const kindFrameworks = { ssn: ["FW_A", "FW_B"], npi: ["FW_A"], phone: ["FW_MISSING"] };

const corpus = [
  { text: "a", difficulty: 0, kind: "ssn" },
  { text: "b", difficulty: 1, kind: "npi" },
];

const scoreWith = (cases, matches) =>
  scoreCorpus(cases, {
    frameworks,
    kindFrameworks,
    kindDetectors,
    scan: scanOf(matches),
    mutateSecrets: realMutate,
    scanOpts: SCAN_OPTS,
  });

test("scoreCorpus tallies egress/identify/wrongKind/miss overall", () => {
  const { overall } = scoreWith(corpus, [m()]);
  assert.equal(overall.n, 2);
  assert.equal(overall.egress, 1, "only the ssn case; npi has no detector");
  assert.equal(overall.identify, 1);
  assert.equal(overall.wrongKind, 1, "npi matched as ssn = wrong kind");
  assert.equal(overall.miss, 0);
});

test("scoreCorpus buckets by difficulty tier", () => {
  const { tiers } = scoreWith(corpus, [m()]);
  assert.equal(tiers.get(0).egress, 1);
  assert.equal(tiers.get(1).egress, 0);
  assert.equal(tiers.get(1).wrongKind, 1);
});

test("scoreCorpus counts a case under every framework its kind maps to", () => {
  const { fw } = scoreWith(corpus, [m()]);
  assert.equal(fw.get("FW_A").n, 2); // ssn + npi
  assert.equal(fw.get("FW_B").n, 1); // ssn only
  assert.equal(fw.get("FW_A").egress, 1);
  assert.equal(fw.get("FW_B").egress, 1);
});

test("scoreCorpus ignores a kind mapped to a framework not in the list", () => {
  const { fw } = scoreWith([{ text: "c", difficulty: 0, kind: "phone" }], [m()]);
  assert.equal(fw.get("FW_A").n, 0);
  assert.equal(fw.get("FW_B").n, 0);
});

test("scoreCorpus surfaces wrong-kind counts per data kind", () => {
  const { wrongKindByKind } = scoreWith(corpus, [m()]);
  assert.equal(wrongKindByKind.get("npi"), 1);
  assert.equal(wrongKindByKind.has("ssn"), false);
});

test("scoreCorpus is empty-safe", () => {
  const { overall, tiers, fw } = scoreWith([], []);
  assert.deepEqual(overall, { n: 0, egress: 0, identify: 0, wrongKind: 0, miss: 0 });
  assert.equal(tiers.size, 0);
  assert.deepEqual(fw.get("FW_A"), { n: 0, egress: 0, identify: 0, wrongKind: 0, miss: 0 });
});

// --- arg parsing -------------------------------------------------------------

test("parseFrameworkArg returns null when the flag is absent", () => {
  assert.equal(parseFrameworkArg(["node", "run.mjs"], ["HIPAA"]), null);
});

test("parseFrameworkArg parses `--framework NAME`", () => {
  assert.equal(parseFrameworkArg(["--framework", "HIPAA"], ["HIPAA", "GDPR"]), "HIPAA");
});

test("parseFrameworkArg parses `--framework=NAME`", () => {
  assert.equal(parseFrameworkArg(["--framework=GDPR"], ["HIPAA", "GDPR"]), "GDPR");
});

// --- ENGINE SELECTION: misconfiguration must FAIL, never fall back -----------

/** Run the bridge as a subprocess; return { status, out }. */
function runBridge(env, script = RUN_MJS) {
  try {
    const out = execFileSync(process.execPath, [script], {
      encoding: "utf8",
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, out };
  } catch (err) {
    return { status: err.status, out: `${err.stdout ?? ""}${err.stderr ?? ""}` };
  }
}

test("an EMPTY PRETENSE_SRC is a hard failure, NOT a silent fallback", () => {
  // Regression, inverted on purpose: the old bridge treated `PRETENSE_SRC=` as
  // "use the default", so a broken CI wrapper still printed a full, plausible
  // report. A misconfiguration must never produce numbers.
  const { status, out } = runBridge({ PRETENSE_SRC: "" });
  assert.equal(status, 2);
  assert.match(out, /FATAL/);
  assert.match(out, /EMPTY/);
  assert.doesNotMatch(out, /HEADLINE/, "a failed run must print NO metrics");
});

test("an explicitly-set but nonexistent PRETENSE_SRC is a hard failure", () => {
  const { status, out } = runBridge({ PRETENSE_SRC: "/nope/not/here" });
  assert.equal(status, 2);
  assert.match(out, /does not exist/);
  assert.doesNotMatch(out, /HEADLINE/);
});

test("pointing at the NON-SHIPPED packages/cli/src engine is a hard failure", () => {
  // The dual-engine trap. cli/src has no package.json, so it fails the shipped
  // -package check and the operator gets the explanation, not a 3pp-inflated number.
  const dir = mkdtempSync(join(tmpdir(), "bridge-notpkg-"));
  try {
    const { status, out } = runBridge({ PRETENSE_SRC: dir });
    assert.equal(status, 2);
    assert.match(out, /DUAL-ENGINE TRAP/);
    assert.match(out, /packages\/scanner/);
    assert.doesNotMatch(out, /HEADLINE/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("main() still runs when the bridge is invoked through a symlink", (t) => {
  // The direct-invocation guard matches on realpath. Proven here by the hard
  // failure it prints for a bad PRETENSE_SRC (previously: the skip message).
  const dir = mkdtempSync(join(tmpdir(), "bridge-symlink-"));
  const link = join(dir, "linked-run.mjs");
  try {
    symlinkSync(RUN_MJS, link);
  } catch (e) {
    rmSync(dir, { recursive: true, force: true });
    return t.skip(`symlinks unavailable here: ${e.code}`);
  }
  try {
    const { status, out } = runBridge({ PRETENSE_SRC: "/nope/not/here" }, link);
    assert.equal(status, 2);
    assert.match(out, /does not exist/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- ANTI-STALENESS: the proxy's scan options are DERIVED, never copied ------
//
// A hardcoded copy of `apps/proxy/src/server.ts`'s scan options went stale when
// pretense #524 flipped `deobfuscate` to true. The harness kept measuring the
// old configuration and reported tiers 3-5 at 0.0%, scoring a real 30-point
// improvement as a no-op. These tests lock in the replacement: read the proxy,
// and refuse to run rather than guess.

test("blankNonCode does not mistake a `/*` inside a STRING for a block comment", () => {
  // This is the exact shape in the real proxy: app.all("/*", ...). A naive
  // stripper erases the rest of the file — including the scan() call site.
  const src = ['app.all("/*", handler);', "scan(text, { egressSafe: true });"].join("\n");
  const out = blankNonCode(src);
  assert.match(out, /scan\(text, \{ egressSafe: true \}\)/, "the call site must survive");
  assert.equal(out.length, src.length, "offsets must be preserved");
});

test("blankNonCode removes real comments and preserves line numbers", () => {
  const src = ["// scan(a, { deobfuscate: false })", "/* scan(b, { x: 1 }) */", "scan(c, { deobfuscate: true });"].join(
    "\n",
  );
  const out = blankNonCode(src);
  assert.equal([...out.matchAll(/\bscan\s*\(/g)].length, 1, "only the real call survives");
  assert.equal(out.split("\n").length, src.split("\n").length);
});

test("parseBooleanObjectLiteral reads a plain boolean option object", () => {
  const r = parseBooleanObjectLiteral("\n contextAware: true,\n deobfuscate: true,\n egressSafe: true,\n");
  assert.equal(r.ok, true);
  assert.deepEqual(r.value, { contextAware: true, deobfuscate: true, egressSafe: true });
});

test("parseBooleanObjectLiteral REFUSES anything it cannot statically evaluate", () => {
  // Approximating an option the proxy computes at run time would report a number
  // the product may not deliver — in either direction.
  for (const body of ["...defaults, egressSafe: true", "deobfuscate: cfg.deob", "egressSafe: isProd ? true : false"]) {
    const r = parseBooleanObjectLiteral(body);
    assert.equal(r.ok, false, `must refuse: ${body}`);
    assert.match(r.reason, /cannot statically evaluate/);
  }
});

test("parseBooleanObjectLiteral refuses an empty option object", () => {
  assert.equal(parseBooleanObjectLiteral("  ").ok, false);
});

test("parseScanOptionKeys reads the option surface out of the scanner's own d.ts", () => {
  const dts = [
    "interface Other { nope?: boolean }",
    "declare interface ScanOptions {",
    "  /** doc */",
    "  contextAware?: boolean;",
    "  deobfuscate?: boolean;",
    "  actionOverrides?: Partial<Record<string, ScanAction>>;",
    "}",
  ].join("\n");
  const keys = parseScanOptionKeys(dts);
  assert.ok(keys.has("contextAware") && keys.has("deobfuscate") && keys.has("actionOverrides"));
  assert.ok(!keys.has("nope"));
});

test("parseScanOptionKeys returns null when ScanOptions is absent (-> the bridge dies)", () => {
  assert.equal(parseScanOptionKeys("export interface Nothing { a?: boolean }"), null);
});

// --- ANTI-STALENESS: kind_detectors.json is VALIDATED against the engine -----
//
// pretense #521 shipped `npi-labeled` / `uk-nhs-number-labeled`; the map still
// said those kinds had no detector, so 20 correctly-redacted cases scored as
// wrong-kind and nothing failed. Now it fails.

const okDoc = () => ({
  kind_detectors: { ssn: ["ssn"], npi: ["npi-labeled"] },
  unmapped_detectors: { "gitlab-token": "no corpus case" },
  kinds_without_shipped_detector: {},
  rejected_name_matches: {},
});
const SHIPPED = ["ssn", "npi-labeled", "gitlab-token"];

test("validateKindDetectors passes a fully-triaged map", () => {
  assert.deepEqual(validateKindDetectors(okDoc(), SHIPPED), []);
});

test("nameMatchedDetectors maps a corpus kind onto same-named shipped detectors", () => {
  assert.deepEqual(nameMatchedDetectors("uk_nhs_number", ["uk-nhs-number-labeled", "ssn"]), ["uk-nhs-number-labeled"]);
  assert.deepEqual(nameMatchedDetectors("github_token", ["github-token", "github-token-split", "github-fine-grained"]), [
    "github-token",
    "github-token-split",
  ]);
});

test("THE #521 REGRESSION: a shipped detector a kind ignores is a HARD FAILURE", () => {
  const doc = okDoc();
  doc.kind_detectors.npi = []; // exactly the stale state that cost 4.0 points
  doc.kinds_without_shipped_detector.npi = "claims the engine has none";
  const problems = validateKindDetectors(doc, SHIPPED);
  // Two independent rules catch it: the detector is now claimed by no kind, AND
  // its NAME means a kind that refuses to list it. Belt and braces, on purpose.
  assert.equal(problems.length, 2);
  assert.ok(problems.every((p) => p.includes("npi-labeled")));
  assert.ok(
    problems.some((p) => /does not list it/.test(p)),
    "the name-match rule must fire",
  );
  assert.ok(
    problems.some((p) => /unmapped_detectors/.test(p)),
    "the unclaimed-detector rule must fire",
  );
});

test("a newly-shipped detector nobody triaged is a HARD FAILURE", () => {
  const problems = validateKindDetectors(okDoc(), [...SHIPPED, "brand-new-detector"]);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /brand-new-detector/);
  assert.match(problems[0], /unmapped_detectors/);
});

test("a mapped detector the engine no longer exports is a HARD FAILURE", () => {
  // Catches a RENAME, which would otherwise silently zero out that kind.
  const problems = validateKindDetectors(okDoc(), ["npi-labeled", "gitlab-token"]);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /'ssn'/);
  assert.match(problems[0], /does not export/);
});

test("an UNDOCUMENTED empty kind is a HARD FAILURE", () => {
  const doc = okDoc();
  doc.kind_detectors.imei = [];
  const problems = validateKindDetectors(doc, SHIPPED);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /kinds_without_shipped_detector/);
});

test("a documented empty kind is accepted — and un-documented once a detector ships", () => {
  const doc = okDoc();
  doc.kind_detectors.imei = [];
  doc.kinds_without_shipped_detector.imei = "the shipped engine has no IMEI detector";
  assert.deepEqual(validateKindDetectors(doc, SHIPPED), []);

  doc.kind_detectors.imei = ["imei"];
  const problems = validateKindDetectors(doc, [...SHIPPED, "imei"]);
  assert.equal(problems.length, 1);
  assert.match(problems[0], /remove the stale note/);
});

test("a name match may be REJECTED, but only with a written reason", () => {
  const doc = okDoc();
  doc.kind_detectors.ssn = ["ssn"];
  const shipped = [...SHIPPED, "ssn-lookalike"];

  doc.unmapped_detectors["ssn-lookalike"] = "triaged";
  assert.equal(validateKindDetectors(doc, shipped).length, 1, "an empty reason is not a decision");

  doc.rejected_name_matches.ssn = { "ssn-lookalike": "" };
  assert.equal(validateKindDetectors(doc, shipped).length, 1, "a blank reason still fails");

  doc.rejected_name_matches.ssn = { "ssn-lookalike": "matches employee badges, not SSNs" };
  assert.deepEqual(validateKindDetectors(doc, shipped), []);
});

test("`_`-prefixed keys are prose, not detector names", () => {
  const doc = okDoc();
  doc.unmapped_detectors._what = "documentation for humans";
  doc.kinds_without_shipped_detector._note = "documentation for humans";
  assert.deepEqual(validateKindDetectors(doc, SHIPPED), []);
});

test("the REAL kind_detectors.json is self-consistent", () => {
  // Sanity: every detector named in the shipped map is also either mapped or
  // triaged, judged against its own declared detector universe.
  const doc = JSON.parse(readFileSync(join(dirname(RUN_MJS), "..", "kind_detectors.json"), "utf8"));
  const shipped = [
    ...new Set([...Object.values(doc.kind_detectors).flat(), ...Object.keys(doc.unmapped_detectors).filter((k) => !k.startsWith("_"))]),
  ];
  assert.deepEqual(validateKindDetectors(doc, shipped), []);
});

// --- classifyCase must never invent a scan configuration ---------------------

test("classifyCase THROWS without the derived scanOpts", () => {
  for (const bad of [undefined, null, {}]) {
    assert.throws(
      () => classifyCase(CASE, { kindDetectors, scan: scanOf([m()]), mutateSecrets: realMutate, scanOpts: bad }),
      /refusing to invent a scan configuration/i,
    );
  }
});

// --- FALSE POSITIVES: the counterweight to every recall number ---------------

test("scoreNegatives counts benign matches, and redaction separately from identify", () => {
  const benign = [{ text: "Employee badge 900-55-1234 printed." }, { text: "nothing here" }];
  const r = scoreNegatives(benign, { scan: scanOf([m()]), mutateSecrets: realMutate, scanOpts: SCAN_OPTS });
  assert.equal(r.n, 2);
  assert.equal(r.fpIdentify, 2, "scan matched on both (mock returns a fixed list)");
  assert.equal(r.fpRedaction, 2);
  assert.equal(r.byDetector.get("ssn"), 2);
});

test("a benign `warn` match is a false IDENTIFY but not a false REDACTION", () => {
  const r = scoreNegatives([{ text: "badge 900-55-1234" }], {
    scan: scanOf([m({ action: "warn" })]),
    mutateSecrets: realMutate,
    scanOpts: SCAN_OPTS,
  });
  assert.equal(r.fpIdentify, 1);
  assert.equal(r.fpRedaction, 0, "the proxy never acts on warn, so nothing is mangled");
});

test("a clean detector scores zero on both false-positive axes", () => {
  const r = scoreNegatives([{ text: "nothing" }], {
    scan: scanOf([]),
    mutateSecrets: realMutate,
    scanOpts: SCAN_OPTS,
  });
  assert.equal(r.fpIdentify, 0);
  assert.equal(r.fpRedaction, 0);
});
