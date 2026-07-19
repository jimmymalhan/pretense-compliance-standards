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
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import { scoreCorpus, classifyCase, parseFrameworkArg } from "./run.mjs";

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

const classify = (c, matches, mutateSecrets = realMutate) =>
  classifyCase(c, { kindDetectors, scan: scanOf(matches), mutateSecrets });

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
