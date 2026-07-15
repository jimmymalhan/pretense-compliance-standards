/**
 * Offline tests for the pretense bridge (run.mjs).
 *
 * The bridge's real value is its scoring core — turning per-case identify/mutate
 * results into per-tier and per-framework coverage. That logic used to be buried
 * inside main(), untestable without a local checkout of the real pretense engine.
 * run.mjs now exports the pure `scoreCorpus` and `parseFrameworkArg`, so these
 * tests exercise the exact code path the real run uses, against a MOCK engine —
 * no engine checkout, no network, no env vars. This is what lets CI catch a
 * regression in the bridge that the graceful-skip path would otherwise hide.
 *
 * Run:  node --test pretense_compliance_standards/pretense_bridge/run.test.mjs
 */

import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { symlinkSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import { scoreCorpus, parseFrameworkArg } from "./run.mjs";

const RUN_MJS = fileURLToPath(new URL("./run.mjs", import.meta.url));

// A mock engine mirroring the real `scan` / `mutate` interface the bridge uses:
//   scan(text)          -> { matches: [...] }              (identify: >=1 match)
//   mutate(text, lang)  -> { stats: { tokensMutated }, mutatedCode }
// The stand-in "secret" is any digit run; mutate masks digits with '#'.
const scan = (text) => ({ matches: /\d/.test(text) ? [{ index: 0 }] : [] });
const mutate = (text) => {
  const mutatedCode = text.replace(/\d/g, "#");
  return { stats: { tokensMutated: mutatedCode === text ? 0 : 1 }, mutatedCode };
};

const frameworks = ["FW_A", "FW_B"];
const kindFrameworks = {
  ssn: ["FW_A", "FW_B"], // maps to two frameworks
  email: ["FW_A"],
  note: ["UNKNOWN_FW"], // maps to a framework not in the ordered list
};
const cases = [
  { text: "ssn 900-11-2222", difficulty: 0, kind: "ssn" }, // identify + mutate
  { text: "call me maybe", difficulty: 0, kind: "email" }, // neither (no digit)
  { text: "code 42", difficulty: 1, kind: "note" }, // identify + mutate
];

test("scoreCorpus tallies overall identify/mutate", () => {
  const { overall } = scoreCorpus(cases, { frameworks, kindFrameworks, scan, mutate });
  assert.equal(overall.n, 3);
  assert.equal(overall.identify, 2); // the two cases containing a digit
  assert.equal(overall.mutate, 2);
});

test("scoreCorpus buckets by difficulty tier", () => {
  const { tiers } = scoreCorpus(cases, { frameworks, kindFrameworks, scan, mutate });
  assert.deepEqual(tiers.get(0), { n: 2, identify: 1, mutate: 1 }); // ssn + email
  assert.deepEqual(tiers.get(1), { n: 1, identify: 1, mutate: 1 }); // note
});

test("scoreCorpus counts a case under every framework its kind maps to", () => {
  const { fw } = scoreCorpus(cases, { frameworks, kindFrameworks, scan, mutate });
  // FW_A: ssn (identify+mutate) + email (neither) = n2, identify1, mutate1
  assert.deepEqual(fw.get("FW_A"), { n: 2, identify: 1, mutate: 1 });
  // FW_B: ssn only
  assert.deepEqual(fw.get("FW_B"), { n: 1, identify: 1, mutate: 1 });
});

test("scoreCorpus ignores a kind mapped to an unlisted framework", () => {
  const { fw } = scoreCorpus(cases, { frameworks, kindFrameworks, scan, mutate });
  // `note` -> UNKNOWN_FW, which is not in `frameworks`, so it appears nowhere.
  assert.equal(fw.has("UNKNOWN_FW"), false);
});

test("scoreCorpus treats a changed mutatedCode as mutated even without stats", () => {
  const noStatsMutate = (text) => ({ mutatedCode: text + "X" }); // no `stats`
  const { overall } = scoreCorpus([{ text: "a", difficulty: 0, kind: "k" }], {
    frameworks: [],
    kindFrameworks: {},
    scan: () => ({ matches: [] }),
    mutate: noStatsMutate,
  });
  assert.equal(overall.mutate, 1);
  assert.equal(overall.identify, 0);
});

test("scoreCorpus does not count a case as mutated when the engine returns no mutatedCode", () => {
  // Regression: `mutatedCode !== text` must not treat an absent mutatedCode as a
  // mutation, which would inflate mutate coverage.
  const { overall } = scoreCorpus([{ text: "x", difficulty: 0, kind: "k" }], {
    frameworks: [],
    kindFrameworks: {},
    scan: () => ({ matches: [] }),
    mutate: () => ({ stats: { tokensMutated: 0 } }), // no `mutatedCode` field
  });
  assert.equal(overall.mutate, 0);
});

test("scoreCorpus is empty-safe", () => {
  const { overall, tiers, fw } = scoreCorpus([], { frameworks, kindFrameworks, scan, mutate });
  assert.deepEqual(overall, { n: 0, identify: 0, mutate: 0 });
  assert.equal(tiers.size, 0);
  assert.deepEqual(fw.get("FW_A"), { n: 0, identify: 0, mutate: 0 }); // present, zeroed
});

test("parseFrameworkArg returns null when the flag is absent", () => {
  assert.equal(parseFrameworkArg(["node", "run.mjs"], ["HIPAA"]), null);
});

test("parseFrameworkArg parses `--framework NAME`", () => {
  assert.equal(parseFrameworkArg(["--framework", "HIPAA"], ["HIPAA", "GDPR"]), "HIPAA");
});

test("parseFrameworkArg parses `--framework=NAME`", () => {
  assert.equal(parseFrameworkArg(["--framework=GDPR"], ["HIPAA", "GDPR"]), "GDPR");
});

// --- direct-invocation contract (the main() entrypoint guard) ------------------

test("main() runs when the bridge is invoked through a symlink", (t) => {
  // Regression: the guard must match on realpath, so `node <symlink-to-run.mjs>`
  // still executes main() (here proven by the graceful-skip line it prints).
  const dir = mkdtempSync(join(tmpdir(), "bridge-symlink-"));
  const link = join(dir, "linked-run.mjs");
  try {
    symlinkSync(RUN_MJS, link);
  } catch (e) {
    rmSync(dir, { recursive: true, force: true });
    return t.skip(`symlinks unavailable here: ${e.code}`);
  }
  try {
    const out = execFileSync(process.execPath, [link], {
      encoding: "utf8",
      env: { ...process.env, PRETENSE_SRC: "/nope/not/here" },
    });
    assert.match(out, /pretense engine not found.*skipping/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an empty PRETENSE_SRC falls back to the default path (not the empty string)", () => {
  // Regression: `?? default` let an exported-empty PRETENSE_SRC through as "".
  const out = execFileSync(process.execPath, [RUN_MJS], {
    encoding: "utf8",
    env: { ...process.env, PRETENSE_SRC: "" },
  });
  // A non-empty path follows "at " — the empty-string bug printed "at ; skipping".
  assert.match(out, /pretense engine not found at \S.*; skipping/);
});
