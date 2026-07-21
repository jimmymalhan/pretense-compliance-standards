#!/usr/bin/env python3
"""Assertion helpers for tests/e2e/run.sh.

Every function here exists to turn a SILENT ZERO into a LOUD FAILURE.
Nothing in this file may return success on an empty, absent, or unparseable
input. A green check that cannot fail proves nothing.

Stdlib only, Python >= 3.10. No third-party imports, so this runs on a bare
system interpreter before `uv sync` has ever been executed.
"""

from __future__ import annotations

import json
import pathlib
import sys

# The 36 frameworks this suite claims to cover. Hardcoded ON PURPOSE: if a
# framework silently disappears from compliance_map.json, a loop that derives
# its list from that file would happily report "35 passed" as a success.
EXPECTED_FRAMEWORKS = [
    "SOC2", "ISO_27001", "ISO_27701", "NIST_800_53", "NIST_800_171", "FedRAMP",
    "FISMA", "NIS2", "NYDFS_500", "DORA", "APRA_CPS234", "HIPAA", "HITECH",
    "HITRUST", "GDPR", "UK_GDPR", "CCPA_CPRA", "LGPD", "PIPEDA", "POPIA",
    "PIPL", "PDPA_SG", "COPPA", "FERPA", "DPDP", "APPI", "PIPA_KR",
    "AU_PRIVACY", "FADP", "PDPA_TH", "CJIS", "IRS_1075", "SOX", "GLBA",
    "CMMC_L2", "PCI_DSS",
]

# The distinct-case count the corpus builder must produce. An authoritative,
# reproduced figure. If the builder produces a different number, the suite must
# say so rather than quietly rescale every published percentage.
EXPECTED_TOTAL_CASES = 648

# CMMC_L2 is fitted to its fixtures. It is measured and printed as a row, but
# it is never cited as evidence and it is excluded from the headline claim.
FITTED_TO_FIXTURES = {"CMMC_L2"}

REPO = pathlib.Path(__file__).resolve().parents[2]
PKG = REPO / "pretense_compliance_standards"


def fail(code: str, msg: str) -> None:
    """Exit non-zero with a NAMED error. Never a bare traceback."""
    print(f"\n[e2e] FAIL {code}: {msg}", file=sys.stderr)
    sys.exit(1)


def read_json(path: pathlib.Path, what: str, code: str) -> dict:
    """Read JSON or die with a named message.

    Missing files, empty files, invalid UTF-8 and truncated JSON all land here,
    so a corrupt artifact produces a named failure instead of a stack trace.
    """
    if not path.exists():
        fail(code, f"{what} does not exist at {path}\n"
                   f"       The corpus was not built. Run:\n"
                   f"         python3 -m pretense_compliance_standards.corpus_builder")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        fail(code, f"{what} at {path} could not be read: {exc}")
    if not raw.strip():
        fail(code, f"{what} at {path} is EMPTY (0 meaningful bytes). "
                   f"An empty artifact must never be scored as a pass.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(code, f"{what} at {path} is not valid UTF-8 "
                   f"(byte {exc.start}: {raw[exc.start:exc.start + 1]!r}). "
                   f"The file is corrupt, not merely empty.")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        fail(code, f"{what} at {path} is not valid JSON: {exc.msg} "
                   f"at line {exc.lineno} col {exc.colno}. The file is corrupt.")
    if not isinstance(doc, dict):
        fail(code, f"{what} at {path} is a {type(doc).__name__}, expected an object.")
    return doc


# --------------------------------------------------------------------------
# subcommand: frameworks — print the authoritative 36 names, one per line
# --------------------------------------------------------------------------
def cmd_frameworks() -> None:
    doc = read_json(PKG / "compliance_map.json", "compliance_map.json", "E_MAP_UNREADABLE")
    declared = doc.get("frameworks")
    if not isinstance(declared, list) or not declared:
        fail("E_MAP_NO_FRAMEWORKS",
             "compliance_map.json declares no frameworks. Refusing to run a zero-iteration loop.")
    if list(declared) != EXPECTED_FRAMEWORKS:
        missing = [f for f in EXPECTED_FRAMEWORKS if f not in declared]
        extra = [f for f in declared if f not in EXPECTED_FRAMEWORKS]
        fail("E_FRAMEWORK_DRIFT",
             f"compliance_map.json framework list does not match the expected 36.\n"
             f"       missing: {missing or 'none'}\n"
             f"       extra:   {extra or 'none'}\n"
             f"       A shrinking loop reports fewer checks as if nothing were wrong.")
    for name in EXPECTED_FRAMEWORKS:
        print(name)


# --------------------------------------------------------------------------
# subcommand: disk-counts — NON-ZERO case count per framework, from disk
# --------------------------------------------------------------------------
def cmd_disk_counts(out_path: str) -> None:
    flat = read_json(PKG / "corpus" / "cases.json", "flat corpus", "E_CORPUS_NOT_BUILT")
    flat_cases = flat.get("cases")
    if not isinstance(flat_cases, list) or len(flat_cases) == 0:
        fail("E_CORPUS_EMPTY",
             f"flat corpus at {PKG / 'corpus' / 'cases.json'} contains ZERO cases. "
             f"A loop over an empty corpus reports 36 green checks having measured nothing.")
    if len(flat_cases) != EXPECTED_TOTAL_CASES:
        fail("E_CORPUS_SIZE",
             f"flat corpus holds {len(flat_cases)} cases, expected {EXPECTED_TOTAL_CASES}. "
             f"Every published figure is scoped to {EXPECTED_TOTAL_CASES} cases; refusing "
             f"to measure a differently sized corpus without an explicit baseline update.")

    neg = read_json(PKG / "corpus" / "negatives.json", "benign look-alike corpus",
                    "E_NEGATIVES_NOT_BUILT")
    neg_cases = neg.get("cases")
    if not isinstance(neg_cases, list) or len(neg_cases) == 0:
        fail("E_NEGATIVES_EMPTY",
             "benign look-alike corpus contains ZERO cases; false-positive rates would be "
             "vacuously perfect.")

    rows, bad = [], []
    for name in EXPECTED_FRAMEWORKS:
        path = PKG.parent / "frameworks" / name / "corpus" / "cases.json"
        if not path.exists():
            bad.append(f"{name}: per-framework case file MISSING at {path}")
            continue
        try:
            doc = json.loads(path.read_bytes().decode("utf-8"))
            cases = doc["cases"]
            if not isinstance(cases, list):
                raise TypeError("cases is not a list")
        except UnicodeDecodeError as exc:
            bad.append(f"{name}: case file is NOT VALID UTF-8 (byte {exc.start}) — corrupt")
            continue
        except json.JSONDecodeError as exc:
            bad.append(f"{name}: case file is NOT VALID JSON ({exc.msg} line {exc.lineno})")
            continue
        except (KeyError, TypeError) as exc:
            bad.append(f"{name}: case file has no usable 'cases' list ({exc})")
            continue
        if len(cases) == 0:
            bad.append(f"{name}: ZERO cases on disk — this is a FALSE GREEN, not a pass")
            continue
        rows.append((name, len(cases)))

    if bad:
        fail("E_FRAMEWORK_CASES",
             "per-framework corpus assertion failed for "
             f"{len(bad)} of {len(EXPECTED_FRAMEWORKS)} frameworks:\n       "
             + "\n       ".join(bad)
             + "\n       A framework with no cases must FAIL, never pass.")

    with open(out_path, "w", encoding="utf-8") as fh:
        for name, n in rows:
            fh.write(f"{name}\t{n}\n")
    print(f"[e2e] non-zero case count asserted for all {len(rows)} frameworks "
          f"(flat corpus {len(flat_cases)} cases, {len(neg_cases)} benign look-alikes)")


# --------------------------------------------------------------------------
# subcommand: bridge-row — validate ONE framework's bridge JSON
# --------------------------------------------------------------------------
def cmd_bridge_row(name: str, json_path: str, disk_count: str, baseline_path: str,
                   row_out: str) -> None:
    doc = read_json(pathlib.Path(json_path), f"bridge JSON for {name}", "E_BRIDGE_OUTPUT")

    if doc.get("framework") != name:
        fail("E_BRIDGE_SCOPE",
             f"bridge JSON says framework={doc.get('framework')!r} but {name} was requested.")

    overall = doc.get("overall")
    if not isinstance(overall, dict):
        fail("E_BRIDGE_OUTPUT", f"{name}: bridge JSON has no 'overall' tally.")

    n = overall.get("n")
    if not isinstance(n, int) or n <= 0:
        fail("E_ZERO_CASES",
             f"{name}: the bridge measured {n} cases. ZERO CASES IS A FAILURE, not a pass.\n"
             f"       run.mjs prints 'n/a' and exits 0 in this state, so a naive\n"
             f"       `node run.mjs --framework $F || fail` loop would report GREEN\n"
             f"       having measured nothing. This assertion is what stops that.")

    want = int(disk_count)
    if n != want:
        fail("E_COUNT_MISMATCH",
             f"{name}: bridge measured {n} cases but the on-disk per-framework corpus "
             f"holds {want}. The two views of the same framework disagree — most likely "
             f"compliance.py FRAMEWORK_KINDS has drifted from compliance_map.json "
             f"(the builder writes the former, the bridge reads the latter).")

    corpus = doc.get("corpus") or {}
    if corpus.get("totalCases") != EXPECTED_TOTAL_CASES:
        fail("E_CORPUS_SIZE",
             f"{name}: bridge reports totalCases={corpus.get('totalCases')}, "
             f"expected {EXPECTED_TOTAL_CASES}.")

    egress = overall.get("egress", 0)
    identify = overall.get("identify", 0)
    rate = 100.0 * egress / n
    irate = 100.0 * identify / n

    base = read_json(pathlib.Path(baseline_path), "baseline", "E_BASELINE_MISSING")
    entry = base.get("frameworks", {}).get(name)
    if entry is None:
        fail("E_BASELINE_MISSING",
             f"{name}: no floor recorded in {baseline_path}. Refusing to accept an "
             f"unbounded rate — a framework with no floor cannot go red.")
    tol = float(base.get("tolerance_pp", 2.0))
    floor = float(entry["egress_rate"]) - tol
    status = "PASS"
    if rate + 1e-9 < floor:
        status = "FAIL"

    with open(row_out, "a", encoding="utf-8") as fh:
        fh.write(f"{name}\t{n}\t{egress}\t{rate:.1f}\t{identify}\t{irate:.1f}\t"
                 f"{overall.get('wrongKind', 0)}\t{overall.get('miss', 0)}\t"
                 f"{entry['egress_rate']:.1f}\t{status}\n")

    if status == "FAIL":
        fail("E_RATE_REGRESSION",
             f"{name}: egress redaction {rate:.1f}% is below the floor "
             f"{floor:.1f}% (baseline {entry['egress_rate']:.1f}% "
             f"- {tol:.1f}pp tolerance). This is a real regression, not a missing file.")

    tag = "  [FITTED TO FIXTURES — not evidence]" if name in FITTED_TO_FIXTURES else ""
    print(f"[e2e]   {name:<14} cases={n:<4} egress={egress}/{n} = {rate:5.1f}%  "
          f"identify={irate:5.1f}%  wrongKind={overall.get('wrongKind', 0)}  OK{tag}")


# --------------------------------------------------------------------------
# subcommand: cross-contamination
# --------------------------------------------------------------------------
def cmd_cross(hipaa_json: str, pci_json: str) -> None:
    """A HIPAA-scoped run must contain ZERO PCI_DSS cases and vice versa.

    Also asserts the probe is LIVE: each run must contain a non-zero count for
    its own framework. A both-zero corpus would otherwise satisfy 'no
    contamination' vacuously — the exact false green this suite exists to stop.
    """
    h = read_json(pathlib.Path(hipaa_json), "HIPAA bridge JSON", "E_BRIDGE_OUTPUT")
    p = read_json(pathlib.Path(pci_json), "PCI_DSS bridge JSON", "E_BRIDGE_OUTPUT")
    hf = h.get("frameworks", {})
    pf = p.get("frameworks", {})

    # Positive control FIRST — prove the probe can see anything at all.
    if hf.get("HIPAA", {}).get("n", 0) <= 0 or pf.get("PCI_DSS", {}).get("n", 0) <= 0:
        fail("E_CROSS_PROBE_DEAD",
             "cross-contamination probe is DEAD: a scoped run reported zero cases for its "
             "own framework, so 'zero contamination' would be vacuously true.")

    problems = []
    for other in ("PCI_DSS",):
        if hf.get(other, {}).get("n", 0) != 0:
            problems.append(f"HIPAA-scoped run contains {hf[other]['n']} {other} cases")
    for other in ("HIPAA", "HITECH"):
        if pf.get(other, {}).get("n", 0) != 0:
            problems.append(f"PCI_DSS-scoped run contains {pf[other]['n']} {other} cases")

    # Taxonomy level: the kind sets must be disjoint too.
    doc = read_json(PKG / "compliance_map.json", "compliance_map.json", "E_MAP_UNREADABLE")
    kf = doc["kind_frameworks"]
    hk = {k for k, v in kf.items() if "HIPAA" in v}
    pk = {k for k, v in kf.items() if "PCI_DSS" in v}
    if not hk or not pk:
        fail("E_CROSS_PROBE_DEAD",
             "cross-contamination probe is DEAD: HIPAA or PCI_DSS claims zero corpus kinds.")
    if hk & pk:
        problems.append(f"HIPAA and PCI_DSS share corpus kinds: {sorted(hk & pk)}")

    if problems:
        fail("E_CROSS_CONTAMINATION", "; ".join(problems))
    print(f"[e2e] cross-contamination: 0 (probe live: HIPAA n={hf['HIPAA']['n']} over "
          f"{len(hk)} kinds, PCI_DSS n={pf['PCI_DSS']['n']} over {len(pk)} kinds, "
          f"kind intersection empty)")


# --------------------------------------------------------------------------
# subcommand: summary — final 36-row named table + one verdict
# --------------------------------------------------------------------------
def cmd_summary(rows_path: str, pytest_path: str) -> None:
    rows = [ln.rstrip("\n").split("\t")
            for ln in open(rows_path, encoding="utf-8") if ln.strip()]
    pyt = dict(ln.rstrip("\n").split("\t")[:2]
               for ln in open(pytest_path, encoding="utf-8") if ln.strip())

    if len(rows) != len(EXPECTED_FRAMEWORKS):
        fail("E_INCOMPLETE_RUN",
             f"only {len(rows)} of {len(EXPECTED_FRAMEWORKS)} frameworks produced a row. "
             f"A partial run is not a pass.")

    w = 122
    print("\n" + "=" * w)
    print("36-FRAMEWORK RESULT TABLE  (egress redaction = headline; identify = secondary)")
    print("=" * w)
    print(f"{'#':>2}  {'FRAMEWORK':<14} {'CASES':>6} {'EGRESS':>8} {'RATE':>7} "
          f"{'IDENT':>7} {'WRONGKIND':>10} {'MISS':>5} {'FLOOR':>7} {'PYTEST':>10} {'BRIDGE':>7}")
    print("-" * w)
    total_cases = 0
    verdict_ok = True
    for i, r in enumerate(rows, 1):
        name, n, eg, rate, idn, irate, wk, miss, base, status = r
        total_cases += int(n)
        pstat = pyt.get(name, "MISSING")
        if status != "PASS" or pstat != "5 passed":
            verdict_ok = False
        note = "  <- FITTED TO FIXTURES, not evidence" if name in FITTED_TO_FIXTURES else ""
        print(f"{i:>2}  {name:<14} {n:>6} {eg:>8} {rate:>6}% {irate:>6}% "
              f"{wk:>10} {miss:>5} {base:>6}% {pstat:>10} {status:>7}{note}")
    print("-" * w)
    print(f"    frameworks={len(rows)}  distinct cases={EXPECTED_TOTAL_CASES}  "
          f"case-x-framework edges={total_cases} (NOT a case count)")

    # Honesty footnote: how many of these rows are genuinely distinct?
    doc = read_json(PKG / "compliance_map.json", "compliance_map.json", "E_MAP_UNREADABLE")
    kf = doc["kind_frameworks"]
    sets = {}
    for name in EXPECTED_FRAMEWORKS:
        key = tuple(sorted(k for k, v in kf.items() if name in v))
        sets.setdefault(key, []).append(name)
    dupes = {tuple(v): len(v) for v in sets.values() if len(v) > 1}
    print(f"    INDEPENDENCE: {len(sets)} distinct kind-set configurations behind "
          f"{len(EXPECTED_FRAMEWORKS)} framework labels.")
    for group in sorted(dupes, key=lambda g: -len(g)):
        print(f"      duplicate x{len(group)}: {', '.join(group)}")
    print("    Report the case count and the redaction rate. 36 is a LABEL count, "
          "not a count of independent tests.")
    print("=" * w)
    if not verdict_ok:
        fail("E_VERDICT", "at least one framework did not pass. See the table above.")
    print("VERDICT: PASS — all 36 frameworks measured a NON-ZERO case set, met their "
          "egress floor, passed their pytest marker, and showed zero cross-contamination.")
    print("=" * w)


def main() -> None:
    if len(sys.argv) < 2:
        fail("E_USAGE", "no subcommand given")
    cmd, args = sys.argv[1], sys.argv[2:]
    table = {
        "frameworks": cmd_frameworks,
        "disk-counts": cmd_disk_counts,
        "bridge-row": cmd_bridge_row,
        "cross": cmd_cross,
        "summary": cmd_summary,
    }
    if cmd not in table:
        fail("E_USAGE", f"unknown subcommand {cmd!r}")
    table[cmd](*args)


if __name__ == "__main__":
    main()
