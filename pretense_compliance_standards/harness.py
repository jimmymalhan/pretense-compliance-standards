"""
harness.py

Runs the reference detector over the benchmark corpus and reports **recall per
difficulty tier**, for both `naive` and `hardened` modes. Recall = (cases whose
`kind` was detected) / (cases expected to be flagged).

The whole point is the shape of the curve: `naive` should hold ~100% on the easy
tiers and fall off as obfuscation increases; `hardened` should claw most of that
back. Every point below 100% is a normalization gap to close in the detector —
that is the actionable output of this benchmark.

Run:  python -m pretense_compliance_standards.harness
"""

from __future__ import annotations

import json
import pathlib
import sys

from .compliance import FRAMEWORKS, frameworks_for
from .detector import detect

CORPUS_DIR = pathlib.Path(__file__).parent / "corpus"
MODES = ("naive", "hardened")


def load_cases() -> list[dict]:
    with open(CORPUS_DIR / "cases.json", encoding="utf-8") as fh:
        return json.load(fh)["cases"]


def load_negatives() -> list[dict]:
    """Load the benign look-alike corpus (empty list if not yet built)."""
    path = CORPUS_DIR / "negatives.json"
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["cases"]


def score(cases: list[dict]) -> dict:
    """Return {mode: {tier: {"hit": int, "total": int}, "all": {...}}}."""
    result = {m: {} for m in MODES}
    for mode in MODES:
        buckets = result[mode]
        for c in cases:
            tier = c["difficulty"]
            hit = c["kind"] in detect(c["text"], mode)
            for key in (tier, "all"):
                b = buckets.setdefault(key, {"hit": 0, "total": 0})
                b["total"] += 1
                b["hit"] += int(hit)
    return result


def score_frameworks(cases: list[dict]) -> dict:
    """Return {mode: {framework: {"hit": int, "total": int}}}.

    A case is counted under EVERY framework its `kind` exercises (the mapping is
    many-to-many), so per-framework totals overlap and need not sum to len(cases).
    """
    result = {m: {} for m in MODES}
    for mode in MODES:
        buckets = result[mode]
        for c in cases:
            hit = c["kind"] in detect(c["text"], mode)
            for fw in frameworks_for(c["kind"]):
                b = buckets.setdefault(fw, {"hit": 0, "total": 0})
                b["total"] += 1
                b["hit"] += int(hit)
    return result


def score_precision(pos_cases: list[dict], neg_cases: list[dict]) -> dict:
    """Return {mode: {tp, fp, fn, tn, precision, recall, f1}}.

    Positives (the should-flag corpus) contribute TP / FN — was the expected
    `kind` found? Negatives (benign look-alikes) contribute FP / TN — a look-alike
    that trips ANY detector is a false positive. This turns the recall-only
    benchmark into a precision + recall one, so an over-broad regex shows up as a
    precision drop rather than passing silently.

    Measurement surface: false positives are counted over the curated NEGATIVE
    corpus — the inputs known to contain no regulated data — which is the standard
    way to measure detector precision. The negatives are deliberately adversarial:
    they include the boundary look-alikes for each tightened detector (e.g. an
    SSN-shaped non-900 id, a clock time vs. IPv6, an "area code A15" vs. an ICD-10
    code, a "vein 12-3456789" vs. an EIN), so an over-broad regex is caught here
    as a concrete false positive. Precision is therefore only as strong as the
    negative corpus is representative; extending `negatives.py` with a new
    look-alike is how a newly-discovered over-broad pattern is locked in.
    """
    result = {}
    for mode in MODES:
        tp = sum(1 for c in pos_cases if c["kind"] in detect(c["text"], mode))
        fn = len(pos_cases) - tp
        fp = sum(1 for c in neg_cases if detect(c["text"], mode))
        tn = len(neg_cases) - fp
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        result[mode] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }
    return result


def format_precision_report(pr: dict) -> str:
    """Precision / recall / F1 table across both modes."""
    lines = [
        "precision / recall / F1",
        "(positives = should-flag corpus; negatives = benign look-alikes that must stay clean)",
        "",
    ]
    header = (
        f"{'mode':<10}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}"
        f"{'precision':>11}{'recall':>9}{'F1':>8}"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for mode in MODES:
        m = pr[mode]
        lines.append(
            f"{mode:<10}{m['tp']:>5}{m['fp']:>5}{m['fn']:>5}{m['tn']:>5}"
            f"{m['precision']:>10.1%} {m['recall']:>8.1%} {m['f1']:>7.1%}"
        )
    return "\n".join(lines)


def false_positives(neg_cases: list[dict], mode: str) -> list[str]:
    """Negative cases the detector wrongly flags in `mode` (the kinds it emitted)."""
    out = []
    for c in neg_cases:
        hits = detect(c["text"], mode)
        if hits:
            out.append(f"{c['id']} -> {sorted(hits)}")
    return out


def _recall(b: dict) -> float:
    return b["hit"] / b["total"] if b["total"] else 0.0


def format_report(cases: list[dict], result: dict) -> str:
    tiers = sorted({c["difficulty"] for c in cases})
    lines = [
        "DLP recall benchmark — recall by difficulty tier",
        "(all data SYNTHETIC; every case is expected-to-be-flagged)",
        "",
    ]
    header = f"{'tier':<6}{'n':>4}   " + "".join(f"{m:>12}" for m in MODES)
    lines.append(header)
    lines.append("-" * len(header))
    for tier in tiers:
        n = result[MODES[0]][tier]["total"]
        cells = "".join(f"{_recall(result[m][tier]):>11.0%} " for m in MODES)
        lines.append(f"{tier:<6}{n:>4}   {cells}")
    lines.append("-" * len(header))
    n_all = result[MODES[0]]["all"]["total"]
    cells = "".join(f"{_recall(result[m]['all']):>11.0%} " for m in MODES)
    lines.append(f"{'all':<6}{n_all:>4}   {cells}")
    return "\n".join(lines)


def format_framework_report(fw_result: dict) -> str:
    """Per-compliance-framework recall, alongside the per-tier table."""
    empty = {"hit": 0, "total": 0}
    lines = [
        "recall by compliance framework",
        "(each case counted under every framework its kind exercises)",
        "",
    ]
    header = f"{'framework':<11}{'n':>4}   " + "".join(f"{m:>12}" for m in MODES)
    lines.append(header)
    lines.append("-" * len(header))
    for fw in FRAMEWORKS:
        n = fw_result[MODES[0]].get(fw, empty)["total"]
        cells = "".join(
            f"{_recall(fw_result[m].get(fw, empty)):>11.0%} " for m in MODES
        )
        lines.append(f"{fw:<11}{n:>4}   {cells}")
    return "\n".join(lines)


def missed(cases: list[dict], mode: str) -> list[str]:
    return [
        f"{c['id']} ({c['obfuscation']})"
        for c in cases
        if c["kind"] not in detect(c["text"], mode)
    ]


def check_corpus_files(cases: list[dict]) -> list[str]:
    problems = []
    for source_file in sorted({c["source_file"] for c in cases}):
        p = pathlib.Path(__file__).parent / source_file
        if not p.exists() or p.stat().st_size == 0:
            problems.append(source_file)
    return problems


def main() -> int:
    cases = load_cases()
    result = score(cases)
    print(format_report(cases, result))
    print()
    print(format_framework_report(score_frameworks(cases)))
    print()
    negatives = load_negatives()
    if negatives:
        print(format_precision_report(score_precision(cases, negatives)))
        fps = false_positives(negatives, "hardened")
        if fps:
            print("\nhardened false positives (benign look-alikes wrongly flagged):")
            for item in fps:
                print(f"  - {item}")
        print()
    print("naive misses (normalization gaps hardened mode closes):")
    for item in missed(cases, "naive"):
        print(f"  - {item}")
    still = missed(cases, "hardened")
    if still:
        print("\nhardened misses (open gaps — detector work remaining):")
        for item in still:
            print(f"  - {item}")

    # Regression guard: canonical, inline values MUST always be caught.
    exit_code = 0
    for tier in (0, 1):
        if _recall(result["naive"][tier]) < 1.0:
            print(f"\nREGRESSION: naive recall on tier {tier} < 100%", file=sys.stderr)
            exit_code = 1
    missing_files = check_corpus_files(cases)
    if missing_files:
        print(
            f"\nMISSING corpus files: {missing_files} — run corpus_builder first",
            file=sys.stderr,
        )
        exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
