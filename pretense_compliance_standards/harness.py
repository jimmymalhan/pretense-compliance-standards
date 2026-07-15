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

import argparse
import json
import os
import pathlib
import sys

from . import BANNER
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


def report_data(
    cases: list[dict],
    negatives: list[dict] | None = None,
    *,
    tier_result: dict | None = None,
    fw_result: dict | None = None,
    precision: dict | None = None,
) -> dict:
    """Assemble a machine-readable report: per-tier + per-framework recall (and
    precision when negatives are supplied). This is the single structured source
    the JSON and Markdown exporters render, so all three outputs never drift.

    The already-computed score tables can be passed in (tier_result / fw_result /
    precision) to avoid re-running the detector; they are computed on demand
    otherwise.
    """
    if tier_result is None:
        tier_result = score(cases)
    if fw_result is None:
        fw_result = score_frameworks(cases)
    empty = {"hit": 0, "total": 0}

    data: dict = {
        "_notice": BANNER,
        "totals": {
            "cases": len(cases),
            "kinds": len({c["kind"] for c in cases}),
            "frameworks": len(FRAMEWORKS),
        },
        "recall_by_tier": {},
        "recall_by_framework": {},
    }
    # Iterate the real tier bucket keys (difficulty values + the "all" rollup).
    # No int() cast — this works for any hashable difficulty, and an empty corpus
    # (no buckets at all) still yields a valid "all" row via the empty default.
    tier_keys = [k for k in tier_result[MODES[0]] if k != "all"]
    tier_keys.sort(key=lambda k: (not isinstance(k, int), k))
    for key in [*tier_keys, "all"]:
        bucket = tier_result[MODES[0]].get(key, empty)
        data["recall_by_tier"][str(key)] = {
            "n": bucket["total"],
            **{m: _recall(tier_result[m].get(key, empty)) for m in MODES},
        }
    for fw in FRAMEWORKS:
        data["recall_by_framework"][fw] = {
            "n": fw_result[MODES[0]].get(fw, empty)["total"],
            **{m: _recall(fw_result[m].get(fw, empty)) for m in MODES},
        }
    if negatives:
        data["precision"] = (
            precision if precision is not None else score_precision(cases, negatives)
        )
    return data


def _write_report(path: str, text: str) -> None:
    """Write `text` to `path`, creating parent directories as needed."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def export_json(path: str, data: dict) -> None:
    """Write the structured report as JSON (for CI diffing / dashboards)."""
    _write_report(path, json.dumps(data, indent=2))


def _md_cell(value: object) -> str:
    # Escape the Markdown table delimiters so a stray '|' / newline in a cell
    # cannot corrupt the table layout.
    return str(value).replace("|", "\\|").replace("\n", " ")


def _md_row(cells: list) -> str:
    return "| " + " | ".join(_md_cell(c) for c in cells) + " |"


def export_markdown(path: str, data: dict) -> None:
    """Write the structured report as a Markdown summary (tables per section)."""
    t = data["totals"]
    lines = [
        "# Pretense Compliance Standards — benchmark report",
        "",
        f"> {_md_cell(data['_notice'])}",
        "",
        f"**{t['cases']} cases · {t['kinds']} kinds · {t['frameworks']} frameworks**",
        "",
        "## Recall by difficulty tier",
        "",
        _md_row(["tier", "n", *MODES]),
        _md_row(["---", "---", *["---"] * len(MODES)]),
    ]
    for tier, row in data["recall_by_tier"].items():
        lines.append(_md_row([tier, row["n"], *(f"{row[m]:.0%}" for m in MODES)]))
    lines += [
        "",
        "## Recall by compliance framework",
        "",
        _md_row(["framework", "n", *MODES]),
        _md_row(["---", "---", *["---"] * len(MODES)]),
    ]
    for fw, row in data["recall_by_framework"].items():
        lines.append(_md_row([fw, row["n"], *(f"{row[m]:.0%}" for m in MODES)]))
    if "precision" in data:
        lines += [
            "",
            "## Precision / recall / F1",
            "",
            _md_row(["mode", "TP", "FP", "FN", "precision", "recall", "F1"]),
            _md_row(["---"] * 7),
        ]
        for m in MODES:
            p = data["precision"][m]
            lines.append(
                _md_row(
                    [
                        m,
                        p["tp"],
                        p["fp"],
                        p["fn"],
                        f"{p['precision']:.1%}",
                        f"{p['recall']:.1%}",
                        f"{p['f1']:.1%}",
                    ]
                )
            )
    _write_report(path, "\n".join(lines) + "\n")


def check_corpus_files(cases: list[dict]) -> list[str]:
    problems = []
    for source_file in sorted({c["source_file"] for c in cases}):
        p = pathlib.Path(__file__).parent / source_file
        if not p.exists() or p.stat().st_size == 0:
            problems.append(source_file)
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Score the reference detector over the synthetic corpus."
    )
    parser.add_argument(
        "--json", metavar="PATH", help="also write the structured report as JSON"
    )
    parser.add_argument(
        "--md", metavar="PATH", help="also write the structured report as Markdown"
    )
    args = parser.parse_args()

    cases = load_cases()
    negatives = load_negatives()
    result = score(cases)
    fw_result = score_frameworks(cases)
    precision = score_precision(cases, negatives) if negatives else None

    print(format_report(cases, result))
    print()
    print(format_framework_report(fw_result))
    print()
    if negatives:
        print(format_precision_report(precision))
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

    # Optional machine-readable exports (text output above is unchanged by default).
    # A write failure is reported but never changes the benchmark's exit code.
    if args.json or args.md:
        data = report_data(
            cases,
            negatives,
            tier_result=result,
            fw_result=fw_result,
            precision=precision,
        )
        try:
            if args.json:
                export_json(args.json, data)
                print(f"\nWrote JSON report to {args.json}")
            if args.md:
                export_markdown(args.md, data)
                print(f"Wrote Markdown report to {args.md}")
        except OSError as exc:
            print(f"\ncould not write report: {exc}", file=sys.stderr)

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
