"""
Regression tests for the synthetic DLP recall benchmark (`pretense_compliance_standards`).

These lock in the benchmark's contract:
  * the corpus is buildable and every corpus file exists,
  * canonical/inline values (tiers 0-1) are ALWAYS caught by the naive detector
    (if this regresses, the reference detector is broken),
  * hardened normalization strictly improves recall over naive on every tier,
  * all corpus values are provably synthetic (fake ranges only).

Nothing here contains real data — every value is fake by construction.
"""

from __future__ import annotations

import collections
import json
import pathlib
import re
import unicodedata

import pytest

from pretense_compliance_standards import BANNER, corpus_builder, harness
from pretense_compliance_standards.compliance import FRAMEWORKS, frameworks_for
from pretense_compliance_standards.detector import detect

# Framework-name guardrail: a compliance framework may be NAMED in a case's
# ``compliance`` metadata field (the new categorization layer), but must NEVER
# leak into the scanned ``text`` payload, which stays clean synthetic data.
# This is the specific set of framework brand names (SOC 2, HIPAA, GDPR, CMMC,
# ISO 27001, PCI) — distinct from the broad acronym guard the old test used.
_FRAMEWORK_RE = re.compile(
    r"soc.?2|hipaa|gdpr|cmmc|iso.?27001|pci",
    re.IGNORECASE,
)
# Any SSN-shaped value must be in the never-issued 900-range (provably fake).
_SSN_SHAPE_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_SSN_FAKE_RE = re.compile(r"9\d\d-\d\d-\d{4}")
# Zero-width / invisible separators used to break up canonical values (matches
# the set the detector strips: ZWSP, ZWNJ, ZWJ, word-joiner, BOM/ZWNBSP).
_ZERO_WIDTH_RE = re.compile("[​‌‍⁠﻿]")

# Difficulty tier 4 is the acknowledged "exotic" frontier (zero-width separators,
# layered/embedded encodings). Tiers 0-3 are the non-exotic recall contract that
# hardened mode is expected to meet for every kind.
_EXOTIC_TIER = 4

_CORPUS_DIR = pathlib.Path(corpus_builder.__file__).parent
# JSON writers escape non-ASCII (the em-dash) as \uXXXX, so the banner may appear
# either verbatim (csv/log) or in its JSON-escaped form (json).
_BANNER_JSON = json.dumps(BANNER)[1:-1]


def _has_banner(content: str) -> bool:
    return BANNER in content or _BANNER_JSON in content


@pytest.fixture(scope="module")
def cases():
    # Rebuild the corpus from source so the test never depends on stale files.
    built = corpus_builder.build_cases()
    corpus_builder.write_corpus(built)
    return built


@pytest.fixture(scope="module")
def result(cases):
    return harness.score(cases)


def test_corpus_files_present(cases):
    assert harness.check_corpus_files(cases) == []


def test_naive_catches_canonical_tiers(result):
    # Tiers 0-1 are canonical / labeled — a working detector must catch them all.
    for tier in (0, 1):
        assert harness._recall(result["naive"][tier]) == 1.0


def test_hardened_never_worse_than_naive(cases, result):
    tiers = sorted({c["difficulty"] for c in cases})
    for tier in tiers:
        assert harness._recall(result["hardened"][tier]) >= harness._recall(
            result["naive"][tier]
        )


def test_hardened_improves_on_obfuscated_tiers(result):
    # The whole point: normalization recovers recall the naive scan loses.
    assert harness._recall(result["hardened"]["all"]) > harness._recall(
        result["naive"]["all"]
    )


def test_every_case_expected_and_detected_hardened(cases):
    # Ground truth: all cases are should-be-flagged; hardened mode should find them.
    for c in cases:
        assert c["expected"] is True
        assert c["kind"] in detect(c["text"], "hardened"), c["id"]


@pytest.mark.parametrize("c", corpus_builder.build_cases(), ids=lambda c: c["id"])
def test_values_are_provably_fake(c):
    """No real PII slips in: SSN in 900-range, phones in a reserved-for-fiction
    range (US 555-01xx or the UK Ofcom 020 7946 0xxx drama range), email
    @example.com."""
    text = c["text"]
    if c["kind"] == "ssn" and c["obfuscation"] == "inline":
        assert re.search(r"\b9\d\d-\d\d-\d{4}\b", text)
    if c["kind"] == "phone" and c["obfuscation"] == "inline":
        assert "555-01" in text or "7946 0" in text or "7946-0" in text
    if c["kind"] == "email" and c["obfuscation"] == "inline":
        assert text.strip().endswith("example.com") or "@example.com" in text


# --- guardrails that must hold for EVERY case (base + auto-discovered) ---


def test_all_corpus_files_carry_banner(cases):
    """Every written corpus file (data files + manifest) carries the BANNER."""
    source_files = sorted({c["source_file"] for c in cases})
    assert source_files, "expected at least the base corpus files"
    for source_file in source_files:
        path = _CORPUS_DIR / source_file
        assert path.exists(), source_file
        assert _has_banner(path.read_text(encoding="utf-8")), source_file
    manifest = _CORPUS_DIR / "corpus" / "cases.json"
    assert _has_banner(manifest.read_text(encoding="utf-8"))


def test_no_framework_names_in_payload_text(cases):
    """No compliance-framework name leaks into a case's scanned ``text`` payload.

    With the new compliance-categorization layer, a framework name (SOC 2, HIPAA,
    GDPR, CMMC, ISO 27001, PCI) is ALLOWED in the per-case ``compliance`` metadata
    field — that field is the taxonomy tag, not scanned content. The guardrail is
    now scoped precisely: only the ``text`` payload (the bytes a scanner sees) is
    checked, and the ``compliance`` field is deliberately NOT scanned. This
    replaces the older guard that forbade framework tokens in *every* string field.
    """
    for c in cases:
        match = _FRAMEWORK_RE.search(c["text"])
        assert match is None, f"{c['id']} text: {match.group() if match else ''}"


def test_all_ssn_shaped_values_are_fake(cases):
    """Any SSN-shaped value anywhere in the corpus is in the fake 900-range.

    Two views of each case are scanned so obfuscation cannot hide a real SSN:

      * NFKC-folded (+ zero-width stripped) — so Unicode-homoglyph digit forms
        are compared as their canonical ASCII digits (e.g. fullwidth ``９``->``9``)
        and invisible separators inside a value are removed.
      * Fragment-joined — quotes/whitespace/join punctuation removed (mirroring
        the detector's hardened normalization) so an SSN split across string
        literals (e.g. ``"900-55" "-1234"``) is reassembled and still checked.

    Dash/dot separators are preserved in both views so the SSN shape survives.
    """
    for c in cases:
        folded = _ZERO_WIDTH_RE.sub("", unicodedata.normalize("NFKC", c["text"]))
        glued = re.sub(r"[\s\"'`+\\|,]", "", folded)
        for view in (folded, glued):
            for hit in _SSN_SHAPE_RE.findall(view):
                assert _SSN_FAKE_RE.fullmatch(hit), f"{c['id']}: {hit}"


def test_every_kind_detected_hardened_on_non_exotic_cases(cases):
    """Per-kind coverage guard against future kind/detector drift.

    For EVERY distinct ``kind`` in the corpus, hardened mode must detect ALL of
    that kind's non-exotic cases (difficulty tiers 0-3). Each kind must also own
    at least one non-exotic case, so a new kind cannot ship as exotic-only (which
    would leave it effectively untested by this contract).

    Why this exists in addition to ``test_every_case_expected_and_detected_hardened``
    (which loops per case over all tiers): organizing the check *per kind* turns a
    silent gap into a named one. If a future change removes/renames a detector,
    renames a kind, or drops a kind's canonical cases, this fails and reports the
    exact kind(s) — the per-case loop would just report scattered ids. It is a
    strict subset of the all-cases contract (non-exotic tiers only), so it can
    never be redder than that test.

    ISOLATION NOTE: in THIS worktree the detector (Unit 1) and regulated data
    (Units 2-6) are the un-merged OLD baseline, so kinds whose detectors/data are
    not yet aligned (e.g. medical_record_number, national_id, icd10) are missed
    and this test is EXPECTED to be red here. It is written to be correct
    post-integration and will go green once Units 1-6 merge; it is deliberately
    NOT weakened to pass in isolation. Tier-4 "exotic" cases are excluded because
    they are the acknowledged open frontier, not a regression signal.
    """
    by_kind: dict[str, list[dict]] = collections.defaultdict(list)
    for c in cases:
        by_kind[c["kind"]].append(c)
    assert by_kind, "expected a non-empty corpus"

    missing_anchor = sorted(
        kind
        for kind, kcases in by_kind.items()
        if all(c["difficulty"] >= _EXOTIC_TIER for c in kcases)
    )
    assert not missing_anchor, (
        f"kinds with no non-exotic (tier<{_EXOTIC_TIER}) case to anchor coverage: "
        f"{missing_anchor}"
    )

    missed: dict[str, list[str]] = {}
    for kind, kcases in by_kind.items():
        for c in kcases:
            if c["difficulty"] >= _EXOTIC_TIER:
                continue
            if kind not in detect(c["text"], "hardened"):
                missed.setdefault(kind, []).append(c["id"])
    assert not missed, (
        "hardened mode missed non-exotic cases for these kinds "
        f"(detector/kind drift): { {k: sorted(v) for k, v in sorted(missed.items())} }"
    )


# --- compliance-categorization layer: taxonomy coverage & per-framework recall ---
#
# ISOLATION NOTE (applies to the two tests below): these rely ONLY on the
# ``frameworks_for`` / ``FRAMEWORKS`` taxonomy (present at baseline) and the
# detector — never on a case's ``compliance`` field. Unit 1 adds that field to
# cases in corpus_builder, but it is absent in this isolated worktree; deriving
# each case's frameworks from ``frameworks_for(c["kind"])`` keeps these tests
# correct both pre- and post-integration.


def test_every_kind_maps_to_a_framework(cases):
    """The taxonomy fully covers the corpus, in both directions.

    * Every distinct ``kind`` present in the corpus maps to at least one
      framework via ``frameworks_for`` (no kind is silently un-categorized).
    * Every framework in ``FRAMEWORKS`` is exercised by at least one corpus case
      (no framework is declared but never covered by regulated data).
    """
    kinds = sorted({c["kind"] for c in cases})
    assert kinds, "expected a non-empty corpus"

    unmapped = [kind for kind in kinds if not frameworks_for(kind)]
    assert not unmapped, f"corpus kinds with no framework mapping: {unmapped}"

    covered = {fw for kind in kinds for fw in frameworks_for(kind)}
    uncovered = [fw for fw in FRAMEWORKS if fw not in covered]
    assert not uncovered, f"frameworks with no corpus case: {uncovered}"


def test_per_framework_hardened_coverage(cases):
    """Per-framework recall guard: hardened mode protects every framework's data.

    For each framework, every NON-EXOTIC (difficulty tier 0-3) case whose ``kind``
    maps to that framework must be detected by hardened mode (its ``kind`` appears
    in ``detect(text, "hardened")``). Organizing the check per framework turns a
    detector/taxonomy gap into a named, per-framework signal and reports the exact
    offending case ids. Tier-4 "exotic" cases are excluded as the acknowledged
    open frontier, matching the per-kind coverage contract.
    """
    missed: dict[str, list[str]] = {}
    for c in cases:
        if c["difficulty"] >= _EXOTIC_TIER:
            continue
        if c["kind"] in detect(c["text"], "hardened"):
            continue
        for fw in frameworks_for(c["kind"]):
            missed.setdefault(fw, []).append(c["id"])
    assert not missed, (
        "hardened mode missed non-exotic cases, leaving these frameworks "
        f"under-protected: { {k: sorted(v) for k, v in sorted(missed.items())} }"
    )


# --- Per-framework tagged tests --------------------------------------------
# One named test id + pytest marker per framework, so every framework is its own
# signal (`test_framework_hardened_coverage_tagged[HIPAA]`) and can be run in
# isolation (`pytest tests/test_pcs.py -m hipaa`). Because `--strict-markers` is
# on, an unregistered framework marker fails at collection — an automatic guard
# that pyproject markers stay in sync with `compliance.FRAMEWORKS`.
_FW_PARAMS = [
    pytest.param(fw, marks=getattr(pytest.mark, fw.lower())) for fw in FRAMEWORKS
]


@pytest.mark.parametrize("fw", _FW_PARAMS)
def test_framework_has_cases(fw, cases):
    """Every compliance framework is exercised by >=1 tagged corpus case."""
    n = sum(1 for c in cases if fw in frameworks_for(c["kind"]))
    assert n >= 1, f"framework {fw} has no corpus case"


@pytest.mark.parametrize("fw", _FW_PARAMS)
def test_framework_hardened_coverage_tagged(fw, cases):
    """Every non-exotic (tier 0-3) case mapping to this framework is detected."""
    missed = [
        c["id"]
        for c in cases
        if fw in frameworks_for(c["kind"])
        and c["difficulty"] < _EXOTIC_TIER
        and c["kind"] not in detect(c["text"], "hardened")
    ]
    assert not missed, f"{fw}: hardened mode missed {sorted(missed)}"


def test_every_case_carries_compliance_tag(cases):
    """Every case carries a `compliance` tag exactly matching its kind's frameworks."""
    for c in cases:
        tag = c.get("compliance")
        assert tag, f"{c['id']} has no compliance tag"
        assert set(tag) == set(frameworks_for(c["kind"])), c["id"]
