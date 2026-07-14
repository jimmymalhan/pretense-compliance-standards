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
from pretense_compliance_standards.negatives import build_negatives

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


def test_tier5_layered_obfuscation(cases):
    """Tier-5 layered/nested encodings: hardened recovers them, naive cannot.

    Tier 5 sits above the tier-4 exotic frontier — the value is wrapped in
    base64-of-base64, gzip+base64, full percent-encoding, or ROT13, none of which
    a single-pass scan reverses. The detector's bounded multi-pass decoder must
    recover every one; the naive scan (which sees only the encoded blob) recovers
    none.
    """
    t5 = [c for c in cases if c["difficulty"] == 5]
    assert len(t5) >= 12, "expected a populated tier-5 layered corpus"
    for c in t5:
        assert c["kind"] in detect(c["text"], "hardened"), f"hardened missed {c['id']}"
    naive_hits = [c["id"] for c in t5 if c["kind"] in detect(c["text"], "naive")]
    assert not naive_hits, f"naive unexpectedly caught tier-5 cases: {naive_hits}"


def test_multipass_decoder_recovers_layers():
    """The multi-pass decoder unwinds each layered encoding back to the value."""
    import base64
    import gzip

    value = "Member SSN 900-55-1234 on file"
    double_b64 = "blob=" + base64.b64encode(base64.b64encode(value.encode())).decode()
    gzip_b64 = "z=" + base64.b64encode(gzip.compress(value.encode())).decode()
    percent = "".join(f"%{b:02x}" for b in value.encode())

    assert "ssn" in detect(double_b64, "hardened")
    assert "ssn" in detect(gzip_b64, "hardened")
    assert "ssn" in detect(percent, "hardened")
    # The layered forms defeat the naive single-pass scan.
    assert "ssn" not in detect(double_b64, "naive")
    assert "ssn" not in detect(gzip_b64, "naive")
    assert "ssn" not in detect(percent, "naive")


def test_hardened_decode_is_dos_safe():
    """The bounded multi-pass decoder must not blow up on hostile input.

    A large wall of base64 tokens and a compression-bomb payload both used to hang
    hardened detect() for tens of seconds; the input/size/token/total caps must
    keep them fast (and correct: no spurious detection)."""
    import base64
    import gzip
    import time

    big_b64 = " ".join("QUJDREVGR0hJSktMTU5PUFFSU1Q=" for _ in range(4000))  # ~110KB
    bomb = "gz=" + base64.b64encode(gzip.compress(b"a" * 90000)).decode()
    # A large paste of benign-shaped text (spaced card-like digit groups) exercises
    # the always-on base-view regex scan, which the scan-length cap must bound.
    big_digits = "1234567890123456 " * 40000  # ~680KB
    for payload in (big_b64, bomb, big_digits):
        start = time.perf_counter()
        detect(payload, "hardened")
        assert time.perf_counter() - start < 2.0, "hardened detect too slow (DoS)"


def test_rot13_view_is_not_scanned():
    """ROT13 is not a decode layer, so benign text that ROT13s onto a denylisted
    secret must NOT be flagged (the false positive the M2 review caught)."""
    # codecs.encode('P@ssw0rd123','rot_13') == 'C@ffj0eq123'
    assert detect("the codename C@ffj0eq123 was assigned", "hardened") == set()


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


# --- precision / false-positive corpus (benign look-alikes) ----------------
# The positive corpus is recall-only (every case is expected:True). The negative
# corpus adds benign look-alikes a correct detector must NOT flag, so the harness
# can report precision / F1 and an over-broad regex surfaces as a false positive
# instead of passing silently. A hardened-mode hit on any negative is a bug.
_NEGATIVES = build_negatives()


@pytest.fixture(scope="module")
def negatives():
    # Rebuild + rewrite the negative corpus so the test never depends on stale files.
    built = corpus_builder.build_negatives()
    corpus_builder.write_negatives(built)
    return built


def test_negatives_present(negatives):
    """The negative corpus exists, is non-trivial, and is uniformly expected:False."""
    assert len(negatives) >= 20, "expected a meaningful negative corpus"
    ids = [c["id"] for c in negatives]
    assert len(ids) == len(set(ids)), "duplicate negative id"
    for c in negatives:
        assert c["expected"] is False, c["id"]
        assert c["text"].strip(), c["id"]
        assert c.get("kind_hint"), f"{c['id']} missing kind_hint"


def test_negatives_carry_banner(negatives):
    """The written negatives.json carries the SYNTHETIC banner like every corpus file."""
    path = _CORPUS_DIR / "corpus" / "negatives.json"
    assert path.exists()
    assert _has_banner(path.read_text(encoding="utf-8"))


def test_no_framework_names_in_negative_text():
    """Negatives are scanned content too — no compliance-framework name may leak in."""
    for c in _NEGATIVES:
        match = _FRAMEWORK_RE.search(c["text"])
        assert match is None, f"{c['id']} text: {match.group() if match else ''}"


@pytest.mark.parametrize("c", _NEGATIVES, ids=lambda c: c["id"])
def test_negative_case_not_flagged(c):
    """A benign look-alike must trip NO detector in hardened mode (no false positive).

    Each negative resembles the sensitive kind named in its ``kind_hint`` but is
    not regulated data; the strongest normalization (hardened) is the most
    false-positive-prone, so this is where over-broad detectors would show up.
    """
    hits = detect(c["text"], "hardened")
    assert (
        not hits
    ), f"{c['id']} falsely flagged {sorted(hits)} (looks like {c['kind_hint']})"


@pytest.mark.parametrize(
    "text,kind",
    [
        # icd10: context on either side / looser clinical phrasing must still fire
        ("Chart notes diagnosis I10 as primary.", "icd10"),
        ("Assessment recorded as diagnosis B20 by the physician.", "icd10"),
        ("icd-10 E11 documented at intake.", "icd10"),
        ("Patient with dx of E11 seen today.", "icd10"),
        ("Encounter closed with primary code I10 today.", "icd10"),
        # ein: real label vocabulary and connector words must still fire
        ("EIN is 12-3456789 for the entity.", "ein"),
        ("Employer identification number 12-3456789 on the W-9.", "ein"),
        ("Employer's Identification Number: 12-3456789 on file.", "ein"),
        ("FEIN 98-7654321 registered with the state.", "ein"),
    ],
)
def test_labeled_regulated_data_still_detected(text, kind):
    """Guard the tightenings against over-correcting into false negatives.

    The regex tightening that removed the look-alike false positives (icd10 /
    ein) must NOT start missing genuinely-labeled regulated data — clinical
    context on either side of an ICD code, and the common EIN label vocabulary,
    still have to be caught in hardened mode.
    """
    assert kind in detect(text, "hardened"), f"{kind} not detected in {text!r}"


def test_hardened_precision_is_perfect(cases, negatives):
    """Hardened mode scores zero false positives (precision 1.0) with recall intact.

    The tightenings that removed the over-broad matches (icd10, ein, ipv6,
    national_id) must not cost any positive recall — precision AND recall stay 1.0.
    """
    pr = harness.score_precision(cases, negatives)["hardened"]
    assert (
        pr["fp"] == 0
    ), f"hardened false positives: {harness.false_positives(negatives, 'hardened')}"
    assert pr["precision"] == 1.0
    assert pr["recall"] == 1.0
    assert pr["f1"] == 1.0
