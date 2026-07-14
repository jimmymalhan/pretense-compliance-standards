"""
Regression tests for the synthetic DLP recall benchmark (`dlp_benchmark`).

These lock in the benchmark's contract:
  * the corpus is buildable and every corpus file exists,
  * canonical/inline values (tiers 0-1) are ALWAYS caught by the naive detector
    (if this regresses, the reference detector is broken),
  * hardened normalization strictly improves recall over naive on every tier,
  * all corpus values are provably synthetic (fake ranges only).

Nothing here contains real data — every value is fake by construction.
"""

from __future__ import annotations

import json
import pathlib
import re
import unicodedata

import pytest

from dlp_benchmark import BANNER, corpus_builder, harness
from dlp_benchmark.detector import detect

# Framework-token guardrail: the corpus must never name a compliance framework.
# Covers the full forbidden set; the short ambiguous acronyms are word-anchored so
# they don't false-match real words (e.g. "military", "morphine", "biscuit").
_FRAMEWORK_RE = re.compile(
    r"soc ?2|hipaa|hi?ppaa|\bcmmc\b|\bgdpr\b|\bitar\b|\bcui\b|\bpii\b|\bphi\b",
    re.IGNORECASE,
)
# Any SSN-shaped value must be in the never-issued 900-range (provably fake).
_SSN_SHAPE_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_SSN_FAKE_RE = re.compile(r"9\d\d-\d\d-\d{4}")

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
    """No real PII slips in: SSN in 900-range, phones 555-01xx, email @example.com."""
    text = c["text"]
    if c["kind"] == "ssn" and c["obfuscation"] == "inline":
        assert re.search(r"\b9\d\d-\d\d-\d{4}\b", text)
    if c["kind"] == "phone" and c["obfuscation"] == "inline":
        assert "555-01" in text
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


def test_no_framework_tokens_in_any_case(cases):
    """No case text/kind names a compliance framework (neutral kinds only)."""
    for c in cases:
        for field in ("text", "kind"):
            match = _FRAMEWORK_RE.search(str(c[field]))
            assert match is None, f"{c['id']} {field}: {match.group() if match else ''}"


def test_all_ssn_shaped_values_are_fake(cases):
    """Any SSN-shaped value anywhere in the corpus is in the fake 900-range.

    Text is NFKC-folded first so Unicode-homoglyph digit forms are compared as
    their canonical ASCII digits (e.g. a fullwidth ``９`` folds to ``9``).
    """
    for c in cases:
        folded = unicodedata.normalize("NFKC", c["text"])
        for hit in _SSN_SHAPE_RE.findall(folded):
            assert _SSN_FAKE_RE.fullmatch(hit), f"{c['id']}: {hit}"
