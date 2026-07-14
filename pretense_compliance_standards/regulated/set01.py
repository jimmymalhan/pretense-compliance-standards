"""
regulated/set01.py — Blended regulated data-set 01 (health-record + credential).

Builds a slice of the SYNTHETIC DLP benchmark that BLENDS health-record kinds
(medical record numbers, ICD-10 codes, insurance member IDs, short diagnosis
phrases paired with a fake name) together with CREDENTIAL kinds (GitHub tokens,
test-mode API keys) — interleaved, never grouped by category — across the same
easy->hard difficulty gradient the core corpus uses:

    tier 0  plain      canonical value, inline in prose
    tier 1  labeled    labeled fields / canonical variants
    tier 2  structural value split across quotes/lines; spaced/grouped digits
    tier 3  encoded    base64 / hex / Unicode-homoglyph forms
    tier 4  exotic     zero-width separators, embedded

Every value is fake by construction (MRN/member IDs are random digits, GitHub
tokens are ``ghp_`` + random alnum, API keys are ``sk_test_`` prefixed, any SSN
is in the never-issued 900- range, phones are 555-01xx, emails @example.com).
Each case is labeled ``expected: true`` — something a correct DLP scanner SHOULD
flag. The obfuscation tiers document detection challenges to overcome, never
ways to smuggle data past a scanner.

Run:  python3 pretense_compliance_standards/regulated/set01.py
      -> writes corpus/blended_regulated_01.json, self-validates, prints summary.
"""

from __future__ import annotations

import base64
import json
import pathlib
import random
import re
import string
import sys

# Allow `python3 pretense_compliance_standards/regulated/set01.py` (script mode) to import the
# package: put the repo root on sys.path when it isn't already importable.
if __package__ in (None, ""):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from pretense_compliance_standards import BANNER
from pretense_compliance_standards.corpus_builder import _write_json
from pretense_compliance_standards.generator import (
    DIAGNOSES,
    FIRST_NAMES,
    LAST_NAMES,
    _api_key,
    _digits,
    _fake_email,
    _fake_phone,
)

# Deterministic: fixed seed so this slice is reproducible for test assertions.
random.seed(20260710)

SOURCE_FILE = "corpus/blended_regulated_01.json"
OUT_PATH = pathlib.Path(__file__).resolve().parent.parent / SOURCE_FILE

ZW = "​"  # zero-width space


# --- fake-value generators (all provably synthetic) ------------------------
def _mrn() -> str:
    """Medical record number: 'MRN' + 8 random digits."""
    return f"MRN{_digits(8)}"


def _member_id() -> str:
    """Insurance member id: 3 uppercase letters + 9 random digits."""
    return f"{''.join(random.choices(string.ascii_uppercase, k=3))}{_digits(9)}"


def _github_token() -> str:
    """GitHub personal-access token shape: 'ghp_' + 36 random alnum chars.

    Matches the pretense firewall's github token pattern; the body is random
    (never a real credential).
    """
    return "ghp_" + "".join(random.choices(string.ascii_letters + string.digits, k=36))


def _name() -> str:
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _hex(s: str) -> str:
    return s.encode().hex()


def _space_digits(s: str) -> str:
    """Regroup a run of digits into space-separated pairs (structural noise)."""
    return " ".join(s[i : i + 2] for i in range(0, len(s), 2))


def build_cases() -> list[dict]:
    """Return the blended health-record + credential ground-truth case list."""
    C: list[dict] = []

    def add(cid, difficulty, kind, obfuscation, text):
        C.append(
            {
                "id": cid,
                "difficulty": difficulty,
                "kind": kind,
                "obfuscation": obfuscation,
                "source_file": SOURCE_FILE,
                "text": text,
                "expected": True,
            }
        )

    # Pre-draw fixed literals so encoded/split tiers reference stable values.
    mrn_a, mrn_b, mrn_c = _mrn(), _mrn(), _mrn()
    mem_a, mem_b = _member_id(), _member_id()
    ghp_a, ghp_b, ghp_c = _github_token(), _github_token(), _github_token()
    key_a, key_b = _api_key(), _api_key()
    icd_a, dx_a = random.choice(DIAGNOSES)
    icd_b, dx_b = random.choice(DIAGNOSES)
    icd_c, _ = random.choice(DIAGNOSES)
    name_a, name_b = _name(), _name()
    phone_a = _fake_phone()
    email_a = _fake_email(name_b.split()[0], name_b.split()[1])

    # --- tier 0: plain, inline (blended order, not grouped by category) ---
    add(
        "r1-mrn-inline",
        0,
        "medical_record_number",
        "inline",
        f"Patient chart pulled under {mrn_a} ahead of the follow-up visit.",
    )
    add(
        "r1-ghp-inline",
        0,
        "github_token",
        "inline",
        f"CI pipeline authenticates with token {ghp_a} before the build step.",
    )
    add(
        "r1-icd-inline",
        0,
        "icd10",
        "inline",
        f"Encounter closed with primary code {icd_a} on the problem list.",
    )
    # health_record free-text carries a detectable anchor (its paired ICD code)
    # because a bare diagnosis phrase is not machine-detectable on its own.
    add(
        "r1-health-inline",
        0,
        "health_record",
        "inline",
        f"{name_a} was seen today and diagnosed with {dx_a} [{icd_a}].",
    )

    # --- tier 1: labeled / canonical field variants ---
    add(
        "r1-member-field",
        1,
        "insurance_member_id",
        "config-field",
        f"member_id: {mem_a}",
    )
    add(
        "r1-apikey-field", 1, "api_key", "config-field", f"billing.stripe_key = {key_a}"
    )
    add("r1-mrn-label", 1, "medical_record_number", "labeled", f"MRN: {mrn_b}")
    add(
        "r1-ghp-field",
        1,
        "github_token",
        "config-field",
        f"github_access_token = {ghp_b}",
    )
    add("r1-icd-label", 1, "icd10", "labeled", f"diagnosis_code = {icd_b}")

    # --- tier 2: structural (split across quotes/lines, grouped digits) ---
    add(
        "r1-mrn-spaced",
        2,
        "medical_record_number",
        "space-grouped",
        f"chart no. MRN {_space_digits(mrn_c[3:])}",
    )
    add(
        "r1-member-split",
        2,
        "insurance_member_id",
        "split-literals",
        f'member = "{mem_b[:3]}" "{mem_b[3:]}"',
    )
    add(
        "r1-ghp-concat",
        2,
        "github_token",
        "concatenated",
        f'token = "ghp_" + "{ghp_c[4:]}"',
    )
    add(
        "r1-apikey-split",
        2,
        "api_key",
        "split-literals",
        f'key = "sk_test_" "{key_b[len("sk_test_"):]}"',
    )

    # --- tier 3: encoded (base64 / hex / homoglyph) ---
    add("r1-mrn-b64", 3, "medical_record_number", "base64", f"blob={_b64(mrn_a)}")
    add("r1-member-hex", 3, "insurance_member_id", "hex", f"blob={_hex(mem_a)}")
    add("r1-ghp-b64", 3, "github_token", "base64", f"payload={_b64(ghp_a)}")
    add(
        "r1-icd-homoglyph",
        3,
        "icd10",
        "unicode-homoglyph",
        f"code={icd_c[0]}１" + icd_c[2:],
    )  # fullwidth digit substitution

    # --- tier 4: exotic (zero-width separators, embedded contact record) ---
    add("r1-ghp-zw", 4, "github_token", "zero-width", f"gh{ZW}p_{ZW.join(ghp_a[4:])}")
    add(
        "r1-mrn-zw",
        4,
        "medical_record_number",
        "zero-width",
        f"ref M{ZW}R{ZW}N{ZW}{_space_digits(mrn_b[3:]).replace(' ', ZW)}end",
    )
    # embedded record keeps an ICD anchor alongside the free-text diagnosis so
    # the detector still fires through the exotic zero-noise framing.
    add(
        "r1-health-embedded",
        4,
        "health_record",
        "embedded",
        f"note::{name_b}|dx={dx_b} {icd_b}|call {phone_a}|{email_a}::eof",
    )

    return C


def _validate(path: pathlib.Path) -> None:
    """Self-check the written corpus against the non-negotiable guardrails."""
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)

    # BANNER present (json.dump escapes the em-dash, so check the parsed field).
    assert data.get("_notice") == BANNER, "BANNER missing from written corpus file"

    # Every SSN-shaped value must be in the never-issued 900- range.
    for m in re.finditer(r"\b\d{3}-\d{2}-\d{4}\b", raw):
        assert m.group().startswith("900-"), f"non-900 SSN-shaped value: {m.group()}"

    # Every phone-shaped value must use the 555-01xx fiction range.
    for m in re.finditer(r"\(\d{3}\)\s*\d{3}-\d{4}", raw):
        assert "555-01" in m.group(), f"phone not in 555-01xx range: {m.group()}"

    # Every email must use the reserved example.com domain.
    for m in re.finditer(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", raw):
        assert m.group().endswith("@example.com"), f"non-example.com email: {m.group()}"

    # No framework/compliance tokens anywhere in the file.
    banned = re.search(r"soc ?2|hi?ppaa|cmmc|gdpr|cui|itar|pii|phi", raw, re.IGNORECASE)
    assert banned is None, f"framework token leaked: {banned.group()!r}"


def main() -> None:
    cases = build_cases()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _write_json(OUT_PATH, cases)
    _validate(OUT_PATH)

    tiers = sorted({c["difficulty"] for c in cases})
    kinds = sorted({c["kind"] for c in cases})
    print(f"{BANNER}")
    print(f"Wrote {len(cases)} blended cases -> {OUT_PATH}")
    print(f"  tiers: {tiers}")
    print(f"  kinds: {kinds}")
    print(
        "  self-validation: PASS (banner present; SSN/phone/email fake; "
        "no framework tokens)"
    )


if __name__ == "__main__":
    main()
