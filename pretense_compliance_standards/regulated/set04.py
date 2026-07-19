"""
regulated/set04.py

Blended data-set 04 for the SYNTHETIC DLP recall benchmark. Emphasizes the hard
obfuscation tiers (3 = encoded, 4 = exotic) across a cross-category mix of neutral
sensitive kinds: iban, national_id, github_token, medical_record_number, passport,
api_key.

Every value here is provably FAKE by construction, and — this is the point of the
set — every obfuscated form DECODES/NORMALIZES back to a single contract-canonical
value that the hardened detector recovers via its `_views()` normalization (NFKC +
zero-width strip, fragment-join, separator-collapse, base64/hex decode):

    iban                  GB…              mod-97 VALID; unallocated EXMP bank code
    national_id           9000-4200-0001   \\d{4}-\\d{4}-\\d{4}, 9000-range synthetic
    github_token          ghp_EXAMPLE…     ghp_ + 36 alnum, obvious example token
    medical_record_number MRN00042001      MRN + 8 digits, synthetic locator
    passport              XA0000042        2 letters + 7 digits, no real holder
    api_key               sk_test_…        sk_test_ + 24 alnum, test-mode key

Each case is labeled `expected: True` — a correct DLP scanner SHOULD flag it. The
obfuscation tiers document detection challenges (base64/hex/homoglyph/zero-width/
split-literals) that a hardened scanner recovers via normalization; they are NOT
ways to smuggle data past a control.

Run:  python3 pretense_compliance_standards/regulated/set04.py
"""

from __future__ import annotations

import pathlib
import random
import re
import sys
import unicodedata

# Make the package importable when this file is run as a standalone script.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from pretense_compliance_standards import BANNER, corpus_builder

# Reproducible corpus for test assertions (values are fixed literals below; the
# seed keeps any incidental ordering/choices stable).
random.seed(404)

SOURCE_FILE = "corpus/blended_regulated_04.json"
ZW = "\u200b"  # zero-width space (same separator the detector strips)

# --- fixed synthetic literals: contract-canonical shapes, all provably fake ---
# iban: the real UK layout — 4-alpha bank code + 6-digit sort code + 8-digit
# account = 22 chars — carrying genuine ISO 7064 mod-97-10 check digits. The
# previous literal was `00`-checked AND 28 chars long, so it was neither a valid
# checksum nor a valid GB length; no IBAN parser would have accepted it, and a
# scanner was being marked down for declining it. `EXMP` is not an allocated
# bank code, which is what keeps the value unable to name a real account.
IBAN = corpus_builder.make_iban("GB", "EXMP" + "60161331926800")
# national_id: \d{4}-\d{4}-\d{4}, first group 9000 -> never-issued synthetic range.
NATIONAL_ID = "9000-4200-0001"
# github_token: ghp_ + 36 alnum; "EXAMPLE" repeats make it an obvious example token.
GITHUB_TOKEN = "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE00000000"
# medical_record_number: MRN + 8 digits.
MRN = "MRN00042001"
# passport: 2 letters + 7 digits.
PASSPORT = "XA0000042"
# api_key: sk_test_ + 24 alnum (test-mode prefix).
API_KEY = "sk_test_ABCdef01ABCdef23ABCdef45"


def _b64(s: str) -> str:
    return corpus_builder._b64(s)


def _hex(s: str) -> str:
    return s.encode().hex()


def _fullwidth(s: str) -> str:
    """Map ASCII digits to fullwidth homoglyphs (NFKC folds them back)."""
    return s.translate({0x30 + d: chr(0xFF10 + d) for d in range(10)})


def _zw(s: str) -> str:
    """Insert zero-width spaces between every character (defeated by ZW strip)."""
    return ZW.join(s)


def _spaced(s: str) -> str:
    """Space-group a value into 4-char blocks (defeated by separator-collapse)."""
    return " ".join(s[i : i + 4] for i in range(0, len(s), 4))


def build_cases() -> list[dict]:
    """Return the blended data-set 04 case list (mostly tier 3-4)."""
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

    # --- a few tier 0-2 baselines (canonical / structural) ---
    add(
        "r4-iban-plain",
        0,
        "iban",
        "inline",
        f"Settlement IBAN {IBAN} on file for the clearing account.",
    )
    add(
        "r4-nid-plain",
        0,
        "national_id",
        "inline",
        f"National identifier recorded as {NATIONAL_ID} in onboarding.",
    )
    add(
        "r4-ghtoken-plain",
        0,
        "github_token",
        "inline",
        f"ci deploy token {GITHUB_TOKEN} was committed to the pipeline config.",
    )
    add("r4-mrn-label", 1, "medical_record_number", "labeled", f"record_locator: {MRN}")
    add("r4-passport-field", 1, "passport", "config-field", f"passport = {PASSPORT}")
    add("r4-iban-spaced", 2, "iban", "space-grouped", f"IBAN: {_spaced(IBAN)} (SEPA)")
    add(
        "r4-apikey-split",
        2,
        "api_key",
        "split-literals",
        f'key = "{API_KEY[:20]}" "{API_KEY[20:]}"',
    )

    # --- tier 3: encoded (base64 / hex / unicode-homoglyph) ---
    add("r4-nid-b64", 3, "national_id", "base64", f"payload blob={_b64(NATIONAL_ID)}")
    add("r4-iban-b64", 3, "iban", "base64", f"remit blob={_b64(IBAN)}")
    add(
        "r4-ghtoken-b64",
        3,
        "github_token",
        "base64",
        f"secret blob={_b64(GITHUB_TOKEN)}",
    )
    add("r4-apikey-b64", 3, "api_key", "base64", f"env blob={_b64(API_KEY)}")
    add("r4-mrn-hex", 3, "medical_record_number", "hex", f"chart blob={_hex(MRN)}")
    add("r4-passport-hex", 3, "passport", "hex", f"doc blob={_hex(PASSPORT)}")
    add(
        "r4-nid-homoglyph",
        3,
        "national_id",
        "unicode-homoglyph",
        f"national id {_fullwidth(NATIONAL_ID)} on the intake form",
    )
    add(
        "r4-mrn-homoglyph",
        3,
        "medical_record_number",
        "unicode-homoglyph",
        f"mrn MRN{_fullwidth(MRN[3:])} attached",
    )

    # --- tier 4: exotic (zero-width separators, split literals, layered) ---
    add(
        "r4-nid-zw",
        4,
        "national_id",
        "zero-width",
        f"subject id {_zw(NATIONAL_ID)} flagged",
    )
    add("r4-iban-zw", 4, "iban", "zero-width", f"acct {_zw(IBAN)} ref")
    add(
        "r4-mrn-zw",
        4,
        "medical_record_number",
        "zero-width",
        f"mrn {_zw(MRN)} on chart",
    )
    add(
        "r4-passport-split",
        4,
        "passport",
        "split-literals",
        f'passport = "{PASSPORT[:4]}" "{PASSPORT[4:]}"',
    )
    add(
        "r4-ghtoken-b64wrap",
        4,
        "github_token",
        "base64-wrapped",
        f"envelope={_b64('token=' + GITHUB_TOKEN)}",
    )

    return C


# --- self-validation: prove every value stays fake AND stays recoverable ---

_FRAMEWORK_RE = re.compile(r"soc ?2|hi?ppaa|cmmc|gdpr|cui|itar|pii|phi", re.IGNORECASE)
# A genuine SSN-style shape carries real separators. Pure-digit runs living inside
# hex/base64 ciphertext are NOT SSNs, so requiring a separator keeps the fake-range
# guardrail from false-positiving on the encoded blobs while still catching any
# real SSN-shaped plaintext.
_SEP_SSN = re.compile(r"\d\d\d[-.\s]\d\d[-.\s]\d{4}")

# kind -> the contract-canonical value every case of that kind must reduce to.
_CANON = {
    "iban": IBAN,
    "national_id": NATIONAL_ID,
    "github_token": GITHUB_TOKEN,
    "medical_record_number": MRN,
    "passport": PASSPORT,
    "api_key": API_KEY,
}


def _recovered_views(text: str):
    """Yield the same normalized/decoded views the hardened detector scans, so a
    hidden value can be range-checked AND its recoverability confirmed."""
    import base64
    import binascii

    yield text
    nfkc = unicodedata.normalize("NFKC", text).replace(ZW, "")
    yield nfkc
    yield re.sub(r"[\s\"'`+\\|,]", "", nfkc)  # fragment-join (split literals)
    yield re.sub(r"[\s\-._]", "", nfkc)  # separator-collapse (spaced groups)
    for tok in re.findall(r"[A-Za-z0-9+/]{12,}={0,2}", text):
        try:
            yield base64.b64decode(tok, validate=True).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            pass
    for tok in re.findall(r"\b[0-9a-fA-F]{12,}\b", text):
        if len(tok) % 2 == 0:
            try:
                yield bytes.fromhex(tok).decode("utf-8", "ignore")
            except (ValueError, UnicodeDecodeError):
                pass


def _assert_fake_ranges() -> None:
    """Every canonical constant is provably synthetic and contract-shaped."""
    assert (
        IBAN[:2].isalpha() and corpus_builder.iban_is_valid(IBAN) and "EXMP" in IBAN
    ), "iban must be mod-97 valid on the unallocated EXMP example bank code"
    assert (
        re.fullmatch(r"\d{4}-\d{4}-\d{4}", NATIONAL_ID) and NATIONAL_ID[0] == "9"
    ), "national_id must be \\d{4}-\\d{4}-\\d{4} in the 9000-range"
    assert (
        GITHUB_TOKEN.startswith("ghp_")
        and re.fullmatch(r"[A-Za-z0-9]{36}", GITHUB_TOKEN[4:])
        and "EXAMPLE" in GITHUB_TOKEN
    ), "github_token must be ghp_ + 36 example alnum"
    assert re.fullmatch(
        r"MRN\d{8}", MRN
    ), "medical_record_number must be MRN + 8 digits"
    assert re.fullmatch(
        r"[A-Za-z]{2}\d{7}", PASSPORT
    ), "passport must be 2 letters + 7 digits"
    assert API_KEY.startswith("sk_test_") and re.fullmatch(
        r"[A-Za-z0-9]{24}", API_KEY[8:]
    ), "api_key must be sk_test_ + 24 alnum"


def validate(cases: list[dict], file_text: str) -> None:
    import json

    payload = json.loads(file_text)
    # BANNER round-trips through json.dump as an ASCII-escaped em-dash, so compare
    # the parsed notice rather than the raw (escaped) file text.
    assert payload.get("_notice") == BANNER, "BANNER missing from corpus file"
    assert not _FRAMEWORK_RE.search(file_text), "framework token leaked into file"
    _assert_fake_ranges()

    for c in cases:
        assert c["expected"] is True, c["id"]
        assert c["source_file"] == SOURCE_FILE, c["id"]
        assert not _FRAMEWORK_RE.search(c["text"]), f"framework token in {c['id']}"

        assert c["kind"] in _CANON, f"unmapped kind in {c['id']}: {c['kind']!r}"
        canon = _CANON[c["kind"]]
        views = list(_recovered_views(c["text"]))
        # Reversibility: the obfuscation must reduce to the contract-canonical
        # value under normalization the hardened detector performs. This also
        # proves the only sensitive token embedded is the known-fake literal.
        assert any(
            canon in v for v in views
        ), f"{c['id']} does not recover canonical {canon!r}"

        for view in views:
            # Any separator-bearing SSN shape (raw or decoded) must be 9-range.
            for m in _SEP_SSN.finditer(view):
                digits = re.sub(r"\D", "", m.group())
                assert digits.startswith(
                    "9"
                ), f"non-900 SSN shape in {c['id']}: {m.group()!r}"
            # Any phone must be reserved 555-01xx; any email @example.com.
            for m in re.finditer(r"555[-.\s]?(\d\d)", view):
                assert m.group(1) == "01", f"non-reserved phone in {c['id']}"
            for m in re.finditer(r"@([A-Za-z0-9.-]+)", view):
                assert (
                    m.group(1).lower().startswith("example.com")
                ), f"non-example email in {c['id']}"


def main() -> None:
    cases = build_cases()
    out_path = pathlib.Path(__file__).resolve().parents[1] / SOURCE_FILE
    out_path.parent.mkdir(parents=True, exist_ok=True)
    corpus_builder._write_json(out_path, cases)

    file_text = out_path.read_text(encoding="utf-8")
    validate(cases, file_text)

    tiers = sorted({c["difficulty"] for c in cases})
    by_tier = {t: sum(1 for c in cases if c["difficulty"] == t) for t in tiers}
    kinds = sorted({c["kind"] for c in cases})
    print(f"Wrote {len(cases)} blended cases to {out_path}")
    print(f"  tiers (difficulty->count): {by_tier}")
    print(f"  kinds: {kinds}")
    print("  self-validation: PASS")
    print(f"Reminder: {BANNER}.")


if __name__ == "__main__":
    main()
