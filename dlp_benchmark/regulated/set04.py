"""
regulated/set04.py

Blended data-set 04 for the SYNTHETIC DLP recall benchmark. Emphasizes the hard
obfuscation tiers (3 = encoded, 4 = exotic) across a cross-category mix of neutral
sensitive kinds: iban, national_id, github_token, medical_record_number, passport,
api_key.

Every value here is provably FAKE by construction:
    national_id  -> 900-55-1234   (900-range SSN shape is NEVER issued)
    iban         -> ...EXMP...     (documentation-example BBAN marker)
    github_token -> ghp_EXAMPLE... (obvious example token, no real grant)
    api_key      -> sk_test_...     (test-mode prefix)
    passport/mrn -> fixed synthetic literals, no real holder

Each case is labeled `expected: True` — a correct DLP scanner SHOULD flag it. The
obfuscation tiers document detection challenges (base64/hex/homoglyph/zero-width/
split-literals) that a hardened scanner recovers via normalization; they are NOT
ways to smuggle data past a control.

Run:  python3 dlp_benchmark/regulated/set04.py
"""

from __future__ import annotations

import pathlib
import random
import re
import sys
import unicodedata

# Make the package importable when this file is run as a standalone script.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from dlp_benchmark import BANNER  # noqa: E402
from dlp_benchmark import corpus_builder  # noqa: E402

# Reproducible corpus for test assertions (values are fixed literals below; the
# seed keeps any incidental ordering/choices stable).
random.seed(404)

SOURCE_FILE = "corpus/blended_regulated_04.json"
ZW = "​"  # zero-width space (same separator the detector strips)

# --- fixed synthetic literals (all provably fake) ---
IBAN = "GB29EXMP60161331926819"      # example BBAN "EXMP" marks it synthetic
NATIONAL_ID = "900-55-1234"          # 900-range SSN shape -> never issued
GITHUB_TOKEN = "ghp_EXAMPLE00000000000000000000000000000"  # obvious example token
MRN = "MRN00042001"                  # synthetic medical record number
PASSPORT = "XA0000042"               # synthetic passport number
API_KEY = "sk_test_ABCdef0123456789ABCdef01"  # test-mode key


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


def build_cases() -> list[dict]:
    """Return the blended data-set 04 case list (mostly tier 3-4)."""
    C: list[dict] = []

    def add(cid, difficulty, kind, obfuscation, text):
        C.append({
            "id": cid, "difficulty": difficulty, "kind": kind,
            "obfuscation": obfuscation, "source_file": SOURCE_FILE,
            "text": text, "expected": True,
        })

    # --- a few tier 0-2 baselines (canonical / structural) ---
    add("r4-iban-plain", 0, "iban", "inline",
        f"Settlement IBAN {IBAN} on file for the clearing account.")
    add("r4-nid-plain", 0, "national_id", "inline",
        f"National identifier recorded as {NATIONAL_ID} in onboarding.")
    add("r4-ghtoken-plain", 0, "github_token", "inline",
        f"ci deploy token {GITHUB_TOKEN} was committed to the pipeline config.")
    add("r4-mrn-label", 1, "medical_record_number", "labeled",
        f"record_locator: {MRN}")
    add("r4-passport-field", 1, "passport", "config-field",
        f"passport = {PASSPORT}")
    add("r4-iban-spaced", 2, "iban", "space-grouped",
        "IBAN: GB29 EXMP 6016 1331 9268 19 (SEPA)")
    add("r4-apikey-split", 2, "api_key", "split-literals",
        'key = "sk_test_ABCdef0123" "456789ABCdef01"')

    # --- tier 3: encoded (base64 / hex / unicode-homoglyph) ---
    add("r4-nid-b64", 3, "national_id", "base64",
        f"payload blob={_b64(NATIONAL_ID)}")
    add("r4-iban-b64", 3, "iban", "base64",
        f"remit blob={_b64(IBAN)}")
    add("r4-ghtoken-b64", 3, "github_token", "base64",
        f"secret blob={_b64(GITHUB_TOKEN)}")
    add("r4-apikey-b64", 3, "api_key", "base64",
        f"env blob={_b64(API_KEY)}")
    add("r4-mrn-hex", 3, "medical_record_number", "hex",
        f"chart blob={_hex(MRN)}")
    add("r4-passport-hex", 3, "passport", "hex",
        f"doc blob={_hex(PASSPORT)}")
    add("r4-nid-homoglyph", 3, "national_id", "unicode-homoglyph",
        f"national id {_fullwidth('900')}-55-1234 on the intake form")
    add("r4-mrn-homoglyph", 3, "medical_record_number", "unicode-homoglyph",
        f"mrn MRN{_fullwidth('00042001')} attached")

    # --- tier 4: exotic (zero-width separators, split literals, layered) ---
    add("r4-nid-zw", 4, "national_id", "zero-width",
        f"subject id 900{ZW}55{ZW}1234 flagged")
    add("r4-iban-zw", 4, "iban", "zero-width",
        f"acct {_zw(IBAN)} ref")
    add("r4-mrn-zw", 4, "medical_record_number", "zero-width",
        f"mrn {_zw(MRN)} on chart")
    add("r4-passport-split", 4, "passport", "split-literals",
        'passport = "XA00" "00042"')
    add("r4-ghtoken-b64wrap", 4, "github_token", "base64-wrapped",
        f"envelope={_b64('token=' + GITHUB_TOKEN)}")

    return C


# --- self-validation: prove every value stays inside the fake ranges ---

_FRAMEWORK_RE = re.compile(r"soc ?2|hi?ppaa|cmmc|gdpr|cui|itar|pii|phi", re.IGNORECASE)
_SSN_SHAPE = re.compile(r"\d\d\d[-.\s]?\d\d[-.\s]?\d{4}")


def _recovered_views(text: str):
    """Yield normalized/decoded views so hidden values can be range-checked."""
    import base64
    import binascii

    yield text
    nfkc = unicodedata.normalize("NFKC", text).replace(ZW, "")
    yield nfkc
    yield re.sub(r"[\s\"'`+\\|,]", "", nfkc)  # fragment-join split literals
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


def validate(cases: list[dict], file_text: str) -> None:
    import json

    payload = json.loads(file_text)
    # BANNER round-trips through json.dump as an ASCII-escaped em-dash, so compare
    # the parsed notice rather than the raw (escaped) file text.
    assert payload.get("_notice") == BANNER, "BANNER missing from corpus file"
    assert not _FRAMEWORK_RE.search(file_text), "framework token leaked into file"

    for c in cases:
        assert c["expected"] is True, c["id"]
        assert c["source_file"] == SOURCE_FILE, c["id"]
        assert not _FRAMEWORK_RE.search(c["text"]), f"framework token in {c['id']}"
        for view in _recovered_views(c["text"]):
            # Any SSN-shaped value (raw or decoded) must sit in the 900 range.
            for m in _SSN_SHAPE.finditer(view):
                digits = re.sub(r"\D", "", m.group())
                assert digits.startswith("9"), f"non-900 SSN shape in {c['id']}: {m.group()!r}"
            # Any phone must be reserved 555-01xx; any email @example.com.
            for m in re.finditer(r"555[-.\s]?(\d\d)", view):
                assert m.group(1) == "01", f"non-reserved phone in {c['id']}"
            for m in re.finditer(r"@([A-Za-z0-9.-]+)", view):
                assert m.group(1).lower().startswith("example.com"), f"non-example email in {c['id']}"


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
