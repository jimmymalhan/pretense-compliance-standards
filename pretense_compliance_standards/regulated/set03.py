"""
regulated/set03.py — blended data set 03 (controlled-program / technical mix).

Builds ~18 SYNTHETIC, un-annotated benchmark cases blending invented
controlled-program and technical identifiers (contract / part / program codes)
with secrets (JWT, database URL, cloud API key) and a little PII (SSN / phone /
email). Every value is provably fake by construction — see the package banner.

These are labeled scanner INPUT meant to RAISE detector recall across the
difficulty gradient (tiers 0-4); they are never a way to smuggle data past a
control. All contract / part / program values are entirely invented; none
reference any real program, contractor, or identifier.

Run:  python3 pretense_compliance_standards/regulated/set03.py
      -> writes pretense_compliance_standards/corpus/blended_regulated_03.json, self-validates,
         prints a summary, and exits non-zero on any guardrail failure.
"""

from __future__ import annotations

import base64
import json
import pathlib
import random
import re
import string

if __package__ in (None, ""):
    # Allow direct execution: `python3 pretense_compliance_standards/regulated/set03.py`.
    import sys

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
    from pretense_compliance_standards import BANNER
    from pretense_compliance_standards.corpus_builder import _write_json
    from pretense_compliance_standards.generator import (
        _digits,
        _fake_email,
        _fake_phone,
        _fake_ssn,
    )
else:
    from .. import BANNER
    from ..corpus_builder import _write_json
    from ..generator import _digits, _fake_email, _fake_phone, _fake_ssn

# Reproducible so the "generated" corpus is stable for test assertions.
random.seed(303)

SOURCE_FILE = "corpus/blended_regulated_03.json"
ZW = "\u200b"  # zero-width space
_OUT_PATH = pathlib.Path(__file__).resolve().parents[1] / SOURCE_FILE


# --- invented, provably-synthetic controlled-program / technical identifiers ---


def _contract_number() -> str:
    # e.g. CTR-2029-004417 — invented contract series, not a real award number.
    return f"CTR-20{random.randint(25, 39)}-{_digits(6)}"


def _part_number() -> str:
    # e.g. PN-AX7K93 — invented part series.
    body = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"PN-{body}"


def _program_code() -> str:
    # e.g. PRG-7QK2ZA — invented internal program code.
    body = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"PRG-{body}"


def _fake_jwt() -> str:
    # Clearly fake 3-segment eyJ... token with random, meaningless segments.
    def seg(n: int) -> str:
        raw = "".join(random.choices(string.ascii_letters + string.digits, k=n))
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"  # {"alg":"HS256","typ":"JWT"}
    return f"{header}.{seg(18)}.{seg(24)}"


def _db_url() -> str:
    # Reserved example host + throwaway credentials -> provably fake conn string.
    pw = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"mysql://user:fakepw_{pw}@db.example.com:3306/svc"


def _gcp_key() -> str:
    # AIza + 35 chars from the Google-key alphabet -> test-shaped, random body.
    body = "".join(random.choices(string.ascii_letters + string.digits + "-_", k=35))
    return f"AIza{body}"


# --- fixed synthetic literals for this set (all provably fake) ---
CONTRACT = _contract_number()
PART = _part_number()
PROGRAM = _program_code()
JWT = _fake_jwt()
DB_URL = _db_url()
GCP_KEY = _gcp_key()
SSN = _fake_ssn()
PHONE = _fake_phone()
EMAIL = _fake_email("dana", "okoro")


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _hex(s: str) -> str:
    return s.encode().hex()


def _homoglyph_digits(s: str) -> str:
    """Swap leading ASCII digits for fullwidth homoglyphs (NFKC-recoverable)."""
    table = {
        "0": "０",
        "1": "１",
        "2": "２",
        "3": "３",
        "4": "４",
        "5": "５",
        "6": "６",
        "7": "７",
        "8": "８",
        "9": "９",
    }
    return "".join(table.get(c, c) for c in s)


def build_cases() -> list[dict]:
    """Return the blended-set-03 case list (id, difficulty, kind, ...)."""
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

    # tier 0 — plain, canonical, inline in prose
    add(
        "r3-contract-plain",
        0,
        "contract_number",
        "inline",
        f"Award reference {CONTRACT} is on file for the build lot.",
    )
    add(
        "r3-part-plain",
        0,
        "part_number",
        "inline",
        f"Ship the assembly for part {PART} to the depot.",
    )
    add(
        "r3-program-plain",
        0,
        "internal_program_code",
        "inline",
        f"Milestone review scheduled under {PROGRAM} next quarter.",
    )
    add(
        "r3-jwt-plain",
        0,
        "jwt",
        "inline",
        f"Service bearer token {JWT} rotates nightly.",
    )
    add(
        "r3-dburl-plain",
        0,
        "db_url",
        "inline",
        f"Primary datastore {DB_URL} handles order writes.",
    )
    add(
        "r3-gcpkey-plain",
        0,
        "gcp_key",
        "inline",
        f"Maps client configured with key {GCP_KEY}.",
    )
    add("r3-ssn-plain", 0, "ssn", "inline", f"Vendor contact SSN on record: {SSN}.")

    # tier 1 — labeled config / CSV fields
    add(
        "r3-contract-field",
        1,
        "contract_number",
        "config-field",
        f"contract_no = {CONTRACT}",
    )
    add("r3-part-csv", 1, "part_number", "csv-cell", f"line_item,{PART},qty=12,active")
    add("r3-gcpkey-field", 1, "gcp_key", "config-field", f"GOOGLE_MAPS_KEY: {GCP_KEY}")
    add("r3-dburl-field", 1, "db_url", "env-field", f"DATABASE_URL={DB_URL}")
    add("r3-phone-field", 1, "phone", "labeled", f"program_poc_phone: {PHONE}")
    add("r3-email-field", 1, "email", "labeled", f"poc_email = {EMAIL}")

    # tier 2 — structural: split across quotes / lines, spaced / grouped
    add(
        "r3-contract-split",
        2,
        "contract_number",
        "split-literals",
        f'contract = "{CONTRACT[:7]}" "{CONTRACT[7:]}"',
    )
    add(
        "r3-program-spaced",
        2,
        "internal_program_code",
        "spaced",
        "code = " + " ".join(PROGRAM),
    )
    add(
        "r3-gcpkey-concat",
        2,
        "gcp_key",
        "concatenated",
        f'key = "{GCP_KEY[:20]}" + "{GCP_KEY[20:]}"',
    )

    # tier 3 — encoded: base64 / hex / homoglyph
    add("r3-jwt-b64", 3, "jwt", "base64", f"payload={_b64('token=' + JWT)}")
    add("r3-contract-b64", 3, "contract_number", "base64", f"blob={_b64(CONTRACT)}")
    add("r3-gcpkey-hex", 3, "gcp_key", "hex", f"blob={_hex(GCP_KEY)}")
    add(
        "r3-contract-homoglyph",
        3,
        "contract_number",
        "unicode-homoglyph",
        f"ref={_homoglyph_digits(CONTRACT)}",
    )

    # tier 4 — exotic: zero-width separators, layered encoding
    add(
        "r3-part-zw",
        4,
        "part_number",
        "zero-width",
        f"pn{ZW}{PART[3:5]}{ZW}{PART[5:]}ref",
    )
    add(
        "r3-dburl-b64wrapped",
        4,
        "db_url",
        "base64-wrapped",
        f"conn={_b64('url=' + DB_URL)}",
    )
    add(
        "r3-gcpkey-hexwrapped",
        4,
        "gcp_key",
        "hex-wrapped",
        f"raw={_hex('AIza-prefix::' + GCP_KEY)}",
    )

    return C


# ---------------------------------------------------------------------------
# Self-validation: every guardrail is checked over the *written* corpus text.
# ---------------------------------------------------------------------------
_SSN_SHAPE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_REAL_SSN = re.compile(r"\b[0-8][0-9][0-9]-[0-9][0-9]-[0-9]{4}\b")
_EMAIL_SHAPE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_FRAMEWORK = re.compile(r"soc ?2|hi?ppaa|cmmc|gdpr|cui|itar|pii|phi", re.IGNORECASE)


def _validate(payload: dict) -> None:
    if payload.get("_notice") != BANNER:
        raise AssertionError("corpus banner missing or wrong")

    texts = [r["text"] for r in payload["records"]]
    blob = "\n".join(texts) + "\n" + "\n".join(r["kind"] for r in payload["records"])

    # No real-range SSN shapes anywhere; every SSN shape is 900-range.
    if _REAL_SSN.search(blob):
        raise AssertionError("real-range SSN shape found — must be 900-xx-xxxx")
    for m in _SSN_SHAPE.findall(blob):
        if not m.startswith("9"):
            raise AssertionError(f"non-900 SSN shape: {m}")

    # Every fictional phone uses the reserved 555-01xx block.
    for t in texts:
        if "555" in t and "555-01" not in t:
            raise AssertionError(f"phone not in 555-01xx block: {t!r}")

    # Every email-shaped token lives in the reserved example.com domain (or a
    # subdomain of it, e.g. the db.example.com host inside a fake db_url). RFC
    # 2606 reserves example.com and its subdomains, so both are provably fake.
    for m in _EMAIL_SHAPE.findall(blob):
        host = m.lower()
        if not (host.endswith("@example.com") or host.endswith(".example.com")):
            raise AssertionError(f"email outside example.com: {m}")

    # No framework tokens may leak into the corpus (neutral kinds only).
    hit = _FRAMEWORK.search(blob)
    if hit:
        raise AssertionError(f"framework token leaked: {hit.group()!r}")


def main() -> None:
    cases = build_cases()
    _OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _write_json(_OUT_PATH, cases)
    with open(_OUT_PATH, encoding="utf-8") as fh:
        payload = json.load(fh)
    _validate(payload)

    tiers = sorted({c["difficulty"] for c in cases})
    kinds = sorted({c["kind"] for c in cases})
    print(f"[{BANNER}]")
    print(
        f"Wrote {len(cases)} blended set-03 cases across tiers {tiers} to {_OUT_PATH}"
    )
    print(f"Kinds: {', '.join(kinds)}")
    print(
        "Self-validation OK: banner present; SSNs 900-range; phones 555-01xx; "
        "emails @example.com; no framework tokens."
    )


if __name__ == "__main__":
    main()
