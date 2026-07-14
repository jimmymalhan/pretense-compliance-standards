"""
regulated/set02.py — Blended data-set 02 (EU-personal + access-log mix).

SYNTHETIC — FAKE DLP BENCHMARK DATA, NOT REAL. Every value in this module is
fake by construction and drawn from a reserved / example range:

    email        -> ...@example.com          (RFC 2606 reserved domain)
    phone (US)   -> (xxx) 555-01xx            (reserved for fiction/testing)
    phone (EU)   -> +44 (0)20 7946 0xxx       (Ofcom fictional drama range)
    iban         -> check digits forced to 00 (structurally NOT a real IBAN)
    vat          -> two-letter prefix + random digits (bogus registration)
    national_id  -> 4-4-4 grouped digits, random (never issued; not SSN-shaped)
    passport     -> 2 letters + 7 digits, random (e.g. XA0000042)
    db_url       -> user:<random>@db.internal.example.com (example host)
    access-log   -> a plaintext password=<random> token in a fake log line

The cases are BLENDED (kinds interleaved, not grouped) and UN-ANNOTATED — they
are labeled *scanner input* meant to raise detector recall, never camouflage.
Each record is something a correct DLP scanner SHOULD flag.

Run:  python3 dlp_benchmark/regulated/set02.py
      -> writes dlp_benchmark/corpus/blended_regulated_02.json, self-validates.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import random
import re
import string
import sys

# Allow `python3 dlp_benchmark/regulated/set02.py` (script dir, not repo root,
# is sys.path[0]) to import the package by adding the repo root to the path.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from dlp_benchmark import BANNER
from dlp_benchmark.corpus_builder import _write_json

SOURCE_FILE = "corpus/blended_regulated_02.json"
ZW = "​"  # zero-width space

# Deterministic so the "generated" corpus is reproducible for assertions.
random.seed(202)

# Framework tokens that must never appear in output (neutral kinds only).
_FRAMEWORK_RE = re.compile(r"soc ?2|hi?ppaa|cmmc|gdpr|cui|itar|pii|phi", re.IGNORECASE)
# Any SSN-shaped run (ddd-dd-dddd); if present it MUST live in the 900- range.
_SSN_SHAPE_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

_FIRST = ["ava", "liam", "mia", "noah", "elena", "omar", "priya", "diego"]
_LAST = ["carter", "nguyen", "patel", "rossi", "larsen", "mensah", "costa", "wong"]


def _digits(n: int) -> str:
    return "".join(random.choices(string.digits, k=n))


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _fake_email() -> str:
    return f"{random.choice(_FIRST)}.{random.choice(_LAST)}{random.randint(1, 99)}@example.com"


def _fake_us_phone() -> str:
    # 555-01xx is reserved for fiction/testing.
    return f"({_digits(3)}) 555-01{_digits(2)}"


def _fake_eu_phone() -> str:
    # +44 (0)20 7946 0xxx is Ofcom's reserved fictional (drama) range.
    return f"+44 (0)20 7946 0{_digits(3)}"


def _fake_iban(country: str) -> str:
    # Check digits forced to "00" -> structurally NOT a valid IBAN.
    return f"{country}00 XXXX {_digits(4)} {_digits(4)} {_digits(4)} {_digits(2)}"


def _fake_vat(country: str) -> str:
    return f"{country}{_digits(9)}"


def _fake_national_id() -> str:
    # Labeled generic id; grouped so it can never form a ddd-dd-dddd SSN shape.
    return f"9{_digits(3)}-{_digits(4)}-{_digits(4)}"


def _fake_passport() -> str:
    # 2 uppercase letters + 7 digits, e.g. XA0000042 (bogus, never issued).
    return (
        f"{random.choice(string.ascii_uppercase)}"
        f"{random.choice(string.ascii_uppercase)}{_digits(7)}"
    )


def _fake_secret(n: int = 20) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def _fake_db_url() -> str:
    return (
        f"postgres://user:REDACTED{_fake_secret(12)}"
        f"@db.internal.example.com:5432/appdb"
    )


def build_cases() -> list[dict]:
    """Return the blended EU-personal + access-log case list (ids prefixed r2-)."""
    C: list[dict] = []

    def add(cid, difficulty, kind, obfuscation, text):
        C.append({
            "id": cid, "difficulty": difficulty, "kind": kind,
            "obfuscation": obfuscation, "source_file": SOURCE_FILE,
            "text": text, "expected": True,
        })

    # Pre-generate literals we reuse across tiers/encodings.
    iban_gb = _fake_iban("GB")
    iban_de = _fake_iban("DE")
    iban_fr = _fake_iban("FR")
    email_a = _fake_email()
    email_b = _fake_email()
    vat_de = _fake_vat("DE")
    vat_fr = _fake_vat("FR")
    nid = _fake_national_id()
    passport = _fake_passport()
    us_phone = _fake_us_phone()
    eu_phone = _fake_eu_phone()
    db_url = _fake_db_url()
    log_pw = _fake_secret(10)

    # --- tier 0: plain / inline (blended kinds) ---
    add("r2-iban-inline", 0, "iban", "inline",
        f"Settlement account {iban_gb} confirmed for the counterparty.")
    add("r2-email-inline", 0, "email", "inline",
        f"Statements are delivered to {email_a} each month.")
    add("r2-log-inline", 0, "access_log", "inline",
        f"2026-07-11T09:02:17Z INFO auth user={email_b.split('@')[0]} "
        f"password={log_pw} result=ok")
    add("r2-vat-inline", 0, "vat", "inline",
        f"Supplier registration on file: {vat_de}.")
    add("r2-dburl-inline", 0, "db_url", "inline",
        f"Connection string {db_url} in the deploy note.")

    # --- tier 1: labeled fields ---
    add("r2-iban-labeled", 1, "iban", "labeled-field", f"iban: {iban_de}")
    add("r2-nid-labeled", 1, "national_id", "labeled-field",
        f"national_id = {nid}")
    add("r2-passport-labeled", 1, "passport", "labeled-field",
        f"passport_no: {passport}")
    add("r2-phone-eu-labeled", 1, "phone", "labeled-field",
        f"contact_phone: {eu_phone}")
    add("r2-vat-labeled", 1, "vat", "labeled-field", f"VAT: {vat_fr}")

    # --- tier 2: structural (split across quotes / spaced / grouped) ---
    grp = iban_fr.replace(" ", "")
    add("r2-iban-split", 2, "iban", "split-literals",
        f'iban = "{grp[:8]}" "{grp[8:]}"')
    add("r2-email-split", 2, "email", "split-literals",
        f'"{email_a.split("@")[0]}" "@example.com"')
    add("r2-phone-us-spaced", 2, "phone", "spaced",
        f"phone = {us_phone[:5]} {us_phone[6:]}")
    add("r2-log-split", 2, "access_log", "split-literals",
        f'entry = "user=svc " "password={log_pw}"')

    # --- tier 3: encoded (base64 / hex) ---
    add("r2-iban-b64", 3, "iban", "base64", f"blob={_b64(iban_gb)}")
    add("r2-email-b64", 3, "email", "base64", f"blob={_b64(email_b)}")
    add("r2-dburl-b64", 3, "db_url", "base64", f"payload={_b64(db_url)}")
    add("r2-pw-hex", 3, "access_log", "hex",
        f"pw_blob={('password=' + log_pw).encode().hex()}")

    # --- tier 4: exotic (zero-width separators / layered encoding) ---
    add("r2-iban-zw", 4, "iban", "zero-width",
        f"acct {ZW.join(grp[i:i+4] for i in range(0, len(grp), 4))} ref")
    add("r2-nid-zw", 4, "national_id", "zero-width",
        f"id9{ZW}{nid[1:].replace('-', ZW)}x")
    add("r2-dburl-wrapped", 4, "db_url", "base64-wrapped",
        f"cfg={_b64('dsn=' + db_url)}")

    return C


# ---------------------------------------------------------------------------
# Self-validation: every guardrail is enforced before the file is trusted.
# ---------------------------------------------------------------------------

def _validate(cases: list[dict], written_text: str) -> None:
    # 1. Banner present in the written corpus file (JSON escapes non-ASCII, so
    #    parse rather than substring-match the raw text).
    payload = json.loads(written_text)
    if payload.get("_notice") != BANNER:
        raise AssertionError("BANNER missing from written corpus")

    # 2. No framework token anywhere in the written corpus.
    m = _FRAMEWORK_RE.search(written_text)
    if m:
        raise AssertionError(f"framework token {m.group()!r} found in corpus")

    # 3. Any SSN-shaped value must be in the 900- range (there should be none).
    for m in _SSN_SHAPE_RE.finditer(written_text):
        if not m.group().startswith("900-"):
            raise AssertionError(f"non-900 SSN-shaped value: {m.group()!r}")

    # 4. Per-kind fakeness checks over the canonical (tier 0-1) values.
    for c in cases:
        text = c["text"]
        if c["kind"] == "email" and c["obfuscation"] in ("inline", "labeled-field"):
            if "@example.com" not in text:
                raise AssertionError(f"email not @example.com: {c['id']}")
        if c["kind"] == "phone" and c["obfuscation"] == "labeled-field":
            # EU-format is the Ofcom fictional range; must be provably fake.
            if "7946" not in text:
                raise AssertionError(f"EU phone not in fiction range: {c['id']}")
        if c["kind"] == "iban" and c["obfuscation"] in ("inline", "labeled-field"):
            # Check digits (2 chars after the country code) must be "00".
            mo = re.search(r"[A-Z]{2}(\d\d)", text)
            if not mo or mo.group(1) != "00":
                raise AssertionError(f"IBAN check digits not 00: {c['id']}")
        if c["kind"] == "national_id" and c["obfuscation"] in ("inline", "labeled-field"):
            # Canonical form is 4-4-4 grouped digits (never SSN-shaped).
            if not re.search(r"\d{4}-\d{4}-\d{4}", text):
                raise AssertionError(f"national_id not 4-4-4: {c['id']}")
        if c["kind"] == "passport" and c["obfuscation"] in ("inline", "labeled-field"):
            # Canonical form is 2 uppercase letters + 7 digits.
            if not re.search(r"\b[A-Z]{2}\d{7}\b", text):
                raise AssertionError(f"passport not 2-letter+7-digit: {c['id']}")
        if c["kind"] == "vat" and c["obfuscation"] in ("inline", "labeled-field"):
            # Canonical form is 2 uppercase letters + 8-12 digits.
            if not re.search(r"\b[A-Z]{2}\d{8,12}\b", text):
                raise AssertionError(f"vat not 2-letter+8-12-digit: {c['id']}")

    # 5. At least one US-format phone with 555-01 survives as a fake anchor.
    if not any("555-01" in c["text"] for c in cases if c["kind"] == "phone"):
        raise AssertionError("no US-format 555-01 phone anchor present")


def main() -> None:
    cases = build_cases()
    out_path = pathlib.Path(_REPO_ROOT) / "dlp_benchmark" / SOURCE_FILE
    out_path.parent.mkdir(parents=True, exist_ok=True)
    _write_json(out_path, cases)

    written_text = out_path.read_text(encoding="utf-8")
    _validate(cases, written_text)

    tiers = sorted({c["difficulty"] for c in cases})
    kinds = sorted({c["kind"] for c in cases})
    print(f"Wrote {len(cases)} synthetic cases across tiers {tiers} to {out_path}")
    print(f"Kinds: {kinds}")
    print(f"Self-validation OK. Reminder: {BANNER}.")


if __name__ == "__main__":
    main()
