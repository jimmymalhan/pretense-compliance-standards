"""
regulated/set05.py  —  Blended data-set 05 (unit #8)

A CROSS-CATEGORY slice of the SYNTHETIC DLP benchmark. Every case embeds a
provably-fake sensitive value inside a realistic-looking container — a
finance-entity CSV row, an env/config blob, a JSON fragment, or a log line —
so a detector (and the `pretense` identify+mutate pipeline) has to find the
value *in situ*, not as a bare literal.

Provable-fakeness contract (identical spirit to the rest of the benchmark):
    - SSN-shaped   -> 9xx-xx-xxxx   (900 range is NEVER issued)
    - phone        -> 555-01xx      (reserved for fiction/testing)
    - email        -> @example.com  (RFC 2606 reserved domain)
    - PAN          -> Luhn-valid but random (generator._luhn_card) -> not real
    - IBAN         -> check digits `00` (never valid) -> guaranteed fake
    - api_key      -> sk_test_...    (test-mode prefix)
    - db_url       -> host .example.com, test creds

Neutral `kind` labels only (no compliance-framework strings anywhere). Each
case is labeled scanner INPUT (`expected: True`) to raise detector recall.

Run:  python3 dlp_benchmark/regulated/set05.py
      -> writes corpus/blended_regulated_05.json, self-validates, prints summary.
"""

from __future__ import annotations

import json
import pathlib
import random
import re
import string
import sys

# Allow running as a plain script (python3 dlp_benchmark/regulated/set05.py)
# as well as `python3 -m dlp_benchmark.regulated.set05`.
if __package__ in (None, ""):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from dlp_benchmark import BANNER
from dlp_benchmark import corpus_builder
from dlp_benchmark.generator import (
    CURRENCIES,
    TICKERS,
    _luhn_card,
)

SOURCE_FILE = "corpus/blended_regulated_05.json"

# Deterministic so the corpus and test assertions are reproducible.
random.seed(505)


# --- provably-fake value helpers ---------------------------------------------

def _digits(n: int) -> str:
    return "".join(random.choices(string.digits, k=n))


def _fake_iban(country: str = "GB", bank: str = "SYNT") -> str:
    """A structurally-shaped IBAN with check digits ``00``.

    Real IBAN check digits are in 02..98; ``00`` never validates, so any IBAN
    emitted here is guaranteed fake while still *looking* like the real thing.
    """
    return f"{country}00{bank}{_digits(14)}"


def _fake_ssn() -> str:
    return f"9{_digits(2)}-{_digits(2)}-{_digits(4)}"


def _fake_phone_dashed() -> str:
    return f"{_digits(3)}-555-01{_digits(2)}"


def _fake_email() -> str:
    first = random.choice(["ava", "liam", "mia", "omar", "priya", "diego"])
    last = random.choice(["carter", "nguyen", "patel", "rossi"])
    return f"{first}.{last}{random.randint(1, 99)}@example.com"


def _api_key() -> str:
    return "sk_test_" + "".join(random.choices(string.ascii_letters + string.digits, k=24))


def _db_url() -> str:
    return (
        f"postgres://svc_reporting:test_pw_{_digits(4)}"
        f"@warehouse-{random.randint(1, 9)}.db.example.com:5432/analytics"
    )


def _mrn() -> str:
    return f"MRN{_digits(8)}"


def _contract_no() -> str:
    return f"CTR-{random.randint(2020, 2026)}-{_digits(6)}"


def _ticker_row(value: str) -> str:
    """Embed *value* as a trailing cell in a finance-entity CSV row."""
    tkr, company, exch, _mic = random.choice(TICKERS)
    ccy = random.choice(CURRENCIES)
    return f"{tkr},{company},{exch},{value},{ccy}"


# --- case construction --------------------------------------------------------

def build_cases() -> list[dict]:
    """Return this unit's ground-truth case list (blended, un-annotated)."""
    C: list[dict] = []

    def add(cid, difficulty, kind, obfuscation, text):
        C.append({
            "id": cid,
            "difficulty": difficulty,
            "kind": kind,
            "obfuscation": obfuscation,
            "source_file": SOURCE_FILE,
            "text": text,
            "expected": True,
        })

    # --- tier 1: labeled fields, canonical-reachable but wrapped in context ---
    add("r5-pan-csv", 1, "pan", "csv-cell", _ticker_row(_luhn_card()))
    add("r5-iban-field", 1, "iban", "config-field", f"settlement_iban = {_fake_iban()}")
    add("r5-apikey-env", 1, "api_key", "env-field", f"STRIPE_API_KEY={_api_key()}")
    add("r5-dburl-env", 1, "db_url", "env-field", f"DATABASE_URL={_db_url()}")
    add("r5-mrn-field", 1, "health_record", "config-field", f"patient_mrn: {_mrn()}")
    add("r5-contract-cell", 1, "contract_number", "csv-cell",
        _ticker_row(_contract_no()))

    # --- tier 2: structural — value split / grouped / inside a JSON fragment ---
    pan2 = _luhn_card()
    add("r5-pan-json", 2, "pan", "json-fragment",
        json.dumps({"ticker": "AAPL", "card_on_file": pan2, "status": "active"}))
    iban2 = _fake_iban("DE", "TEST")
    add("r5-iban-spaced", 2, "iban", "space-grouped",
        f"IBAN {iban2[0:4]} {iban2[4:8]} {iban2[8:12]} {iban2[12:16]} {iban2[16:]}")
    add("r5-ssn-json", 2, "ssn", "json-fragment",
        json.dumps({"holder": "Ava Carter", "tax_id": _fake_ssn(), "sector": "Financials"}))
    add("r5-dburl-log", 2, "db_url", "log-line",
        f"2026-07-11T09:12:03Z WARN pool connect dsn={_db_url()} retries=3")
    add("r5-contract-log", 2, "contract_number", "log-line",
        f"2026-07-11T09:15:44Z INFO renew contract={_contract_no()} portfolio=NMS")

    # --- tier 3: exotic — encoded / concatenated / homoglyph in a container ---
    api3 = _api_key()
    add("r5-apikey-split", 3, "api_key", "concatenated",
        f'key = "{api3[:12]}" + "{api3[12:]}"')
    ssn3 = _fake_ssn()
    add("r5-ssn-homoglyph", 3, "ssn", "unicode-homoglyph",
        f"account_holder_ssn=９{ssn3[1:]}")  # fullwidth leading 9
    iban3 = _fake_iban("FR", "SYNT")
    add("r5-iban-json-b64", 3, "iban", "base64-in-json",
        json.dumps({"acct": "brokerage",
                    "iban_b64": corpus_builder._b64(iban3)}))
    add("r5-email-log", 3, "email", "log-line",
        f"2026-07-11T09:20:10Z INFO statement_sent to={_fake_email()} exch=XNAS")

    # --- tier 4: layered / zero-width inside realistic finance rows -----------
    zw = corpus_builder.ZW
    pan4 = _luhn_card()
    add("r5-pan-zw-csv", 4, "pan", "zero-width",
        _ticker_row(f"{pan4[:4]}{zw}{pan4[4:8]}{zw}{pan4[8:12]}{zw}{pan4[12:]}"))
    phone4 = _fake_phone_dashed()
    add("r5-phone-hex-log", 4, "phone", "hex-encoded",
        f"2026-07-11T09:31:02Z DEBUG contact raw={phone4.encode().hex()} region=NYQ")
    iban4 = _fake_iban("NL", "TEST")
    add("r5-iban-zw-field", 4, "iban", "zero-width",
        f"beneficiary_iban:{iban4[:8]}{zw}{iban4[8:]}")

    return C


# --- self-validation ----------------------------------------------------------

_FRAMEWORK_RE = re.compile(r"soc ?2|hi?ppaa|cmmc|gdpr|cui|itar|pii|phi", re.IGNORECASE)
_SSN_SHAPED_RE = re.compile(r"\b[0-8][0-9][0-9]-[0-9][0-9]-[0-9]{4}\b")
_NINE_SSN_RE = re.compile(r"9\d\d-\d\d-\d{4}")


def _validate(cases: list[dict], payload_text: str) -> None:
    """Raise AssertionError on any guardrail violation."""
    # BANNER round-trips through the parsed structure (json.dump escapes the
    # em-dash to —, so a raw substring check on the serialized text fails).
    payload = json.loads(payload_text)
    assert payload.get("_notice") == BANNER, "banner missing from written corpus"
    assert not _FRAMEWORK_RE.search(payload_text), "framework token leaked into corpus"
    # No real-looking (0-8 leading) SSN shapes anywhere in the serialized file.
    assert not _SSN_SHAPED_RE.search(payload_text), "non-900 SSN shape found"

    for c in cases:
        text = c["text"]
        assert not _FRAMEWORK_RE.search(text), f"{c['id']}: framework token in text"
        assert c["expected"] is True, f"{c['id']}: expected must be True"
        assert c["source_file"] == SOURCE_FILE, f"{c['id']}: wrong source_file"
        assert 1 <= c["difficulty"] <= 4, f"{c['id']}: difficulty out of range"

        if c["kind"] == "ssn" and c["obfuscation"] != "unicode-homoglyph":
            assert _NINE_SSN_RE.search(text), f"{c['id']}: SSN not in 900 range"
        if c["kind"] == "phone" and c["obfuscation"] == "dashed":
            assert "555-01" in text, f"{c['id']}: phone not 555-01xx"
        if c["kind"] == "email" and "@" in text:
            assert "@example.com" in text, f"{c['id']}: email not @example.com"
        if c["kind"] == "iban" and c["obfuscation"] in ("config-field", "csv-cell"):
            # Country code + '00' check digits, un-obfuscated forms only.
            assert re.search(r"[A-Z]{2}00", text), f"{c['id']}: IBAN check digits not 00"


def main() -> int:
    cases = build_cases()
    out_path = pathlib.Path(__file__).resolve().parents[1] / SOURCE_FILE
    out_path.parent.mkdir(parents=True, exist_ok=True)
    corpus_builder._write_json(out_path, cases)

    payload_text = out_path.read_text(encoding="utf-8")
    _validate(cases, payload_text)

    tiers = sorted({c["difficulty"] for c in cases})
    kinds = sorted({c["kind"] for c in cases})
    print(f"[set05] wrote {len(cases)} blended cases -> {out_path}")
    print(f"[set05] tiers={tiers} kinds={kinds}")
    print(f"[set05] self-validation PASSED. {BANNER}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
