"""
generator.py

SYNTHETIC test-data generator for DLP / PII / PHI / secret-scanner benchmarking.
(Refactored from the original top-level ``sensitive_data_samples.py``.)

Every value produced here is FAKE and randomly generated. No record maps to a
real person, account, or medical file. The purpose is to exercise data-loss-
prevention (DLP) tools, PII/PHI classifiers, and secret scanners with records
that *look* like violations of PII, PHI/HIPAA, PCI, NIST and SOC 2 controls.

To keep the fakeness *provable*, every value is drawn from a reserved / example
range:
    - SSN         -> 9xx-xx-xxxx  (the 900 range is NEVER issued)
    - phone       -> (xxx) 555-01xx  (555-01xx is reserved for fiction/testing)
    - email       -> ...@example.com  (RFC 2606 reserved domain)
    - AWS key     -> AKIAIOSFODNN7EXAMPLE  (AWS's own documentation example)
    - card (PAN)  -> Luhn-valid but random -> not a real account
    - API key     -> sk_test_...  (test-mode prefix)

Records are given a *finance-domain* flavor (tickers, exchanges, sectors drawn
from this repository's own data) so the corpus reads as representative of this
project — but they remain 100% synthetic.

Do NOT put real production data in this file. Do NOT commit real secrets.
"""

from __future__ import annotations

import json
import random
import string
from dataclasses import asdict, dataclass
from datetime import date, timedelta

from . import BANNER

# Seed so the "generated" data is reproducible for test assertions.
random.seed(42)

FIRST_NAMES = ["Ava", "Liam", "Noah", "Mia", "Ethan", "Sofia", "Lucas", "Isla",
               "Mason", "Zoe", "Elena", "Omar", "Priya", "Diego", "Hana"]
LAST_NAMES = ["Carter", "Nguyen", "Patel", "Garcia", "Rossi", "Kim", "Okafor",
              "Silva", "Haddad", "Larsen", "Ivanov", "Mensah", "Costa", "Wong"]
STREETS = ["Maple Ave", "Oak St", "Cedar Ln", "Birch Rd", "Elm Ct", "Pine Way"]
CITIES = [("Austin", "TX", "78701"), ("Denver", "CO", "80202"),
          ("Portland", "OR", "97201"), ("Tampa", "FL", "33602"),
          ("Reno", "NV", "89501")]
DIAGNOSES = [
    ("E11.9", "Type 2 diabetes mellitus without complications"),
    ("I10", "Essential (primary) hypertension"),
    ("F32.1", "Major depressive disorder, moderate"),
    ("J45.909", "Unspecified asthma, uncomplicated"),
    ("B20", "Human immunodeficiency virus [HIV] disease"),
]
MEDICATIONS = ["Metformin 500mg", "Lisinopril 10mg", "Sertraline 50mg",
               "Albuterol HFA", "Atorvastatin 20mg"]
INSURERS = ["BlueCross Synthetic", "UnitedFake Health", "Aetna-Test", "Cigna-Demo"]

# --- Finance-domain flavor, drawn from this repo's own entities (fake pairing) ---
TICKERS = [
    ("AAPL", "Apple Inc.", "NMS", "XNAS"),
    ("MSFT", "Microsoft Corporation", "NMS", "XNAS"),
    ("NVDA", "NVIDIA Corporation", "NMS", "XNAS"),
    ("AMZN", "Amazon.com, Inc.", "NMS", "XNAS"),
    ("TSLA", "Tesla, Inc.", "NMS", "XNAS"),
    ("GOOGL", "Alphabet Inc.", "NMS", "XNAS"),
]
SECTORS = ["Information Technology", "Financials", "Health Care",
           "Consumer Discretionary", "Communication Services", "Energy"]
CURRENCIES = ["USD", "EUR", "GBP", "CAD", "AUD"]


def _digits(n: int) -> str:
    return "".join(random.choices(string.digits, k=n))


def _luhn_card() -> str:
    """Generate a fake 16-digit number that passes the Luhn check (test PAN)."""
    body = [random.randint(0, 9) for _ in range(15)]
    total = 0
    for i, d in enumerate(reversed(body)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    check = (10 - (total % 10)) % 10
    return "".join(map(str, body + [check]))


def _fake_ssn() -> str:
    # Uses the 900-xx-xxxx range, which is NEVER issued -> guaranteed fake.
    return f"9{_digits(2)}-{_digits(2)}-{_digits(4)}"


def _fake_dob() -> str:
    start = date(1950, 1, 1)
    return (start + timedelta(days=random.randint(0, 25000))).isoformat()


def _fake_email(first: str, last: str) -> str:
    return f"{first.lower()}.{last.lower()}{random.randint(1, 99)}@example.com"


def _fake_phone() -> str:
    # 555-01xx is reserved for fiction/testing.
    return f"({_digits(3)}) 555-01{_digits(2)}"


def _api_key() -> str:
    return "sk_test_" + "".join(random.choices(string.ascii_letters + string.digits, k=24))


@dataclass
class SubjectRecord:
    """A single synthetic person combining PII + PHI (HIPAA-style violation)."""
    record_id: str
    full_name: str
    ssn: str                    # PII
    date_of_birth: str          # PII / HIPAA identifier
    email: str                  # PII
    phone: str                  # PII
    street_address: str         # PII
    city_state_zip: str         # PII
    drivers_license: str        # PII
    passport_number: str        # PII
    credit_card: str            # PCI / SOC 2 (unmasked PAN)
    card_cvv: str               # PCI (must never be stored)
    # --- PHI / HIPAA ---
    medical_record_number: str
    icd10_code: str
    diagnosis: str
    medication: str
    insurance_provider: str
    insurance_member_id: str
    # --- finance-domain flavor (fake brokerage account) ---
    brokerage_ticker: str
    brokerage_exchange: str
    brokerage_mic: str
    account_currency: str
    sector: str


def generate_subject(i: int) -> SubjectRecord:
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    city, st, zc = random.choice(CITIES)
    icd, dx = random.choice(DIAGNOSES)
    ticker, _company, exch, mic = random.choice(TICKERS)
    return SubjectRecord(
        record_id=f"REC-{1000 + i}",
        full_name=f"{first} {last}",
        ssn=_fake_ssn(),
        date_of_birth=_fake_dob(),
        email=_fake_email(first, last),
        phone=_fake_phone(),
        street_address=f"{random.randint(100, 9999)} {random.choice(STREETS)}",
        city_state_zip=f"{city}, {st} {zc}",
        drivers_license=f"{random.choice(string.ascii_uppercase)}{_digits(7)}",
        passport_number=f"{random.choice(string.ascii_uppercase)}{_digits(8)}",
        credit_card=_luhn_card(),
        card_cvv=_digits(3),
        medical_record_number=f"MRN{_digits(8)}",
        icd10_code=icd,
        diagnosis=dx,
        medication=random.choice(MEDICATIONS),
        insurance_provider=random.choice(INSURERS),
        insurance_member_id=f"{random.choice(string.ascii_uppercase)*3}{_digits(9)}",
        brokerage_ticker=ticker,
        brokerage_exchange=exch,
        brokerage_mic=mic,
        account_currency=random.choice(CURRENCIES),
        sector=random.choice(SECTORS),
    )


# --- NIST / SOC 2 style anti-patterns: hardcoded secrets & weak config ---
# (Intentionally "bad" so secret scanners have something to flag.)
INSECURE_CONFIG = {
    "db_connection": "postgres://admin:P@ssw0rd123@db.internal.example.com:5432/prod",
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",              # AWS example key
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "stripe_api_key": _api_key(),
    "jwt_signing_secret": "hardcoded-not-rotated-secret",
    "password_hash_algorithm": "md5",                          # NIST: weak hash
    "tls_min_version": "1.0",                                  # NIST: deprecated
    "encryption_at_rest": False,                               # SOC 2 gap
}

# SOC 2 anti-pattern: plaintext credentials landing in application logs.
INSECURE_LOG_LINES = [
    "2026-07-10T08:14:22Z INFO login user=ava.carter password=hunter2 result=success",
    "2026-07-10T08:15:03Z DEBUG charge card=4111111111111111 cvv=123 amount=42.00",
    "2026-07-10T08:16:47Z INFO reset_token=abc123resettoken sent to liam.kim9@example.com",
]


def build_dataset(n_subjects: int = 10) -> dict:
    return {
        "_notice": BANNER + " — all values are fake/generated.",
        "subjects": [asdict(generate_subject(i)) for i in range(n_subjects)],
        "insecure_config": INSECURE_CONFIG,
        "insecure_logs": INSECURE_LOG_LINES,
    }


if __name__ == "__main__":
    data = build_dataset(10)
    out_path = "sample_violations.json"
    with open(out_path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"Wrote {len(data['subjects'])} synthetic subject records to {out_path}")
    print(f"Reminder: {BANNER}. For DLP/PII/PHI scanner testing only.")
