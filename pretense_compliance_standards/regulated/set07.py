"""
regulated/set07.py  —  Blended data-set 07 (deepen: vendor secrets + thin-kind top-ups)

Adds SYNTHETIC cases for additional secret/credential kinds (openai_key,
anthropic_key, azure_key, sendgrid_key, twilio_key, slack_token) and tops up
previously-thin kinds (aws_key, gcp_key, jwt, secret, vat, icd10,
insurance_member_id, health_record, access_log, contract_number, part_number,
internal_program_code, passport, npi) across difficulty tiers 0-4.

Every secret uses a test/example form with a random-but-fake body (or the
denylisted test literal); no value is a real credential. Neutral `kind` labels
only (no compliance-framework strings in any payload). Each generated case is
self-checked to be detected by the reference detector in hardened mode.

Run:  python3 pretense_compliance_standards/regulated/set07.py
"""

from __future__ import annotations

import base64
import pathlib
import re
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from pretense_compliance_standards import BANNER
from pretense_compliance_standards import corpus_builder as _cb
from pretense_compliance_standards.detector import detect

SOURCE_FILE = "corpus/blended_regulated_07.json"


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _tiers(cid_prefix: str, kind: str, value: str):
    return [
        (f"{cid_prefix}-t0", 0, kind, "inline", f"Record: {value} on file"),
        (f"{cid_prefix}-t1", 1, kind, "labeled-field", f"[{kind}] {value}"),
        (
            f"{cid_prefix}-t2",
            2,
            kind,
            "log-line",
            f"2026-01-01T00:00:00Z INFO audit {value} ok",
        ),
        (f"{cid_prefix}-t3", 3, kind, "base64", f"blob={_b64(value)}"),
        (f"{cid_prefix}-t4", 4, kind, "hex", f"raw={value.encode().hex()}"),
    ]


# canonical fake "label value" strings per kind (2 each -> 10 cases/kind)
_VALUES = {
    "openai_key": ["openai key sk-" + "A" * 40, "openai sk-proj-" + "B" * 30],
    "anthropic_key": [
        "anthropic sk-ant-api03-" + "B" * 24 + "FAKE",
        "anthropic sk-ant-api03-" + "C" * 20 + "TEST",
    ],
    "azure_key": ["conn AccountKey=" + "C" * 44, "conn AccountKey=" + "D" * 50],
    "sendgrid_key": [
        "sendgrid SG." + "d" * 22 + "." + "e" * 43,
        "sendgrid SG." + "f" * 22 + "." + "g" * 43,
    ],
    "twilio_key": ["twilio SK" + "a" * 32, "twilio SK" + "0123456789abcdef" * 2],
    "slack_token": ["slack xoxb-1234567890-FAKE", "slack xoxp-0987654321-TEST"],
    "aws_key": ["aws AKIAIOSFODNN7EXAMPLE", "aws AKIAI44QH8DHBEXAMPLE"],
    "gcp_key": ["gcp AIza" + "F" * 35, "gcp AIza" + "G" * 35],
    "jwt": [
        "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJlX2Zha2U",
        "token eyJhbGciOiJSUzI1NiJ9.eyJpZCI6IjEyMyJ9.YW5vdGhlcl9mYWtlX3NpZw",
    ],
    "secret": ["signing hardcoded-not-rotated-secret", "cred hunter2 rotated"],
    "vat": ["vat DE123456789", "vat FR12345678901"],
    "icd10": ["diagnosis code F32.1 noted", "primary code E11.9 listed"],
    "insurance_member_id": ["member RRF139047426", "member OTQ678234461"],
    "health_record": [
        "note patient diagnosed with hypertension today",
        "chart diagnosed with asthma this visit",
    ],
    "access_log": [
        "auth user=svc password=NE8vjuSe6M",
        "login user=admin password=Zx7QwErTy1",
    ],
    "contract_number": ["award CTR-2026-934216", "renew CTR-2024-805123"],
    "part_number": ["part PN-9FRUDT", "part PN-AX7K93Q"],
    "internal_program_code": ["program PRG-1B3ZEK", "code PRG-9ZK4Q2"],
    "passport": ["passport XA0000042", "passport ZB1234567"],
    "npi": ["provider npi: 1234567890", "npi 9876543210"],
}


def build_cases() -> list[dict]:
    C: list[dict] = []
    for kind, values in _VALUES.items():
        for i, value in enumerate(values):
            for cid, tier, k, obf, text in _tiers(f"r7-{kind}-{i}", kind, value):
                C.append(
                    {
                        "id": cid,
                        "difficulty": tier,
                        "kind": k,
                        "obfuscation": obf,
                        "source_file": SOURCE_FILE,
                        "text": text,
                        "expected": True,
                    }
                )
    return C


_FRAMEWORK_RE = re.compile(
    r"soc ?2|hi?ppaa|cmmc|gdpr|iso.?27|nist|hitrust|pci|itar", re.IGNORECASE
)


def _validate(cases: list[dict]) -> None:
    for c in cases:
        assert _FRAMEWORK_RE.search(c["text"]) is None, f"framework token in {c['id']}"
        assert not re.search(
            r"\b[0-8]\d\d-\d\d-\d{4}\b", c["text"]
        ), f"non-900 SSN in {c['id']}"
        assert c["kind"] in detect(
            c["text"], "hardened"
        ), f"undetectable: {c['id']} ({c['obfuscation']})"


def main() -> None:
    cases = build_cases()
    _validate(cases)
    _cb._write_json(pathlib.Path(__file__).parent.parent / SOURCE_FILE, cases)
    kinds = sorted({c["kind"] for c in cases})
    print(
        f"set07: {len(cases)} cases, {len(kinds)} kinds, all detected in hardened mode ✓"
    )
    print(f"Reminder: {BANNER}")


if __name__ == "__main__":
    main()
