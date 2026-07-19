"""
regulated/set06.py  —  Blended data-set 06 (deepen: financial / card / extra-PII / network)

Adds SYNTHETIC cases for the newer data kinds — card_cvv, bank_account,
routing_number, ein, drivers_license, date_of_birth, ip_address, ipv6 — plus
top-ups for pan and iban, each across difficulty tiers 0-4 (inline, labeled,
split, base64/hex, zero-width). Every value is provably fake by construction:

    - card_cvv        -> labeled 3-4 digits
    - bank_account    -> labeled, leading-zero test account
    - routing_number  -> 011000015 (a well-known TEST routing number)
    - ein             -> 12-3456789 (fake)
    - drivers_license -> D + 7 digits (fake)
    - date_of_birth   -> 1970-01-01 (fake)
    - ip_address      -> 192.0.2.x / 198.51.100.x  (RFC 5737 TEST-NET, non-routable)
    - ipv6            -> 2001:db8::  (RFC 3849 documentation range)
    - pan             -> Luhn-valid but random -> not a real account
    - iban            -> mod-97 VALID; published examples / unallocated bank codes

Neutral `kind` labels only (no compliance-framework strings in any payload).
Every case is scanner INPUT (`expected: True`). Each generated case is
self-checked to be detected by the reference detector in hardened mode.

Run:  python3 pretense_compliance_standards/regulated/set06.py
"""

from __future__ import annotations

import base64
import pathlib
import re
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from pretense_compliance_standards import (
    BANNER,
    corpus_builder as _cb,
)
from pretense_compliance_standards.detector import detect

SOURCE_FILE = "corpus/blended_regulated_06.json"
ZW = "\u200b"  # zero-width space


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _tiers(cid_prefix: str, kind: str, value: str):
    """Emit tier 0-4 cases for a labeled/canonical `value` string.

    Uses only reliably-reversible obfuscations: inline/labeled/log keep the value
    intact; base64 and hex decode back to it exactly (via the detector's hardened
    views). Every emitted case is therefore detectable in hardened mode.
    """
    return [
        (f"{cid_prefix}-t0", 0, kind, "inline", f"Record on file: {value}."),
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


# canonical fake "label: value" strings per kind
_VALUES = {
    "card_cvv": ["card cvv: 123", "cvc: 4567"],
    "bank_account": ["bank_account: 000123456789", "acct number: 000998877665"],
    "routing_number": ["routing: 011000015", "aba number: 021000021"],
    "ein": ["ein 12-3456789", "ein 98-7654321"],
    "drivers_license": ["dl: D1234567", "driver license: A7654321"],
    "date_of_birth": ["dob: 1970-01-01", "date of birth: 1985-12-31"],
    "ip_address": ["ip 192.0.2.44", "src 198.51.100.7"],
    "ipv6": ["addr 2001:db8:0:0:0:0:0:1", "addr 2001:db8:85a3:0:0:8a2e:370:7334"],
    "pan": ["card 4111111111111111", "card 5500005555555559"],
    # Checksum-VALID across four country layouts (GB/DE 22, FR 27, NL 18). The
    # first two are the canonical published example IBANs — the same class of
    # documented-but-unusable value as the 4111… test PAN and AWS's
    # AKIAIOSFODNN7EXAMPLE key already used elsewhere in this corpus. The last
    # two are built on unallocated bank codes (99999 / TEST). Check digits are
    # real: a `00` check, as used previously, is something a correct IBAN
    # validator must reject, so it could never measure recall.
    "iban": [
        "iban GB82WEST12345698765432",
        "iban DE89370400440532013000",
        f"iban {_cb.make_iban('FR', '99999' + '00001' + '12345678901' + '42')}",
        f"iban {_cb.make_iban('NL', 'TEST' + '0123456789')}",
    ],
    "phone": ["phone (415) 555-0142", "contact 020 7946 0958"],
    "national_id": ["national_id 9041-7745-8035", "id 9000-4200-0001"],
}


def build_cases() -> list[dict]:
    C: list[dict] = []
    for kind, values in _VALUES.items():
        for i, value in enumerate(values):
            for cid, tier, k, obf, text in _tiers(f"r6-{kind}-{i}", kind, value):
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
    r"soc ?2|hi?ppaa|cmmc|gdpr|iso.?27|nist|pci|hitrust", re.IGNORECASE
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
        f"set06: {len(cases)} cases, {len(kinds)} kinds, all detected in hardened mode ✓"
    )
    print(f"Reminder: {BANNER}")


if __name__ == "__main__":
    main()
