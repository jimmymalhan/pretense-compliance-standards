"""
regulated/set09.py  —  Blended data-set 09 (breadth: new data kinds)

Adds SYNTHETIC cases for the M3 data kinds, each across difficulty tiers 0-4
(inline, labeled, log-line, base64, hex). Every value is provably fake:

    - mac_address           -> 00:00:5E:00:53:xx  (RFC 7042 documentation range)
    - crypto_wallet_address -> Ethereum 0x + 40 hex, a null/burn-style address
    - ssh_private_key       -> a PEM "BEGIN ... PRIVATE KEY" header (no real key)
    - swift_bic             -> "TEST"-prefixed BIC (no such institution)
    - vehicle_vin           -> a public NHTSA/maker example VIN
    - medicare_id           -> a CMS example MBI format

Neutral `kind` labels only — no compliance-framework strings in any payload.
Every case is scanner INPUT (`expected: True`) and is self-checked to be detected
by the reference detector in hardened mode.

Run:  python3 pretense_compliance_standards/regulated/set09.py
"""

from __future__ import annotations

import pathlib
import re
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from pretense_compliance_standards import corpus_builder as _cb
from pretense_compliance_standards.detector import detect

SOURCE_FILE = "corpus/blended_regulated_09.json"
_b64 = _cb._b64  # reuse the shared base64 helper (no divergent copy)


def _tiers(cid_prefix: str, kind: str, value: str):
    """Emit tier 0-4 cases for a labeled/canonical `value` (reliably reversible)."""
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
    "mac_address": ["mac 00:00:5e:00:53:af", "mac 00:00:5e:00:53:1b"],
    "crypto_wallet_address": [
        "wallet 0x000000000000000000000000000000000000dEaD",
        "eth 0x00000000000000000000000000000000DeaDBeef",
    ],
    "ssh_private_key": [
        "key -----BEGIN OPENSSH PRIVATE KEY-----",
        "key -----BEGIN RSA PRIVATE KEY-----",
    ],
    "swift_bic": ["bic: TESTGB2LXXX", "swift TESTUS33"],
    "vehicle_vin": ["vin: 1HGBH41JXMN109186", "vin 5YJ3E1EA7JF000316"],
    "medicare_id": ["medicare id: 1EG4TE5MK73", "mbi 2CT3E4RM56K"],
}


def build_cases() -> list[dict]:
    C: list[dict] = []
    for kind, values in _VALUES.items():
        for i, value in enumerate(values):
            for cid, tier, k, obf, text in _tiers(f"r9-{kind}-{i}", kind, value):
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
    r"soc ?2|hip+a+|cmmc|gdpr|iso.?27|nist|pci|hitrust", re.IGNORECASE
)


def _validate(cases: list[dict]) -> None:
    for c in cases:
        assert _FRAMEWORK_RE.search(c["text"]) is None, f"framework token in {c['id']}"
        assert c["kind"] in detect(
            c["text"], "hardened"
        ), f"undetectable: {c['id']} ({c['obfuscation']})"


def main() -> None:
    cases = build_cases()
    _validate(cases)
    _cb._write_json(pathlib.Path(__file__).parent.parent / SOURCE_FILE, cases)
    kinds = sorted({c["kind"] for c in cases})
    print(
        f"set09: {len(cases)} cases, {len(kinds)} kinds, all detected in hardened mode ✓"
    )


if __name__ == "__main__":
    main()
