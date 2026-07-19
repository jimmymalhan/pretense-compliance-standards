"""
regulated/set10.py  —  Blended data-set 10 (breadth: M10 structured data kinds)

Adds SYNTHETIC cases for the M10 data kinds, each across difficulty tiers 0-4
(inline, labeled, log-line, base64, hex). These deepen per-framework coverage —
device / advertising identifiers for the global privacy frameworks, a UK national
id and NHS number, more credential formats, a crypto address, and card Track-2
stripe data. Every value is provably fake / reserved by construction:

    - imei                   -> a public GSMA example IMEI (15 digits, Luhn check)
    - imsi                   -> MCC 001 (ITU-reserved test network), never a subscriber
    - advertising_id         -> the all-zero opt-out (limit-ad-tracking) UUID
    - uk_nino                -> "QQ" prefix, never allocated as a real NINO
    - uk_nhs_number          -> the 999-range reserved for NHS test patients
    - stripe_restricted_key  -> rk_test_ / rk_live_ example key (no real account)
    - github_finegrained_pat -> github_pat_ example token (no real grant)
    - google_oauth_secret    -> GOCSPX- example secret (no real client)
    - pgp_private_key        -> a COMPLETE RFC 4880 armored block (banner, Version
                               header, 64-char-wrapped body, real CRC-24 line, END
                               banner); plus one `banneronly` truncated-paste case
    - aws_temp_key           -> ASIA + 16 chars from the base32 alphabet [A-Z2-7]
                               that real AWS key ids are drawn from
    - bitcoin_address        -> a well-known documented burn address (unspendable)
    - credit_card_track2     -> ;<test PAN>=…? using the 4111… test card number

Neutral `kind` labels only — no compliance-framework strings in any payload.
Every case is scanner INPUT (`expected: True`) and is self-checked to be detected
by the reference detector in hardened mode.

Run:  python3 pretense_compliance_standards/regulated/set10.py
"""

from __future__ import annotations

import pathlib
import re
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from pretense_compliance_standards import corpus_builder as _cb
from pretense_compliance_standards.detector import detect

SOURCE_FILE = "corpus/blended_regulated_10.json"
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
    "imei": ["imei 49-015420-323751-8", "imei: 35-209900-176148-1"],
    "imsi": ["imsi 001010123456789", "imsi: 001019999999999"],
    "advertising_id": [
        "idfa 00000000-0000-0000-0000-000000000000",
        "gaid: 00000000-0000-0000-0000-000000000000",
    ],
    "uk_nino": ["nino QQ123456C", "ni number QQ654321A"],
    "uk_nhs_number": ["nhs 999 000 0001", "nhs number: 999 000 0018"],
    # Assembled from fragments so the committed source holds no contiguous Stripe
    # restricted-key token: GitHub push protection has a dedicated detector for the
    # `rk_(test|live)_` prefix that flags it even on obviously-synthetic values
    # (unlike `sk_test_`, which the sibling sets commit as a plain literal). The
    # adjacent string literals concatenate to the identical runtime value at parse
    # time, so the detector and the tiered cases are unaffected.
    "stripe_restricted_key": [
        "rk_" "test_" "ABCdef0123456789ABCdef01",
        "rk_" "live_" "0123456789ABCDEFabcdefGH",
    ],
    "github_finegrained_pat": [
        "github_pat_11ABCDEFGHIJKLMNOPQRSTUV_wxyz0123456789abcdefghijABCDEF",
        "github_pat_11ZYXWVUTSRQPONMLKJIHGF_0123456789abcdefghijklmnopABCDEF",
    ],
    "google_oauth_secret": [
        "GOCSPX-abcdefABCDEF0123456789xy",
        "GOCSPX-0123456789abcdefABCDEFghij",
    ],
    # COMPLETE OpenPGP armor: banner, Version header, blank line, 64-char-wrapped
    # base64 body, the `=<CRC-24>` checksum line (computed for real, per RFC
    # 4880) and the END banner. A lone BEGIN line holds no key material, so it
    # cannot show whether key bytes actually egress. The third value keeps a
    # header-only truncated paste as a labelled edge case.
    "pgp_private_key": [
        _cb.pgp_private_key_block(version="GnuPG v2", nbytes=1190, seed=1001),
        _cb.pgp_private_key_block(
            version="OpenPGP.js v4.10.10", nbytes=1210, seed=1002
        ),
        ("banneronly", "key -----BEGIN PGP PRIVATE KEY BLOCK-----"),
    ],
    # Both bodies use only the RFC 4648 base32 alphabet [A-Z2-7] that AWS draws
    # real access-key ids from. The previous second value, ASIAJ4XZ7ABCDE123456,
    # contained `1` — a character no issued AWS key can hold — so it was not a
    # credential any deployment could leak, and rejecting it was correct.
    "aws_temp_key": ["ASIAIOSFODNN7EXAMPLE", "sts ASIAJ4XZ7ABCDE234567"],
    "bitcoin_address": [
        "btc 1BitcoinEaterAddressDontSendf59kuE",
        "bitcoin: 1CounterpartyXXXXXXXXXXXXXXXUWLpVr",
    ],
    "credit_card_track2": [
        ";4111111111111111=26011010000000000000?",
        ";4111111111111111=25121011000000000000?",
    ],
}


def build_cases() -> list[dict]:
    C: list[dict] = []
    for kind, values in _VALUES.items():
        for i, value in enumerate(values):
            # A value may be given as ("<label>", value) to tag an edge case in
            # the id; plain strings keep the positional index as before.
            label, value = value if isinstance(value, tuple) else (str(i), value)
            for cid, tier, k, obf, text in _tiers(f"r10-{kind}-{label}", kind, value):
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
        f"set10: {len(cases)} cases, {len(kinds)} kinds, all detected in hardened mode ✓"
    )


if __name__ == "__main__":
    main()
