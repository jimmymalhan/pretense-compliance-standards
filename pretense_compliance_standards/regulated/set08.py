"""
regulated/set08.py  —  Blended data-set 08 (tier-5 LAYERED obfuscation)

Adds SYNTHETIC tier-5 cases whose sensitive value is hidden under *layered /
nested* encodings that a single decode pass cannot recover:

    - double-base64   base64(base64(value))          -> needs 2 decode passes
    - gzip-base64     base64(gzip(value))             -> decompress after decode
    - percent         every byte percent-encoded %xx  -> URL-decode

Tier 5 sits above the tier-4 "exotic" frontier: the naive scan sees only the
encoded blob and misses it, while the detector's hardened mode follows up to a
bounded decode depth (`detector._MAX_DECODE_DEPTH`) to recover the value.

ROT13 is intentionally NOT used: it is a 1:1 map on plaintext, so having the
detector scan a ROT13 view would double its false-positive surface for no
realistic gain (see `detector._decode_layer`).

Every value is provably fake (900-range SSN, @example.com, sk_test_ key, the AWS
documentation key, a denylisted secret, the published example IBAN). Neutral `kind` labels
only — no compliance-framework strings in any payload. Every case is scanner
INPUT (`expected: True`) and is self-checked to be detected in hardened mode.

Run:  python3 pretense_compliance_standards/regulated/set08.py
"""

from __future__ import annotations

import base64
import gzip
import pathlib
import re
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from pretense_compliance_standards import corpus_builder as _cb
from pretense_compliance_standards.detector import detect

SOURCE_FILE = "corpus/blended_regulated_08.json"
_TIER5 = 5


def _double_b64(s: str) -> str:
    return base64.b64encode(base64.b64encode(s.encode())).decode()


def _gzip_b64(s: str) -> str:
    """base64(gzip(s)) — BIT-REPRODUCIBLE.

    `mtime=0` is load-bearing. The gzip header carries a modification time, so
    the default (`time.time()`) makes these 6 tier-5 cases differ byte-for-byte
    between builds, purely in the header. That was the ONLY source of run-to-run
    corpus drift: `generator.py` seeds `random` at 42, so every value in the
    corpus is otherwise identical build to build. Pinning it makes the whole
    648-case corpus reproducible, so any change in a reported number is
    attributable to the ENGINE and never to the clock.
    """
    return base64.b64encode(gzip.compress(s.encode(), mtime=0)).decode()


def _percent(s: str) -> str:
    return "".join(f"%{b:02x}" for b in s.encode())


# Layered encoders, keyed by the obfuscation label used on the case. Every layer
# is a reliably-reversible *encoding* (base64/gzip/percent); ROT13 is excluded
# because scanning its view would double the detector's false-positive surface.
_ENCODERS = {
    "double-base64": lambda v: f"payload={_double_b64(v)}",
    "gzip-base64": lambda v: f"gz={_gzip_b64(v)}",
    "percent-encoded": lambda v: f"q={_percent(v)}",
}

# (kind, labeled fake value, [techniques]). Secret-shaped values are pulled from
# corpus_builder's canonical fakes rather than written inline, so no plaintext
# key literal lives in this source file (they only ever appear base64/gzip/
# percent-ENCODED in the generated corpus, which secret scanners do not match).
_ITEMS: list[tuple[str, str, list[str]]] = [
    ("ssn", f"SSN {_cb.SSN}", ["double-base64", "gzip-base64", "percent-encoded"]),
    ("pan", f"card {_cb.PAN}", ["double-base64", "gzip-base64"]),
    ("email", f"email {_cb.EMAIL}", ["gzip-base64", "double-base64"]),
    ("api_key", f"stripe key {_cb.API_KEY}", ["double-base64"]),
    ("aws_key", f"aws_access_key_id {_cb.AWS_KEY}", ["gzip-base64", "percent-encoded"]),
    ("secret", f"jwt_signing_secret {_cb.SECRET}", ["gzip-base64", "double-base64"]),
    ("national_id", "national_id 9041-7745-8035", ["percent-encoded", "double-base64"]),
    # The canonical published example IBAN, with its real mod-97 check digits
    # (82). The previous `GB00…` form could not pass IBAN validation at all.
    ("iban", "iban GB82WEST12345698765432", ["percent-encoded", "gzip-base64"]),
]


def build_cases() -> list[dict]:
    C: list[dict] = []
    for kind, value, techniques in _ITEMS:
        for tech in techniques:
            C.append(
                {
                    "id": f"r8-{kind}-{tech}",
                    "difficulty": _TIER5,
                    "kind": kind,
                    "obfuscation": tech,
                    "source_file": SOURCE_FILE,
                    "text": _ENCODERS[tech](value),
                    "expected": True,
                }
            )
    return C


_FRAMEWORK_RE = re.compile(
    r"soc ?2|hi?ppaa|cmmc|gdpr|iso.?27|nist|pci|hitrust", re.IGNORECASE
)


def _validate(cases: list[dict]) -> None:
    for c in cases:
        # No framework token leaks into the (encoded) payload.
        assert _FRAMEWORK_RE.search(c["text"]) is None, f"framework token in {c['id']}"
        # Hardened mode must recover the layered value ...
        assert c["kind"] in detect(
            c["text"], "hardened"
        ), f"hardened miss (layered): {c['id']} ({c['obfuscation']})"
        # ... and the naive scan must NOT — otherwise it is not a tier-5 case.
        assert c["kind"] not in detect(
            c["text"], "naive"
        ), f"naive unexpectedly caught {c['id']} ({c['obfuscation']})"


def main() -> None:
    cases = build_cases()
    _validate(cases)
    _cb._write_json(pathlib.Path(__file__).parent.parent / SOURCE_FILE, cases)
    kinds = sorted({c["kind"] for c in cases})
    print(
        f"set08: {len(cases)} tier-5 layered cases, {len(kinds)} kinds, "
        "all hardened-detected & naive-missed ✓"
    )


if __name__ == "__main__":
    main()
