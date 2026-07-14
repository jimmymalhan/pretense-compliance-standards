"""
corpus_builder.py

Builds the graded DLP benchmark corpus. Emits several realistic-looking files
(json / csv / log) so the corpus is *spread out* the way a real scan target is,
plus a `cases.json` ground-truth manifest the harness scores against.

Difficulty gradient (easy -> hard to catch):
    tier 0  plain      canonical value, inline in prose
    tier 1  labeled    labeled CSV/config fields, canonical-reachable variants
    tier 2  structural value split across quotes/lines; spaced/grouped digits
    tier 3  encoded    base64 / hex / Unicode-homoglyph forms
    tier 4  exotic     zero-width separators, single embedded encodings
    tier 5  layered    nested encodings (base64-of-base64, gzip+base64, full
                       percent-encoding, ROT13) that need a multi-pass decode

EVERY value is synthetic and provably fake (900-range SSNs, 555-01xx phones,
@example.com, AWS example key, Luhn-valid-but-random PANs). Each case is labeled
`expected: true` — it is something a correct DLP scanner SHOULD flag. The tiers
document detection challenges to overcome, never ways to smuggle data past a
scanner.

Run:  python -m pretense_compliance_standards.corpus_builder
"""

from __future__ import annotations

import base64
import csv
import json
import pathlib

from . import BANNER
from .compliance import frameworks_for
from .negatives import build_negatives
from .regulated import collect_regulated_cases

CORPUS_DIR = pathlib.Path(__file__).parent / "corpus"
ZW = "​"  # zero-width space


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _luhn_complete(body15: str) -> str:
    """Append the Luhn check digit to a 15-digit body -> valid 16-digit test PAN."""
    for c in "0123456789":
        if _luhn_ok(body15 + c):
            return body15 + c
    raise AssertionError("unreachable")


# --- fixed synthetic literals (all provably fake) ---
SSN = "900-55-1234"  # 900-range: never issued
PAN = _luhn_complete("448523601785829")  # Luhn-valid, random -> not a real account
EMAIL = "ava.carter7@example.com"  # RFC 2606 reserved domain
PHONE = "(415) 555-0142"  # 555-01xx: reserved for fiction
API_KEY = "sk_test_ABCdef0123456789ABCdef01"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS's own documentation example key
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJlX2Zha2U"  # fake
SECRET = "hardcoded-not-rotated-secret"  # on the detector denylist


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _groups(pan: str, sep: str) -> str:
    return sep.join((pan[0:4], pan[4:8], pan[8:12], pan[12:16]))


def build_cases() -> list[dict]:
    """Return the full ground-truth case list (id, difficulty, kind, text, ...)."""
    C: list[dict] = []

    def add(cid, difficulty, kind, obfuscation, source_file, text):
        C.append(
            {
                "id": cid,
                "difficulty": difficulty,
                "kind": kind,
                "obfuscation": obfuscation,
                "source_file": source_file,
                "text": text,
                "expected": True,
            }
        )

    f0 = "corpus/tier0_plain.json"
    add("t0-ssn", 0, "ssn", "inline", f0, f"Member SSN on file: {SSN}.")
    add("t0-pan", 0, "pan", "inline", f0, f"Primary card {PAN} charged $42.00.")
    add("t0-apikey", 0, "api_key", "inline", f0, f"stripe_api_key={API_KEY}")
    add("t0-aws", 0, "aws_key", "inline", f0, f"aws_access_key_id={AWS_KEY}")
    add("t0-jwt", 0, "jwt", "inline", f0, f"session token {JWT}")
    add("t0-email", 0, "email", "inline", f0, f"Contact {EMAIL} for statements.")
    add("t0-phone", 0, "phone", "inline", f0, f"Call center {PHONE}.")
    add("t0-secret", 0, "secret", "inline", f0, f"jwt_signing_secret={SECRET}")

    f1 = "corpus/tier1_labeled.csv"
    add("t1-ssn-dot", 1, "ssn", "dot-separated", f1, "tax_id: 900.55.1234")
    add("t1-phone-dash", 1, "phone", "dashed", f1, "phone: 415-555-0142")
    add("t1-email-upper", 1, "email", "uppercase", f1, "EMAIL: AVA.CARTER7@EXAMPLE.COM")
    add("t1-pan-cell", 1, "pan", "csv-cell", f1, f"card_on_file,{PAN},active")
    add("t1-aws-field", 1, "aws_key", "config-field", f1, f"access_key = {AWS_KEY}")
    add("t1-apikey-field", 1, "api_key", "config-field", f1, f"stripe.key = {API_KEY}")
    add("t1-secret-field", 1, "secret", "config-field", f1, f"signing = {SECRET}")

    f2 = "corpus/tier2_split.log"
    add(
        "t2-pan-spaced",
        2,
        "pan",
        "space-grouped",
        f2,
        f"Card: {_groups(PAN, ' ')} exp 12/29",
    )
    add("t2-pan-dashed", 2, "pan", "dash-grouped", f2, f"PAN={_groups(PAN, '-')}")
    add("t2-ssn-split", 2, "ssn", "split-literals", f2, 'ssn = "900-55" "-1234"')
    add(
        "t2-secret-concat",
        2,
        "secret",
        "concatenated",
        f2,
        'signing = "hardcoded-not-rotated" + "-secret"',
    )
    add(
        "t2-email-split",
        2,
        "email",
        "split-literals",
        f2,
        '"ava.carter7" "@example.com"',
    )

    f3 = "corpus/tier3_encoded.json"
    add("t3-ssn-b64", 3, "ssn", "base64", f3, f"blob={_b64(SSN)}")
    add("t3-pan-b64", 3, "pan", "base64", f3, f"blob={_b64(PAN)}")
    add("t3-email-b64", 3, "email", "base64", f3, f"blob={_b64(EMAIL)}")
    add("t3-secret-hex", 3, "secret", "hex", f3, f"blob={SECRET.encode().hex()}")
    add("t3-ssn-homoglyph", 3, "ssn", "unicode-homoglyph", f3, "ssn=９" + "00-55-1234")

    f4 = "corpus/tier4_embedded_equities.csv"
    add("t4-pan-zw", 4, "pan", "zero-width", f4, f"acct{_groups(PAN, ZW)}ref")
    add("t4-ssn-zw", 4, "ssn", "zero-width", f4, f"id900{ZW}55{ZW}1234x")
    add("t4-jwt-b64", 4, "jwt", "base64-wrapped", f4, f"payload={_b64('token=' + JWT)}")
    add("t4-pan-hex", 4, "pan", "hex-digits", f4, f"raw={PAN.encode().hex()}")

    # Additional regulated-data categories, auto-discovered from the
    # `regulated/` package. Safe no-op ([]) until data modules are present.
    C.extend(collect_regulated_cases())

    # Tag every case (base + regulated) with the compliance framework(s) its
    # data `kind` exercises, so the benchmark can report coverage per framework.
    # Framework names live only in this metadata field, never in `text`.
    for c in C:
        c["compliance"] = frameworks_for(c["kind"])

    return C


# --- file writers: realistic containers, every file banner-marked SYNTHETIC ---


def _write_json(path, cases):
    payload = {
        "_notice": BANNER,
        "records": [
            {"id": c["id"], "kind": c["kind"], "text": c["text"]} for c in cases
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def _write_csv(path, cases, header):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(f"# {BANNER}\n")
        w = csv.writer(fh)
        w.writerow(header)
        for c in cases:
            w.writerow([c["id"], c["kind"], c["text"]])


def _write_log(path, cases):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"# {BANNER}\n")
        for c in cases:
            fh.write(f"TIER2 {c['id']} kind={c['kind']} :: {c['text']}\n")


def write_corpus(cases: list[dict]) -> None:
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    by_file: dict[str, list[dict]] = {}
    for c in cases:
        by_file.setdefault(c["source_file"], []).append(c)

    for source_file, group in by_file.items():
        path = pathlib.Path(__file__).parent / source_file
        if source_file.endswith(".json"):
            _write_json(path, group)
        elif source_file.endswith(".log"):
            _write_log(path, group)
        elif source_file.endswith(".csv"):
            _write_csv(path, group, header=["id", "kind", "payload"])
        else:
            # Fail loud rather than silently dropping ground-truth cases that
            # are already in cases.json but would have no backing corpus file.
            raise ValueError(
                f"Unhandled source_file extension for {source_file!r}: "
                f"expected .json/.log/.csv ({len(group)} case(s) affected)"
            )

    manifest = {
        "_notice": BANNER + " — ground-truth labels for DLP recall scoring.",
        "cases": cases,
    }
    with open(CORPUS_DIR / "cases.json", "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)


def write_negatives(cases: list[dict]) -> None:
    """Write the benign look-alike (negative) corpus alongside the positives.

    Kept in its own `negatives.json` manifest — deliberately NOT merged into
    `cases.json` — so every recall test keeps seeing only `expected: True`
    cases, while the harness reads both files to score precision.
    """
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {
        "_notice": BANNER
        + " — benign look-alikes; a correct detector flags NONE of these.",
        "cases": cases,
    }
    with open(CORPUS_DIR / "negatives.json", "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)


def main() -> None:
    cases = build_cases()
    write_corpus(cases)
    negatives = build_negatives()
    write_negatives(negatives)
    tiers = sorted({c["difficulty"] for c in cases})
    print(f"Wrote {len(cases)} synthetic cases across tiers {tiers} to {CORPUS_DIR}/")
    print(
        f"Wrote {len(negatives)} benign look-alike (negative) cases to {CORPUS_DIR}/negatives.json"
    )
    print(f"Reminder: {BANNER}.")


if __name__ == "__main__":
    main()
