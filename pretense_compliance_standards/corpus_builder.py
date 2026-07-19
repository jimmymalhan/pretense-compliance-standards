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
import random
import re

from . import BANNER
from .compliance import FRAMEWORKS, frameworks_for
from .framework_targets import validate_scannable, write_framework_targets
from .negatives import build_negatives
from .regulated import collect_regulated_cases

CORPUS_DIR = pathlib.Path(__file__).parent / "corpus"
# Root-level per-framework view (generated): frameworks/<FRAMEWORK>/…
FRAMEWORKS_DIR = pathlib.Path(__file__).parent.parent / "frameworks"
ZW = "\u200b"  # zero-width space


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


# --- IBAN: checksum-VALID, but provably not an allocated account ------------
#
# Earlier revisions of this corpus forced the check digits to "00" so an IBAN
# could never validate. That made the value safe, but it also made it useless as
# a recall fixture: a correct IBAN implementation MUST reject a `00` check, so a
# scanner was being scored for missing a value no bank would ever accept. The
# fixture now carries real ISO 7064 mod-97-10 check digits, and provable fakeness
# comes from the *bank code* instead — `SYNT` / `TEST` / `ZZZZ` and the reserved
# numeric bank codes below are not allocated to any institution, so the value is
# structurally perfect and still cannot route to a real account. (A checksum only
# proves the digits are self-consistent; it never proves the account exists.)

# Real ISO 13616 registry lengths, so a length check on the country code passes.
IBAN_LENGTHS = {
    "GB": 22,  # 4a bank + 6n sort code + 8n account
    "DE": 22,  # 8n Bankleitzahl + 10n account
    "FR": 27,  # 5n bank + 5n branch + 11c account + 2n RIB key
    "ES": 24,  # 4n bank + 4n branch + 2n check + 10n account
    "NL": 18,  # 4a bank + 10n account
    "CH": 21,  # 5n bank + 12c account
    "IT": 27,  # 1a CIN + 5n ABI + 5n CAB + 12c account
}


def iban_is_valid(iban: str) -> bool:
    """True iff `iban` passes the ISO 7064 mod-97-10 check (a valid IBAN -> 1)."""
    s = iban.replace(" ", "").upper()
    if not (15 <= len(s) <= 34) or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    rearranged = s[4:] + s[:4]
    if not rearranged.isalnum():
        return False
    return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1


_IBAN_CANDIDATE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Za-z0-9])+")


def first_valid_iban(text: str) -> str | None:
    """Extract the first mod-97-valid IBAN from `text`, or None.

    A permissive scan would run past the end of the IBAN into the following
    words (an IBAN body and ordinary prose are both `[A-Za-z0-9 ]`), so each
    candidate is trimmed one character at a time until it checksums. Used by the
    corpus self-validators to prove the value they emitted is genuinely valid.
    """
    for mo in _IBAN_CANDIDATE.finditer(text):
        candidate = mo.group(0)
        while len(candidate.replace(" ", "")) >= 15:
            if iban_is_valid(candidate):
                return candidate
            candidate = candidate[:-1].rstrip()
    return None


def iban_check_digits(country: str, bban: str) -> str:
    """Return the two ISO 7064 mod-97-10 check digits for `country` + `bban`."""
    rearranged = f"{bban}{country}00".upper()
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return f"{98 - int(numeric) % 97:02d}"


def make_iban(country: str, bban: str) -> str:
    """Assemble a checksum-valid IBAN from a country code and a BBAN body.

    Asserts both the registry length for `country` and the mod-97 check, so a
    malformed BBAN fails at corpus-build time rather than silently producing an
    invalid fixture.
    """
    iban = f"{country}{iban_check_digits(country, bban)}{bban}"
    expected = IBAN_LENGTHS[country]
    assert (
        len(iban) == expected
    ), f"{country} IBAN must be {expected} chars, built {len(iban)}: {iban}"
    assert iban_is_valid(iban), f"mod-97 check failed for built IBAN {iban}"
    return iban


# --- AWS access-key ids: real base32 alphabet -------------------------------
#
# AWS access-key ids are a 4-char type prefix (`AKIA` long-term, `ASIA` STS /
# temporary) followed by 16 characters drawn from the RFC 4648 base32 alphabet
# `[A-Z2-7]`. The digits 0/1/8/9 never appear in the body of a real key, so a
# fixture containing them is not a credential any AWS deployment could issue.
AWS_KEY_BODY_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def aws_key_body_is_valid(key: str) -> bool:
    """True iff `key` is a 20-char AWS key id whose 16-char body is base32."""
    return (
        len(key) == 20
        and key[:4].isalpha()
        and key[:4].isupper()
        and all(ch in AWS_KEY_BODY_ALPHABET for ch in key[4:])
    )


# --- PEM / armored private keys: complete keys, not bare banners -------------
#
# A `-----BEGIN … PRIVATE KEY-----` line on its own is a banner, not a key: it
# carries no key material, so redacting it protects nothing and a scanner that
# passes it through has leaked nothing. Real exfiltration looks like the whole
# armored block — banner, optional armor headers, a base64 body wrapped at 64
# characters per line (RFC 7468 / RFC 4880), and the matching END banner. These
# helpers emit that complete shape. The body is random bytes, so it is not a
# functioning key, but it is byte-shaped exactly like one.
_PEM_WRAP = 64


def _pem_body(nbytes: int, seed: int) -> list[str]:
    """Deterministic base64 body lines wrapped at 64 chars (real base64, padded)."""
    rng = random.Random(seed)
    raw = bytes(rng.getrandbits(8) for _ in range(nbytes))
    b64 = base64.b64encode(raw).decode()
    return [b64[i : i + _PEM_WRAP] for i in range(0, len(b64), _PEM_WRAP)]


def pem_private_key(
    label: str,
    *,
    armor_headers: tuple[str, ...] = (),
    nbytes: int = 1190,
    seed: int = 0,
) -> str:
    """A complete PEM private key: banner, optional armor headers, body, END.

    `label` is the banner type, e.g. "RSA PRIVATE KEY" or "OPENSSH PRIVATE KEY".
    `armor_headers` are RFC 1421-style lines such as "Proc-Type: 4,ENCRYPTED" or
    "DEK-Info: AES-128-CBC,0123…"; when present they are followed by a blank line.
    `nbytes` of 1190 base64-encodes to ~1588 chars ≈ a 2048-bit RSA private key.
    """
    lines = [f"-----BEGIN {label}-----"]
    if armor_headers:
        lines.extend(armor_headers)
        lines.append("")
    lines.extend(_pem_body(nbytes, seed))
    lines.append(f"-----END {label}-----")
    return "\n".join(lines)


def _crc24(data: bytes) -> int:
    """RFC 4880 CRC-24 over the raw (pre-base64) armored data."""
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def pgp_private_key_block(
    *,
    version: str = "GnuPG v2",
    nbytes: int = 1190,
    seed: int = 0,
) -> str:
    """A complete OpenPGP armored private-key block, including the CRC-24 line.

    RFC 4880 armor is the banner, a `Version:` header, a blank line, the base64
    body wrapped at 64 chars, a `=<base64 CRC-24>` checksum line, and the END
    banner. The CRC is computed for real, so the block is well-formed armor.
    """
    rng = random.Random(seed)
    raw = bytes(rng.getrandbits(8) for _ in range(nbytes))
    b64 = base64.b64encode(raw).decode()
    body = [b64[i : i + _PEM_WRAP] for i in range(0, len(b64), _PEM_WRAP)]
    crc = base64.b64encode(_crc24(raw).to_bytes(3, "big")).decode()
    return "\n".join(
        [
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            f"Version: {version}",
            "",
            *body,
            f"={crc}",
            "-----END PGP PRIVATE KEY BLOCK-----",
        ]
    )


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


def _framework_readme(fw: str, sub_cases: list[dict]) -> str:
    """Render the committed README for one framework's generated corpus folder."""
    kinds = sorted({c["kind"] for c in sub_cases})
    lines = [
        f"# {fw} — synthetic compliance corpus",
        "",
        f"> {BANNER}",
        "",
        f"**{len(sub_cases)} synthetic cases** across **{len(kinds)} data kinds** that the "
        f"**{fw}** framework regulates.",
        "",
        "This folder is a **generated, self-contained** per-framework view of the shared",
        "corpus: one data kind maps to many frameworks, so a case appears under every",
        "framework it belongs to. It is independent of the other framework folders — point",
        "a scanner at just this directory to test this framework in isolation. Regenerate",
        "with `python3 -m pretense_compliance_standards.corpus_builder`.",
        "",
        "## Scan targets (realistic codebase + database files)",
        "",
        "Each file below embeds this framework's cases (all data kinds, obfuscation tiers",
        "0-5) in a realistic format, so pretense scans real-looking data, not a bare manifest:",
        "",
        "| File | What |",
        "|------|------|",
        "| `database/dump.sql` | SQL `CREATE TABLE` + `INSERT` dump |",
        '| `codebase/.env` | `KEY="value"` credential-style config |',
        "| `codebase/config.yaml` | YAML config records |",
        "| `codebase/seed.json` | JSON seed data |",
        "| `codebase/app.py` | source with string-literal constants |",
        "| `data/export.csv` | CSV export |",
        "| `logs/service.log` | application log lines |",
        "| `corpus/cases.json` | ground-truth manifest (id, kind, tier, compliance) |",
        "",
        "The data files are git-ignored (build artifacts regenerated on demand); this README",
        "is committed so the folder is visible in git.",
        "",
        "## Data kinds covered",
        "",
        *(f"- `{k}`" for k in kinds),
        "",
        "## Run pretense against just this framework",
        "",
        "```bash",
        "# point the pretense scanner at this whole folder …",
        f"#   pretense scan frameworks/{fw}/",
        "# … or drive the synthetic corpus through the bridge:",
        "node --experimental-transform-types \\",
        f"  pretense_compliance_standards/pretense_bridge/run.mjs --framework {fw}",
        "```",
        "",
        "## Run this framework's tests",
        "",
        "```bash",
        f"uv run pytest tests/test_pcs.py -m {fw.lower()} -q --noconftest",
        "```",
        "",
        "`corpus/cases.json` here is git-ignored (a build artifact regenerated on demand);",
        "it holds only cases whose `compliance` list includes this framework.",
    ]
    return "\n".join(lines) + "\n"


def _frameworks_index(counts: dict[str, int]) -> str:
    """Render the committed index README for the frameworks/ tree."""
    lines = [
        "# Per-framework corpus views",
        "",
        f"> {BANNER}",
        "",
        "Each subfolder is a **generated** view of the synthetic corpus scoped to a single",
        "compliance framework, so you can point **pretense** (or the test suite) at exactly",
        "one framework's regulated data. Because one data `kind` maps to many frameworks, a",
        "case appears under every framework it belongs to (the mapping is many-to-many).",
        "",
        "Regenerate the whole tree (and the flat corpus) with:",
        "",
        "```bash",
        "python3 -m pretense_compliance_standards.corpus_builder",
        "```",
        "",
        "The per-framework `corpus/cases.json` files are git-ignored (build artifacts); the",
        "folder + this index + each `<FRAMEWORK>/README.md` are committed so the layout is",
        "visible in git.",
        "",
        "## Frameworks",
        "",
        "| Framework | Cases | Run pretense | Run tests |",
        "|-----------|------:|--------------|-----------|",
    ]
    for fw in FRAMEWORKS:
        lines.append(
            f"| [`{fw}`]({fw}/README.md) | {counts[fw]} | "
            f"`run.mjs --framework {fw}` | `pytest -m {fw.lower()}` |"
        )
    return "\n".join(lines) + "\n"


def write_by_framework(cases: list[dict]) -> None:
    """Generate the root `frameworks/<FRAMEWORK>/` view of the corpus.

    For each framework, writes `corpus/cases.json` (only the cases whose `kind`
    maps to that framework) plus a committed `README.md`; also writes the
    `frameworks/README.md` index. The per-framework corpus data is a build
    artifact (git-ignored); the READMEs are committed so the folders are visible
    in git. Framework names live in metadata / these reports only — never in a
    scanned `text` payload.
    """
    FRAMEWORKS_DIR.mkdir(parents=True, exist_ok=True)
    # Bucket cases by framework in a single pass (the mapping is many-to-many),
    # so the membership rule is applied once rather than per-framework twice.
    by_fw: dict[str, list[dict]] = {fw: [] for fw in FRAMEWORKS}
    for c in cases:
        for fw in c.get("compliance", []):
            if fw in by_fw:
                by_fw[fw].append(c)
    with open(FRAMEWORKS_DIR / "README.md", "w", encoding="utf-8") as fh:
        fh.write(_frameworks_index({fw: len(by_fw[fw]) for fw in FRAMEWORKS}))
    for fw in FRAMEWORKS:
        sub = by_fw[fw]
        fw_dir = FRAMEWORKS_DIR / fw
        (fw_dir / "corpus").mkdir(parents=True, exist_ok=True)
        manifest = {
            "_notice": BANNER + f" — {fw} view (cases whose kind maps to {fw}).",
            "framework": fw,
            "cases": sub,
        }
        with open(fw_dir / "corpus" / "cases.json", "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        # Realistic codebase + database scan targets embedding this framework's data.
        write_framework_targets(fw_dir, fw, sub)
        with open(fw_dir / "README.md", "w", encoding="utf-8") as fh:
            fh.write(_framework_readme(fw, sub))


def main() -> None:
    cases = build_cases()
    write_corpus(cases)
    negatives = build_negatives()
    write_negatives(negatives)
    write_by_framework(cases)
    # Build-time guarantee: every case survives embedding into each scan target.
    validate_scannable(cases)
    tiers = sorted({c["difficulty"] for c in cases})
    print(f"Wrote {len(cases)} synthetic cases across tiers {tiers} to {CORPUS_DIR}/")
    print(
        f"Wrote {len(negatives)} benign look-alike (negative) cases to {CORPUS_DIR}/negatives.json"
    )
    print(
        f"Wrote per-framework views for {len(FRAMEWORKS)} frameworks to {FRAMEWORKS_DIR}/"
    )
    print(f"Reminder: {BANNER}.")


if __name__ == "__main__":
    main()
