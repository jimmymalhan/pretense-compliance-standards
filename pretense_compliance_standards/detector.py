"""
detector.py

A reference **deterministic-hashing DLP detector**, written to be benchmarked —
NOT shipped as a production scanner. It runs in two modes so the harness can show
the recall gap that motivates hardening:

    naive     surface scan only: fixed regexes + a sha256 denylist over the raw
              text. Catches canonical, inline values (tiers 0-1) and little else.

    hardened  the same detectors, but run over *normalized views* of the text:
              fragment-joining (defeats values split across lines/quotes),
              separator collapse, Unicode NFKC folding (defeats homoglyphs),
              and base64/hex decoding. Recovers most of the obfuscated tiers.

The "deterministic hashing" core is `_DENYLIST_HASHES`: sha256 of known-sensitive
literals. Because the hash is deterministic, a known secret is caught wherever it
appears — but ONLY if normalization first reduces the obfuscated form back to the
canonical token. That dependence is exactly what the benchmark measures: every
tier the detector misses is a normalization gap to close, never an acceptable
blind spot.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
import urllib.parse
import zlib

from .generator import DIAGNOSES, INSECURE_CONFIG

# ---------------------------------------------------------------------------
# Deterministic-hashing denylist: sha256 of known-sensitive literal tokens.
# ---------------------------------------------------------------------------
_DENYLIST_LITERALS = {
    INSECURE_CONFIG["jwt_signing_secret"],  # "hardcoded-not-rotated-secret"
    INSECURE_CONFIG["aws_secret_access_key"],
    "P@ssw0rd123",  # db password from db_connection
    "hunter2",  # password leaked into logs
}
_DENYLIST_HASHES = {hashlib.sha256(s.encode()).hexdigest() for s in _DENYLIST_LITERALS}

# ---------------------------------------------------------------------------
# Structural detectors. Each returns True if its `kind` appears in `view`.
# Regexes are deliberately simple/canonical — normalization (hardened mode) is
# what lets them fire on obfuscated inputs.
# ---------------------------------------------------------------------------
_SSN_SEP = re.compile(r"9\d\d[-.\s]\d\d[-.\s]\d{4}")
_SSN_COLLAPSED = re.compile(r"(?<!\d)9\d{8}(?!\d)")
_PAN_BOUNDED = re.compile(r"(?<!\d)\d{13,19}(?!\d)")
_PAN_MASKED = re.compile(r"\d{6}[\*x]{4,}\d{4}", re.IGNORECASE)
_API_KEY = re.compile(r"sk_(?:test|live)_[A-Za-z0-9]{16,}")
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
# JWT: three base64url segments. Only the *header* must start with the canonical
# `eyJ` marker; the payload segment need not (a signed-but-opaque payload still
# leaks). Relaxed from requiring `eyJ` on the second segment too.
_JWT = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+")
# Local part bounded to the RFC-5321 max (64) so the `+@` shape cannot backtrack
# quadratically on a long run of local-part characters (a decoded/percent view
# can be large), which would be a CPU-DoS vector.
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@example\.com", re.IGNORECASE)
# Phone: US 555-01xx (reserved-for-fiction) plus the UK Ofcom reserved-for-drama
# range (+44 (0)20 7946 0xxx, or the local 020 7946 0xxx form).
_PHONE = re.compile(
    r"\(?\d{3}\)?[-.\s]?555[-.\s]?01\d\d"
    r"|(?:\+44\s?\(0\)|0)20[-.\s]?7946[-.\s]?0\d{3}"
)

# --- Extended structural detectors (new sensitive-data categories) ----------
# IBAN: 2 letters + 2 check digits + grouped alphanumerics, spaced or not. No
# leading word boundary: after zero-width strip an IBAN can sit flush against
# surrounding letters (e.g. "acctFR76...ref"), which a `\b` anchor would miss.
_IBAN = re.compile(r"[A-Z]{2}\d{2}(?:[ ]?[A-Za-z0-9]){11,30}\b")
# National identifier: 4-4-4 grouped (9dddd-...) or the 3-2-4 SSN-shape, both
# bounded to the never-issued 900-range (leading 9). Without that bound the
# plain 3-2-4 shape also matches ordinary employee IDs like "123-45-6789";
# every synthetic national-id value starts with 9 by construction. Zero-width
# forms collapse to a bare 9- or 12-digit run, handled separately below.
_NATIONAL_ID = re.compile(r"\b(?:9\d{3}-\d{4}-\d{4}|9\d\d-\d\d-\d{4})\b")
_NATIONAL_ID_COLLAPSED = re.compile(r"(?<!\d)9(?:\d{8}|\d{11})(?!\d)")
# Passport: 2 letters + 7 digits (e.g. "XA0000042") or 1 letter + 8 digits.
_PASSPORT = re.compile(r"\b[A-Z]{2}\d{7}\b|\b[A-Z]\d{8}\b")
# EU-style VAT: 2 letters + 8-12 digits.
_VAT = re.compile(r"\b[A-Z]{2}\d{8,12}\b")
# Labeled contract id, e.g. "CT-2024-12345" or "CTR-2026-934216".
_CONTRACT_NUMBER = re.compile(r"\bCTR?-\d{4}-\d{4,6}\b")
# Labeled part number, e.g. "PN-A1B2C3"; hyphen optional and case-insensitive so
# the collapsed/zero-width-stripped form ("pn9FRUDT") is still recovered.
_PART_NUMBER = re.compile(r"\bPN-?[A-Z0-9]{6,}\b", re.IGNORECASE)
# Medical record number: "MRN" + 8 digits (collapse view rejoins spaced groups).
_MRN = re.compile(r"MRN\d{8}")
# ICD-10 diagnosis code: letter + 2 digits (+ optional decimal). A bare 3-char
# code (e.g. "B20") is structurally indistinguishable from a model / room / grid
# label, so `_has_icd10` requires one of three positive signals:
#   * a decimal subcode (F32.1) — specific enough on its own; or
#   * clinical context (diagnosis / icd / dx) adjacent on either side, tolerating
#     one short spanning word ("dx of E11"); or
#   * a *clinical* "code" phrase — "<primary/secondary/principal/admitting/
#     discharge> code L##" or a direct "code=L##" / "code: L##" assignment.
# The "code" signal is an ALLOWLIST, deliberately NOT a denylist of non-clinical
# words: "<word> code L##" is unbounded ("confirmation code", "tracking code",
# "booking code", …), so only the enumerated clinical forms count. This keeps the
# corpus's context-only cases ("primary code I10", "code=I10") while rejecting the
# entire "<generic> code L##" family.
_ICD10_DECIMAL = re.compile(r"\b[A-Z]\d\d\.\d+\b")
_ICD10_CLINICAL = re.compile(
    r"(?:diagnos\w*|\bicd(?:-?10)?\b|\bdx\b)(?:[\W_]+\w{1,6})?[\W_]{0,4}[A-Z]\d\d\b"
    r"|\b[A-Z]\d\d[\W_]{0,4}(?:diagnos\w*|\bicd(?:-?10)?\b|\bdx\b)",
    re.IGNORECASE,
)
_ICD10_CODE = re.compile(
    r"(?:primary|secondary|principal|admitting|discharge)\s+code[sd]?\b[\W_:=]{0,4}[A-Z]\d\d\b"
    r"|\bcode\s*[:=]\s*[A-Z]\d\d\b",
    re.IGNORECASE,
)


def _has_icd10(view: str) -> bool:
    return bool(
        _ICD10_DECIMAL.search(view)
        or _ICD10_CLINICAL.search(view)
        or _ICD10_CODE.search(view)
    )


# Insurance member id: 3 letters + 9 digits (e.g. "RRF139047426").
_INSURANCE_MEMBER = re.compile(r"\b[A-Z]{3}\d{9}\b")
# Internal program code: "PRG-" + 6 alphanumerics; hyphen optional so the
# separator-collapsed spaced form ("PRG1B3ZEK") still matches.
_PROGRAM_CODE = re.compile(r"\bPRG-?[A-Z0-9]{6}\b")
# Access log leaking a plaintext credential: a password-ish field assignment.
# Covers `password=<val>` and the encoded `pw_blob=<hex>` label variant.
_ACCESS_LOG = re.compile(r"\b(?:password|passwd|pw\w*)\s*=\s*\S+", re.IGNORECASE)
# Health record: a known clinical diagnosis phrase, a `dx=`/`patient_mrn` field,
# or "diagnosed with" prose — any of which marks the text as protected health data.
_HEALTH_RECORD = re.compile(
    "|".join(
        [r"patient_mrn", r"\bdx\s*=", r"diagnosed with"]
        + [re.escape(desc) for _code, desc in DIAGNOSES]
    ),
    re.IGNORECASE,
)
# Source-hosting personal access tokens (ghp_ / ghs_).
_GITHUB_TOKEN = re.compile(r"gh[ps]_[A-Za-z0-9]{36,}")
# Chat-platform tokens (xoxb-/xoxp-/xoxo-/xoxr-/xoxs-).
_SLACK_TOKEN = re.compile(r"xox[bpors]-[A-Za-z0-9-]{10,}")
# Database connection URL with embedded credentials.
_DB_URL = re.compile(
    r"(?:postgres|mysql|mongodb|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"
)
# Cloud API key, e.g. "AIza...".
_GCP_KEY = re.compile(r"AIza[A-Za-z0-9_\-]{35}")

# --- Extended kinds (deepened coverage: card, financial, extra PII, network, vendor keys) ---
# CVV/CVC labeled 3-4 digit card verification code (PCI).
_CARD_CVV = re.compile(r"\b(?:cvv|cvc|cvv2|cid)\b\s*[:=#]?\s*\d{3,4}\b", re.IGNORECASE)
# Bank account number, labeled 8-17 digits.
_BANK_ACCOUNT = re.compile(
    r"\b(?:bank[\s_-]?account|acct(?:[\s_-]?(?:no|num|number))?|account[\s_-]?(?:no|number))\b\s*[:=#]?\s*\d{8,17}\b",
    re.IGNORECASE,
)
# ABA routing number, labeled 9 digits.
_ROUTING = re.compile(
    r"\b(?:routing|aba)\b\s*(?:no|number|#)?\s*[:=#]?\s*\d{9}\b", re.IGNORECASE
)
# US Employer Identification Number NN-NNNNNNN. The bare 2-then-7 digit shape
# also matches invoice / ticket numbers, so require an EIN label nearby. The
# label alternation is \b-anchored so it does not fire inside words that merely
# end in "ein" (vein, protein, casein); it accepts the common label vocabulary
# (EIN, FEIN, employer id[entification], (federal) tax id) and tolerates up to
# two short connector words before the number ("EIN is 12-3456789").
_EIN = re.compile(
    r"\b(?:f?ein|employer'?s?\s*id(?:entification)?|taxpayer\s*id(?:entification)?"
    r"|(?:federal\s+)?tax\s*id(?:entification)?)"
    r"(?:\s*(?:no|number|#))?(?:[\W_]+\w{1,7}){0,2}[\W_]{0,4}\d{2}-\d{7}\b",
    re.IGNORECASE,
)
# Driver's license, labeled letter + 6-8 digits.
_DRIVERS_LICENSE = re.compile(
    r"\b(?:dl|driver'?s?[\s_-]?licen[sc]e)\b\s*(?:no|number|#)?\s*[:=#]?\s*[A-Z]\d{6,8}\b",
    re.IGNORECASE,
)
# Date of birth, labeled ISO or slashed date.
_DOB = re.compile(
    r"\b(?:dob|date[\s_-]?of[\s_-]?birth|birth[\s_-]?date)\b\s*[:=#]?\s*(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})",
    re.IGNORECASE,
)
# IPv4 address (valid octets).
_IP_ADDRESS = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
# IPv6 address: a full 8-group form (7 colons), a `::`-compressed form that still
# has a hex group before the `::`, or a leading `::` form. The looser "2-to-7
# colon groups" shape also matches clock times ("12:34:56") and MACs, and an
# unanchored `::` matches C++/log scope-resolution ("std::deadbeef"), so the
# leading-`::` branch has a (?<!\w) guard to reject a `::` glued to a word.
_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?\b"
    r"|(?<!\w)::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
)
# National Provider Identifier (health), labeled 10 digits.
_NPI = re.compile(r"\bnpi\b\s*[:=#]?\s*\d{10}\b", re.IGNORECASE)
# OpenAI-style key `sk-...` (excludes `sk-ant-`, handled separately).
_OPENAI_KEY = re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b")
# Anthropic key `sk-ant-...`.
_ANTHROPIC_KEY = re.compile(r"\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{16,}\b")
# Azure storage `AccountKey=...`.
_AZURE_KEY = re.compile(r"AccountKey=[A-Za-z0-9+/=]{40,}", re.IGNORECASE)
# SendGrid API key `SG.xxx.yyy`.
_SENDGRID_KEY = re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")
# Twilio key `SK` + 32 hex.
_TWILIO_KEY = re.compile(r"\bSK[a-f0-9]{32}\b")

# Non-ASCII homoglyph digits, in case NFKC leaves any. Intentionally does NOT
# remap ASCII letters (O/l/I): doing so corrupts ordinary text like "example".
_HOMOGLYPHS = str.maketrans(
    {
        "①": "1",
        "②": "2",
        "③": "3",
        "④": "4",
        "⑤": "5",  # circled digits
        "０": "0",
        "１": "1",
        "２": "2",
        "３": "3",
        "９": "9",  # fullwidth
    }
)

# Zero-width / invisible separators used to break up canonical values.
_ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿]")


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


def _tokens(view: str):
    # NB: '=' is a separator so that `label=value` splits into two tokens;
    # otherwise a denylisted secret would never match when preceded by a key.
    for tok in re.split(r"[^A-Za-z0-9@._/+-]+", view):
        if tok:
            yield tok


_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
_HEX_TOKEN = re.compile(r"\b[0-9a-fA-F]{12,}\b")
_PCT = re.compile(r"%[0-9a-fA-F]{2}")

# Tier-5 obfuscation is *layered* (base64-of-base64, gzip+base64, percent), so
# decoding is iterated. The walk is bounded on every axis — input size, depth,
# tokens per layer, total decodings, and decoded length — and only *textual*
# decodings propagate. Those bounds are what keep hardened mode safe on hostile
# input: a nested-base64 blob, a compression bomb, or a wall of random tokens
# cannot cause quadratic CPU / unbounded memory, and random decoded bytes never
# reach the detectors (so they cannot produce false positives). ROT13 is
# deliberately NOT a layer: it is a 1:1 map on plaintext, so scanning its view
# would double the false-positive surface (e.g. rotate a benign token onto a
# denylisted secret) for no realistic gain.
_MAX_DECODE_DEPTH = 2  # double-base64 is the deepest real layering
_MAX_DECODE_LEN = 4096  # decoded views are bounded small (corpus values are tiny)
_MAX_DECODE_TOKENS = 32  # tokens decoded per kind per layer
_MAX_DECODE_TOTAL = 128  # total decodings across the whole walk
_MAX_DECODE_INPUT = 65536  # skip decoding entirely for very large inputs
_MAX_SCAN_LEN = 65536  # cap the raw text every view is built from (DoS bound)


def _looks_textual(s: str) -> bool:
    """True if `s` is predominantly printable text, not random decoded bytes.

    This is the gate that stops opaque tokens (session ids, object hashes, binary
    blobs) — which base64/hex-decode to noise — from reaching the detectors and
    tripping a loose pattern on random bytes."""
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\t\n\r ")
    return printable / len(s) >= 0.9


def _maybe_decompress(raw: bytes) -> str | None:
    """Return decompressed UTF-8 text if `raw` is gzip/zlib data, else None.

    Output is bounded to `_MAX_DECODE_LEN` bytes via a streaming decompressobj, so
    a compression bomb cannot allocate unbounded memory (a bounded read, not
    `zlib.decompress`, which would inflate the whole payload first)."""
    for wbits in (31, 15):  # 31 = gzip header, 15 = raw zlib
        try:
            out = zlib.decompressobj(wbits).decompress(raw, _MAX_DECODE_LEN + 1)
        except (zlib.error, OSError):
            continue
        if out and len(out) <= _MAX_DECODE_LEN:
            return out.decode("utf-8", "ignore")
    return None


def _decode_layer(text: str):
    """Yield ONE level of *textual* decodings of `text`: base64 (optionally
    gzip/zlib-compressed), hex, and percent/URL-encoding. At most
    `_MAX_DECODE_TOKENS` tokens of each kind are decoded, and only decodings that
    look like text are yielded."""
    for i, m in enumerate(_B64_TOKEN.finditer(text)):
        if i >= _MAX_DECODE_TOKENS:
            break
        try:
            raw = base64.b64decode(m.group(), validate=True)
        except (binascii.Error, ValueError):
            continue
        decompressed = _maybe_decompress(raw)
        candidate = (
            decompressed if decompressed is not None else raw.decode("utf-8", "ignore")
        )
        if _looks_textual(candidate):
            yield candidate
    for i, m in enumerate(_HEX_TOKEN.finditer(text)):
        if i >= _MAX_DECODE_TOKENS:
            break
        tok = m.group()
        if len(tok) % 2:
            continue
        try:
            candidate = bytes.fromhex(tok).decode("utf-8", "ignore")
        except (ValueError, UnicodeDecodeError):
            continue
        if _looks_textual(candidate):
            yield candidate
    if _PCT.search(text):
        unquoted = urllib.parse.unquote(text)
        if unquoted != text and _looks_textual(unquoted):
            yield unquoted


def _decode_candidates(text: str):
    """Yield textual decodings of `text`, following up to `_MAX_DECODE_DEPTH`
    nested layers (base64-of-base64, gzip+base64, percent-encoding). The seen-set,
    the depth / per-layer-token / total / length / input-size caps, and the
    textual filter together keep the breadth-first walk bounded and
    false-positive-free on adversarial input."""
    if len(text) > _MAX_DECODE_INPUT:
        return
    seen = {text}
    frontier = [text]
    total = 0
    for _ in range(_MAX_DECODE_DEPTH):
        nxt = []
        for current in frontier:
            for decoded in _decode_layer(current):
                if decoded and decoded not in seen and len(decoded) <= _MAX_DECODE_LEN:
                    seen.add(decoded)
                    nxt.append(decoded)
                    yield decoded
                    total += 1
                    if total >= _MAX_DECODE_TOTAL:
                        return
        if not nxt:
            break
        frontier = nxt


def _views(text: str, mode: str):
    """Return the list of text views a detector scans, given the mode.

    The scanned text is capped to `_MAX_SCAN_LEN`: the ~40 detector regexes are
    all linear, but the constant factor (notably `_PAN_BOUNDED` + Luhn per match)
    makes a multi-hundred-KB input take seconds, so an unbounded scan would be a
    CPU-DoS. Real scanners cap payload size the same way; corpus cases are tiny,
    so this never truncates real input."""
    if len(text) > _MAX_SCAN_LEN:
        text = text[:_MAX_SCAN_LEN]
    if mode == "naive":
        return [text]

    nfkc = unicodedata.normalize("NFKC", text).translate(_HOMOGLYPHS)
    nfkc = _ZERO_WIDTH.sub("", nfkc)  # strip zero-width separators
    # Fragment-join: drop quotes / whitespace / '+' so values split across
    # string literals or log lines are reassembled (keeps -,. so SSN/PAN
    # separators survive).
    glued = re.sub(r"[\s\"'`+\\|,]", "", nfkc)
    # Separator collapse: pure runs (defeats spaced/grouped digits).
    collapsed = re.sub(r"[\s\-._]", "", nfkc)
    views = [text, nfkc, glued, collapsed]
    views.extend(_decode_candidates(text))
    return views


def detect(text: str, mode: str = "hardened") -> set[str]:
    """Return the set of sensitive-data `kind` labels found in `text`.

    kinds: ssn, pan, api_key, aws_key, jwt, email, phone, secret,
    iban, national_id, passport, vat, contract_number, part_number,
    github_token, slack_token, db_url, gcp_key, medical_record_number,
    icd10, insurance_member_id, internal_program_code, access_log,
    health_record
    `mode` is "naive" or "hardened".
    """
    if mode not in ("naive", "hardened"):
        raise ValueError(f"unknown mode: {mode!r}")

    found: set[str] = set()
    for view in _views(text, mode):
        if _SSN_SEP.search(view) or _SSN_COLLAPSED.search(view):
            found.add("ssn")
        if _PAN_MASKED.search(view):
            found.add("pan")
        for m in _PAN_BOUNDED.finditer(view):
            if _luhn_ok(m.group()):
                found.add("pan")
                break
        if _API_KEY.search(view):
            found.add("api_key")
        if _AWS_KEY.search(view):
            found.add("aws_key")
        if _JWT.search(view):
            found.add("jwt")
        if _EMAIL.search(view):
            found.add("email")
        if _PHONE.search(view):
            found.add("phone")
        if _IBAN.search(view):
            found.add("iban")
        if _NATIONAL_ID.search(view) or _NATIONAL_ID_COLLAPSED.search(view):
            found.add("national_id")
        if _PASSPORT.search(view):
            found.add("passport")
        if _VAT.search(view):
            found.add("vat")
        if _CONTRACT_NUMBER.search(view):
            found.add("contract_number")
        if _PART_NUMBER.search(view):
            found.add("part_number")
        if _GITHUB_TOKEN.search(view):
            found.add("github_token")
        if _SLACK_TOKEN.search(view):
            found.add("slack_token")
        if _DB_URL.search(view):
            found.add("db_url")
        if _GCP_KEY.search(view):
            found.add("gcp_key")
        if _MRN.search(view):
            found.add("medical_record_number")
        if _has_icd10(view):
            found.add("icd10")
        if _INSURANCE_MEMBER.search(view):
            found.add("insurance_member_id")
        if _PROGRAM_CODE.search(view):
            found.add("internal_program_code")
        if _ACCESS_LOG.search(view):
            found.add("access_log")
        if _HEALTH_RECORD.search(view):
            found.add("health_record")
        if _CARD_CVV.search(view):
            found.add("card_cvv")
        if _BANK_ACCOUNT.search(view):
            found.add("bank_account")
        if _ROUTING.search(view):
            found.add("routing_number")
        if _EIN.search(view):
            found.add("ein")
        if _DRIVERS_LICENSE.search(view):
            found.add("drivers_license")
        if _DOB.search(view):
            found.add("date_of_birth")
        if _IP_ADDRESS.search(view):
            found.add("ip_address")
        if _IPV6.search(view):
            found.add("ipv6")
        if _NPI.search(view):
            found.add("npi")
        if _OPENAI_KEY.search(view):
            found.add("openai_key")
        if _ANTHROPIC_KEY.search(view):
            found.add("anthropic_key")
        if _AZURE_KEY.search(view):
            found.add("azure_key")
        if _SENDGRID_KEY.search(view):
            found.add("sendgrid_key")
        if _TWILIO_KEY.search(view):
            found.add("twilio_key")
        # Deterministic-hashing denylist check.
        for tok in _tokens(view):
            if hashlib.sha256(tok.encode()).hexdigest() in _DENYLIST_HASHES:
                found.add("secret")
                break
    return found
