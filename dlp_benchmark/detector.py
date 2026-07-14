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

from .generator import INSECURE_CONFIG

# ---------------------------------------------------------------------------
# Deterministic-hashing denylist: sha256 of known-sensitive literal tokens.
# ---------------------------------------------------------------------------
_DENYLIST_LITERALS = {
    INSECURE_CONFIG["jwt_signing_secret"],          # "hardcoded-not-rotated-secret"
    INSECURE_CONFIG["aws_secret_access_key"],
    "P@ssw0rd123",                                   # db password from db_connection
    "hunter2",                                       # password leaked into logs
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
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@example\.com", re.IGNORECASE)
_PHONE = re.compile(r"\(?\d{3}\)?[-.\s]?555[-.\s]?01\d\d")

# --- Extended structural detectors (new sensitive-data categories) ----------
# IBAN: 2 letters + 2 check digits + grouped alphanumerics, spaced or not.
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Za-z0-9]){11,30}\b")
# Generic labeled national identifier, e.g. "ID-1234567".
_NATIONAL_ID = re.compile(r"\bID[- ]?\d{6,9}\b")
# Passport: 1 letter + 8 digits, e.g. "X12345678".
_PASSPORT = re.compile(r"\b[A-Za-z]\d{8}\b")
# EU-style VAT: 2 letters + 8-12 digits.
_VAT = re.compile(r"\b[A-Z]{2}\d{8,12}\b")
# Labeled contract id, e.g. "CT-2024-12345".
_CONTRACT_NUMBER = re.compile(r"\bCT-\d{4}-\d{4,6}\b")
# Labeled part number, e.g. "PN-A1B2C3".
_PART_NUMBER = re.compile(r"\bPN-[A-Z0-9]{6,}\b")
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

# Non-ASCII homoglyph digits, in case NFKC leaves any. Intentionally does NOT
# remap ASCII letters (O/l/I): doing so corrupts ordinary text like "example".
_HOMOGLYPHS = str.maketrans({
    "①": "1", "②": "2", "③": "3", "④": "4", "⑤": "5",   # circled digits
    "０": "0", "１": "1", "２": "2", "３": "3", "９": "9",   # fullwidth
})

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


def _decode_candidates(text: str):
    """Yield plausible base64/hex decodings of tokens in `text` (hardened only)."""
    for tok in re.findall(r"[A-Za-z0-9+/]{12,}={0,2}", text):
        try:
            dec = base64.b64decode(tok, validate=True)
            yield dec.decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            pass
    for tok in re.findall(r"\b[0-9a-fA-F]{12,}\b", text):
        if len(tok) % 2 == 0:
            try:
                yield bytes.fromhex(tok).decode("utf-8", "ignore")
            except (ValueError, UnicodeDecodeError):
                pass


def _views(text: str, mode: str):
    """Return the list of text views a detector scans, given the mode."""
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
    github_token, slack_token, db_url, gcp_key
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
        if _NATIONAL_ID.search(view):
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
        # Deterministic-hashing denylist check.
        for tok in _tokens(view):
            if hashlib.sha256(tok.encode()).hexdigest() in _DENYLIST_HASHES:
                found.add("secret")
                break
    return found
