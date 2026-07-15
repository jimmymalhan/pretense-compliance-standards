"""
negatives.py

The **negative corpus**: benign look-alikes a correct detector should NOT flag.

The positive corpus (`corpus_builder.build_cases`) is recall-only — every case is
`expected: True`. That measures how much regulated data a scanner *catches*, but
says nothing about how much benign data it *wrongly* flags. A detector that
returns "sensitive" for everything scores 100% recall and is useless.

These cases close that gap. Each is structurally close to a real sensitive value
(an SSN-shaped employee id, a non-Luhn 16-digit order number, a clock time that
looks like IPv6) but is NOT regulated data. A correct detector emits the empty
set for every one; anything it flags is a **false positive**. The harness pairs
this list with the positive corpus to report precision / recall / F1, so an
over-broad regex shows up as a precision drop, not a silent bug.

Everything here is synthetic. `build_negatives()` returns the cases; the corpus
builder writes them to `corpus/negatives.json` with the standard banner.
"""

from __future__ import annotations

from .detector import detect

# Every case below is hand-authored and fully static — no RNG. (Deliberately no
# module-level random.seed(): this module is imported by corpus_builder before
# the regulated data sets are generated, and seeding here would perturb the
# global RNG state those sets draw from, changing their synthetic values.)

# (id, kind_hint, text, note) — kind_hint names the sensitive kind each case
# superficially resembles; a correct detector still finds nothing in `text`.
_NEGATIVES: list[tuple[str, str, str, str]] = [
    # --- national-id / SSN shape, but outside the never-issued 900 range ---
    (
        "n-ssn-badge",
        "ssn",
        "Employee badge 123-45-6789 printed at reception.",
        "3-2-4 shape but not in the 900 range -> not an SSN/national id",
    ),
    (
        "n-ssn-ticket",
        "national_id",
        "Support ticket ref 456-78-9012 archived.",
        "ordinary 3-2-4 reference, non-900",
    ),
    (
        "n-nid-grouped",
        "national_id",
        "Asset tag 1042-7745-8035 in the register.",
        "4-4-4 grouping but leading digit is not 9",
    ),
    # --- card / PAN look-alikes ---
    (
        "n-pan-order",
        "pan",
        "Order number 1234 5678 9012 3458 shipped Tuesday.",
        "16 digits but fails the Luhn check -> not a card number",
    ),
    (
        "n-pan-serial",
        "pan",
        "Device serial 4000111122223333 registered.",
        "16-digit serial, non-Luhn",
    ),
    (
        "n-cvv-room",
        "card_cvv",
        "Guest assigned to room 123 for the night.",
        "bare 3 digits with no cvv/cvc label",
    ),
    # --- contact info look-alikes ---
    (
        "n-email-org",
        "email",
        "Please contact jordan@example.org for the report.",
        "example.org, not the reserved example.com the detector keys on",
    ),
    (
        "n-email-test",
        "email",
        "Distribution alias team@sample.test on record.",
        "non-example.com domain",
    ),
    (
        "n-phone-real",
        "phone",
        "Reception line (212) 867-5309, ask for dispatch.",
        "not in the 555-01xx fiction range or the UK drama range",
    ),
    (
        "n-phone-555x",
        "phone",
        "Old demo line 555-0299 has been retired.",
        "555-02xx, outside the reserved 555-01xx block",
    ),
    # --- IPv4 / IPv6 look-alikes ---
    (
        "n-ip-invalid",
        "ip_address",
        "Firmware build v256.300.1.4 rolled out.",
        "octets exceed 255 -> not a valid IPv4 address",
    ),
    (
        "n-ip-partial",
        "ip_address",
        "Rack position 10.20.30 on the floor plan.",
        "only three octets -> not an IPv4 address",
    ),
    (
        "n-ipv6-time",
        "ipv6",
        "Nightly backup finished at 12:34:56 UTC.",
        "clock time: 2 colon groups, no :: compression",
    ),
    (
        "n-mac-short",
        "mac_address",
        "Cache tag de:ad:be:ef logged for the node.",
        "only 4 hex groups -> not a full 6-octet MAC (and not IPv6)",
    ),
    # --- M3 new-kind look-alikes ---
    (
        "n-crypto-short",
        "crypto_wallet_address",
        "Debug pointer at 0x1a2b3c logged during the crash.",
        "0x + short hex -> a memory pointer, not a 40-hex wallet address",
    ),
    (
        "n-crypto-hash",
        "crypto_wallet_address",
        "Commit 0xdeadbeef tagged in the release notes.",
        "0x + 8 hex -> a short hash, not a 40-hex wallet address",
    ),
    (
        "n-vin-nolabel",
        "vehicle_vin",
        "The vin lookup service returned no record today.",
        "the word 'vin' with no following 17-char VIN",
    ),
    (
        "n-bic-noword",
        "swift_bic",
        "Please swift-track the shipment to the loading dock.",
        "'swift' as an adjective, no BIC code following",
    ),
    (
        "n-ssh-pubkey",
        "ssh_private_key",
        "Stored the -----BEGIN PUBLIC KEY----- in the vault.",
        "a PUBLIC key header is not a private key",
    ),
    (
        "n-medicare-partb",
        "medicare_id",
        "Enrolled in medicare part b for 2026 coverage.",
        "'medicare' as a program name, no 11-char MBI following",
    ),
    (
        "n-medicare-info",
        "medicare_id",
        "Patient medicare information was updated in the portal.",
        "'medicare information' (lowercase prose) is not an uppercase MBI",
    ),
    (
        "n-bic-swiftword",
        "swift_bic",
        "We expect a swift response from the vendor team.",
        "'swift response' (lowercase) is not an uppercase BIC code",
    ),
    (
        "n-vin-slug",
        "vehicle_vin",
        "Job vin lookupabcdefgh1234567 processed overnight.",
        "a lowercase 17-char slug after 'vin' is not an uppercase VIN",
    ),
    (
        "n-mac-fingerprint",
        "mac_address",
        "SSH host fingerprint 43:51:43:a1:b5:fc:8b:b7:0a:3a logged.",
        "10-octet colon-hex fingerprint -> neither a 6-octet MAC nor IPv6",
    ),
    (
        "n-ipv6-scope",
        "ipv6",
        "Refactored the parser around namespace Foo::bar1 last week.",
        "C++/log scope resolution X::Y, not an IPv6 :: compression",
    ),
    (
        "n-ipv6-cpp",
        "ipv6",
        "The logger prints std::deadbeef when the cache key is missing.",
        "std::<hex-ish word> scope resolution, not IPv6",
    ),
    # --- financial-account look-alikes (label absent) ---
    (
        "n-routing-aisle",
        "routing_number",
        "Warehouse aisle 011000015 restocked.",
        "9 digits with no routing/aba label",
    ),
    (
        "n-acct-locker",
        "bank_account",
        "Locker combination 000123456789 reset.",
        "12-digit code with no account label",
    ),
    (
        "n-ein-invoice",
        "ein",
        "Invoice 12-3456789 marked settled today.",
        "NN-NNNNNNN shape with no EIN/employer-id label",
    ),
    (
        "n-ein-po",
        "ein",
        "Purchase order 34-7654321 approved by finance.",
        "NN-NNNNNNN shape, no EIN label (non-9 prefix so it is not a 900-range id)",
    ),
    (
        "n-ein-vein",
        "ein",
        "Blood was drawn from a vein; sample 12-3456789 went to the lab.",
        "the word 'vein' ends in 'ein' but is not an EIN label (word-boundary guard)",
    ),
    (
        "n-npi-batch",
        "npi",
        "Batch 1234567890 completed processing overnight.",
        "10-digit batch id with no NPI label",
    ),
    # --- health look-alikes ---
    (
        "n-icd-model",
        "icd10",
        "Model B20 and unit I10 are back in stock.",
        "letter+2-digit codes with no clinical context",
    ),
    (
        "n-icd-grid",
        "icd10",
        "Grid reference A15 is marked on the map.",
        "map grid ref, ICD-10 shape but no diagnosis/code context",
    ),
    (
        "n-icd-areacode",
        "icd10",
        "Front desk wrote down the area code A15 by mistake.",
        "'area code' is a non-clinical 'code' phrase -> not a diagnosis code",
    ),
    (
        "n-icd-product",
        "icd10",
        "Warehouse says product code B20 is out of stock.",
        "'product code' is non-clinical -> not a diagnosis code",
    ),
    (
        "n-icd-errcode",
        "icd10",
        "The nightly service returned error code E11 twice.",
        "'error code' is non-clinical -> not a diagnosis code",
    ),
    (
        "n-icd-confirmation",
        "icd10",
        "Your confirmation code B20 was emailed to you.",
        "'confirmation code' is transactional; only clinical 'code' phrases count",
    ),
    (
        "n-icd-tracking",
        "icd10",
        "The tracking code B20 shows the parcel in transit.",
        "'tracking code' is non-clinical -> not a diagnosis code",
    ),
    (
        "n-icd-job",
        "icd10",
        "Timesheet lists job code E44 for the shift.",
        "'job code' is non-clinical -> not a diagnosis code",
    ),
    (
        "n-health-survey",
        "health_record",
        "Patient satisfaction survey completed this week.",
        "mentions 'patient' but carries no diagnosis or record marker",
    ),
    (
        "n-mrn-aisle",
        "medical_record_number",
        "Shelf MRN reference table on aisle 4.",
        "the letters MRN with no following 8-digit number",
    ),
    # --- date-of-birth / driver's-license look-alikes (label absent) ---
    (
        "n-dob-meeting",
        "date_of_birth",
        "The kickoff meeting is set for 2024-03-15.",
        "ISO date with no DOB/birth-date label",
    ),
    (
        "n-dl-seat",
        "drivers_license",
        "Seat D1234567 assigned for the conference.",
        "letter+7-digit seat id with no driver-license label",
    ),
    # --- identifier look-alikes (too short / wrong prefix) ---
    (
        "n-passport-sku",
        "passport",
        "North bay inventory restocked, SKU ref ABC-12345.",
        "3 letters + 5 digits -> neither passport nor insurance-member shape",
    ),
    (
        "n-vat-batch",
        "vat",
        "Production run sealed and labeled, batch ref DE-12345.",
        "2 letters + 5 digits, short of the VAT 8-12 digit length",
    ),
    (
        "n-iban-sort",
        "iban",
        "The memo notes the regional office code GB29.",
        "IBAN-style prefix but far too short to be an IBAN",
    ),
    (
        "n-contract-doc",
        "contract_number",
        "Circulated for review this week: draft doc CT-24-99.",
        "resembles a contract id but the field widths do not match",
    ),
    (
        "n-part-bin",
        "part_number",
        "Kept the loading dock clear near storage bin PN-99.",
        "PN- prefix but only two trailing chars",
    ),
    (
        "n-program-lane",
        "internal_program_code",
        "Ground crew kept clear the loading lane PRG-99.",
        "PRG- prefix but too short for a program code",
    ),
    # --- credential / secret look-alikes ---
    (
        "n-aws-label",
        "aws_key",
        "Left as a stub in the sample config: label AKIB1234.",
        "AKIB, not the AKIA prefix the detector keys on",
    ),
    (
        "n-apikey-demo",
        "api_key",
        "Sample token sk_demo_abc123 used in the tutorial.",
        "sk_demo, not the sk_test_/sk_live_ prefix",
    ),
    (
        "n-jwt-frag",
        "jwt",
        "Log fragment eyJhbGci truncated by the collector.",
        "a single base64 segment, not three dot-joined JWT segments",
    ),
    (
        "n-github-tag",
        "github_token",
        "Cut the gh-release-42 tag on the repo.",
        "gh- prefix but not a ghp_/ghs_ personal access token",
    ),
    (
        "n-secret-vault",
        "secret",
        "Vault rotation used passphrase hunter3 this cycle.",
        "hunter3 is not on the deterministic-hash denylist (hunter2 is)",
    ),
    (
        "n-slack-chan",
        "slack_token",
        "Posted the notes in channel xox-general.",
        "xox- without the b/p/o/r/s type char and length of a real token",
    ),
    (
        "n-gcp-path",
        "gcp_key",
        "Left the AIza-short placeholder in the sample config.",
        "AIza prefix but far short of the 35-char key body",
    ),
    (
        "n-openai-note",
        "openai_key",
        "Renamed the sk-notes file in the shared drive.",
        "sk- followed by a short word, not a 20+ char key body",
    ),
    # --- M10 new-kind look-alikes (label present, value absent / wrong shape) ---
    (
        "n-imei-lookup",
        "imei",
        "The imei lookup service returned no device today.",
        "the word 'imei' with no following 15-digit device id",
    ),
    (
        "n-imsi-catcher",
        "imsi",
        "Security review flagged a rogue imsi catcher near the site.",
        "'imsi' as a noun with no 15-digit subscriber identity",
    ),
    (
        "n-adid-optout",
        "advertising_id",
        "The user toggled advertising id tracking off in settings.",
        "'advertising id' phrase with no following UUID value",
    ),
    (
        "n-nino-appt",
        "uk_nino",
        "Booked a nino appointment at the job centre next week.",
        "'nino' with no following 2-letter/6-digit/1-letter code",
    ),
    (
        "n-nhs-helpline",
        "uk_nhs_number",
        "Called the nhs helpline about the new coverage.",
        "'nhs' as an org name with no following 10-digit number",
    ),
    (
        "n-rk-config",
        "stripe_restricted_key",
        "Renamed the rk_config helper in the billing module.",
        "rk_ prefix but not the rk_test_/rk_live_ restricted-key form",
    ),
    (
        "n-ghpat-release",
        "github_finegrained_pat",
        "Cut the github_release_v2 branch on the repo.",
        "github_ prefix but not a github_pat_ fine-grained token",
    ),
    (
        "n-gocspx-stub",
        "google_oauth_secret",
        "Left the GOCSPX placeholder text in the sample config.",
        "GOCSPX without the '-' + 20-char secret body",
    ),
    (
        "n-pgp-public",
        "pgp_private_key",
        "Imported the -----BEGIN PGP PUBLIC KEY BLOCK----- from the keyserver.",
        "a PGP PUBLIC key block is not a private key",
    ),
    (
        "n-asia-region",
        "aws_temp_key",
        "Failover shifted traffic to the ASIB region overnight.",
        "ASIB, not the ASIA temporary-key prefix the detector keys on",
    ),
    (
        "n-btc-price",
        "bitcoin_address",
        "The btc price ticker updated on the dashboard.",
        "'btc' as a ticker with no following base58 address",
    ),
    (
        "n-track2-log",
        "credit_card_track2",
        "Parsed record ;field=value? from the terminal log.",
        "the ;...=...? sentinel shape but the fields are not digits",
    ),
]


def build_negatives() -> list[dict]:
    """Return the negative (benign look-alike) cases; each is `expected: False`."""
    return [
        {
            "id": cid,
            "kind_hint": kind_hint,
            "text": text,
            "note": note,
            "expected": False,
        }
        for cid, kind_hint, text, note in _NEGATIVES
    ]


def _validate(cases: list[dict]) -> None:
    """Every negative must be a clean miss: the detector finds nothing in it.

    A hardened-mode hit on any negative is a false positive — the whole point of
    this corpus is to keep that at zero, so we fail loudly here rather than let a
    regression slip into the precision report.
    """
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate negative id"
    for c in cases:
        assert c["expected"] is False, c["id"]
        hits = detect(c["text"], "hardened")
        assert not hits, f"false positive on {c['id']}: detector flagged {sorted(hits)}"


def main() -> None:
    cases = build_negatives()
    _validate(cases)
    print(
        f"negatives: {len(cases)} benign look-alikes, 0 false positives in hardened mode ✓"
    )


if __name__ == "__main__":
    main()
