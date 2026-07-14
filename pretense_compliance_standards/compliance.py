"""
compliance.py

Compliance-framework taxonomy for the synthetic DLP benchmark: maps each data
`kind` in the corpus to the framework(s) whose regulated data it exercises.

This lets the benchmark answer "how well does a scanner (and the pretense
firewall) protect each compliance framework's data?" — recall / identify /
mutate coverage reported PER FRAMEWORK.

The mapping is many-to-many (e.g. `email` is both HIPAA contact info and GDPR
personal data). Framework names live here, in the per-case `compliance`
metadata, and in reports/docs ONLY — never inside a case's scanned `text`
payload, which stays clean synthetic data.

Running this module (`python -m pretense_compliance_standards.compliance`) regenerates
`compliance_map.json` next to it, so the JS bridge can read the same mapping
without importing Python.
"""

from __future__ import annotations

import json
import pathlib

# Data-kind groups (building blocks; each kind belongs to exactly one group).
_CREDENTIALS = [
    "api_key",
    "aws_key",
    "gcp_key",
    "github_token",
    "slack_token",
    "db_url",
    "jwt",
    "secret",
    "access_log",
]  # SOC2 / security controls
_PHI = ["medical_record_number", "icd10", "health_record", "insurance_member_id"]
_CONTACT = ["email", "phone"]  # PII contact info
_NATIONAL_ID = ["ssn", "national_id", "passport"]  # government identifiers
_EU_FINANCE = ["iban", "vat"]  # EU financial identifiers
_CUI = [
    "contract_number",
    "part_number",
    "internal_program_code",
]  # controlled tech info
_CARD = ["pan"]  # cardholder data

# framework -> kinds it regulates. Source of truth; KIND_FRAMEWORKS is derived
# from it so the two can never drift. Ordering here sets the report order.
# Each framework is mapped to the kinds whose data category it plausibly governs.
FRAMEWORK_KINDS: dict[str, list[str]] = {
    # --- security / credential regimes ---
    "SOC2": _CREDENTIALS,
    "ISO_27001": _CREDENTIALS + _NATIONAL_ID + _CONTACT,
    "NIST_800_53": _CREDENTIALS + ["ssn"] + _CONTACT,
    "NIST_800_171": _CUI + _CREDENTIALS,  # protecting CUI systems
    "FedRAMP": _CREDENTIALS,  # cloud auth (NIST 800-53 based)
    "NIS2": _CREDENTIALS,  # EU network & info security
    "DORA": _CREDENTIALS + ["iban", "pan"],  # EU financial ICT resilience
    # --- health regimes ---
    "HIPAA": _PHI + ["ssn"] + _CONTACT,
    "HITECH": _PHI + ["ssn"] + _CONTACT,  # strengthens HIPAA (ePHI)
    # --- privacy regimes ---
    "GDPR": ["national_id", "passport"] + _EU_FINANCE + _CONTACT,
    "CCPA_CPRA": _NATIONAL_ID + _CONTACT + _CARD,  # California consumer privacy
    "LGPD": _NATIONAL_ID + _CONTACT,  # Brazil
    "PIPEDA": _NATIONAL_ID + _CONTACT,  # Canada
    "POPIA": _NATIONAL_ID + _CONTACT,  # South Africa
    "FERPA": ["ssn"] + _CONTACT,  # US student education records
    # --- financial / controlled / card ---
    "GLBA": _CARD + ["iban", "ssn"] + _CONTACT,  # US financial privacy
    "CMMC_L2": _CUI,  # DoD controlled unclassified info
    "PCI_DSS": _CARD,  # cardholder data
}

# Canonical framework order for reports.
FRAMEWORKS: list[str] = list(FRAMEWORK_KINDS)

# kind -> frameworks it exercises (derived from FRAMEWORK_KINDS; never drifts).
KIND_FRAMEWORKS: dict[str, list[str]] = {}
for _fw in FRAMEWORKS:
    for _kind in FRAMEWORK_KINDS[_fw]:
        KIND_FRAMEWORKS.setdefault(_kind, [])
        if _fw not in KIND_FRAMEWORKS[_kind]:
            KIND_FRAMEWORKS[_kind].append(_fw)


def frameworks_for(kind: str) -> list[str]:
    """Frameworks a given data `kind` exercises (empty list if unmapped)."""
    return list(KIND_FRAMEWORKS.get(kind, []))


def kinds_for(framework: str) -> list[str]:
    """All kinds that map to a given framework."""
    return sorted(k for k, fws in KIND_FRAMEWORKS.items() if framework in fws)


def _validate() -> None:
    """Every kind maps to >=1 framework; every framework claims >=1 kind."""
    for kind, fws in KIND_FRAMEWORKS.items():
        assert fws, f"kind {kind!r} maps to no framework"
        for fw in fws:
            assert fw in FRAMEWORKS, f"kind {kind!r} names unknown framework {fw!r}"
    for fw in FRAMEWORKS:
        assert kinds_for(fw), f"framework {fw!r} claims no kind"


_MAP_PATH = pathlib.Path(__file__).parent / "compliance_map.json"


def write_map() -> None:
    """Emit compliance_map.json so non-Python consumers (the JS bridge) can read it."""
    payload = {
        "_notice": "SYNTHETIC benchmark taxonomy — kind -> compliance frameworks.",
        "frameworks": FRAMEWORKS,
        "kind_frameworks": KIND_FRAMEWORKS,
    }
    with open(_MAP_PATH, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


if __name__ == "__main__":
    _validate()
    write_map()
    print(
        f"Compliance taxonomy: {len(KIND_FRAMEWORKS)} kinds -> {len(FRAMEWORKS)} frameworks"
    )
    for fw in FRAMEWORKS:
        print(f"  {fw:12} {len(kinds_for(fw))} kinds")
    print(f"Wrote {_MAP_PATH.name}")
