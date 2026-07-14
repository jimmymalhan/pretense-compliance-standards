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

Running this module (`python -m dlp_benchmark.compliance`) regenerates
`compliance_map.json` next to it, so the JS bridge can read the same mapping
without importing Python.
"""

from __future__ import annotations

import json
import pathlib

# kind -> frameworks it exercises. Every corpus kind must appear here with a
# non-empty list; every framework must claim at least one kind.
KIND_FRAMEWORKS: dict[str, list[str]] = {
    # --- health / PHI (HIPAA) ---
    "medical_record_number": ["HIPAA"],
    "icd10": ["HIPAA"],
    "health_record": ["HIPAA"],
    "insurance_member_id": ["HIPAA"],
    # --- identifiers that straddle multiple regimes ---
    "ssn": ["HIPAA", "ISO_27001"],                 # US identifier / PII in PHI context
    "email": ["HIPAA", "GDPR", "ISO_27001"],       # contact info + EU personal data
    "phone": ["HIPAA", "GDPR", "ISO_27001"],
    # --- EU personal data (GDPR) ---
    "national_id": ["GDPR", "ISO_27001"],
    "passport": ["GDPR", "ISO_27001"],
    "iban": ["GDPR"],
    "vat": ["GDPR"],
    # --- credentials / security (SOC2 + ISO 27001) ---
    "api_key": ["SOC2", "ISO_27001"],
    "aws_key": ["SOC2", "ISO_27001"],
    "gcp_key": ["SOC2", "ISO_27001"],
    "github_token": ["SOC2", "ISO_27001"],
    "slack_token": ["SOC2", "ISO_27001"],
    "db_url": ["SOC2", "ISO_27001"],
    "jwt": ["SOC2", "ISO_27001"],
    "secret": ["SOC2", "ISO_27001"],
    "access_log": ["SOC2", "ISO_27001"],
    # --- controlled unclassified / technical info (CMMC Level 2) ---
    "contract_number": ["CMMC_L2"],
    "part_number": ["CMMC_L2"],
    "internal_program_code": ["CMMC_L2"],
    # --- cardholder data (PCI DSS) ---
    "pan": ["PCI_DSS"],
}

# Canonical framework order for reports (stable, not derived from dict order).
FRAMEWORKS: list[str] = ["SOC2", "HIPAA", "GDPR", "CMMC_L2", "ISO_27001", "PCI_DSS"]


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
    print(f"Compliance taxonomy: {len(KIND_FRAMEWORKS)} kinds -> {len(FRAMEWORKS)} frameworks")
    for fw in FRAMEWORKS:
        print(f"  {fw:12} {len(kinds_for(fw))} kinds")
    print(f"Wrote {_MAP_PATH.name}")
