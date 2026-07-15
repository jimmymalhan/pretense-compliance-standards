# HIPAA — synthetic compliance corpus

> SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL

**128 synthetic cases** across **11 data kinds** that the **HIPAA** framework regulates.

This folder is a **generated** per-framework view of the shared corpus: one data
kind maps to many frameworks, so a case appears under every framework it belongs
to. Regenerate with `python3 -m pretense_compliance_standards.corpus_builder`.

## Data kinds covered

- `date_of_birth`
- `email`
- `health_record`
- `icd10`
- `insurance_member_id`
- `medical_record_number`
- `medicare_id`
- `npi`
- `phone`
- `ssn`
- `vehicle_vin`

## Run pretense against just this framework

```bash
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs --framework HIPAA
```

## Run this framework's tests

```bash
uv run pytest tests/test_pcs.py -m hipaa -q --noconftest
```

`corpus/cases.json` here is git-ignored (a build artifact regenerated on demand);
it holds only cases whose `compliance` list includes this framework.
