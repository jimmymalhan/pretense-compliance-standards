# PIPL — synthetic compliance corpus

> SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL

**101 synthetic cases** across **8 data kinds** that the **PIPL** framework regulates.

This folder is a **generated** per-framework view of the shared corpus: one data
kind maps to many frameworks, so a case appears under every framework it belongs
to. Regenerate with `python3 -m pretense_compliance_standards.corpus_builder`.

## Data kinds covered

- `date_of_birth`
- `drivers_license`
- `email`
- `national_id`
- `passport`
- `phone`
- `ssn`
- `vehicle_vin`

## Run pretense against just this framework

```bash
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs --framework PIPL
```

## Run this framework's tests

```bash
uv run pytest tests/test_pcs.py -m pipl -q --noconftest
```

`corpus/cases.json` here is git-ignored (a build artifact regenerated on demand);
it holds only cases whose `compliance` list includes this framework.
