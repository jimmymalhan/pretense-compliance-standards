# FADP — synthetic compliance corpus

> SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL

**148 synthetic cases** across **11 data kinds** that the **FADP** framework regulates.

This folder is a **generated** per-framework view of the shared corpus: one data
kind maps to many frameworks, so a case appears under every framework it belongs
to. Regenerate with `python3 -m pretense_compliance_standards.corpus_builder`.

## Data kinds covered

- `date_of_birth`
- `drivers_license`
- `email`
- `iban`
- `national_id`
- `passport`
- `phone`
- `ssn`
- `swift_bic`
- `vat`
- `vehicle_vin`

## Run pretense against just this framework

```bash
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs --framework FADP
```

## Run this framework's tests

```bash
uv run pytest tests/test_pcs.py -m fadp -q --noconftest
```

`corpus/cases.json` here is git-ignored (a build artifact regenerated on demand);
it holds only cases whose `compliance` list includes this framework.
