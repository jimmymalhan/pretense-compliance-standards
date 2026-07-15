# IRS_1075 — synthetic compliance corpus

> SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL

**74 synthetic cases** across **6 data kinds** that the **IRS_1075** framework regulates.

This folder is a **generated** per-framework view of the shared corpus: one data
kind maps to many frameworks, so a case appears under every framework it belongs
to. Regenerate with `python3 -m pretense_compliance_standards.corpus_builder`.

## Data kinds covered

- `bank_account`
- `drivers_license`
- `ein`
- `national_id`
- `passport`
- `ssn`

## Run pretense against just this framework

```bash
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs --framework IRS_1075
```

## Run this framework's tests

```bash
uv run pytest tests/test_pcs.py -m irs_1075 -q --noconftest
```

`corpus/cases.json` here is git-ignored (a build artifact regenerated on demand);
it holds only cases whose `compliance` list includes this framework.
