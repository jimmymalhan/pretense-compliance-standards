# GLBA — synthetic compliance corpus

> SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL

**126 synthetic cases** across **9 data kinds** that the **GLBA** framework regulates.

This folder is a **generated** per-framework view of the shared corpus: one data
kind maps to many frameworks, so a case appears under every framework it belongs
to. Regenerate with `python3 -m pretense_compliance_standards.corpus_builder`.

## Data kinds covered

- `bank_account`
- `card_cvv`
- `ein`
- `email`
- `iban`
- `pan`
- `phone`
- `routing_number`
- `ssn`

## Run pretense against just this framework

```bash
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs --framework GLBA
```

## Run this framework's tests

```bash
uv run pytest tests/test_pcs.py -m glba -q --noconftest
```

`corpus/cases.json` here is git-ignored (a build artifact regenerated on demand);
it holds only cases whose `compliance` list includes this framework.
