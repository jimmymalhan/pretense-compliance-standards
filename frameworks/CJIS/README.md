# CJIS — synthetic compliance corpus

> SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL

**111 synthetic cases** across **9 data kinds** that the **CJIS** framework regulates.

This folder is a **generated** per-framework view of the shared corpus: one data
kind maps to many frameworks, so a case appears under every framework it belongs
to. Regenerate with `python3 -m pretense_compliance_standards.corpus_builder`.

## Data kinds covered

- `drivers_license`
- `email`
- `ip_address`
- `ipv6`
- `mac_address`
- `national_id`
- `passport`
- `phone`
- `ssn`

## Run pretense against just this framework

```bash
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs --framework CJIS
```

## Run this framework's tests

```bash
uv run pytest tests/test_pcs.py -m cjis -q --noconftest
```

`corpus/cases.json` here is git-ignored (a build artifact regenerated on demand);
it holds only cases whose `compliance` list includes this framework.
