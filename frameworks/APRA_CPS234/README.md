# APRA_CPS234 — synthetic compliance corpus

> SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL

**219 synthetic cases** across **19 data kinds** that the **APRA_CPS234** framework regulates.

This folder is a **generated** per-framework view of the shared corpus: one data
kind maps to many frameworks, so a case appears under every framework it belongs
to. Regenerate with `python3 -m pretense_compliance_standards.corpus_builder`.

## Data kinds covered

- `access_log`
- `anthropic_key`
- `api_key`
- `aws_key`
- `azure_key`
- `bank_account`
- `db_url`
- `ein`
- `gcp_key`
- `github_token`
- `jwt`
- `openai_key`
- `pan`
- `routing_number`
- `secret`
- `sendgrid_key`
- `slack_token`
- `ssh_private_key`
- `twilio_key`

## Run pretense against just this framework

```bash
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs --framework APRA_CPS234
```

## Run this framework's tests

```bash
uv run pytest tests/test_pcs.py -m apra_cps234 -q --noconftest
```

`corpus/cases.json` here is git-ignored (a build artifact regenerated on demand);
it holds only cases whose `compliance` list includes this framework.
