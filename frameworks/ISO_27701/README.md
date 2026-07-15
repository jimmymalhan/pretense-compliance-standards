# ISO_27701 — synthetic compliance corpus

> SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL

**298 synthetic cases** across **26 data kinds** that the **ISO_27701** framework regulates.

This folder is a **generated** per-framework view of the shared corpus: one data
kind maps to many frameworks, so a case appears under every framework it belongs
to. Regenerate with `python3 -m pretense_compliance_standards.corpus_builder`.

## Data kinds covered

- `access_log`
- `anthropic_key`
- `api_key`
- `aws_key`
- `azure_key`
- `date_of_birth`
- `db_url`
- `drivers_license`
- `email`
- `gcp_key`
- `github_token`
- `ip_address`
- `ipv6`
- `jwt`
- `mac_address`
- `national_id`
- `openai_key`
- `passport`
- `phone`
- `secret`
- `sendgrid_key`
- `slack_token`
- `ssh_private_key`
- `ssn`
- `twilio_key`
- `vehicle_vin`

## Run pretense against just this framework

```bash
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs --framework ISO_27701
```

## Run this framework's tests

```bash
uv run pytest tests/test_pcs.py -m iso_27701 -q --noconftest
```

`corpus/cases.json` here is git-ignored (a build artifact regenerated on demand);
it holds only cases whose `compliance` list includes this framework.
