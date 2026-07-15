# HITRUST — synthetic compliance corpus

> SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL

**256 synthetic cases** across **23 data kinds** that the **HITRUST** framework regulates.

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
- `gcp_key`
- `github_token`
- `health_record`
- `icd10`
- `insurance_member_id`
- `jwt`
- `medical_record_number`
- `medicare_id`
- `npi`
- `openai_key`
- `secret`
- `sendgrid_key`
- `slack_token`
- `ssh_private_key`
- `twilio_key`
- `vehicle_vin`

## Run pretense against just this framework

```bash
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs --framework HITRUST
```

## Run this framework's tests

```bash
uv run pytest tests/test_pcs.py -m hitrust -q --noconftest
```

`corpus/cases.json` here is git-ignored (a build artifact regenerated on demand);
it holds only cases whose `compliance` list includes this framework.
