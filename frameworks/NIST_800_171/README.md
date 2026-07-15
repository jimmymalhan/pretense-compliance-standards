# NIST_800_171 — synthetic compliance corpus

> SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL

**209 synthetic cases** across **18 data kinds** that the **NIST_800_171** framework regulates.

This folder is a **generated** per-framework view of the shared corpus: one data
kind maps to many frameworks, so a case appears under every framework it belongs
to. Regenerate with `python3 -m pretense_compliance_standards.corpus_builder`.

## Data kinds covered

- `access_log`
- `anthropic_key`
- `api_key`
- `aws_key`
- `azure_key`
- `contract_number`
- `db_url`
- `gcp_key`
- `github_token`
- `internal_program_code`
- `jwt`
- `openai_key`
- `part_number`
- `secret`
- `sendgrid_key`
- `slack_token`
- `ssh_private_key`
- `twilio_key`

## Run pretense against just this framework

```bash
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs --framework NIST_800_171
```

## Run this framework's tests

```bash
uv run pytest tests/test_pcs.py -m nist_800_171 -q --noconftest
```

`corpus/cases.json` here is git-ignored (a build artifact regenerated on demand);
it holds only cases whose `compliance` list includes this framework.
