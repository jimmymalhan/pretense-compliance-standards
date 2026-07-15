# NIST_800_53 — synthetic compliance corpus

> SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL

**236 synthetic cases** across **21 data kinds** that the **NIST_800_53** framework regulates.

This folder is a **generated** per-framework view of the shared corpus: one data
kind maps to many frameworks, so a case appears under every framework it belongs
to. Regenerate with `python3 -m pretense_compliance_standards.corpus_builder`.

## Data kinds covered

- `access_log`
- `anthropic_key`
- `api_key`
- `aws_key`
- `azure_key`
- `db_url`
- `email`
- `gcp_key`
- `github_token`
- `ip_address`
- `ipv6`
- `jwt`
- `mac_address`
- `openai_key`
- `phone`
- `secret`
- `sendgrid_key`
- `slack_token`
- `ssh_private_key`
- `ssn`
- `twilio_key`

## Run pretense against just this framework

```bash
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs --framework NIST_800_53
```

## Run this framework's tests

```bash
uv run pytest tests/test_pcs.py -m nist_800_53 -q --noconftest
```

`corpus/cases.json` here is git-ignored (a build artifact regenerated on demand);
it holds only cases whose `compliance` list includes this framework.
