# FedRAMP — synthetic compliance corpus

> SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL

**257 synthetic cases** across **23 data kinds** that the **FedRAMP** framework regulates.

This folder is a **generated, self-contained** per-framework view of the shared
corpus: one data kind maps to many frameworks, so a case appears under every
framework it belongs to. It is independent of the other framework folders — point
a scanner at just this directory to test this framework in isolation. Regenerate
with `python3 -m pretense_compliance_standards.corpus_builder`.

## Scan targets (realistic codebase + database files)

Each file below embeds this framework's cases (all data kinds, obfuscation tiers
0-5) in a realistic format, so pretense scans real-looking data, not a bare manifest:

| File | What |
|------|------|
| `database/dump.sql` | SQL `CREATE TABLE` + `INSERT` dump |
| `codebase/.env` | `KEY="value"` credential-style config |
| `codebase/config.yaml` | YAML config records |
| `codebase/seed.json` | JSON seed data |
| `codebase/app.py` | source with string-literal constants |
| `data/export.csv` | CSV export |
| `logs/service.log` | application log lines |
| `corpus/cases.json` | ground-truth manifest (id, kind, tier, compliance) |

The data files are git-ignored (build artifacts regenerated on demand); this README
is committed so the folder is visible in git.

## Data kinds covered

- `access_log`
- `anthropic_key`
- `api_key`
- `aws_key`
- `aws_temp_key`
- `azure_key`
- `db_url`
- `gcp_key`
- `github_finegrained_pat`
- `github_token`
- `google_oauth_secret`
- `ip_address`
- `ipv6`
- `jwt`
- `mac_address`
- `openai_key`
- `pgp_private_key`
- `secret`
- `sendgrid_key`
- `slack_token`
- `ssh_private_key`
- `stripe_restricted_key`
- `twilio_key`

## Run pretense against just this framework

```bash
# point the pretense scanner at this whole folder …
#   pretense scan frameworks/FedRAMP/
# … or drive the synthetic corpus through the bridge:
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs --framework FedRAMP
```

## Run this framework's tests

```bash
uv run pytest tests/test_pcs.py -m fedramp -q --noconftest
```

`corpus/cases.json` here is git-ignored (a build artifact regenerated on demand);
it holds only cases whose `compliance` list includes this framework.
