---
name: pcs-project
description: >-
  Orient in the Pretense Compliance Standards testbed — what it is, its layout, the
  key commands, and where the other skills apply. Use at the start of any task in
  this repo to load the project's shape and conventions.
---

# Pretense Compliance Standards — project orientation

A graded, **fully synthetic**, standalone DLP / compliance testbed that scores how
well the **pretense.ai** firewall
(*identify* + *mutate*) and a reference detector catch regulated data across the world's
major compliance frameworks. Two axes: **recall per obfuscation tier** and **coverage per
compliance framework**.

## Scale (current)

44 data kinds · **36 compliance frameworks** · 528 synthetic cases · 6 obfuscation tiers
(0 inline → 1 labeled → 2 split → 3 encoded → 4 zero-width → 5 layered/nested) · 58
adversarial negatives · hardened detector at 100% precision / 100% recall / F1 100%.

## Layout

```
pretense_compliance_standards/
├─ compliance.py       taxonomy: FRAMEWORK_KINDS (source of truth) -> FRAMEWORKS,
│                      frameworks_for(kind), kinds_for(framework); writes compliance_map.json
├─ detector.py         reference deterministic-hashing DLP detector; detect(text, "naive"|"hardened");
│                      hardened = normalized views + a bounded multi-pass decoder
├─ generator.py        shared fake-value generators (all provably fake ranges)
├─ regulated/setNN.py  auto-discovered synthetic data modules (set01..set09)
├─ negatives.py        benign look-alikes (expected:False) for precision
├─ corpus_builder.py   build_cases() + writes corpus/, negatives.json, and the frameworks/ tree
├─ framework_targets.py renders per-framework codebase+database scan targets
├─ harness.py          scores recall per tier + per framework, precision/F1; --json / --md exporters
└─ pretense_bridge/run.mjs   drives the real pretense engine; --framework <NAME> scopes to one
frameworks/<FRAMEWORK>/   generated per-framework view (HIPAA/, GDPR/, PCI_DSS/, … 36) — each a
                          self-contained scan target (database/dump.sql, codebase/.env|config.yaml|
                          seed.json|app.py, data/export.csv, logs/service.log, corpus/cases.json).
                          Data is git-ignored; README.md per folder is committed.
tests/test_pcs.py         the suite; per-framework pytest markers (pytest -m hipaa)
```

## Commands

```bash
python3 -m pretense_compliance_standards.corpus_builder   # (re)build corpus + frameworks/ tree
python3 -m pretense_compliance_standards.compliance       # taxonomy + compliance_map.json
python3 -m pretense_compliance_standards.harness          # recall per tier + per framework
python3 -m pretense_compliance_standards.harness --json report.json --md report.md
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs --framework HIPAA   # scope pretense to one framework
uv run pytest tests/test_pcs.py -q --noconftest           # full suite (local needs --noconftest)
uv run pytest tests/test_pcs.py -m hipaa -q --noconftest  # one framework's tests
```

## Conventions & the other skills

- Everything synthetic + banner-marked; framework names never inside a scanned payload value.
- Generated corpus / per-framework data is git-ignored — regenerate, don't commit it.
- To ship a change: use [milestone-release](../milestone-release/SKILL.md).
- If CI goes red or the user gets "Run failed" emails: use [ci-triage](../ci-triage/SKILL.md).
