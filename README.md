# Pretense Compliance Standards

> A graded, **fully synthetic** compliance / data-loss-prevention (DLP) testbed that
> measures how well the **pretense.ai** firewall — *identify* (secret/PII scan) and
> *mutate* (identifier redaction) — protects regulated data across the major global
> compliance frameworks. Scored two ways at once: **recall per difficulty tier** and
> **coverage per compliance framework**.

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](tests/test_pcs.py)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Synthetic Data](https://img.shields.io/badge/data-100%25%20synthetic-orange)](pretense_compliance_standards/README.md)

## What it is

The testbed lives in **[`pretense_compliance_standards/`](pretense_compliance_standards/README.md)**:

- A **graded corpus** of 470+ synthetic sensitive-data cases across 6 obfuscation tiers
  (inline → labeled → split → encoded → zero-width → layered/nested), covering 38 data kinds.
- A reference **deterministic-hashing detector** (naive vs. hardened) scoring **recall
  per difficulty tier** and **per compliance framework**.
- A **pretense bridge** that runs the real pretense.ai engine over the corpus and reports
  **identify % / mutate %** coverage per framework.

**28 frameworks covered:** SOC2, ISO 27001, ISO 27701, NIST 800-53, NIST 800-171,
FedRAMP, FISMA, NIS2, NYDFS 500, DORA, APRA CPS 234, HIPAA, HITECH, HITRUST, GDPR,
UK-GDPR, CCPA/CPRA, LGPD, PIPEDA, POPIA, PIPL, PDPA-SG, COPPA, FERPA, SOX, GLBA,
CMMC L2, PCI DSS.

## The guarantee

Every value is **provably fake** (900-range SSNs, `555-01xx` phones, `@example.com`
emails, `sk_test_`/`AKIA…EXAMPLE` test-mode secrets, Luhn-valid-but-random PANs,
`00`-check IBANs). Every corpus file carries a `SYNTHETIC — FAKE COMPLIANCE TEST DATA,
NOT REAL` banner. Framework names appear only in metadata/reports — never in a scanned
payload. It is **test input to raise detection coverage**, not real data.

## Run it

```bash
python3 -m pretense_compliance_standards.corpus_builder    # build corpus + cases.json
python3 -m pretense_compliance_standards.compliance        # print the framework taxonomy
python3 -m pretense_compliance_standards.harness           # recall per tier + per framework
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs     # pretense identify/mutate per framework
uv run pytest tests/test_pcs.py -q --noconftest             # test suite
```

See [`pretense_compliance_standards/README.md`](pretense_compliance_standards/README.md)
for the full taxonomy and report formats, and [`PRETENSE_COMPLIANCE_STANDARDS.md`](PRETENSE_COMPLIANCE_STANDARDS.md)
for the project overview.

---

## Built on FinanceDatabase

This project is a fork that reuses **[FinanceDatabase](https://github.com/JerBouma/FinanceDatabase)**
— © 2023 **Jeroen Bouma**, MIT licensed — as the realistic *codebase under test*. The
finance-symbol library at [`financedatabase/`](financedatabase/) and the data in
`database/` remain the work of its original author and are used here under the MIT
License (see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)). Full credit to Jeroen Bouma:

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor_Jeroen_Bouma-grey?logo=github)](https://github.com/sponsors/JerBouma)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-grey?logo=Linkedin&logoColor=white)](https://www.linkedin.com/in/boumajeroen/)
[![Upstream](https://img.shields.io/badge/Upstream-FinanceDatabase-grey?logo=github)](https://github.com/JerBouma/FinanceDatabase)

The original FinanceDatabase documentation is preserved upstream at the link above.
