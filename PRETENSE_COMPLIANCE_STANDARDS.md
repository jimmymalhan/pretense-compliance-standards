# Pretense Compliance Standards

> A graded, **fully synthetic** compliance / data-loss-prevention (DLP) testbed that
> measures how well the **pretense.ai** firewall — *identify* (secret/PII scan) and
> *mutate* (identifier redaction) — protects regulated data across the major global
> compliance frameworks. End to end, reproducible, and scored per framework.

**This is a customized fork.** The finance-symbol code at the repo root
(`financedatabase/`, `database/`, `compression/`) is the upstream
[FinanceDatabase](https://github.com/JerBouma/FinanceDatabase) project by Jeroen Bouma
(MIT, preserved — see `LICENSE` and `NOTICE`), reused here as a realistic *codebase
under test*. The testbed itself lives in **[`pretense_compliance_standards/`](pretense_compliance_standards/README.md)**.

## What it does

- A **graded corpus** of 132 synthetic sensitive-data cases across 5 obfuscation
  tiers (easy → hard: inline → labeled → split → encoded → zero-width/embedded).
- A reference **deterministic-hashing detector** (naive vs. hardened) that scores
  **recall per difficulty tier** and **per compliance framework**.
- A **pretense bridge** that runs the real pretense engine over the corpus and
  reports **identify % / mutate %** coverage per framework — i.e. *how well is each
  framework's data actually protected?*

## The guarantee

Every value is **provably fake** (900-range SSNs, `555-01xx` phones, `@example.com`
emails, `sk_test_`/`AKIA…EXAMPLE` secrets, Luhn-valid-but-random PANs, `00`-check
IBANs). Every corpus file carries a `SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL`
banner. Framework names appear only in metadata and reports — never inside a scanned
payload. It is **test input to raise detection coverage**, not real data and not
scanner-evasion.

## Run it

```bash
python3 -m pretense_compliance_standards.corpus_builder    # build corpus + cases.json
python3 -m pretense_compliance_standards.harness           # recall per tier + per framework
python3 -m pretense_compliance_standards.compliance        # print the framework taxonomy
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs     # pretense identify/mutate per framework
uv run pytest tests/test_pcs.py -q --noconftest             # test suite
```

See [`pretense_compliance_standards/README.md`](pretense_compliance_standards/README.md)
for the full framework taxonomy and report format.
