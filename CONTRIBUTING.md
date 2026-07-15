# Contributing to Pretense Compliance Standards

Thanks for contributing! 🚀 This repo is the **Pretense Compliance Standards** testbed —
a fully-synthetic DLP/compliance corpus and scorer. The suite lives in
[`pretense_compliance_standards/`](pretense_compliance_standards/README.md).

## Ways to contribute

- **Add synthetic test cases** — new `regulated/setNN.py` data modules (auto-discovered).
  Every value must be **provably fake** (900-range SSNs, `555-01xx` phones, `@example.com`,
  Luhn-but-random PANs, `sk_test_`/example secrets) and every file must carry the
  `SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL` banner. Never put real data or
  framework names inside a scanned payload.
- **Extend the framework taxonomy** — map data `kind`s to more frameworks in
  `pretense_compliance_standards/compliance.py`.
- **Harden the detector** — close naive→hardened normalization gaps in `detector.py`.

## Before opening a PR

```bash
uv run pytest tests/test_pcs.py -q                          # green
uv run black --check .
uv run ruff check pretense_compliance_standards tests
python3 -m pretense_compliance_standards.harness            # exit 0
```

All data is SYNTHETIC by construction. Do not commit the generated corpus / per-framework
data (`corpus/`, `frameworks/*/{corpus,database,codebase,data,logs}/` are git-ignored build
artifacts). See the `milestone-release` skill in `.claude/skills/` for the full workflow.
