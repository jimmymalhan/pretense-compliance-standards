# Per-framework corpus views

> SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL

Each subfolder is a **generated** view of the synthetic corpus scoped to a single
compliance framework, so you can point **pretense** (or the test suite) at exactly
one framework's regulated data. Because one data `kind` maps to many frameworks, a
case appears under every framework it belongs to (the mapping is many-to-many).

Regenerate the whole tree (and the flat corpus) with:

```bash
python3 -m pretense_compliance_standards.corpus_builder
```

The per-framework `corpus/cases.json` files are git-ignored (build artifacts); the
folder + this index + each `<FRAMEWORK>/README.md` are committed so the layout is
visible in git.

## Frameworks

| Framework | Cases | Run pretense | Run tests |
|-----------|------:|--------------|-----------|
| [`SOC2`](SOC2/README.md) | 257 | `run.mjs --framework SOC2` | `pytest -m soc2` |
| [`ISO_27001`](ISO_27001/README.md) | 348 | `run.mjs --framework ISO_27001` | `pytest -m iso_27001` |
| [`ISO_27701`](ISO_27701/README.md) | 398 | `run.mjs --framework ISO_27701` | `pytest -m iso_27701` |
| [`NIST_800_53`](NIST_800_53/README.md) | 296 | `run.mjs --framework NIST_800_53` | `pytest -m nist_800_53` |
| [`NIST_800_171`](NIST_800_171/README.md) | 269 | `run.mjs --framework NIST_800_171` | `pytest -m nist_800_171` |
| [`FedRAMP`](FedRAMP/README.md) | 257 | `run.mjs --framework FedRAMP` | `pytest -m fedramp` |
| [`FISMA`](FISMA/README.md) | 321 | `run.mjs --framework FISMA` | `pytest -m fisma` |
| [`NIS2`](NIS2/README.md) | 257 | `run.mjs --framework NIS2` | `pytest -m nis2` |
| [`NYDFS_500`](NYDFS_500/README.md) | 277 | `run.mjs --framework NYDFS_500` | `pytest -m nydfs_500` |
| [`DORA`](DORA/README.md) | 334 | `run.mjs --framework DORA` | `pytest -m dora` |
| [`APRA_CPS234`](APRA_CPS234/README.md) | 279 | `run.mjs --framework APRA_CPS234` | `pytest -m apra_cps234` |
| [`HIPAA`](HIPAA/README.md) | 128 | `run.mjs --framework HIPAA` | `pytest -m hipaa` |
| [`HITECH`](HITECH/README.md) | 128 | `run.mjs --framework HITECH` | `pytest -m hitech` |
| [`HITRUST`](HITRUST/README.md) | 316 | `run.mjs --framework HITRUST` | `pytest -m hitrust` |
| [`GDPR`](GDPR/README.md) | 238 | `run.mjs --framework GDPR` | `pytest -m gdpr` |
| [`UK_GDPR`](UK_GDPR/README.md) | 238 | `run.mjs --framework UK_GDPR` | `pytest -m uk_gdpr` |
| [`CCPA_CPRA`](CCPA_CPRA/README.md) | 213 | `run.mjs --framework CCPA_CPRA` | `pytest -m ccpa_cpra` |
| [`LGPD`](LGPD/README.md) | 141 | `run.mjs --framework LGPD` | `pytest -m lgpd` |
| [`PIPEDA`](PIPEDA/README.md) | 141 | `run.mjs --framework PIPEDA` | `pytest -m pipeda` |
| [`POPIA`](POPIA/README.md) | 141 | `run.mjs --framework POPIA` | `pytest -m popia` |
| [`PIPL`](PIPL/README.md) | 141 | `run.mjs --framework PIPL` | `pytest -m pipl` |
| [`PDPA_SG`](PDPA_SG/README.md) | 141 | `run.mjs --framework PDPA_SG` | `pytest -m pdpa_sg` |
| [`COPPA`](COPPA/README.md) | 95 | `run.mjs --framework COPPA` | `pytest -m coppa` |
| [`FERPA`](FERPA/README.md) | 89 | `run.mjs --framework FERPA` | `pytest -m ferpa` |
| [`DPDP`](DPDP/README.md) | 141 | `run.mjs --framework DPDP` | `pytest -m dpdp` |
| [`APPI`](APPI/README.md) | 141 | `run.mjs --framework APPI` | `pytest -m appi` |
| [`PIPA_KR`](PIPA_KR/README.md) | 141 | `run.mjs --framework PIPA_KR` | `pytest -m pipa_kr` |
| [`AU_PRIVACY`](AU_PRIVACY/README.md) | 171 | `run.mjs --framework AU_PRIVACY` | `pytest -m au_privacy` |
| [`FADP`](FADP/README.md) | 198 | `run.mjs --framework FADP` | `pytest -m fadp` |
| [`PDPA_TH`](PDPA_TH/README.md) | 141 | `run.mjs --framework PDPA_TH` | `pytest -m pdpa_th` |
| [`CJIS`](CJIS/README.md) | 121 | `run.mjs --framework CJIS` | `pytest -m cjis` |
| [`IRS_1075`](IRS_1075/README.md) | 84 | `run.mjs --framework IRS_1075` | `pytest -m irs_1075` |
| [`SOX`](SOX/README.md) | 257 | `run.mjs --framework SOX` | `pytest -m sox` |
| [`GLBA`](GLBA/README.md) | 146 | `run.mjs --framework GLBA` | `pytest -m glba` |
| [`CMMC_L2`](CMMC_L2/README.md) | 42 | `run.mjs --framework CMMC_L2` | `pytest -m cmmc_l2` |
| [`PCI_DSS`](PCI_DSS/README.md) | 42 | `run.mjs --framework PCI_DSS` | `pytest -m pci_dss` |
