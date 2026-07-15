# `pretense_compliance_standards` — the Pretense compliance standard

A graded, **fully synthetic** testbed that measures how well sensitive data is
caught and protected across the major global compliance frameworks — and, via the
**pretense.ai** bridge, how well the pretense firewall's *identify* + *mutate*
covers each framework's data. It scores two axes at once: **recall per difficulty
tier** (how obfuscation-resistant is detection?) and **coverage per compliance
framework** (whose regulated data is under-protected?).

> **Everything here is SYNTHETIC.** Every "sensitive" value is fake by
> construction — SSNs in the never-issued `900-xx-xxxx` range, `555-01xx` phone
> numbers (reserved for fiction), `@example.com` emails, the AWS *example* key,
> Luhn-valid-but-random card numbers, `sk_test_` keys, `00`-check IBANs. No value
> maps to a real person, account, or secret. Every generated file carries a
> `SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL` banner.
>
> The corpus is **scanner input with ground-truth labels**. Every case is
> `expected: true` — something a correct scanner *should* flag. Obfuscation tiers
> document detection challenges to overcome; a case the detector misses is a bug
> to fix, never a way to slip data past a control. This raises detection coverage,
> it does not evade it.

## Layout

| File | Role |
|------|------|
| `generator.py` | Synthetic PII/PHI/PCI record generator. |
| `regulated/` | Auto-discovered synthetic data-sets (health, EU-personal, controlled/technical, credentials, embedded). |
| `corpus_builder.py` | Writes the graded corpus (`corpus/*.json/.csv/.log`) + `corpus/cases.json` manifest; tags each case with its `compliance` frameworks. |
| `detector.py` | Reference **deterministic-hashing** detector, `naive` and `hardened` modes. |
| `harness.py` | Scores the detector: **recall per difficulty tier** and **per compliance framework**. |
| `compliance.py` | Framework taxonomy — maps each data `kind` to the frameworks it exercises; emits `compliance_map.json`. |
| `pretense_bridge/` | Drives the real pretense.ai engine over the corpus; reports **identify / mutate** coverage per framework. |

## Difficulty gradient (easy → hard)

| Tier | Challenge |
|------|-----------|
| 0 | canonical value, inline in prose |
| 1 | labeled CSV/config fields; canonical-reachable format variants |
| 2 | value split across quotes/lines; space/dash-grouped digits |
| 3 | base64 / hex / Unicode-homoglyph encodings |
| 4 | zero-width separators, single embedded encodings |
| 5 | layered/nested encodings: base64-of-base64, gzip+base64, full percent-encoding, ROT13 |

`detector.detect(text, mode)` returns the set of sensitive `kind`s found. **`naive`**
= fixed regexes + a `sha256` denylist over raw text (catches canonical forms only).
**`hardened`** = the same detectors over *normalized views* (fragment-join, separator
collapse, NFKC + zero-width strip, and a bounded **multi-pass** decoder that unwinds
base64/hex/gzip/percent/ROT13 layers). Naive holds on the easy tiers and collapses
under obfuscation; hardened normalization recovers it to 100%. Each naive miss is
printed as a named normalization gap — the actionable to-do for a real scanner.

## Compliance framework coverage

Every data `kind` is mapped to the compliance framework(s) whose regulated data it
exercises (`compliance.py`, a many-to-many taxonomy). Each corpus case carries a
`compliance` metadata field; the harness and pretense bridge roll coverage up
**per framework** — so a gap reads as *"framework X's data is under-protected"*,
not just *"tier N is hard."*

**36 frameworks covered:** SOC2, ISO 27001, ISO 27701, NIST 800-53, NIST 800-171,
FedRAMP, FISMA, NIS2, NYDFS 500, DORA, APRA CPS 234, HIPAA, HITECH, HITRUST, GDPR,
UK-GDPR, CCPA/CPRA, LGPD, PIPEDA, POPIA, PIPL, PDPA-SG, COPPA, FERPA, DPDP (India),
APPI (Japan), PIPA (Korea), Australia Privacy Act, Swiss FADP, PDPA (Thailand),
CJIS, IRS Pub 1075, SOX, GLBA, CMMC L2, PCI DSS — spanning security/credential
regimes, health (PHI), global privacy laws, financial, and controlled-unclassified
categories. Across 44 data kinds (incl. card CVV, bank/routing/EIN, driver's
license, DOB, IPv4/IPv6, MAC, crypto wallet, SSH/PEM private key, SWIFT/BIC, VIN,
Medicare ID, NPI, and cloud/vendor API keys).

The taxonomy is defined once in `compliance.py` (`FRAMEWORK_KINDS` is the source of
truth; `KIND_FRAMEWORKS` is derived so the two can't drift). Print the live mapping:

```bash
python3 -m pretense_compliance_standards.compliance   # summary + regenerates compliance_map.json
```

### Reading the per-framework reports

```bash
python3 -m pretense_compliance_standards.harness      # recall per framework (+ per tier)
python3 -m pretense_compliance_standards.harness \
  --json report.json --md report.md                   # also emit machine-readable reports
node --experimental-transform-types \
  pretense_compliance_standards/pretense_bridge/run.mjs   # pretense identify / mutate per framework
```

`--json` writes a structured report (totals, recall per tier, recall per framework,
and the precision / recall / F1 matrix) suitable for CI diffing; `--md` writes the
same data as a Markdown summary. The default text output is unchanged.

### Guardrails

- Framework names live in the `compliance` metadata field, in `compliance_map.json`,
  and in reports/docs **only** — never inside a case's scanned `text` payload.
- Categorizing by framework changes nothing about the values: they remain
  **synthetic and fake** by construction.
- Every corpus file carries the `SYNTHETIC — FAKE COMPLIANCE TEST DATA, NOT REAL` banner.

## Usage

```bash
python3 -m pretense_compliance_standards.corpus_builder   # (re)generate corpus/ + cases.json
python3 -m pretense_compliance_standards.compliance       # (re)generate compliance_map.json + taxonomy
python3 -m pretense_compliance_standards.harness          # score recall (per tier + per framework)
uv run pytest tests/test_pcs.py -q           # test suite
```
