# `pretense_compliance_standards` — a graded DLP recall benchmark

A benchmark for measuring how well a **DLP (data-loss-prevention) detector**
catches sensitive data across a difficulty gradient, and for showing exactly
which obfuscations a naive deterministic-hashing scanner misses so it can be
hardened.

> **Everything here is SYNTHETIC.** Every "sensitive" value is fake by
> construction — SSNs in the never-issued `900-xx-xxxx` range, `555-01xx` phone
> numbers (reserved for fiction), `@example.com` emails, the AWS *example* key,
> Luhn-valid-but-random card numbers, `sk_test_` keys. No value maps to a real
> person, account, or secret. Every generated file carries a
> `SYNTHETIC — FAKE DLP BENCHMARK DATA, NOT REAL` banner.
>
> The corpus is **scanner input with ground-truth labels**. Every case is
> `expected: true` — something a correct scanner *should* flag. The obfuscation
> tiers document detection challenges to overcome; a case the detector misses is
> a bug to fix, never a way to slip data past a control. The benchmark exists to
> **raise** recall.

## Layout

| File | Role |
|------|------|
| `generator.py` | Synthetic, finance-flavored PII/PHI/PCI record generator (refactored from the old `sensitive_data_samples.py`). |
| `corpus_builder.py` | Writes the graded corpus (`corpus/*.json/.csv/.log`) + `corpus/cases.json` ground-truth manifest. |
| `detector.py` | Reference **deterministic-hashing** DLP detector, `naive` and `hardened` modes. |
| `harness.py` | Runs the detector over the corpus, reports **recall per difficulty tier** (and per compliance framework). |
| `compliance.py` | Maps each data `kind` to the compliance framework(s) it exercises; emits `compliance_map.json` for non-Python consumers. |

## Difficulty gradient (easy → hard)

| Tier | Challenge |
|------|-----------|
| 0 | canonical value, inline in prose |
| 1 | labeled CSV/config fields; canonical-reachable format variants |
| 2 | value split across quotes/lines; space/dash-grouped digits |
| 3 | base64 / hex / Unicode-homoglyph encodings |
| 4 | zero-width separators, embedded/wrapped encodings |

## The detector, and what the benchmark shows

`detector.detect(text, mode)` returns the set of sensitive `kind`s found.

- **`naive`** — fixed regexes + a `sha256` denylist over the raw text. The
  "deterministic hashing" core: known secrets are hashed and matched wherever
  they appear — but only in their canonical form.
- **`hardened`** — the same detectors run over *normalized views*:
  fragment-joining (rejoins split values), separator collapse, Unicode NFKC +
  zero-width stripping (defeats homoglyphs/invisible chars), and base64/hex
  decoding.

Running the harness produces the motivating result — naive holds on the easy
tiers and collapses under obfuscation; hardened normalization recovers it:

```
tier     n          naive    hardened
0        8          100%        100%
1        7          100%        100%
2        5            0%        100%
3        5            0%        100%
4        4            0%        100%
all     29           52%        100%
```

Each naive miss is printed as a named normalization gap. That list is the
actionable output: it's the set of transforms a real scanner must apply before
hashing/matching in order to catch obfuscated sensitive data.

## Compliance categorization

On top of the difficulty gradient, every data `kind` is tagged with the
compliance framework(s) whose regulated data it exercises. This lets the
benchmark answer a second question — *"how well is each framework's data
protected?"* — alongside the tier-by-tier recall story.

- **`compliance.py`** owns the taxonomy: a many-to-many `kind -> frameworks`
  map (`KIND_FRAMEWORKS`). `email`, for example, is HIPAA contact info, GDPR
  personal data, *and* ISO 27001 PII at once.
- Each corpus case carries a **`compliance` metadata field** — the list of
  frameworks its `kind` exercises — so the label rides along with the case.
- The harness and the pretense bridge use that field to report coverage
  **per framework**, not just per tier: recall (harness) and identify / mutate
  (bridge) broken out for each of HIPAA, GDPR, SOC2, CMMC L2, ISO 27001, and
  PCI DSS.

### Taxonomy (`kind` → frameworks)

Reproduced from `compliance.py`; run `python3 -m pretense_compliance_standards.compliance` to
regenerate `compliance_map.json` and print the summary.

| `kind` | Frameworks |
|--------|------------|
| `medical_record_number` | HIPAA |
| `icd10` | HIPAA |
| `health_record` | HIPAA |
| `insurance_member_id` | HIPAA |
| `ssn` | HIPAA, ISO 27001 |
| `email` | HIPAA, GDPR, ISO 27001 |
| `phone` | HIPAA, GDPR, ISO 27001 |
| `national_id` | GDPR, ISO 27001 |
| `passport` | GDPR, ISO 27001 |
| `iban` | GDPR |
| `vat` | GDPR |
| `api_key` | SOC2, ISO 27001 |
| `aws_key` | SOC2, ISO 27001 |
| `gcp_key` | SOC2, ISO 27001 |
| `github_token` | SOC2, ISO 27001 |
| `slack_token` | SOC2, ISO 27001 |
| `db_url` | SOC2, ISO 27001 |
| `jwt` | SOC2, ISO 27001 |
| `secret` | SOC2, ISO 27001 |
| `access_log` | SOC2, ISO 27001 |
| `contract_number` | CMMC L2 |
| `part_number` | CMMC L2 |
| `internal_program_code` | CMMC L2 |
| `pan` | PCI DSS |

By framework (kinds claimed): **HIPAA** (7) medical_record_number, icd10,
health_record, insurance_member_id, ssn, email, phone; **GDPR** (6) national_id,
passport, iban, vat, email, phone; **SOC2** (9) api_key, aws_key, gcp_key,
github_token, slack_token, db_url, jwt, secret, access_log; **CMMC L2** (3)
contract_number, part_number, internal_program_code; **ISO 27001** (14) the
SOC2 credentials plus ssn, national_id, passport, email, phone; **PCI DSS** (1)
pan.

### Reading the per-framework reports

```bash
python3 -m pretense_compliance_standards.harness   # recall per compliance framework (plus per tier)
```

```bash
node --experimental-transform-types pretense_compliance_standards/pretense_bridge/run.mjs   # pretense identify / mutate per framework
```

The harness rolls detector recall up per framework, and the pretense bridge
rolls pretense `identify` / `mutate` coverage up per framework — so a gap can be
read as *"framework X's data is under-protected"*, not just *"tier N is hard"*.

### Guardrails

- Framework names live in the `compliance` metadata field, in
  `compliance_map.json`, and in reports/docs **only** — never inside a case's
  scanned `text` payload, which stays clean synthetic data.
- Categorizing by framework changes nothing about the values: they remain
  **synthetic and fake** by construction (see the SYNTHETIC note above).
- Every corpus file still carries the
  `SYNTHETIC — FAKE DLP BENCHMARK DATA, NOT REAL` banner.

## Usage

```bash
python3 -m pretense_compliance_standards.corpus_builder   # (re)generate corpus/ + cases.json
python3 -m pretense_compliance_standards.compliance       # (re)generate compliance_map.json + print taxonomy summary
python3 -m pretense_compliance_standards.harness          # score + print recall table (exit 1 on regression)
pytest tests/test_dlp_recall.py -q        # regression guard
```
