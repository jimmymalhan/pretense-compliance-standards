# `dlp_benchmark` — a graded DLP recall benchmark

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
| `harness.py` | Runs the detector over the corpus, reports **recall per difficulty tier**. |

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

## Usage

```bash
python3 -m dlp_benchmark.corpus_builder   # (re)generate corpus/ + cases.json
python3 -m dlp_benchmark.harness          # score + print recall table (exit 1 on regression)
pytest tests/test_dlp_recall.py -q        # regression guard
```
