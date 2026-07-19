# Pretense egress-redaction bridge

Drives the synthetic corpus (`pretense_compliance_standards/corpus/cases.json`)
through the **real, shipped pretense engine** and reports what the product
actually protects — per difficulty tier and per compliance framework.

All input is synthetic, fake and banner-marked. This tool only *reads* the
corpus, the compliance map and the engine; it never modifies corpus data.

> **This harness measures a product, so it is deliberately built to be hard to
> inflate.** Every ambiguous case resolves against the product, and every
> misconfiguration is a loud failure rather than a silent fallback that yields a
> good-looking number. If a change here makes the reported number go *up*,
> that change needs a very good justification.

## What is measured

### PRIMARY — egress redaction

> *What fraction of sensitive values actually left the proxy **transformed**.*

This is the headline number, and it is the only one that describes protection.
It is computed the way `apps/proxy/src/server.ts` really behaves. A case counts
only when **all** of these hold:

1. a match whose detector **kind agrees** with the case's expected kind;
2. that match's action is one the proxy acts on — `block`, `redact` or `mutate`
   (the proxy **skips `warn`/`pass` entirely** — see `toSecretFindings`);
3. the match has a **real, non-zero span** (`end > start`) — a zero-span
   deobfuscation-only hit can never be spliced in place and is stripped by
   `egressSafe: true`, so it protects nothing;
4. the **real redaction path** `mutateSecrets(text, findings)` — the exact
   function the proxy calls — produced output in which the matched value is
   **verifiably gone**.

The bridge scans with the proxy's own options, copied verbatim:

```js
{ contextAware: true, entropyAnalysis: false, deobfuscate: false, egressSafe: true }
```

### SECONDARY — identify

> *The detector recognized this datum for what it is.*

A kind-agreeing match of any action or span. **Identify is not protection.** A
`warn` match and a zero-span match both read as "identified" while the data
egresses in plaintext. Never quote identify as a protection or compliance
figure.

### wrong-kind

A case that matched *something*, but nothing that means the right datum — e.g.
an **NPI** or a **UK NHS number** caught by the `phone-us` detector. These get
their own column and are never folded into identify: counting them would
manufacture false compliance credit (HIPAA "coverage" for data that is, in
fact, leaving in plaintext).

Kind agreement is defined in `../kind_detectors.json`, which maps each corpus
`kind` to the shipped detector names that mean the same datum. An **empty list**
is a valid, deliberate answer: it records that the shipped engine has *no*
detector for that kind, making every such case an honest miss. A corpus kind
with no entry at all makes the bridge **throw** rather than score arbitrarily
(and `tests/test_pcs.py` fails if any kind is unmapped).

## Output

```
==============================================================================
Pretense EGRESS-REDACTION benchmark  (synthetic DLP corpus)
==============================================================================
  engine        : @pretense/scanner@0.2.0   [SHIPPED]
  redaction     : @pretense/mutator@0.2.0  (mutateSecrets — the proxy's own path)
  commit        : c3dc109 (release/v0.6.0-always-mutate) [clean]
  corpus        : 648 cases — REGENERATED via uv
==============================================================================

tier       |    n | egress | ident. | wrong | miss
-----------+------+--------+--------+-------+-----
0          |  127 |  77.2% |  87.4% |     8 |    8
...
ALL        |  648 |  44.3% |  50.3% |    26 |  296
```

Every report header names the engine, package version, git commit and case
count actually measured, so a number can always be traced to what produced it.

Per-framework rows aggregate over the cases whose `kind` maps to that framework
(from `../compliance_map.json`). Because one `kind` maps to many frameworks, a
case counts toward every framework it belongs to — the per-framework `n` values
overlap and do **not** sum to the corpus size. A framework with no cases shows
`n/a`.

## Requirements

A local checkout of the **pretense** product repo, by default a **sibling** of
this repo, with the shipped packages built:

```bash
cd ../pretense
pnpm install
pnpm --filter @pretense/compliance-engine \
     --filter @pretense/scanner \
     --filter @pretense/mutator build
```

The bridge loads the **built `dist/` artifacts** — what actually ships — never
loose source files.

### ⚠ The dual-engine trap

`pretense` contains **two** scanner implementations:

| path | package | status |
|------|---------|--------|
| `packages/scanner` | `@pretense/scanner` | **SHIPPED** — the binary and proxy build this |
| `packages/cli/src` | *(none)* | **NOT SHIPPED** — a stale copy that scores several points higher |

This bridge previously defaulted to `packages/cli/src` and so reported numbers
the product does not deliver. It now measures **only** the shipped engine and
**hard-fails (exit 2)** if pointed anywhere else — at a non-package, at a
differently-named package, or at an unbuilt one. There is intentionally **no
fallback**.

`PRETENSE_SRC` overrides the scanner path (the mutator is resolved beside it):

```bash
PRETENSE_SRC=/path/to/pretense/packages/scanner \
  node pretense_compliance_standards/pretense_bridge/run.mjs
```

Note that an **empty** `PRETENSE_SRC=` is treated as a misconfiguration and
fails, rather than silently falling back to the default. If `PRETENSE_SRC` is
unset *and* no sibling checkout exists, the bridge prints a `SKIPPED` line and
exits 0 — printing **no numbers**, so a skip can never be mistaken for a result.

## Corpus freshness

`cases.json` and the other corpus files are **build artifacts**. They used to
be committed, and they silently went stale — 452 cases committed against the
648 the builder actually emits — which quietly moved every published figure.

They are now **git-ignored rather than committed**, so the drift is impossible
by construction: the only corpus that can be measured is one just built from
source. The bridge **regenerates before every run** and hard-fails if it
cannot, the test fixtures rebuild it, and
`tests/test_pcs.py::test_generated_corpus_is_not_committed` fails if anyone
re-adds them to git.

`--no-regenerate` skips this, but prints a loud warning that the results must
not be published.

## How to run

```bash
node pretense_compliance_standards/pretense_bridge/run.mjs
node pretense_compliance_standards/pretense_bridge/run.mjs --framework HIPAA
node pretense_compliance_standards/pretense_bridge/run.mjs --json
```

No `--experimental-transform-types` is needed any more: the bridge imports built
JavaScript, so the old "copy sources to a temp dir and rewrite `.js` → `.ts`
imports" trick is gone. That trick was also what made it easy to point the
harness at the wrong engine.

## Testing (offline, no engine checkout)

The scoring core is exported (`classifyCase`, `scoreCorpus`, `parseFrameworkArg`)
and covered by `run.test.mjs` against a **mock engine** — no checkout, no
network, no env vars. These tests lock in the anti-inflation contract: `warn`
matches, zero-span matches, unverified replacements and wrong-kind matches must
each score **zero** egress, and every engine misconfiguration must exit 2
without printing metrics.

```bash
node --check pretense_compliance_standards/pretense_bridge/run.mjs
node --test  pretense_compliance_standards/pretense_bridge/run.test.mjs
```
