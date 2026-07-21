# `tests/e2e` — the 36-framework suite, hardened against false greens

```sh
tests/e2e/run.sh              # build the corpus, then run everything
tests/e2e/run.sh --no-build   # assert a PRE-BUILT corpus, then run
```

## Why this exists

Two things were true of the 36-framework loop before this directory existed.

**1. The per-framework corpus files are git-ignored build artifacts.** A loop that
runs before the builder makes every framework fail on a *missing file*. Thirty-six
red checks that are all the same missing artifact read like thirty-six detector
regressions, and people learn to ignore the suite. `run.sh` builds first and dies
with `E_CORPUS_BUILD` rather than entering the loop.

**2. Zero cases exited 0.** `run.mjs` prints `n/a` and exits 0 when a framework
filters to zero cases, so the loop everyone actually writes —

```sh
for F in $FRAMEWORKS; do node run.mjs --framework "$F" || fail; done
```

— returns **green checks having measured nothing**. Reproduced: with the flat
corpus emptied to `{"cases": []}`, that loop reported 8/8 green, exit 0 every
time. `run.sh` asserts a **non-zero case count twice** — once on disk, once from
the bridge's own `overall.n` — and requires the two to agree, so a zero is
`E_ZERO_CASES`, a loud failure.

## Named failure codes

| code | meaning |
|---|---|
| `E_CORPUS_BUILD` | the corpus builder exited non-zero; the loop is NOT entered |
| `E_CORPUS_NOT_BUILT` | `--no-build` given but no corpus exists |
| `E_CORPUS_EMPTY` / `E_CORPUS_SIZE` | flat corpus has zero cases, or is not 648 |
| `E_FRAMEWORK_CASES` | a per-framework case file is missing, empty, non-UTF-8, or malformed JSON |
| `E_FRAMEWORK_DRIFT` / `E_FRAMEWORK_COUNT` | the framework list is no longer the expected 36 |
| `E_ZERO_CASES` | the bridge measured zero cases for a framework — **the false green** |
| `E_COUNT_MISMATCH` | disk view and bridge view of one framework disagree (map drift) |
| `E_RATE_REGRESSION` | egress redaction fell below the recorded floor in `baseline.json` |
| `E_BRIDGE_EXIT` | the bridge exited non-zero; the loop STOPS and names the framework |
| `E_PYTEST_EXIT` / `E_PYTEST_ZERO` | a marker failed, or collected zero tests (pytest exit 5) |
| `E_CROSS_CONTAMINATION` / `E_CROSS_PROBE_DEAD` | contamination found, or the probe itself was vacuous |
| `E_ENGINE_DRIFT` | the scanner/mutator/corpus changed *while the loop ran* |

`E_CROSS_PROBE_DEAD` and `E_ENGINE_DRIFT` exist because a probe that cannot fail
proves nothing. A concurrent `packages/mutator` rebuild was observed *during this
work* to move the headline from 88.9% to 89.4% with no change on our side, which
silently makes rows measured either side of it non-comparable. Drift is therefore
a failure, never a retry.

## Shell constraints

`set -eu`, **not** `set -euo pipefail` — `/bin/sh` on Ubuntu is dash, where
`-o pipefail` dies with `Illegal option -o pipefail`. Verified by running the
script under `/bin/dash` (exit 0) and with `shellcheck -s sh` (clean). Every
command inside a loop has its exit status captured explicitly, because `set -e`
does not abort for a command whose status is inspected. There is no `|| true`,
no swallowed status, and no retry-until-green.

`grep -a` is used throughout: the corpus contains synthetic secret-shaped values
and plain `grep` prints nothing on a file it decides is binary.

## `baseline.json`

Measured egress-redaction floors, one per framework, plus the scanner and mutator
`dist/index.js` SHA-256 they were recorded against. Tolerance is 2.0pp. Without
floors a framework cannot go red on a real detector regression — it would only go
red on a crash. Proven: detaching one detector from one kind dropped HIPAA from
83.6% to 77.3% and turned the run red at `HIPAA` while the eleven frameworks that
do not use that kind stayed green.

**Regenerate deliberately, never automatically, and only against a pinned engine.**
The recorded hashes are the only thing that makes a number in this file mean
anything.

## Prerequisites

* Node >= 18 and `python3` >= 3.10 (`uv` is used when present).
* A **full** sibling `pretense` checkout with `packages/scanner/dist` and
  `packages/mutator/dist` built. `run.mjs` also parses `apps/proxy/src/server.ts`
  for the real scan options, so a snapshot of the scanner alone is not enough.
  Override the location with `PRETENSE_SRC`.

Because of that second prerequisite this script is **not** wired into the GitHub
workflows in this repo, which have no access to the engine checkout. It is a
local / self-hosted gate. `.github/workflows/testing.yml` runs only
`pytest tests/test_pcs.py`, and `bridge.yml` runs the bridge unit tests against a
mock engine — neither has ever executed the real 36-framework loop.

## What the numbers mean

The headline is **egress redaction over 648 synthetic cases**, with false
positives measured against a 70-case benign look-alike set. Those 648 cases are
then *projected* onto 36 framework labels by a single kind→framework lookup.
Those projections resolve to **24 distinct configurations** — 12 of the 36 rows
are exact duplicates of another row (GDPR/UK_GDPR, HIPAA/HITECH,
SOC2/FedRAMP/NIS2, and nine APAC/LatAm privacy laws sharing one 141-case set).
`run.sh` prints that count and those groups under `INDEPENDENCE:` in every run,
so nobody can quote "36 passed" from this output without also seeing "24 distinct
configurations".

**CMMC_L2 is fitted to its fixtures.** It is printed as a row and flagged inline;
it is never evidence of anything.

The per-framework case counts sum to 6888. That is the case×framework edge count,
not a case count. Do not publish it as one.
