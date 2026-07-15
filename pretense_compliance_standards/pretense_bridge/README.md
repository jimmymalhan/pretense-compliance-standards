# Pretense identify + mutate bridge

Feeds the Pretense Compliance Standards synthetic corpus
(`pretense_compliance_standards/corpus/cases.json`) through the real
**pretense.ai** firewall engine and reports how much of the sensitive test data
pretense covers — broken down by difficulty tier **and by compliance framework**
(so you can read coverage as "how well is each framework's data protected?").
All input is synthetic and fake (see the suite's SYNTHETIC banner).

Two independent measurements per case:

- **IDENTIFY** — pretense `scan(text)` runs its secret/identifier pattern scan.
  A case counts as identified when the scan returns at least one match.
- **MUTATE** — pretense `mutate(text, "typescript")` deterministically rewrites
  identifiers. A case counts as mutated when `stats.tokensMutated > 0` (or the
  mutated output differs from the input).

The bridge prints a per-tier table plus an overall row:

```
tier |   n | identify | mutate
-----+-----+----------+-------
   0 |  27 |    55.6% |  25.9%
   ...
 all | 132 |    35.6% |  12.1%
```

## Per-framework report

The bridge also reports how well pretense protects **each compliance
framework's** data. It reads the taxonomy in `pretense_compliance_standards/compliance_map.json`
(`{ "frameworks": [...], "kind_frameworks": { "<kind>": ["<fw>", ...] } }`) and,
for every framework, aggregates identify% and mutate% over the corpus cases
whose `kind` maps to that framework. Because a single `kind` can map to more
than one framework (e.g. `email` → HIPAA, GDPR, ISO_27001), one case counts
toward every framework it belongs to, so the per-framework `n` values overlap
and do not sum to the corpus size. Frameworks are printed in the fixed order
declared in `compliance_map.json`:

```
Per-framework coverage (cases whose kind maps to the framework)
framework  |   n | identify | mutate
-----------+-----+----------+-------
SOC2       |  42 |    64.3% |  11.9%
HIPAA      |  43 |    30.2% |  20.9%
GDPR       |  40 |    25.0% |  15.0%
CMMC_L2    |  12 |     0.0% |   8.3%
ISO_27001  |  76 |    51.3% |  14.5%
PCI_DSS    |  10 |    60.0% |  10.0%
-----------+-----+----------+-------
```

A framework with no matching cases shows `n/a`. Kinds that map to a framework
absent from the ordered `frameworks` list are ignored.

All corpus input is **synthetic, fake, and banner-marked**. This tool only
*reads* the corpus, the compliance map, and the pretense source; it never
modifies corpus data.

## Requirements

You need a local checkout of the pretense engine. The bridge looks for its CLI
source at `$PRETENSE_SRC`, defaulting to:

```
/Users/jimmymalhan/Documents/pretense/packages/cli/src
```

Set `PRETENSE_SRC` to point at your own checkout:

```
PRETENSE_SRC=/path/to/pretense/packages/cli/src \
  node --experimental-transform-types pretense_compliance_standards/pretense_bridge/run.mjs
```

If the path does not exist the bridge prints
`pretense engine not found at <path>; skipping` and exits 0, so it is safe to
run in environments without the checkout.

## Testing (offline, no engine checkout)

The scoring core is exported (`scoreCorpus`, `parseFrameworkArg` in `run.mjs`) and
covered by `run.test.mjs` against a **mock engine** — so the per-tier / per-framework
tallying is verified with no pretense checkout, no network, and no env vars. This runs
in CI (the **Bridge Tests** workflow), which the graceful-skip path would otherwise
leave untested:

```
node --check pretense_compliance_standards/pretense_bridge/run.mjs
node --test  pretense_compliance_standards/pretense_bridge/run.test.mjs
```

## How to run

```
node --experimental-transform-types pretense_compliance_standards/pretense_bridge/run.mjs
```

`--experimental-transform-types` lets Node execute the engine's TypeScript
source directly.

## The temp-copy / `.js` → `.ts` rewrite trick

The pretense engine is authored in TypeScript, but its internal relative
imports use `.js` specifiers (e.g. `import { scan } from "./scanner.js";`) that
are meant to resolve to the sibling `.ts` files after a build. Node's TS loader
resolves those specifiers literally, so importing the source in place fails —
`./scanner.js` does not exist on disk.

To work around this without touching the pretense checkout, the bridge:

1. Copies the 7 files it needs
   (`types.ts scanner.ts mutator.ts reverser.ts deterministic-id.ts salt.ts
   secrets.ts`) into a fresh temp dir created with `os.tmpdir()` +
   `fs.mkdtempSync`.
2. In each copy, rewrites relative import specifiers `from "./X.js"` →
   `from "./X.ts"` (regex replacing `(from\s+["']\./[A-Za-z0-9_-]+)\.js(["'])`
   with `$1.ts$2`).
3. Dynamic-`import()`s `mutator.ts` (for `mutate`) and `secrets.ts` (for `scan`)
   from the temp dir.

This keeps the original pretense source untouched and is the known-working
approach under `node --experimental-transform-types`.
