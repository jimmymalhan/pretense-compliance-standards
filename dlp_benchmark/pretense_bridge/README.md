# Pretense identify + mutate bridge

Feeds the synthetic DLP benchmark corpus (`dlp_benchmark/corpus/cases.json`)
through the real **pretense** AI-firewall engine and reports how much of the
sensitive test data pretense covers, broken down by difficulty tier.

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
   0 |   8 |    87.5% |  37.5%
   ...
 all |  29 |    51.7% |  17.2%
```

All corpus input is **synthetic, fake, and banner-marked**. This tool only
*reads* the corpus and the pretense source; it never modifies corpus data.

## Requirements

You need a local checkout of the pretense engine. The bridge expects its CLI
source at:

```
/Users/jimmymalhan/Documents/pretense/packages/cli/src
```

If that path does not exist the bridge prints
`pretense engine not found at <path>; skipping` and exits 0, so it is safe to
run in environments without the checkout.

## How to run

```
node --experimental-transform-types dlp_benchmark/pretense_bridge/run.mjs
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
