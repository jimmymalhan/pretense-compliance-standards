#!/bin/sh
# =====================================================================
# End-to-end 36-framework compliance suite — HARDENED AGAINST FALSE GREENS.
#
# The two failure modes this script exists to prevent:
#
#   1. MISSING BUILD ARTIFACT REPORTED AS A REGRESSION (or worse, as a PASS).
#      The per-framework corpus files are git-ignored build artifacts. This
#      script builds them FIRST and dies with a named error if the build
#      fails, so the loop never runs against absent files.
#
#   2. ZERO CASES REPORTED AS A PASS.
#      run.mjs exits 0 and prints "n/a" when a framework filters to zero
#      cases, so `for F in ...; do node run.mjs --framework $F || fail; done`
#      returns 36 GREEN CHECKS having measured nothing. Every framework here
#      must prove a NON-ZERO case count, from disk AND from the bridge, and
#      the two must agree, before any pass is believed.
#
# Deliberate shell choices (see KNOWN LANDMINES):
#   * `set -eu`, NOT `set -euo pipefail` — /bin/sh on Ubuntu is dash and
#     `-o pipefail` dies with "Illegal option -o pipefail".
#   * Every command inside a loop has its exit status captured EXPLICITLY,
#     because `set -e` does not abort the script for a command whose status
#     is inspected, and people routinely assume it does.
#   * `grep -a` everywhere: the corpus holds synthetic secret-shaped values,
#     and plain grep prints NOTHING on a file it decides is binary.
#   * There is no `|| true`, no `|| :`, no swallowed status on a
#     status-bearing command, no retry-until-green, and no skippable phase.
#
# Usage:
#   tests/e2e/run.sh              build the corpus, then run everything
#   tests/e2e/run.sh --no-build   assert a PRE-BUILT corpus exists, then run
#                                 (for CI that builds in a separate step; the
#                                 artifact assertions still fire)
# =====================================================================
set -eu

E2E_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$E2E_DIR/../.." && pwd)
CHECKS="$E2E_DIR/checks.py"
BASELINE="$E2E_DIR/baseline.json"
BRIDGE="$REPO/pretense_compliance_standards/pretense_bridge/run.mjs"
WORK="$REPO/.e2e-work"

DO_BUILD=1
for arg in "$@"; do
  case "$arg" in
    --no-build) DO_BUILD=0 ;;
    *) echo "[e2e] FAIL E_USAGE: unknown argument '$arg'" >&2; exit 1 ;;
  esac
done

say() { echo "[e2e] $*"; }
die() { echo "" >&2; echo "[e2e] FAIL $1: $2" >&2; echo "" >&2; exit 1; }

# ---------------------------------------------------------------------
# PHASE 0 — preflight. Missing tooling is named, never inferred.
# ---------------------------------------------------------------------
say "PHASE 0 — preflight"
command -v node >/dev/null 2>&1 || die E_NO_NODE "node is not on PATH; the bridge is ESM and needs Node >= 18."
command -v python3 >/dev/null 2>&1 || die E_NO_PYTHON "python3 is not on PATH; the corpus builder is pure stdlib Python >= 3.10."
[ -f "$BRIDGE" ] || die E_NO_BRIDGE "bridge not found at $BRIDGE"
[ -f "$CHECKS" ] || die E_NO_CHECKS "assertion helper not found at $CHECKS"
[ -f "$BASELINE" ] || die E_BASELINE_MISSING "rate baseline not found at $BASELINE; without floors no framework can go red on a regression."

if command -v uv >/dev/null 2>&1; then
  PY="uv run python"; PYTEST="uv run pytest"
else
  PY="python3"; PYTEST="python3 -m pytest"
fi
say "python=$PY  pytest=$PYTEST  node=$(node --version)"

rm -rf "$WORK"
mkdir -p "$WORK"
ROWS="$WORK/rows.tsv"
PYROWS="$WORK/pytest.tsv"
: > "$ROWS"
: > "$PYROWS"

# ---------------------------------------------------------------------
# PHASE 1 — build the corpus FIRST. A failed build is named E_CORPUS_BUILD
# and stops the run. It never degrades into 36 missing-file "failures"
# that look like 36 detector regressions.
# ---------------------------------------------------------------------
if [ "$DO_BUILD" -eq 1 ]; then
  say "PHASE 1 — building the corpus (git-ignored build artifacts)"
  set +e
  ( cd "$REPO" && $PY -m pretense_compliance_standards.corpus_builder ) > "$WORK/build.log" 2>&1
  BUILD_RC=$?
  set -e
  if [ "$BUILD_RC" -ne 0 ]; then
    echo "--- corpus_builder output ---" >&2
    cat "$WORK/build.log" >&2
    echo "-----------------------------" >&2
    die E_CORPUS_BUILD "the corpus builder exited $BUILD_RC. STOPPING. \
Not running the 36-framework loop: every framework would fail on a MISSING FILE, \
which reads like 36 detector regressions and teaches people to ignore this suite."
  fi
  grep -a "Wrote" "$WORK/build.log" | sed 's/^/[e2e]   /'
else
  say "PHASE 1 — SKIPPED (--no-build): asserting a PRE-BUILT corpus instead"
fi

# ---------------------------------------------------------------------
# PHASE 2 — the framework list, then a NON-ZERO case count per framework.
# This is the assertion that converts the false green into a loud failure.
# ---------------------------------------------------------------------
say "PHASE 2 — framework list + NON-ZERO case-count assertion"
set +e
( cd "$REPO" && python3 "$CHECKS" frameworks ) > "$WORK/frameworks.txt" 2>"$WORK/frameworks.err"
RC=$?
set -e
if [ "$RC" -ne 0 ]; then cat "$WORK/frameworks.err" >&2; exit 1; fi

FW_COUNT=$(wc -l < "$WORK/frameworks.txt" | tr -d ' ')
[ "$FW_COUNT" -eq 36 ] || die E_FRAMEWORK_COUNT "expected 36 frameworks, got $FW_COUNT. A shrinking loop is not a passing loop."

set +e
( cd "$REPO" && python3 "$CHECKS" disk-counts "$WORK/counts.tsv" )
RC=$?
set -e
[ "$RC" -eq 0 ] || exit 1

# ---------------------------------------------------------------------
# PHASE 3 — the bridge, once per framework, NAMED, with its exit status
# checked explicitly. A non-zero exit stops the loop and names the
# framework. A zero-case result is a FAILURE (checks.py E_ZERO_CASES).
#
# The engine under test lives in a SEPARATE checkout that other work
# rebuilds. A scanner rebuild mid-loop has been observed to move the
# headline by ~0.5pp, which silently makes the 36 rows non-comparable.
# So the engine and corpus fingerprints are pinned before the loop and
# re-checked after it. Any drift is a FAILURE, never a retry.
# ---------------------------------------------------------------------
fingerprint() {
  ( cd "$REPO" && python3 - "$1" <<'PYEOF'
import hashlib, json, pathlib, subprocess, sys
out = pathlib.Path(sys.argv[1])
doc = json.loads(subprocess.run(
    ["node", "pretense_compliance_standards/pretense_bridge/run.mjs",
     "--framework", "PCI_DSS", "--no-regenerate", "--json"],
    capture_output=True, text=True, check=True).stdout)
sd = pathlib.Path(doc["engine"]["scannerDir"])
parts = {"corpus": pathlib.Path("pretense_compliance_standards/corpus/cases.json")}
parts["scanner"] = sd / "dist" / "index.js"
parts["mutator"] = sd.parent / "mutator" / "dist" / "index.js"
lines = []
for k, p in parts.items():
    if not p.exists():
        print(f"[e2e] FAIL E_ENGINE_MISSING: {k} artifact absent at {p}", file=sys.stderr)
        sys.exit(1)
    lines.append(f"{k}={hashlib.sha256(p.read_bytes()).hexdigest()}")
out.write_text("\n".join(lines) + "\n")
print("[e2e] " + "  ".join(l[:l.index('=') + 17] for l in lines))
PYEOF
  )
}

say "PHASE 3 — pinning engine + corpus fingerprints"
set +e
fingerprint "$WORK/fp-before.txt"
RC=$?
set -e
[ "$RC" -eq 0 ] || exit 1

say "PHASE 3 — bridge: 36 frameworks, each named, exit status checked"
while IFS='	' read -r FW N; do
  [ -n "$FW" ] || continue
  OUT="$WORK/bridge-$FW.json"
  set +e
  ( cd "$REPO" && node "$BRIDGE" --framework "$FW" --no-regenerate --json ) \
      > "$OUT" 2> "$WORK/bridge-$FW.err"
  RC=$?
  set -e
  if [ "$RC" -ne 0 ]; then
    echo "--- bridge stderr for $FW ---" >&2
    cat "$WORK/bridge-$FW.err" >&2
    echo "-----------------------------" >&2
    die E_BRIDGE_EXIT "framework $FW: the bridge exited $RC. STOPPING at $FW — \
the remaining frameworks are NOT reported as passing."
  fi
  set +e
  ( cd "$REPO" && python3 "$CHECKS" bridge-row "$FW" "$OUT" "$N" "$BASELINE" "$ROWS" )
  RC=$?
  set -e
  [ "$RC" -eq 0 ] || exit 1
done < "$WORK/counts.tsv"

ROW_COUNT=$(wc -l < "$ROWS" | tr -d ' ')
[ "$ROW_COUNT" -eq 36 ] || die E_INCOMPLETE_RUN "only $ROW_COUNT of 36 bridge rows were produced."

set +e
fingerprint "$WORK/fp-after.txt"
RC=$?
set -e
[ "$RC" -eq 0 ] || exit 1
if ! cmp -s "$WORK/fp-before.txt" "$WORK/fp-after.txt"; then
  echo "--- before ---" >&2; cat "$WORK/fp-before.txt" >&2
  echo "--- after  ---" >&2; cat "$WORK/fp-after.txt" >&2
  die E_ENGINE_DRIFT "the engine or corpus CHANGED while the 36-framework loop was \
running. The rows above were measured against different builds and are NOT comparable. \
Re-run against a pinned engine. This is deliberately NOT a retry."
fi
say "engine + corpus fingerprints stable across the whole loop"

# ---------------------------------------------------------------------
# PHASE 4 — cross-contamination. HIPAA-scoped must contain zero PCI_DSS
# cases and vice versa, with a LIVE positive control so the assertion
# cannot pass vacuously on an empty corpus.
# ---------------------------------------------------------------------
say "PHASE 4 — cross-contamination assertion (HIPAA <-> PCI_DSS)"
set +e
( cd "$REPO" && python3 "$CHECKS" cross "$WORK/bridge-HIPAA.json" "$WORK/bridge-PCI_DSS.json" )
RC=$?
set -e
[ "$RC" -eq 0 ] || exit 1

# ---------------------------------------------------------------------
# PHASE 5 — pytest, once per framework marker, NAMED. A bad marker exits
# 5 (no tests collected) and is treated as a failure, not a skip.
# ---------------------------------------------------------------------
say "PHASE 5 — pytest: 36 markers, each named, exit status checked"
while IFS='	' read -r FW N; do
  [ -n "$FW" ] || continue
  MARK=$(echo "$FW" | tr '[:upper:]' '[:lower:]')
  set +e
  ( cd "$REPO" && $PYTEST tests/test_pcs.py -m "$MARK" -q ) > "$WORK/pytest-$FW.log" 2>&1
  RC=$?
  set -e
  if [ "$RC" -ne 0 ]; then
    echo "--- pytest output for $FW (-m $MARK) ---" >&2
    tail -40 "$WORK/pytest-$FW.log" >&2
    echo "----------------------------------------" >&2
    die E_PYTEST_EXIT "framework $FW: pytest -m $MARK exited $RC (exit 5 = NO TESTS \
COLLECTED, which is a zero-test false green, not a skip). STOPPING at $FW."
  fi
  PASSED=$(grep -a -o '[0-9]* passed' "$WORK/pytest-$FW.log" | head -1)
  case "$PASSED" in
    ""|"0 passed") die E_PYTEST_ZERO "framework $FW: pytest -m $MARK collected ZERO passing tests but exited 0." ;;
  esac
  printf '%s\t%s\n' "$FW" "$PASSED" >> "$PYROWS"
  say "  $FW pytest -m $MARK -> $PASSED"
done < "$WORK/counts.tsv"

PY_COUNT=$(wc -l < "$PYROWS" | tr -d ' ')
[ "$PY_COUNT" -eq 36 ] || die E_INCOMPLETE_RUN "only $PY_COUNT of 36 pytest markers ran."

# ---------------------------------------------------------------------
# PHASE 6 — the named 36-row table and ONE verdict.
# ---------------------------------------------------------------------
set +e
( cd "$REPO" && python3 "$CHECKS" summary "$ROWS" "$PYROWS" )
RC=$?
set -e
exit "$RC"
