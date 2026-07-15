---
name: ci-triage
description: >-
  Diagnose and fix a failing GitHub Actions run in this repo by learning from the
  workflow RUN HISTORY. Use when a CI check is red, the user reports "Run failed"
  emails, or you need to know whether a failing workflow is owned (fix it) or
  inherited from upstream FinanceDatabase (disable it).
---

# CI triage — learn from the workflow history, then fix

This repo has exactly **three** GitHub Actions workflows. Two are **owned** and must
stay green; one is **inherited from upstream FinanceDatabase** and is disabled.

| Workflow file | Run name | Owned? | Triggers | Must be green? |
|---|---|---|---|---|
| `.github/workflows/testing.yml` | **Run Tests** | owned | push + pull_request | **yes** |
| `.github/workflows/linting.yml` | **General Linting** | owned | push + pull_request | **yes** |
| `.github/workflows/database_update.yml` | **Database Update** | inherited | `workflow_dispatch` only (disabled) | n/a |

## Step 1 — read the history first (this is the "learn from history" step)

Never guess from a single run. Look at the pass/fail **pattern across recent runs**:

```bash
gh run list --limit 20 --json name,event,conclusion,headBranch \
  --jq '.[] | "\(.name) | \(.event) | \(.conclusion)"' | sort | uniq -c | sort -rn
```

Interpret the pattern:
- A workflow that is **red on EVERY run** (never green in history) is broken by design in
  this repo — usually **inherited machinery that needs a secret/resource the fork lacks**.
  → disable it (Step 3b), don't try to make it pass.
- A workflow that is **usually green but red on a specific commit/PR** is a **real
  regression you introduced** → fix the code (Step 3a).
- A workflow **red only on `push` (main) but never on `pull_request`** is triggered by an
  event your PRs don't exercise — check its `on:` block.

## Step 2 — get the exact failing step

```bash
RID=$(gh run list --workflow "<Run name>" --limit 1 --json databaseId --jq '.[0].databaseId')
gh run view "$RID" --log-failed | grep -iE "error|fatal|denied|exit code|Traceback|assert" | head
```
Or open the dashboard visually with the `claude-in-chrome` browser tools:
`https://github.com/<owner>/<repo>/actions` → click the red run → read the failed job's
annotation. (View only — never click **Re-run jobs**, and never touch a repo's
**Settings → Secrets** page.)

## Step 3a — fix an OWNED workflow (Run Tests / General Linting)

Reproduce locally, exactly as CI does, then fix:
```bash
uv run pytest tests/test_pcs.py -q --noconftest    # what "Run Tests" runs
uv run black --check . && uv run ruff check financedatabase   # what "General Linting" runs
```
Fix the code, re-run locally to green, then ship via the [milestone-release](../milestone-release/SKILL.md) flow.

## Step 3b — disable an INHERITED workflow (never re-enable without its secret)

If the failing workflow is upstream FinanceDatabase machinery (its steps `git pull …@JerBouma/FinanceDatabase.git` or need a `PAT`/data source this fork lacks), it has no
role here. **Disable its automatic triggers** instead of deleting it, so it stays for
provenance but never auto-fails:

```yaml
name: <Name>
# DISABLED in this fork — inherited FinanceDatabase machinery; needs upstream <secret>.
on:
  workflow_dispatch:   # manual-only; no push/schedule triggers
```

## Worked example (the case this skill was written from)

`Database Update` failed on **every** push to `main` (Run Tests + General Linting were
green every time). The failed run: `database_update.yml` `on: push` → job
`Add-New-Ticker` → `git pull https://${{secrets.PAT}}@github.com/JerBouma/FinanceDatabase.git main` → **`fatal: Need to specify how to reconcile divergent
branches … exit code 128`** (the fork has diverged from upstream and there is no `PAT`).
All five of its jobs are ticker-database updates irrelevant to this testbed. **Fix:**
set `on: workflow_dispatch:` (as above). Result: no Database Update run fires on
future pushes → no failure → **no more failure emails**.

## About the emails

The "Run failed" emails are GitHub's notifications for **failed Actions runs** — once the
run no longer fails (or no longer fires), the emails stop; that is the root-cause fix. You
**cannot** change the user's account notification settings from the repo. If they also want
to mute Actions emails globally, that lives at github.com → **Settings → Notifications →
Actions** (their account) — tell them; don't attempt it yourself.
