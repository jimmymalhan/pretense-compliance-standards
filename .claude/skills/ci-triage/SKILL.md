---
name: ci-triage
description: >-
  Diagnose and fix a failing GitHub Actions run in this repo by learning from the
  workflow RUN HISTORY. Use when a CI check is red, the user reports "Run failed"
  emails, or you need to classify a failing workflow as owned (fix it) or a
  leftover/inherited one (remove or disable it).
---

# CI triage — learn from the workflow history, then fix

This repo has exactly **two** GitHub Actions workflows, both **owned** and both must
stay green:

| Workflow file | Run name | Triggers | What it runs |
|---|---|---|---|
| `.github/workflows/testing.yml` | **Run Tests** | push + pull_request | `pytest tests/test_pcs.py` |
| `.github/workflows/linting.yml` | **General Linting** | push + pull_request | `black --check .` + `ruff check pretense_compliance_standards tests` + markdown-lint |

## Step 1 — read the history first (this is the "learn from history" step)

Never guess from a single run. Look at the pass/fail **pattern across recent runs**:

```bash
gh run list --limit 20 --json name,event,conclusion,headBranch \
  --jq '.[] | "\(.name) | \(.event) | \(.conclusion)"' | sort | uniq -c | sort -rn
```

Interpret the pattern:
- A workflow that is **red on EVERY run** (never green in history) is broken by design —
  usually a **leftover/inherited workflow that needs a secret or resource this repo lacks**.
  → remove it (or disable via `on: workflow_dispatch`), don't try to make it pass (Step 3b).
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
uv run pytest tests/test_pcs.py -q                                  # what "Run Tests" runs
uv run black --check . && uv run ruff check pretense_compliance_standards tests   # "General Linting"
```
Fix the code, re-run locally to green, then ship via the [milestone-release](../milestone-release/SKILL.md) flow.

## Step 3b — remove/disable a LEFTOVER or INHERITED workflow

A workflow that only ever fails because it needs an upstream repo, a `PAT`, or a data
source this repo does not have has no role here. **Delete it** (if it is pure upstream
machinery) or **disable its automatic triggers** if you want to keep it for reference:

```yaml
name: <Name>
# DISABLED — leftover machinery that needs <secret/resource> this repo lacks.
on:
  workflow_dispatch:   # manual-only; no push/schedule triggers
```

## Worked example (historical — the case this skill was written from)

When this repo was still a fork of an upstream project, an inherited **"Database Update"**
workflow (`database_update.yml`) failed on **every** push to `main` while the owned
workflows stayed green. Its `git pull …@<upstream>.git main` step died with
`exit code 128` (divergent branches; no `PAT`), emailing a failure each time. It was
irrelevant to this testbed, so it was first disabled (`on: workflow_dispatch`) and later
**deleted outright** along with the rest of the upstream heritage. Pattern to reuse:
**red-on-every-run + needs-an-upstream-secret ⇒ remove/disable, don't fix.**

## About the emails

The "Run failed" emails are GitHub's notifications for **failed Actions runs** — once the
run no longer fails (or no longer fires), the emails stop; that is the root-cause fix. You
**cannot** change the user's account notification settings from the repo. If they also want
to mute Actions emails globally, that lives at github.com → **Settings → Notifications →
Actions** (their account) — tell them; don't attempt it yourself.
