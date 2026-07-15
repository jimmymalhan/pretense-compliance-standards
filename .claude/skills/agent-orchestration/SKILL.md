---
name: agent-orchestration
description: >-
  How AI agents coordinate with other AI agents in this repo — when to fan out
  read-only explorers, run the Workflow-backed multi-agent code review, spawn
  adversarial probes, isolate parallel work in worktrees, and continue a specific
  agent. Use when a task is broad, uncertain, or safety-critical enough that one
  agent working alone would be slower or less trustworthy than several.
---

# Agent-to-agent coordination (how work is delegated here)

One agent reads and writes in a single line of reasoning. That is the right shape for
most edits. It is the wrong shape when the task is **broad** (many files to understand
at once), **uncertain** (the answer needs independent confirmation), or **larger than
one context can hold**. Then the move is to **delegate to other agents** and keep only
their conclusions. Every milestone in this repo was shipped this way; the patterns below
are the ones that actually paid off, with real examples.

The golden rule: **a delegating agent owns the result, not the transcript.** You spawn
an agent to do the reading/searching/verifying, and you keep the one-paragraph answer —
never the file dumps. And you **verify before acting** on what an agent returns: agents
are confident even when wrong.

## When to spawn vs. do it yourself

| Situation | Do it yourself | Delegate to agent(s) |
|-----------|----------------|----------------------|
| Known file, single fact | ✅ read it | ❌ |
| "Where/how is X done across the codebase?" | ❌ | ✅ fan out `Explore` |
| Designing a non-trivial change | ❌ | ✅ `Plan` agent(s) |
| Confirming a fix is correct | risky alone | ✅ adversarial verify |
| Many independent edits in parallel | serial + slow | ✅ worktree-isolated agents |

If you can answer from a file/symbol you already know, just do it. Delegation has setup
cost; spend it only when breadth, confidence, or scale justifies it.

## Pattern 1 — Fan out read-only explorers (breadth)

For "understand the shape of this before I change it," launch `Explore` agents **in
parallel** (one message, multiple tool calls) with **non-overlapping** focuses, and keep
each agent's conclusion, not its excerpts. Example from M10: before adding data kinds,
one explorer mapped the 44 existing kinds by group, another traced the exact 4-place
add-a-kind pattern (`detector.py` regex + call-site, `compliance.py` group,
`regulated/setNN.py` synthetic data, `negatives.py` benign look-alike), a third confirmed
the hardened-detection invariant. Result: the plan was written from three conclusions,
not from re-reading the whole package.

Give each explorer a **specific** brief ("find every place a new `kind` must be
registered") and a breadth hint ("medium" vs "very thorough"). Explorers are read-only —
they locate and summarize, they do not edit.

## Pattern 2 — The Workflow-backed code review (confidence)

The review gate (`/code-review`, run before **every** merge here) is itself a multi-agent
program: independent **finder** agents each take one angle (correctness, collisions,
provably-fake values, taxonomy), then an independent **verifier** agent adversarially
re-checks every candidate finding before it is reported. Finders and verifiers are
separate agents on purpose — the one who found a bug is the worst judge of whether it is
real.

This has caught real defects every milestone: a 95-second CPU-DoS in the decoder (M2), an
unwinnable regex denylist (M1), `re.IGNORECASE` false positives (M3), a tautology test and
a 64 KB seed truncation false-fail (M9), and in M10 four label-gated false-negatives
(grouped `imsi`/`imei`/`nhs` formats the single canonical corpus case never exercised,
plus a zero-width label-gluing gap).
**Fix every confirmed finding before merging.** See [milestone-release](../milestone-release/SKILL.md).

## Pattern 3 — Adversarial probe (break your own fix)

After a risky fix, spawn one focused agent whose whole job is to **refute** it: feed it
hostile inputs and ask "show me where this still fails." In M10 an independent probe fed
the new detectors slash/dot-grouped and zero-width-glued inputs; it confirmed the
separator fixes and surfaced the zero-width label-gluing tradeoff as a documented known
gap rather than a silent one. A probe that tries to break the fix is worth more than three
that agree it looks fine — for verification, prefer **diverse skeptics over redundant
confirmers**.

## Pattern 4 — Worktree-isolated parallel work (scale)

When several edits are genuinely independent, spawn one agent per unit with
**`isolation: worktree`** so they mutate files without colliding, and run them in the
background. Each unit must be independently implementable and mergeable — no shared state,
no "must land first" ordering. Worktrees cost real setup time and disk, so use them only
when agents write in parallel; for read-only fan-out (Pattern 1) they are wasteful.

## Pattern 5 — Continue a specific agent (context reuse)

A fresh agent starts blank. To keep going with an agent that already has the context, send
it a follow-up message instead of re-spawning and re-explaining. Re-brief a new agent only
when you want a **fresh, unbiased** perspective (e.g. a second-opinion reviewer that must
not inherit the first one's assumptions).

## Anti-patterns

- **Delegating a single-fact lookup.** If you know the file and symbol, read it — do not
  pay agent-setup cost for one grep.
- **Acting on an unverified finding.** An agent said a line is a bug? Confirm it against
  the code before you edit. This repo's reviews report `CONFIRMED` vs `PLAUSIBLE` for
  exactly this reason.
- **Redundant confirmers.** Five agents asked "is this right?" mostly agree with each
  other. One asked "prove this is wrong" earns its cost.
- **Keeping the transcript.** Relay the conclusion to the user; the tool output was for
  you, and dumping it back defeats the point of delegating.
- **Overlapping explorers.** Two agents told to "look at the detector" do the same work
  twice. Partition the search space.

## Fit with this repo's process

Orchestration serves the milestone cadence in [milestone-release](../milestone-release/SKILL.md),
it does not replace it: explorers and `Plan` agents inform the **plan**, the Workflow
review is the **review gate**, probes harden **risky fixes** — but it is still one
reviewed PR at a time, with all four CI checks green, and [ci-triage](../ci-triage/SKILL.md)
if a check goes red.
