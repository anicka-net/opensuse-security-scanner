# AI Agent Contract

This repository accepts AI agent contributions. Keep the contract lean and
practical: preserve the scanner's behavior, make runs inspectable, and prefer
small changes.

## Read First

Before making substantial changes, read:

1. `AGENTS.md`
2. `scan.py`
3. files directly touched by the task

## Priorities

When goals conflict, follow this order:

1. Correctness
2. Stable CLI behavior
3. Session transparency and reproducibility
4. Task completion
5. Code quality

## Hard Rules

- Do not commit secrets, tokens, or local credentials.
- Do not silently break the CLI or change flag meaning.
- Do not remove or weaken session artifacts without replacing the same visibility.
- Do not overwrite another contributor's in-progress changes.
- Do not claim a scan succeeded if a backend, checkout, or report step failed.

## Stable Interfaces

Treat these as contracts:

- the `scan.py` CLI flags and argument semantics
- the staged scanning model: `triage -> reasoning -> verdict`
- per-run session metadata and stage output layout in scratch space
- final report fields for package, date, and session identity

## Change Discipline

- Prefer small, reviewable changes.
- Keep report output, JSON output, and session metadata aligned.
- If stage handoff behavior changes, update both persistence and tests together.
- For long-running workflows, favor explicit progress and resumable artifacts over hidden state.

## Verification

Minimum expectation for non-trivial changes:

- run targeted tests for the changed behavior
- for scanner flow changes, cover persistence and stage handoff in tests
- if you cannot run the relevant verification, say so explicitly

Baseline test command:

```bash
python3 -m pytest -q tests
```

## Definition of Done

A change is complete when:

- the relevant tests pass, or the exact gap is stated plainly
- CLI behavior remains coherent
- session artifacts remain understandable and useful for debugging
- reports and metadata reflect the current behavior
