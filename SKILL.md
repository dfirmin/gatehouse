---
name: gatehouse
description: Use for multi-part or long-running work where "done" must be provable. Write a GATES.md acceptance ledger of outcomes with runnable CHECK/EXPECT oracles, lint it, run gatehouse check, re-verify returned subagent work, and report only what the evidence supports.
---

# gatehouse

Completion gates backed by runnable checks. Run the CLI as `gatehouse` if installed, otherwise
`python3 <skill-dir>/scripts/gatehouse.py`. Full format: `docs/ledger-format.md`.

## Workflow

1. **Write the ledger before the work.** Copy `templates/GATES.md` to `GATES.md` (or
   `.gatehouse/<scope>/GATES.md`). One gate per observable outcome, each with a unique id.
2. **Make checks able to fail.** `CHECK:` measures the artifact directly and exits non-zero on failure;
   `EXPECT:` is a success-only marker printed after all assertions. No `echo ok`. Manual gates
   (no CHECK/EXPECT) only for outcomes no command can decide, with real evidence.
3. **Lint:** `gatehouse lint GATES.md` (add `--strict` to fail on warnings).
4. **Do the work.** Then `gatehouse check --status` to see state without running anything.
5. **Run:** `gatehouse check GATES.md`. An unapproved oracle is printed, not run. Read the CHECK and
   anything it calls; only then `gatehouse check --approve GATES.md`.
6. **Never hand-write evidence for runnable gates or tick their boxes.** The checker does that.
7. **Parents re-verify children:** `gatehouse check --reverify` before accepting a subagent's report.
8. **Impossible gate:** keep it, add `ABANDON: <id> <reason>` at column 1, and say so in the report.
   It is a handoff, never a pass.
9. **Report** only what the final `ALL MET` / `UNMET` / `HANDOFF REQUIRED` output supports.

## Rules

- CHECK lines are shell code. Never approve a ledger you have not read.
- Exit codes: 0 met, 1 unmet, 2 usage/parse error, 3 lease conflict.
- The Stop hook blocks stopping while gates are unmet; make progress via `gatehouse check`, do not
  try to bypass it.
