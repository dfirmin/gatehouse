# Gates: <leaf or task name>

OWNS: <repository-relative globs this leaf may write, for example src/api/**, tests/api/**>

Scope: <one sentence describing the complete deliverable>

- [ ] G1: <observable outcome measured directly from the artifact>
  CHECK: python3 scripts/verify_outcome.py
  EXPECT: outcome verification passed
  EVIDENCE: pending

- [ ] G2: <integration outcome in a subproject>
  CHECK: python3 ../../scripts/verify_integration.py
  EXPECT: integration verification passed
  CWD: packages/example
  EVIDENCE: pending

- [ ] G3: <manual outcome that no command can decide>
  EVIDENCE: pending

<!--
Replace every placeholder before running the checker, then lint it:
  gatehouse lint GATES.md

Strict format:
- Use a unique explicit id for every gate.
- Indent CHECK, EXPECT, CWD, and EVIDENCE.
- Give a runnable gate both CHECK and EXPECT; give a manual gate neither.
- Success requires process exit 0 AND EXPECT matching the combined output.
- Make EXPECT a success-only marker printed after every assertion passes.
- For an absence or negative assertion, run the same check against a known
  positive fixture and record that control in the gate's manual review.
- Measure supplied figures from source. Do not copy a supplied number into
  EXPECT as its own proof.
- OWNS is optional and only for coordinating concurrent leaves (see
  `gatehouse check --claim`). Paths are repository-relative. Claims coordinate
  writers; they do not sandbox.

If a gate becomes genuinely impossible, keep the gate and add, at column 1:

```text
ABANDON: G<n> <non-empty reason and handoff>
```

An abandoned gate is a visible handoff, never a pass.
-->