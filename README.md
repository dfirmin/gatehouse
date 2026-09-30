# gatehouse

[![tests](https://github.com/dfirmin/gatehouse/actions/workflows/tests.yml/badge.svg)](https://github.com/dfirmin/gatehouse/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
[![license](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

**Completion gates for AI-agent work, backed by runnable checks.**

Write the acceptance ledger first. Run reviewed checks. Re-verify returned work. Report only what the evidence supports.

gatehouse gives an agent (or a person) a file of outcomes, each paired with a command that can fail. A gate counts as met only when its command exits `0` **and** its output contains the success marker you declared, and only when the recorded evidence is bound to the exact current definition of that gate. Optional Claude Code Stop hook support keeps an agent from declaring "done" while gates are still open.

It is a standard-library-only Python port of the gate core of [Leonxlnx/unlazy](https://github.com/Leonxlnx/unlazy) (MIT). See [Relationship to unlazy](#relationship-to-unlazy).

## Contents

- [Why](#why)
- [How it works](#how-it-works)
- [Install](#install)
- [Quick start](#quick-start)
- [Ledger format](#ledger-format)
- [CLI reference](#cli-reference)
- [Claude Code Stop hook](#claude-code-stop-hook)
- [Security model](#security-model)
- [Scope and status](#scope-and-status)
- [Relationship to unlazy](#relationship-to-unlazy)
- [Development](#development)
- [License](#license)

## Why

Agents on long tasks tend to stop early, skip parts of a multi-part request, and report success from a subagent's self-description. A written checklist does not fix that by itself, because nothing forces the boxes to mean anything.

gatehouse makes completion testable:

- **Outcomes are declared before the work**, so "done" has a definition that exists independently of the person or agent claiming it.
- **Every runnable gate is a real oracle**: exit status plus an expected marker in the combined output. Printing the marker while failing does not pass.
- **Evidence is bound to the gate definition.** Edit the command, the expectation, or the working directory and the old evidence goes stale instead of silently staying green.
- **A parent can re-run everything** (`--reverify`) rather than trusting a child's report.

What it cannot do: it proves only the command oracle you wrote. A gate titled "invoices reconcile" with `CHECK: echo ok` will pass. The bundled linter flags the mechanical versions of that mistake; judging whether a check really measures the outcome is still your job.

## How it works

```
GATES.md  ──lint──▶  review CHECK lines  ──approve──▶  run  ──▶  evidence written into the ledger
   ▲                                                                       │
   └──────────────  --reverify re-runs every gate, demotes any that fail ◀─┘

Stop hook: blocks "done" while any gate is unmet (reads state only, never executes a check)
```

1. Write gates in a Markdown ledger (`GATES.md`), each with a `CHECK:` command and an `EXPECT:` marker.
2. `gatehouse lint` catches gates that cannot fail honestly. It never executes anything.
3. `gatehouse check --status` shows what is met without running anything.
4. You review the commands, then `gatehouse check --approve` approves each exact command and runs it.
5. On success, the gate is checked and a fingerprint of the output is written next to it. Raw output is not stored.
6. `gatehouse check --reverify` re-runs every runnable gate, including ones already met.

## Install

Requires Python 3.9+ on Linux or macOS. No third-party packages.

```bash
pip install git+https://github.com/dfirmin/gatehouse.git
gatehouse --help
```

Or use it without installing, from a checkout:

```bash
git clone https://github.com/dfirmin/gatehouse.git
python3 gatehouse/scripts/gatehouse.py check --help
```

As a Claude Code skill, clone into the skills directory. The skill instructions are in [SKILL.md](SKILL.md):

```bash
git clone https://github.com/dfirmin/gatehouse.git ~/.claude/skills/gatehouse
```

## Quick start

Create a ledger:

```markdown
# Gates: demo

- [ ] G1: the unit test suite passes
  CHECK: python3 -m unittest discover -s tests
  EXPECT: /^OK$/m
  EVIDENCE: pending

- [ ] G2: release notes read well to a stranger
  EVIDENCE: pending
```

Lint it, inspect it, then approve and run it:

```console
$ gatehouse lint GATES.md
GATES.md
  WARN  G2: no CHECK, so this outcome is judged by hand and its evidence is only as good as the reader  [manual-gate]
LINT OK (1 warning(s))

$ gatehouse check --status GATES.md        # never executes
  UNMET GATES:G1 (unchecked): the unit test suite passes
  UNMET GATES:G2 (unchecked): release notes read well to a stranger

$ gatehouse check GATES.md                 # first run: prints the oracle, does not execute
APPROVAL REQUIRED GATES:G1
    CHECK: python3 -m unittest discover -s tests
    EXPECT: /^OK$/m
    NOT RUN: inspect this oracle, then re-run with --approve

$ gatehouse check --approve GATES.md       # you have read the command; approve and run
  PASS GATES:G1: the unit test suite passes
UNMET: 1 (met: 1)
  GATES:G2
```

`G2` is a manual gate, so it stays open until you record human evidence and tick it:

```markdown
- [x] G2: release notes read well to a stranger
  EVIDENCE: read by a second reviewer, no changes requested
```

```console
$ gatehouse check --reverify GATES.md
ALL MET (2 met, reran: 1, previously met reverified: 1)
```

If you did not install the package, replace `gatehouse` with `python3 scripts/gatehouse.py`. A blank starting ledger is in [templates/GATES.md](templates/GATES.md).

## Ledger format

A gate is a checkbox line with an explicit id, followed by indented attributes:

```markdown
- [ ] G1: <observable outcome>
  CHECK: <shell command>
  EXPECT: <substring, or /regex/flags>
  CWD: <optional directory, relative to the default>
  EVIDENCE: pending
```

Rules worth knowing:

- A runnable gate needs both `CHECK` and `EXPECT`. A manual gate has neither and needs human `EVIDENCE`.
- Success = process exits `0` **and** `EXPECT` matches stdout+stderr combined.
- `ABANDON: <id> <reason>` at column 1 records an impossible gate. It is a handoff, never a pass: the checker exits `1` with `HANDOFF REQUIRED`.
- Malformed ledgers, duplicate ids, unknown `ABANDON` ids, and empty ledgers are errors (exit `2`), not completion.
- Fenced code blocks are ignored, so you can document the format inside a ledger.

The full specification, including evidence binding, regex dialect, and scope discovery, is in [docs/ledger-format.md](docs/ledger-format.md).

## CLI reference

```
gatehouse check   [options] [file ...]     run gates, record evidence, manage scopes and leases
gatehouse lint    [--strict] [--json] FILE audit gate quality; never executes
gatehouse stop-hook                        Claude Code Stop hook (reads the payload on stdin)
```

| `check` option | Meaning |
| --- | --- |
| *(default)* | Run unmet runnable gates that already have an approval; print unapproved oracles without running them |
| `--status` | Report only. Never executes, approves, or writes |
| `--approve` | Approve each exact pending oracle, then run it |
| `--reverify` | Re-run every runnable gate, including met ones; demote any that now fail |
| `--jobs N` | Run independent checks concurrently, 1 to 64 (default 1). Results stay in ledger order |
| `--timeout S` | Per-check timeout in seconds, 1 to 86400 (default 120) |
| `--shell PATH` | Shell used to run `CHECK` (also `GATEHOUSE_SHELL`; default `/bin/sh`) |
| `--cwd DIR` | Default directory for checks |
| `--scope ID`, `--root DIR` | Select a pipeline under `.gatehouse/ID`, and the repository root |
| `--claim`, `--release` | Claim or release the ownership paths (`OWNS:`) of a leaf |
| `--log TEXT`, `--bind SESSION`, `--list-scopes` | Append a status line, bind a session to a scope, list pipelines |

Exit codes: `0` all met (or action succeeded), `1` unmet or handoff required, `2` usage / parse / infrastructure error, `3` lease conflict. `lint` uses `0` no strict failures, `1` strict findings, `2` usage or parse error.

## Claude Code Stop hook

The hook blocks the agent from stopping while gates remain unmet. It reads ledger and dispatch state only. It **never executes a `CHECK`**, and it releases after six consecutive blocks with no change in resolved gate state, so it cannot wedge a session.

Add it to `.claude/settings.local.json` (personal, keep it untracked):

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 /absolute/path/to/gatehouse/scripts/gatehouse.py stop-hook",
            "timeout": 20
          }
        ]
      }
    ]
  }
}
```

If you installed the package, `"command": "gatehouse stop-hook"` works too. Use `stop-hook --scope <id>` to pin a pipeline. Keep `.gatehouse/`, `.gatehouse-hook-state.json` and `gatehouse-status.log` in your ignore rules. The hook only observes state: the agent still has to run `gatehouse check` to make progress. There is no automatic installer yet, so back up any existing settings file before editing it.

## Security model

**`CHECK:` lines are shell code.** They run with your user's permissions, environment, credentials, and network access. gatehouse's boundary is explicit review and approval, not sandboxing.

- **`--status` and the Stop hook never execute a check.** Use `--status` to inspect an inherited ledger, and read every `CHECK` and any script it calls before approving.
- **Approval is per exact oracle.** It binds the ledger path, gate id, `CHECK`, `EXPECT`, resolved `CWD` and shell, timeout, limits, platform, and the full `PATH`. Change any of them and approval is required again.
- **Approval is consent, not proof.** It does not hash files a command calls, so a changed script can run under an old approval. Re-inspect dependencies and run `--reverify`.
- **The approval store must be private and outside the repo.** Default `~/.gatehouse/approved` (override with `GATEHOUSE_APPROVAL_DIR`); it must be owned by you, mode `0700`, and not symlinked. Otherwise the run is refused.
- **Evidence is not tamper-proof.** The definition digest detects drift, not forgery: anyone who can edit the ledger can write a valid-looking header.
- **Regexes run in a disposable process** with a 250 ms budget, so a catastrophic pattern fails the gate instead of hanging the checker.
- **Ledgers and state files are read defensively**: no symlinks, FIFOs, hard links, or oversized files; state writes are atomic.
- **Scopes and leases are coordination, not isolation.** They do not restrict what a process can read or write.

Use a disposable environment for ledgers you do not trust. See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Scope and status

This is the core of unlazy, ported to Python. It is early (`0.1.0`).

| Area | Status |
| --- | --- |
| Ledger parser and evidence model | Ported |
| `check`: run, `--status`, `--approve`, `--reverify`, `--jobs`, `--timeout`, `--shell`, `--cwd` | Ported |
| Scopes, `--claim` / `--release`, `--log`, `--bind`, `--list-scopes` | Ported |
| `lint` | Ported |
| Stop hook | Ported |
| Reading dispatch-wave state (blocks completion while a wave is open) | Ported, read-only |
| Dispatch-wave recorder (`dispatch-check`) | Not yet |
| Hook installer | Not yet (manual snippet above) |
| Depth Tree method, PLAN and branch templates, orchestration docs | Not yet, see upstream |
| Windows | Not supported (POSIX-first; Windows-specific hardening is intentionally not ported) |

## Relationship to unlazy

gatehouse is a derivative of [Leonxlnx/unlazy](https://github.com/Leonxlnx/unlazy), used under its MIT license. The ledger format, gate semantics, evidence model, approval model, and Stop-hook behavior follow it. Credit for the design, including the Depth Tree method that this port does not yet include, belongs to its author.

Differences you should know about:

- **Names:** state lives in `.gatehouse/`, approvals in `~/.gatehouse/approved`, environment variables are `GATEHOUSE_*`.
- **Evidence is not interchangeable.** The definition digest uses a different domain tag, so automatic evidence written by unlazy reads as stale here, and the other way round. The ledger text itself is compatible.
- **Regex dialect:** `EXPECT: /pattern/flags` uses Python `re` syntax with JavaScript semantics restored for `$`, `^` (with `m`), `.`, `\s`, `\d`, `\w`, and named groups (`(?<n>…)`, `\k<n>`). JS-only syntax such as `\p{…}`, `\u{…}` and `[^]` is a parse error. Python-only inline syntax such as `(?i)` is accepted.

To check the port against the original, `tests/crosscheck_unlazy.py` feeds identical ledgers to both implementations and compares parse results, status output, and regex verdicts. On the current source it compared 179 ledgers and 47 regex expectations with no differences. That is evidence of behavioral agreement on those inputs, not a proof of equivalence.

## Development

```bash
git clone https://github.com/dfirmin/gatehouse.git && cd gatehouse
python3 -m unittest discover -s tests -v          # ~110 tests, standard library only

# optional: compare against the original Node implementation (needs Node 16+)
git clone https://github.com/Leonxlnx/unlazy.git /tmp/unlazy
UNLAZY_REPO=/tmp/unlazy python3 tests/crosscheck_unlazy.py
```

Layout:

```
src/gatehouse/gates.py       ledger parser, evidence model, scopes, safe file I/O, locks, leases
src/gatehouse/check.py       the checker (approval, execution, evidence writing)
src/gatehouse/lint.py        ledger linter
src/gatehouse/stop_hook.py   Claude Code Stop hook
src/gatehouse/dispatch.py    read-only dispatch-wave state
scripts/gatehouse.py         run from a checkout or skill folder without installing
templates/GATES.md           starter ledger
docs/ledger-format.md        full format and behavior specification
SKILL.md                     agent instructions
```

Issues and pull requests are welcome. Behavior changes need a test; changes to the parser or evidence model should also keep the cross-check clean.

## License

[MIT](LICENSE). Copyright (c) 2026 Leonxlnx (unlazy) and dfirmin (gatehouse).
