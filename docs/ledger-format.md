# Ledger format and behavior

A gate ledger is a machine-checked completion contract. The checker, linter and Stop hook share one strict parser. Invalid structure fails closed instead of producing a completion certificate.

## Minimal ledger

````markdown
# Gates: account import

OWNS: src/import/**, tests/import/**

Scope: import valid records and reject malformed records

- [ ] G1: valid fixture imports completely
  CHECK: python3 scripts/check_import.py fixtures/valid.json
  EXPECT: import verification passed
  EVIDENCE: pending

- [ ] G2: package-level integration succeeds
  CHECK: python3 ../../scripts/check_package.py
  EXPECT: package verification passed
  CWD: packages/importer
  EVIDENCE: pending

- [ ] G3: migration wording is reviewed against the product decision
  EVIDENCE: pending

ABANDON: G3 decision owner unavailable; handoff recorded in issue 123
````

Lines inside fenced code blocks (backticks or tildes, following CommonMark's fence rules) are ignored, which is why the example above can be documented in a ledger.

## Parsing rules

- Start a gate with `- [ ] ID: outcome` or `- [x] ID: outcome`. The id is required and unique within the file (`[A-Za-z0-9][A-Za-z0-9._-]*`). An id-less gate is an error, because line-derived ids are not stable.
- Indent `CHECK:`, `EXPECT:`, `CWD:` and `EVIDENCE:` beneath their gate. An unindented attribute is diagnosed, not silently reattached or dropped. An attribute with no gate is an orphan error.
- A runnable gate has both `CHECK` and `EXPECT`. A manual gate has neither. Blank values are errors.
- At most one of each attribute per gate.
- `OWNS:` is an optional header before the first gate. Comma-separated, repository-relative globs; absolute paths, `..` traversal and empty paths are errors.
- `ABANDON: <id> <reason>` must start at column 1 and name a gate in the same file. The reason must be non-blank. An indented `ABANDON:` is diagnosed rather than applied; an unknown id is an error.
- A ledger with zero gates is an error, never `ALL MET`.
- Original line endings (LF or CRLF) and the final-newline state are preserved when the checker rewrites a ledger. If a gate has no `EVIDENCE:` line, one is inserted.

## Success and evidence

A runnable gate passes only when both hold:

1. The process starts and exits with status `0`.
2. `EXPECT` matches the command's combined output: all stdout decoded as UTF-8, one newline if both streams are non-empty, then all stderr.

A non-zero exit never passes because its error text contains the marker. A timeout, shell-start failure, missing command, or output overflow also fails. The default timeout is 120 seconds. Each check has a 1 MiB ceiling, applied first to the raw captured bytes and then to the UTF-8 length of the combined string; exceeding either is a failure and the output is never truncated into a match.

On success the checker records automatic evidence:

```
EVIDENCE: automatic-evidence=v1; definition-sha256=<64 hex>; exit=0; EXPECT=matched; output-sha256=<64 hex>; output-bytes=<n>; shell=<path>; cwd=<path>; path=<hash>/<n> entries
```

- `definition-sha256` is a digest of the parsed `CHECK`, `EXPECT` and raw `CWD`. It excludes the gate id and title, formatting, paths, shell, timeout and `PATH`.
- The exit, match, output digest and byte count come immediately after it and are validated. Only the trailing machine-specific transcript is opaque, and the total is capped at 900 characters so truncation cannot remove a deciding field.
- Raw output and the full `PATH` are not persisted.

A checked runnable gate is **met** only when that exact header is present and matches the current definition. Missing, `pending`, prose, malformed or mismatched evidence is `stale-unmet`; a failed re-run clears the box and restores `EVIDENCE: pending`. A checked **manual** gate is met with any human evidence other than `pending`.

The digest is unkeyed. It detects drift in the definition; it does not authenticate a result against someone who can edit the ledger.

### Gate states

| State | Meaning |
| --- | --- |
| `met` | Checked and (runnable) evidence is current, or (manual) has human evidence |
| `unmet` | Not checked |
| `stale-unmet` | Checked runnable gate whose evidence is missing, hand-written, or bound to a different definition |
| `unmet-no-evidence` | Checked manual gate whose evidence is still `pending` |
| `abandoned` | Named by `ABANDON:`; a handoff, never success |

## `--status`, `--reverify`, and approvals

`--status` parses and reports state without executing, resolving a shell, reading the approval store, or writing. The Stop hook uses the same non-executing model. Neither inspects current artifacts.

`--reverify` executes every runnable gate, including already-met ones, and returns any that no longer pass to unmet. Its summary reports how many commands were re-run and how many of those had previously been met.

A normal run executes a gate only if an approval exists for that exact oracle; otherwise it prints the oracle (`CHECK`, `EXPECT`, `CWD`, shell, `PATH`) and does not run it. `--approve` records the approval and then runs it.

Approval identity includes the absolute ledger path and gate id, exact `CHECK` and `EXPECT`, resolved `CWD` and shell, timeout, output and regex limits, platform and the full `PATH`. It is deliberately separate from the evidence digest: approval decides whether this runtime may execute the oracle, the digest decides whether recorded evidence describes the current definition. Approval does not hash scripts or fixtures a command calls.

The store is `~/.gatehouse/approved` (or `GATEHOUSE_APPROVAL_DIR`). It must be a real directory owned by the current user with no group or other permissions, resolve outside the repository root, and hold only single-link private regular files.

## Shell, PATH and working directory

Shell resolution order: `--shell`, then `GATEHOUSE_SHELL`, then `/bin/sh`. A bare name is searched on `PATH`. The command is run as `<shell> -c <CHECK>` in its own process group, inheriting the checker's environment. On timeout or overflow the whole group is killed.

`CWD:` is resolved relative to the default working directory. With `--cwd`, that is the default. Otherwise explicitly named ledgers anchor beside the ledger, and discovered ledgers anchor at `--root`. Keep `CWD:` repository-relative.

## Regular-expression expectations

`EXPECT:` is a plain substring unless it has the form `/pattern/flags`, in which case the last `/` splits pattern from flags and the pattern is matched anywhere in the output. Wrapping slashes always win: `EXPECT: /etc/app/conf/` is the pattern `etc/app/conf`, not that path, so an unescaped inner slash produces a warning.

Patterns use Python `re` syntax with these JavaScript semantics restored:

| Construct | Behavior |
| --- | --- |
| `$` (no `m`) | End of input only, not before a trailing newline |
| `^`, `$` with `m` | Also treat `\r`, U+2028 and U+2029 as line terminators |
| `.` (no `s`) | Excludes `\n`, `\r`, U+2028 and U+2029 |
| `\s`, `\S` | The JavaScript whitespace set (includes NBSP and BOM) |
| `\d`, `\w`, `\b` | ASCII only |
| `(?<n>…)`, `\k<n>` | Translated to Python named groups |

Flags `i`, `m`, `s` are applied; `d`, `g`, `u`, `v`, `y` are accepted and ignored; anything else, or a repeated flag, is a parse error. Patterns longer than 1000 characters are rejected. JS-only syntax (`\p{…}`, `\u{…}`, `[^]`) is a parse error; Python-only inline flags such as `(?i)` are accepted.

Matching runs in a disposable `python -I` subprocess: a 5 s startup limit, then a 250 ms match budget, with at most four running at once. A timeout fails the gate.

## Scopes and discovery

With no file arguments, the checker looks for ledgers in this order:

1. `.gatehouse/<scope>/GATES.md` and `.gatehouse/<scope>/gates/*.md`, when exactly one scope exists, or `--scope` / `GATEHOUSE_SCOPE` names one (several scopes without a selector is an error: it refuses to guess).
2. `GATES.md` and `gates/*.md` at the root.

A scope id matches `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`. A named entry that exists but is unsafe (a link, a FIFO, outside the root) is an error, not an empty pipeline. The Stop hook can pick a scope through a session binding (`--bind`).

Scoped pipelines also read `.gatehouse/<scope>/dispatch.json`. Completion requires every wave to be `complete`; an `open` or `sealed` wave is unmet and an `abandoned` wave is a handoff. Malformed dispatch state is an error. Only reading is implemented.

## Ownership leases

`OWNS:` plus `--claim` / `--release` coordinate concurrent writers. A claim is refused when any of its globs may overlap a held claim; disjointness is proven only when literal path segments disagree, so the check is conservative and may refuse a safe-looking pair. Leases are serialized with a lock and live in `.gatehouse/locks/`. They coordinate cooperating processes and do not restrict what any process can read or write.

## Abandonment

Use `ABANDON:` only when a required outcome is genuinely impossible. Keep the gate, add one non-blank reason, and name the abandonment in the final report. The checker prints `HANDOFF REQUIRED` and exits `1` even if every other gate is met. The Stop hook allows the session to end but emits a bounded handoff message that lists qualified ids and never copies free-form reasons.

## Authoring gates that can fail

The checker validates a declared oracle. It cannot know whether the English title and the shell command mean the same thing.

- **Observe the outcome directly.** Read the artifact or service the title names.
- **Emit a success-only marker** after all assertions pass, and exit non-zero on any failure.
- **Test negative controls.** Before trusting an absence check, run the same logic on a known positive fixture and confirm it fails.
- **Measure supplied numbers independently** rather than copying them into `EXPECT`.
- **Review consequential manual gates** with evidence proportional to risk.
- **Keep evidence decisive.** Successful runs store a fingerprint, not output. For manual gates, record the smallest non-sensitive fact that proves the outcome.

`gatehouse lint` reports the mechanical subset: fixed-output commands (`echo`, `printf`, `true`, `:`, `exit 0`), expectations from vocabulary that failure output shares (`ok`, `done`, `pass`, …), slash-wrapped path-like regexes, titles that name an activity instead of an outcome, unmeasured numbers in manual gates, and mostly manual ledgers. It never executes a `CHECK`. Warnings are advisory and default to exit `0`; `--strict` makes them fail. A ledger can lint itself as a gate:

```markdown
- [ ] G0: this ledger states outcomes that can fail
  CHECK: gatehouse lint GATES.md
  EXPECT: LINT OK
  EVIDENCE: pending
```
