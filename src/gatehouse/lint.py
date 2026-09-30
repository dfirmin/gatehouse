"""gatehouse lint: audit whether a ledger is worth passing.

The checker and the Stop hook decide whether gates were met. Neither asks
whether the gates were worth meeting. A gate reading "the entire feature works
perfectly" with `CHECK: echo ok` and `EXPECT: ok` passes both, because the
oracle is real, runs, and returns what it promised. This reads the ledger and
judges its oracles; it never executes a CHECK.

    gatehouse lint [--strict] [--json] <ledger.md ...>

Exit codes: 0 no strict failures, 1 strict findings, 2 usage or parse error.

Usable as a gate, so a ledger can require its own quality:
    CHECK: gatehouse lint GATES.md
    EXPECT: LINT OK
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any, Dict, List, Optional

from . import gates as G

HELP = """usage: gatehouse lint [--strict] [--json] <ledger.md ...>

Audit gate quality, not gate completion. Report lexical signs of fixed-output
oracles, weak expectations, manual measurements, and titles that name an
activity instead of an outcome. Never executes a CHECK.

exit codes: 0 no strict failures, 1 strict findings, 2 usage or parse error."""

KNOWN_OPTIONS = {"--strict", "--json", "--help", "-h"}
MAX_GATE_LEDGER_BYTES = 8 * 1024 * 1024
MAX_REPORTED_FINDINGS = 64
MAX_REPORT_BYTES = 256 * 1024
TRUNCATION_MARKER = "...[truncated]"

# Advisory and whole-command only. Shell text beginning with `echo` can still
# chain a real verifier, and argv containing EXPECT says nothing about what the
# called program prints or whether it exits zero.
FIXED_OUTPUT_COMMAND = re.compile(
    r"^\s*(?:(?:echo|printf)(?:\s+[^&|;]*)?|true|:|exit\s+0)\s*\Z", re.IGNORECASE)
# Tokens that appear in failure output as readily as in success output.
WEAK_EXPECT = {
    "ok", "okay", "done", "pass", "passed", "success", "successful", "succeeded",
    "complete", "completed", "finished", "yes", "true", "0", "good", "fine", "working",
}
# Openings that name an activity rather than an outcome a stranger could judge.
ACTIVITY_START = re.compile(
    r"^(work(ing)? on|improve|enhance|handle|support|ensure|make sure|try|attempt|look (at|into)|"
    r"investigate|consider|review|refactor|clean ?up|polish|update|tidy|address|deal with|add support)\b",
    re.IGNORECASE)
_TERMINAL_CONTROL = re.compile("[\u0000-\u001f\u007f-\u009f؜‎‏ -‮⁦-⁩]")


def _escape(value: Any, max_bytes: int = 1024) -> str:
    """Escape terminal controls at data boundaries, capping the encoded size."""
    pieces: List[str] = []
    sizes: List[int] = []
    total = 0
    truncated = False
    for char in str(value):
        piece = char
        if _TERMINAL_CONTROL.match(char):
            code = ord(char)
            piece = ("\\x%02x" % code) if code <= 0xFF else ("\\u%04x" % code)
        size = len(piece.encode("utf-8", "replace"))
        if total + size > max_bytes:
            truncated = True
            break
        pieces.append(piece)
        sizes.append(size)
        total += size
    if not truncated:
        return "".join(pieces)
    marker = len(TRUNCATION_MARKER.encode("utf-8"))
    while pieces and total + marker > max_bytes:
        pieces.pop()
        total -= sizes.pop()
    return "".join(pieces) + TRUNCATION_MARKER


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        sys.stderr.write(HELP + "\n")
        return 2
    # `--` makes every following token a filename, including literal files named
    # `--help` and `-h`. Only scan the option prefix for the help flags.
    prefix = args[:args.index("--")] if "--" in args else args
    if "--help" in prefix or "-h" in prefix:
        print(HELP)
        return 0

    strict = False
    as_json = False
    positional = False
    files: List[str] = []
    for arg in args:
        if not positional and arg == "--":
            positional = True
            continue
        if not positional and arg in KNOWN_OPTIONS:
            if arg == "--strict":
                strict = True
            elif arg == "--json":
                as_json = True
            continue
        if not positional and arg.startswith("-"):
            sys.stderr.write(f"gatehouse lint: unknown option {_escape(arg, 512)}\n")
            sys.stderr.write("run gatehouse lint --help for usage\n")
            return 2
        files.append(arg)
    if not files:
        sys.stderr.write("gatehouse lint: name at least one ledger file\n")
        return 2

    findings: List[Dict[str, Optional[str]]] = []
    counts = {"error": 0, "warn": 0, "all": 0}

    def add(file: str, level: str, gate: Optional[str], rule: str, message: str) -> None:
        counts["all"] += 1
        if level == "error":
            counts["error"] += 1
        elif level == "warn":
            counts["warn"] += 1
        if len(findings) >= MAX_REPORTED_FINDINGS:
            return
        findings.append({
            "file": _escape(file, 512), "level": _escape(level, 16),
            "gate": _escape(gate, 128) if gate else None,
            "rule": _escape(rule, 64), "message": _escape(message, 1024),
        })

    parse_failed = False
    for file in files:
        try:
            # Explicit lint targets may intentionally live outside the current
            # working directory, so constrain file kind and size without a root.
            text = G.read_stable_regular_file(file, max_bytes=MAX_GATE_LEDGER_BYTES, label="gate ledger")
        except (OSError, G.GateFileError) as error:
            sys.stderr.write(f"gatehouse lint: cannot read {_escape(file, 512)}: {_escape(error, 1024)}\n")
            return 2

        doc = G.parse_gates(text)
        if doc.errors:
            # A ledger the shared parser rejects cannot be judged on quality.
            parse_failed = True
            for error in doc.errors:
                add(file, "error", None, "parse", error)
            continue

        live = [g for g in doc.gates if g.id not in doc.abandoned]
        runnable = [g for g in live if g.check]
        for gate in live:
            if gate.check and FIXED_OUTPUT_COMMAND.match(gate.check):
                add(file, "warn", gate.id, "tautological-check",
                    f'CHECK looks like a fixed-output command: "{gate.check}"; '
                    "use an oracle that observes the named outcome")
            if gate.expect and gate.expect.strip().lower() in WEAK_EXPECT:
                add(file, "warn", gate.id, "weak-expect",
                    f'EXPECT "{gate.expect}" also appears in failure output; '
                    "match a line only success can print")
            expectation = gate.expectation
            if expectation and expectation.get("kind") == "regex" and expectation.get("pathLike"):
                add(file, "warn", gate.id, "path-read-as-regex",
                    f'EXPECT "{gate.expect}" looks like a literal path but is read as a regular '
                    "expression, so its dots are wildcards")
            if not gate.check:
                add(file, "warn", gate.id, "manual-gate",
                    "no CHECK, so this outcome is judged by hand and its evidence is only as good as the reader")
                if re.search(r"\d", gate.title):
                    add(file, "warn", gate.id, "unmeasured-number",
                        f'title states a number that nothing measures: "{gate.title}"')
            if ACTIVITY_START.match(gate.title):
                add(file, "warn", gate.id, "activity-not-outcome",
                    f'names an activity, not an outcome a stranger could judge: "{gate.title}"')

        if live and len(runnable) / len(live) < 0.5:
            add(file, "warn", None, "mostly-manual",
                f"{len(runnable)}/{len(live)} gates are runnable; a mostly manual ledger is prose with checkboxes")

    failed = counts["error"] > 0 or (strict and counts["warn"] > 0)

    if as_json:
        report: Dict[str, Any] = {
            "ok": not failed, "errors": counts["error"], "warnings": counts["warn"],
            "findings": list(findings), "truncated": counts["all"] > len(findings),
            "omittedFindings": counts["all"] - len(findings),
        }
        output = json.dumps(report, indent=2, ensure_ascii=False)
        while len(output.encode("utf-8")) > MAX_REPORT_BYTES and report["findings"]:
            report["findings"].pop()
            report["truncated"] = True
            report["omittedFindings"] = counts["all"] - len(report["findings"])
            output = json.dumps(report, indent=2, ensure_ascii=False)
        print(output)
    else:
        last_file = None
        for finding in findings:
            if finding["file"] != last_file:
                print(finding["file"])
                last_file = finding["file"]
            label = "ERROR" if finding["level"] == "error" else "WARN "
            who = f"{finding['gate']}: " if finding["gate"] else ""
            print(f"  {label} {who}{finding['message']}  [{finding['rule']}]")
        omitted = counts["all"] - len(findings)
        if omitted:
            print(f"... [report truncated: {omitted} finding(s) omitted]")
        if not failed:
            print(f"LINT OK ({counts['warn']} warning(s))" if counts["warn"] else "LINT OK")
        else:
            print(f"LINT FINDINGS: {counts['error']} error(s), {counts['warn']} warning(s)")
    sys.stdout.flush()
    return 2 if parse_failed else 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
