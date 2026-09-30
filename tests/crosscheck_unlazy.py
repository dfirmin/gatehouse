#!/usr/bin/env python3
"""Differential check of gatehouse against the original Node implementation (Leonxlnx/unlazy).

Not part of the default test run. Requires Node 16+ and a checkout of upstream:

    UNLAZY_REPO=/path/to/unlazy python3 tests/crosscheck_unlazy.py

It feeds identical ledgers to both implementations and compares:
  1. parse results, via `lint --json` (errors, warnings, finding rules and messages)
  2. `check --status` output and exit code
  3. PASS/FAIL of runnable gates whose EXPECT is a regular expression
Known, documented differences (regex engine error text) are normalized.
"""

import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.abspath(os.path.join(HERE, "..", "src"))
UNLAZY = os.environ.get("UNLAZY_REPO")
if not UNLAZY or not os.path.isdir(os.path.join(UNLAZY, "scripts")):
    sys.exit("set UNLAZY_REPO to a checkout of Leonxlnx/unlazy")
NODE = shutil.which("node") or sys.exit("node not found")

SEED = """# Gates: seed

OWNS: src/**, tests/**

Scope: something

- [ ] G1: outcome one
  CHECK: python3 verify.py
  EXPECT: verified one
  EVIDENCE: pending

- [x] G2: reviewed by hand
  EVIDENCE: read the diff

- [ ] G3: improve the parser
  CHECK: echo ok
  EXPECT: ok
  CWD: sub
  EVIDENCE: pending

```
- [ ] G9: fenced example
  CHECK: rm -rf /
```

ABANDON: G3 impossible here
"""

HANDWRITTEN = [
    SEED,
    "",
    "# only heading\n",
    "- [ ] G1: a\r\n  CHECK: true\r\n  EXPECT: ok\r\n  EVIDENCE: pending\r\n",
    "- [ ] no id\n",
    "- [ ] G1: a\n- [ ] G1: b\n",
    "- [ ] G1:\n",
    "- [ ] G1: a\nCHECK: true\nEXPECT: ok\n",
    "- [ ] G1: a\n  ABANDON: G1 x\n",
    "- [ ] G1: a\nABANDON: G1\nABANDON: G2 nope\n",
    "OWNS: /abs\nOWNS: ../up\nOWNS:\n- [ ] G1: a\n",
    "- [ ] G1: a\nOWNS: late\n",
    "- [ ] G1: a\n  CHECK: true\n",
    "- [ ] G1: a\n  CHECK:\n  EXPECT: x\n",
    "- [ ] G1: a\n  CHECK: true\n  EXPECT: /a/b/c/\n",
    "- [ ] G1: a\n  CHECK: true\n  EXPECT: /etc/app/conf/\n",
    "- [ ] G1: a\n  CHECK: true\n  EXPECT: /\\/etc\\/app/\n",
    "- [ ] G1: a\n  EVIDENCE: x\n  EVIDENCE: y\n",
    "  CHECK: orphan\n- [ ] G1: a\n",
    "```\n- [ ] G1: a\n",
    "````\n```\n````\n- [ ] G1: a\n",
    "- [X] G1: upper x\n  EVIDENCE: ok\n",
    "- [ ] G-1.x_y: odd but valid id\n",
    "- [ ] bad id!: title\n",
    "- [ ] G1: 95 percent coverage\n  EVIDENCE: pending\n",
    "- [ ] G1: ensure it works\n  CHECK: printf done\n  EXPECT: done\n",
    "- [ ] G1: a\n  CHECK: exit 0\n  EXPECT: PASS\n",
    "- [ ] G1: a\n  CHECK: python3 v.py\n  EXPECT: /a|b/i\n",
    "- [ ] G1: a\n  CHECK: python3 v.py\n  EXPECT: /" + "x" * 1001 + "/\n",
]

MUTATIONS = [
    lambda lines, r: lines.insert(r.randrange(len(lines) + 1), r.choice(
        ["- [ ] G7: injected", "  CHECK: true", "  EXPECT: ok", "CHECK: unindented", "ABANDON: G1 reason",
         "ABANDON: G7", "OWNS: a/b", "```", "  EVIDENCE: pending", "", "# heading", "  ABANDON: G1 x",
         "- [x] G1: dup", "  CWD: sub", "~~~", "   ```", "- [ ] G8: t"])),
    lambda lines, r: lines.pop(r.randrange(len(lines))) if lines else None,
    lambda lines, r: lines.__setitem__(r.randrange(len(lines)), lines[r.randrange(len(lines))]) if lines else None,
]


def fuzz_cases(n, seed=1234):
    rng = random.Random(seed)
    cases = []
    base = SEED.split("\n")
    for _ in range(n):
        lines = list(base)
        for _ in range(rng.randint(1, 4)):
            rng.choice(MUTATIONS)(lines, rng)
        cases.append("\n".join(lines))
    return cases


def run_js(script, args, cwd, env=None):
    e = os.environ.copy()
    e.update(env or {})
    return subprocess.run([NODE, os.path.join(UNLAZY, "scripts", script), *args], cwd=cwd, env=e,
                          capture_output=True, text=True, timeout=120)


def run_py(args, cwd, env=None):
    e = os.environ.copy()
    e["PYTHONPATH"] = SRC
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "gatehouse", *args], cwd=cwd, env=e,
                          capture_output=True, text=True, timeout=120)


def norm_message(text):
    text = re.sub(r"invalid EXPECT regex: .*", "invalid EXPECT regex: <engine text>", text)
    return text.replace("unlazy", "gatehouse").replace(".unlazy", ".gatehouse")


def norm_lint(proc):
    try:
        report = json.loads(proc.stdout)
    except ValueError:
        return {"raw": proc.stdout, "code": proc.returncode}
    findings = sorted((f["rule"], f["gate"] or "", norm_message(f["message"])) for f in report["findings"])
    return {"ok": report["ok"], "errors": report["errors"], "warnings": report["warnings"],
            "findings": findings, "code": proc.returncode}


def norm_status(proc):
    lines = [norm_message(line) for line in proc.stdout.splitlines()]
    return {"code": proc.returncode, "stdout": lines,
            "stderr_errors": sorted(norm_message(re.sub(r"^(gate-check|gatehouse check): ", "", ln))
                                    for ln in proc.stderr.splitlines()
                                    if "error" in ln or "line " in ln)}


# Patterns where both engines should agree. (output, EXPECT)
REGEX_CASES = [
    ("build 42 passed", r"/build \d+ passed/"),
    ("Build 42 Passed", r"/build \d+ passed/i"),
    ("Build 42 Passed", r"/build \d+ passed/"),
    ("a\nb", r"/^b$/m"),
    ("a\nb", r"/^b$/"),
    ("a\nb", r"/a.b/s"),
    ("a\nb", r"/a.b/"),
    ("v1.2.3", r"/v(\d+)\.(\d+)\.(\d+)/"),
    ("abcabc", r"/(abc)\1/"),
    ("2026-09-30", r"/(?<y>\d{4})-(?<m>\d{2})-(?<d>\d{2})/"),
    ("aa-aa", r"/(?<x>a+)-\k<x>/"),
    ("foobar", r"/foo(?=bar)/"),
    ("foobaz", r"/foo(?=bar)/"),
    ("foobar", r"/(?<=foo)bar/"),
    ("tokens: alpha beta", r"/\balpha\b/"),
    ("x", r"/^$/"),
    ("ok\n", r"/ok$/"),
    ("hello world", r"/hello|nothere/"),
    ("hello world", r"/^hello$/"),
    ("café", r"/caf./"),
    ("tab\there", r"/tab\there/"),
    ("count=007", r"/count=0+7/"),
    ("PATH=/usr/bin", r"/PATH=\/usr\/bin/"),
    ("a.b", r"/a\.b/"),
    ("axb", r"/a\.b/"),
    ("x", r"/[[:alpha:]]/"),
    ("digits 12", r"/\d{2}/"),
    ("٣٤", r"/\d\d/"),
    ("word_1", r"/^\w+$/"),
    ("ok\n", r"/ok$/m"),
    ("x\r\ny", r"/x$/m"),
    ("x\r\ny", r"/^y/m"),
    ("x\r\ny", r"/x$/"),
    ("a\rb", r"/a.b/"),
    ("a\rb", r"/a.b/s"),
    ("a b", r"/a\sb/"),
    ("a b", r"/a[\s]b/"),
    ("a b", r"/a\Sb/"),
    ("line1\nline2", r"/line1$/"),
    ("line1\nline2", r"/^line2$/m"),
    ("cost $5", r"/\$5/"),
    ("cost $5", r"/cost \$/"),
    ("a$b", r"/a[$]b/"),
    ("a.b", r"/a[.]b/"),
    ("axb", r"/a[.]b/"),
    ("ab", r"/a$b/"),
    ("", r"/^$/"),
]


def main():
    failures = 0
    tmp = tempfile.mkdtemp()
    try:
        cases = HANDWRITTEN + fuzz_cases(150)
        print(f"comparing {len(cases)} ledgers (lint --json and check --status)")
        for index, text in enumerate(cases):
            work = os.path.join(tmp, f"case{index}")
            os.makedirs(os.path.join(work, "sub"))
            path = os.path.join(work, "GATES.md")
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(text)
            js_lint = norm_lint(run_js("gate-lint.mjs", ["--json", "GATES.md"], work))
            py_lint = norm_lint(run_py(["lint", "--json", "GATES.md"], work))
            if js_lint != py_lint:
                failures += 1
                print(f"\nLINT MISMATCH case {index}:\n--- ledger\n{text}\n--- js\n{js_lint}\n--- py\n{py_lint}")
                continue
            js_status = norm_status(run_js("gate-check.mjs", ["--status", "GATES.md"], work,
                                           {"UNLAZY_APPROVAL_DIR": os.path.join(tmp, "a-js")}))
            py_status = norm_status(run_py(["check", "--status", "GATES.md"], work,
                                           {"GATEHOUSE_APPROVAL_DIR": os.path.join(tmp, "a-py")}))
            if js_status != py_status:
                failures += 1
                print(f"\nSTATUS MISMATCH case {index}:\n--- ledger\n{text}\n--- js\n{js_status}\n--- py\n{py_status}")

        print(f"comparing {len(REGEX_CASES)} regex expectations (run with approval)")
        work = os.path.join(tmp, "regex")
        os.makedirs(work)
        gates = []
        for i, (output, expect) in enumerate(REGEX_CASES):
            with open(os.path.join(work, f"out{i}.txt"), "w", encoding="utf-8", newline="") as handle:
                handle.write(output)
            gates.append(f"- [ ] R{i}: case {i}\n  CHECK: cat out{i}.txt\n  EXPECT: {expect}\n  EVIDENCE: pending\n")
        with open(os.path.join(work, "GATES.md"), "w", encoding="utf-8") as handle:
            handle.write("# Gates\n\n" + "\n".join(gates))
        appr_js, appr_py = os.path.join(tmp, "ra-js"), os.path.join(tmp, "ra-py")
        for d in (appr_js, appr_py):
            os.makedirs(d, mode=0o700)
        js = run_js("gate-check.mjs", ["--approve", "GATES.md"], work, {"UNLAZY_APPROVAL_DIR": appr_js})
        # Reset ledger so the second implementation starts from pending gates too.
        with open(os.path.join(work, "GATES.md"), "w", encoding="utf-8") as handle:
            handle.write("# Gates\n\n" + "\n".join(gates))
        py = run_py(["check", "--approve", "GATES.md"], work, {"GATEHOUSE_APPROVAL_DIR": appr_py})

        def verdicts(proc):
            return {m.group(2): m.group(1) for m in re.finditer(r"^  (PASS|FAIL) \S+?:(\S*?)?:? ", "", re.M)} or \
                {m.group(2): m.group(1) for m in re.finditer(r"^  (PASS|FAIL) GATES:(R\d+):", proc.stdout, re.M)}

        js_v, py_v = verdicts(js), verdicts(py)
        for i, (output, expect) in enumerate(REGEX_CASES):
            key = f"R{i}"
            if js_v.get(key) != py_v.get(key):
                failures += 1
                print(f"REGEX DIFF  expect={expect!r} output={output!r}: js={js_v.get(key)} py={py_v.get(key)}")
        print(f"regex verdicts compared: js={len(js_v)} py={len(py_v)}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\nRESULT:", "no differences" if not failures else f"{failures} difference(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
