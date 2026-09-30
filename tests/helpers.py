"""Shared test scaffolding: an isolated repo, approval store, and CLI runner."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, SRC)


class RepoCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = os.path.realpath(self._tmp.name)
        self.repo = os.path.join(base, "repo")
        self.approvals = os.path.join(base, "approvals")
        os.mkdir(self.repo)
        os.mkdir(self.approvals)
        os.chmod(self.approvals, 0o700)

    def tearDown(self):
        self._tmp.cleanup()

    def env(self, **extra):
        env = os.environ.copy()
        env["PYTHONPATH"] = SRC
        env["GATEHOUSE_APPROVAL_DIR"] = self.approvals
        for name in ("GATEHOUSE_SCOPE", "GATEHOUSE_SHELL"):
            env.pop(name, None)
        env.update(extra)
        return env

    def gatehouse(self, *args, stdin=None, cwd=None, env=None, timeout=60):
        return subprocess.run(
            [sys.executable, "-m", "gatehouse", *args],
            cwd=cwd or self.repo, env=env or self.env(), input=stdin,
            capture_output=True, text=True, timeout=timeout,
        )

    def check(self, *args, **kwargs):
        return self.gatehouse("check", *args, **kwargs)

    def write(self, rel, text, newline="\n"):
        path = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(text.replace("\n", newline))
        return path

    def read(self, rel):
        with open(os.path.join(self.repo, rel), "r", encoding="utf-8", newline="") as handle:
            return handle.read()

    def exists(self, rel):
        return os.path.exists(os.path.join(self.repo, rel))

    def hook(self, session="s1", scope=None, cwd=None):
        args = ["stop-hook"] + (["--scope", scope] if scope else [])
        payload = json.dumps({"cwd": cwd or self.repo, "session_id": session})
        proc = self.gatehouse(*args, stdin=payload)
        out = proc.stdout.strip()
        return proc, (json.loads(out) if out else None)


def gate(gate_id, title, check=None, expect=None, checked=False, evidence="pending", cwd=None):
    lines = [f"- [{'x' if checked else ' '}] {gate_id}: {title}"]
    if check is not None:
        lines.append(f"  CHECK: {check}")
        lines.append(f"  EXPECT: {expect}")
    if cwd:
        lines.append(f"  CWD: {cwd}")
    lines.append(f"  EVIDENCE: {evidence}")
    return "\n".join(lines) + "\n"
