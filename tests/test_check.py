import os
import sys
import time
import unittest

from helpers import RepoCase, gate

PY = sys.executable


class StatusAndApprovalTests(RepoCase):
    def test_status_never_executes_or_writes(self):
        path = self.write("GATES.md", "# Gates\n" + gate("G1", "touches a file", "touch ran.txt && echo done", "done"))
        before = self.read("GATES.md")
        proc = self.check("--status", "GATES.md")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("UNMET GATES:G1 (unchecked)", proc.stdout)
        self.assertFalse(self.exists("ran.txt"))
        self.assertEqual(self.read("GATES.md"), before)
        self.assertEqual(os.listdir(self.approvals), [])
        self.assertTrue(os.path.exists(path))

    def test_unapproved_oracle_is_printed_and_not_run(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "touches a file", "touch ran.txt && echo done", "done"))
        proc = self.check("GATES.md")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("APPROVAL REQUIRED GATES:G1", proc.stdout)
        self.assertIn("CHECK: touch ran.txt && echo done", proc.stdout)
        self.assertIn("NOT RUN", proc.stdout)
        self.assertFalse(self.exists("ran.txt"))

    def test_approve_runs_records_evidence_and_all_met(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "prints marker", "echo build ok", "build ok"))
        proc = self.check("--approve", "GATES.md")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("PASS GATES:G1", proc.stdout)
        self.assertIn("ALL MET (1 met)", proc.stdout)
        ledger = self.read("GATES.md")
        self.assertIn("- [x] G1:", ledger)
        self.assertIn("EVIDENCE: automatic-evidence=v1; definition-sha256=", ledger)
        self.assertIn("output-bytes=9", ledger)
        self.assertNotIn("build ok", ledger.split("EVIDENCE:")[1])  # raw output is never persisted

    def test_second_run_uses_existing_approval_without_flag(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one") + gate("G2", "b", "echo two", "two"))
        self.assertEqual(self.check("--approve", "GATES.md").returncode, 0)
        self.write("GATES.md", self.read("GATES.md").replace("- [x] G2", "- [ ] G2"))
        proc = self.check("GATES.md")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("APPROVAL REQUIRED", proc.stdout)

    def test_changed_command_needs_new_approval_and_old_evidence_goes_stale(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        self.assertEqual(self.check("--approve", "GATES.md").returncode, 0)
        self.write("GATES.md", self.read("GATES.md").replace("echo one", "echo one && touch sneaky.txt"))
        status = self.check("--status", "GATES.md")
        self.assertEqual(status.returncode, 1)
        self.assertIn("automatic evidence is stale or unbound", status.stdout)
        run = self.check("GATES.md")
        self.assertIn("APPROVAL REQUIRED", run.stdout)
        self.assertFalse(self.exists("sneaky.txt"))

    def test_forged_prose_evidence_is_not_completion(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one", checked=True,
                                                  evidence="trust me, it passed"))
        proc = self.check("--status", "GATES.md")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("stale or unbound", proc.stdout)

    def test_tampered_definition_digest_is_stale(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        self.check("--approve", "GATES.md")
        text = self.read("GATES.md")
        marker = "definition-sha256="
        start = text.index(marker) + len(marker)
        flipped = ("0" if text[start] != "0" else "1") + text[start + 1:]
        self.write("GATES.md", text[:start] + flipped)
        self.assertEqual(self.check("--status", "GATES.md").returncode, 1)

    def test_approval_dir_inside_repo_is_rejected(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        inside = os.path.join(self.repo, "approvals")
        os.mkdir(inside, 0o700)
        proc = self.check("--approve", "GATES.md", env=self.env(GATEHOUSE_APPROVAL_DIR=inside))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("must be outside the repository root", proc.stderr)

    def test_approval_dir_must_be_private(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        os.chmod(self.approvals, 0o755)
        proc = self.check("--approve", "GATES.md")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("must not grant group or other permissions", proc.stderr)
        self.assertNotIn("PASS", proc.stdout)


class ExecutionTests(RepoCase):
    def run_one(self, check, expect, *flags):
        self.write("GATES.md", "# Gates\n" + gate("G1", "the outcome", check, expect))
        return self.check("--approve", *flags, "GATES.md")

    def test_nonzero_exit_fails_even_when_expect_is_printed(self):
        proc = self.run_one("echo passed; exit 3", "passed")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("FAIL GATES:G1", proc.stdout)
        self.assertIn("exit=3; EXPECT=matched", proc.stdout)
        self.assertIn("- [ ] G1", self.read("GATES.md"))

    def test_zero_exit_without_marker_fails(self):
        proc = self.run_one("echo something else", "success marker")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("EXPECT=not matched", proc.stdout)

    def test_expect_sees_stderr_and_stdout_combined(self):
        proc = self.run_one("echo out; echo err-marker 1>&2", "err-marker")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_missing_command_fails(self):
        proc = self.run_one("definitely-not-a-real-command-xyz", "anything")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("FAIL", proc.stdout)

    def test_timeout_kills_the_whole_process_group(self):
        started = time.monotonic()
        proc = self.run_one("(sleep 20; touch late.txt) & wait", "never", "--timeout", "1")
        elapsed = time.monotonic() - started
        self.assertEqual(proc.returncode, 1)
        self.assertIn("timed out after 1s", proc.stdout)
        self.assertLess(elapsed, 15)
        time.sleep(0.5)
        self.assertFalse(self.exists("late.txt"))

    def test_background_holder_of_stdio_is_bounded_by_timeout(self):
        started = time.monotonic()
        proc = self.run_one("sleep 20 & echo launched", "launched", "--timeout", "1")
        self.assertLess(time.monotonic() - started, 15)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("timed out", proc.stdout)

    def test_output_limit_is_enforced_not_truncated_into_a_match(self):
        code = "import sys; sys.stdout.write('a' * 2_000_000); sys.stdout.write('MARKER')"
        proc = self.run_one(f'{PY} -c "{code}"', "MARKER")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("output exceeded 1048576 bytes", proc.stdout)

    def test_regex_expectation_with_flags_and_named_groups(self):
        proc = self.run_one("echo 'BUILD 42 Passed'", r"/(?<n>\d+) passed/i")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_end_anchor_is_strict_like_the_original(self):
        # `echo ok` prints "ok\n"; without the m flag `$` must not match before the newline.
        self.assertEqual(self.run_one("echo ok", "/^ok$/").returncode, 1)
        self.assertEqual(self.run_one("printf ok", "/^ok$/").returncode, 0)

    def test_catastrophic_regex_is_cut_off_and_cannot_certify(self):
        check = f"{PY} -c \"print('a' * 40 + 'b')\""
        started = time.monotonic()
        proc = self.run_one(check, r"/(a+)+$/")
        self.assertLess(time.monotonic() - started, 30)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("EXPECT regex exceeded 250ms", proc.stdout)

    def test_cwd_attribute_and_explicit_ledger_anchor(self):
        os.makedirs(os.path.join(self.repo, "sub"))
        self.write("sub/flag.txt", "here")
        self.write("ledgers/GATES.md", "# Gates\n" + gate("G1", "reads flag", "cat flag.txt", "here", cwd="../sub"))
        proc = self.check("--approve", "ledgers/GATES.md")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_missing_cwd_is_a_usage_error(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo x", "x", cwd="nope"))
        proc = self.check("--approve", "GATES.md")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("CWD does not exist", proc.stderr)

    def test_jobs_keep_ledger_order_and_all_pass(self):
        gates = "".join(gate(f"G{i}", f"g{i}", f"sleep 0.{i}; echo m{i}", f"m{i}") for i in range(1, 5))
        self.write("GATES.md", "# Gates\n" + gates)
        proc = self.check("--approve", "--jobs", "4", "GATES.md")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        order = [line.split()[1].rstrip(":") for line in proc.stdout.splitlines() if line.startswith("  PASS")]
        self.assertEqual(order, ["GATES:G1", "GATES:G2", "GATES:G3", "GATES:G4"])

    def test_custom_shell(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo $0", "bash"))
        bash = "/bin/bash"
        if not os.path.exists(bash):
            self.skipTest("bash not available")
        proc = self.check("--approve", "--shell", bash, "GATES.md")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_crlf_ledger_keeps_crlf(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"), newline="\r\n")
        self.assertEqual(self.check("--approve", "GATES.md").returncode, 0)
        raw = self.read("GATES.md")
        self.assertIn("\r\n", raw)
        self.assertNotIn("\r\r", raw)
        self.assertEqual(raw.count("\n"), raw.count("\r\n"))

    def test_missing_evidence_line_is_inserted(self):
        self.write("GATES.md", "# Gates\n- [ ] G1: a\n  CHECK: echo one\n  EXPECT: one\n\nnext paragraph\n")
        self.assertEqual(self.check("--approve", "GATES.md").returncode, 0)
        lines = self.read("GATES.md").split("\n")
        idx = next(i for i, ln in enumerate(lines) if ln.startswith("  EVIDENCE:"))
        self.assertEqual(lines[idx - 1], "  EXPECT: one")


class ReverifyAndOutcomeTests(RepoCase):
    def test_reverify_reruns_met_gates_and_demotes_when_oracle_now_fails(self):
        self.write("state.txt", "good")
        self.write("GATES.md", "# Gates\n" + gate("G1", "state is good", "cat state.txt", "good"))
        self.assertEqual(self.check("--approve", "GATES.md").returncode, 0)
        self.assertEqual(self.check("--status", "GATES.md").returncode, 0)
        self.write("state.txt", "bad")
        # --status cannot see the regression; it never re-executes.
        self.assertEqual(self.check("--status", "GATES.md").returncode, 0)
        proc = self.check("--reverify", "GATES.md")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("FAIL GATES:G1", proc.stdout)
        self.assertIn("- [ ] G1", self.read("GATES.md"))
        self.assertIn("EVIDENCE: pending", self.read("GATES.md"))
        self.assertEqual(self.check("--status", "GATES.md").returncode, 1)

    def test_reverify_reports_counts(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        self.check("--approve", "GATES.md")
        proc = self.check("--reverify", "GATES.md")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("ALL MET (1 met, reran: 1, previously met reverified: 1)", proc.stdout)

    def test_manual_gate_blocks_all_met_until_human_evidence(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one")
                   + "- [x] G2: reviewed\n  EVIDENCE: pending\n")
        proc = self.check("--approve", "GATES.md")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("UNMET: 1 (met: 1)", proc.stdout)

    def test_abandonment_is_a_handoff_never_success(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one")
                   + "- [ ] G2: needs an owner\n  EVIDENCE: pending\n\nABANDON: G2 owner unavailable\n")
        proc = self.check("--approve", "GATES.md")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("HANDOFF REQUIRED: 1 abandoned (met: 1", proc.stdout)
        self.assertNotIn("ALL MET", proc.stdout)

    def test_invalid_ledger_is_exit_2_not_completion(self):
        self.write("GATES.md", "# Gates\n- [ ] no id here\n")
        proc = self.check("--status", "GATES.md")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("explicit ID", proc.stderr)

    def test_empty_ledger_is_exit_2(self):
        self.write("GATES.md", "# Gates\n")
        self.assertEqual(self.check("--status", "GATES.md").returncode, 2)

    def test_no_ledger_found(self):
        proc = self.check("--status")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("no gate files found", proc.stderr)


class DiscoveryAndScopeTests(RepoCase):
    def test_legacy_discovery_of_gates_md_and_gates_dir(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        self.write("gates/leaf-1.md", "# Gates\n" + gate("G1", "b", "echo two", "two"))
        proc = self.check("--status")
        self.assertIn("GATES:G1", proc.stdout)
        self.assertIn("leaf-1:G1", proc.stdout)

    def test_single_scope_is_discovered_and_multiple_scopes_are_ambiguous(self):
        self.write(".gatehouse/api/GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        self.assertIn("[scope api]", self.check("--status").stdout)
        self.write(".gatehouse/web/GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        proc = self.check("--status")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("Refusing to guess", proc.stderr)
        self.assertIn("[scope web]", self.check("--status", "--scope", "web").stdout)

    def test_list_scopes_and_scope_validation(self):
        self.assertIn("no pipelines", self.check("--list-scopes").stdout)
        self.write(".gatehouse/api/GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        self.assertEqual(self.check("--list-scopes").stdout.strip(), "api")
        self.assertEqual(self.check("--status", "--scope", "../evil").returncode, 2)
        self.assertEqual(self.check("--status", "--scope", "nope").returncode, 2)

    def test_open_dispatch_wave_blocks_completion(self):
        self.write(".gatehouse/api/GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        self.assertEqual(self.check("--approve").returncode, 0)
        self.write(".gatehouse/api/dispatch.json",
                   '{"schema":1,"waves":{"w1":{"state":"open","leaves":["leaf-1"],'
                   '"openedAt":"2026-09-30T10:00:00.000Z","started":{},"returned":{}}}}')
        proc = self.check("--status")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("UNMET dispatch:w1 open (0/1 started)", proc.stdout)

    def test_invalid_dispatch_state_is_exit_2(self):
        self.write(".gatehouse/api/GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        self.write(".gatehouse/api/dispatch.json", "{not json")
        proc = self.check("--status")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("invalid dispatch state", proc.stderr)

    def test_log_and_bind(self):
        self.write(".gatehouse/api/GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        self.assertEqual(self.check("--log", "started leaf", "--scope", "api").returncode, 0)
        self.assertIn("started leaf", self.read(".gatehouse/api/status.log"))
        self.assertEqual(self.check("--bind", "sess-9", "--scope", "api").returncode, 0)
        self.assertEqual(self.read(".gatehouse/api/session").strip(), "sess-9")


class UsageTests(RepoCase):
    def test_conflicting_and_unknown_options(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        for args in (["--status", "--reverify"], ["--status", "--approve"], ["--bogus"], ["--timeout", "0"],
                     ["--jobs", "65"], ["--status", "--status"], ["--claim"], ["--leaf", "x"]):
            with self.subTest(args=args):
                self.assertEqual(self.check(*args, "GATES.md").returncode, 2)

    def test_help_exits_zero(self):
        proc = self.check("--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("usage: gatehouse check", proc.stdout)

    def test_terminal_control_characters_are_neutralized(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "evil \x1b]0;pwned\x07 title", "echo one", "one"))
        proc = self.check("--status", "GATES.md")
        self.assertNotIn("\x1b", proc.stdout)
        self.assertNotIn("\x07", proc.stdout)


if __name__ == "__main__":
    unittest.main()
