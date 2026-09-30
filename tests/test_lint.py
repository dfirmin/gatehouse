import json
import unittest

from helpers import RepoCase, gate


class LintTests(RepoCase):
    def lint(self, text, *flags):
        self.write("GATES.md", text)
        return self.gatehouse("lint", *flags, "GATES.md")

    def test_clean_ledger(self):
        proc = self.lint("# Gates\n" + gate("G1", "invoice total matches the ledger", "python3 verify.py", "totals verified"))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.strip(), "LINT OK")

    def test_tautological_check(self):
        for check in ("echo ok", "printf 'done\\n'", "true", ":", "exit 0"):
            with self.subTest(check=check):
                proc = self.lint("# Gates\n" + gate("G1", "outcome", check, "marker"))
                self.assertIn("[tautological-check]", proc.stdout)

    def test_chained_verifier_is_not_flagged(self):
        proc = self.lint("# Gates\n" + gate("G1", "outcome", "echo start && python3 verify.py", "marker"))
        self.assertNotIn("tautological", proc.stdout)

    def test_weak_expect(self):
        proc = self.lint("# Gates\n" + gate("G1", "outcome", "python3 v.py", "OK"))
        self.assertIn("[weak-expect]", proc.stdout)

    def test_manual_gate_and_unmeasured_number(self):
        proc = self.lint("# Gates\n- [ ] G1: coverage reaches 95 percent\n  EVIDENCE: pending\n")
        self.assertIn("[manual-gate]", proc.stdout)
        self.assertIn("[unmeasured-number]", proc.stdout)
        self.assertIn("[mostly-manual]", proc.stdout)

    def test_activity_title(self):
        proc = self.lint("# Gates\n" + gate("G1", "improve the parser", "python3 v.py", "verified parse"))
        self.assertIn("[activity-not-outcome]", proc.stdout)

    def test_path_like_expect_regex(self):
        proc = self.lint("# Gates\n" + gate("G1", "outcome", "python3 v.py", "/etc/app/conf/"))
        self.assertIn("[path-read-as-regex]", proc.stdout)

    def test_strict_turns_warnings_into_failure(self):
        text = "# Gates\n" + gate("G1", "outcome", "echo ok", "marker")
        self.assertEqual(self.lint(text).returncode, 0)
        proc = self.lint(text, "--strict")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("LINT FINDINGS: 0 error(s), 1 warning(s)", proc.stdout)
        self.assertNotIn("LINT OK", proc.stdout)

    def test_parse_failure_is_exit_2(self):
        proc = self.lint("# Gates\n- [ ] no id\n")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("[parse]", proc.stdout)

    def test_json_output(self):
        proc = self.lint("# Gates\n" + gate("G1", "outcome", "echo ok", "OK"), "--json")
        report = json.loads(proc.stdout)
        self.assertTrue(report["ok"])
        self.assertEqual(report["warnings"], 2)
        self.assertEqual({f["rule"] for f in report["findings"]}, {"tautological-check", "weak-expect"})

    def test_findings_are_capped_but_counted(self):
        text = "# Gates\n" + "".join(gate(f"G{i}", f"improve part {i}", "python3 v.py", f"verified {i}") for i in range(80))
        report = json.loads(self.lint(text, "--json").stdout)
        self.assertEqual(report["warnings"], 80)
        self.assertEqual(len(report["findings"]), 64)
        self.assertTrue(report["truncated"])
        self.assertEqual(report["omittedFindings"], 16)

    def test_control_characters_are_escaped_in_findings(self):
        proc = self.lint("# Gates\n" + gate("G1", "improve \x1b[31mred", "python3 v.py", "verified"))
        self.assertNotIn("\x1b", proc.stdout)
        self.assertIn("\\x1b", proc.stdout)

    def test_usage_errors(self):
        self.assertEqual(self.gatehouse("lint").returncode, 2)
        self.assertEqual(self.gatehouse("lint", "--bogus", "GATES.md").returncode, 2)
        self.assertEqual(self.gatehouse("lint", "--strict").returncode, 2)
        self.assertEqual(self.gatehouse("lint", "missing.md").returncode, 2)
        self.assertEqual(self.gatehouse("lint", "--help").returncode, 0)

    def test_double_dash_treats_help_like_a_filename(self):
        self.write("--help", "# Gates\n" + gate("G1", "outcome", "python3 v.py", "verified"))
        proc = self.gatehouse("lint", "--", "--help")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_lint_as_a_gate_in_its_own_ledger(self):
        self.write("GATES.md", "# Gates\n" + gate("G0", "this ledger states outcomes that can fail",
                                                  "python3 -m gatehouse lint GATES.md", "LINT OK"))
        proc = self.check_run()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def check_run(self):
        return self.check("--approve", "GATES.md")


if __name__ == "__main__":
    unittest.main()
