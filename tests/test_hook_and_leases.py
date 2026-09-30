import os
import unittest

from helpers import RepoCase, gate


class StopHookTests(RepoCase):
    def unmet_repo(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))

    def test_blocks_while_gates_are_unmet(self):
        self.unmet_repo()
        proc, out = self.hook()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(out["decision"], "block")
        self.assertIn("GATES:G1", out["reason"])
        self.assertIn("gatehouse check --status", out["reason"])

    def test_allows_when_everything_is_met(self):
        self.unmet_repo()
        self.assertEqual(self.check("--approve").returncode, 0)
        proc, out = self.hook()
        self.assertEqual(proc.returncode, 0)
        self.assertIsNone(out)

    def test_allows_silently_without_any_ledger(self):
        proc, out = self.hook()
        self.assertEqual(proc.returncode, 0)
        self.assertIsNone(out)

    def test_never_executes_a_check(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "touch hook-ran.txt && echo one", "one"))
        self.hook()
        self.assertFalse(self.exists("hook-ran.txt"))

    def test_bad_payload_and_invalid_scope_never_trap(self):
        proc = self.gatehouse("stop-hook", stdin="not json")
        self.assertEqual((proc.returncode, proc.stdout.strip()), (0, ""))
        proc = self.gatehouse("stop-hook", "--scope", "../x", stdin="{}")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("invalid --scope", proc.stdout)

    def test_releases_after_six_blocks_without_progress(self):
        self.unmet_repo()
        for attempt in range(1, 7):
            _, out = self.hook()
            self.assertEqual(out["decision"], "block", f"attempt {attempt}")
        _, out = self.hook()
        self.assertNotIn("decision", out)
        self.assertIn("releasing after 6 blocks", out["systemMessage"])

    def test_real_progress_resets_the_guard_but_cosmetic_edits_do_not(self):
        self.write("GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one") + gate("G2", "b", "echo two", "two"))
        for _ in range(4):
            self.hook()
        # A comment edit shifts bytes but not resolved gate state.
        self.write("GATES.md", self.read("GATES.md") + "\n<!-- cosmetic -->\n")
        for _ in range(2):
            _, out = self.hook()
            self.assertEqual(out["decision"], "block")
        _, out = self.hook()
        self.assertIn("releasing", out["systemMessage"])
        # Checking a gate changes resolved state, so the counter starts over.
        text = self.read("GATES.md").replace("- [ ] G1", "- [x] G1", 1)
        self.write("GATES.md", text)
        _, out = self.hook()
        self.assertEqual(out["decision"], "block")

    def test_sessions_are_counted_independently(self):
        self.unmet_repo()
        for _ in range(6):
            self.hook(session="a")
        _, out = self.hook(session="b")
        self.assertEqual(out["decision"], "block")

    def test_state_cleared_once_gates_are_met(self):
        self.unmet_repo()
        self.hook()
        self.assertTrue(self.exists(".gatehouse-hook-state.json"))
        self.check("--approve")
        self.hook()
        self.assertFalse(self.exists(".gatehouse-hook-state.json"))

    def test_invalid_ledger_blocks_with_parse_reason(self):
        self.write("GATES.md", "# Gates\n- [ ] missing id\n")
        _, out = self.hook()
        self.assertEqual(out["decision"], "block")
        self.assertIn("GATES:PARSE", out["reason"])

    def test_abandonment_allows_stop_with_handoff_message(self):
        self.write("GATES.md", "# Gates\n- [ ] G1: needs owner\n  EVIDENCE: pending\n\nABANDON: G1 owner gone\n")
        proc, out = self.hook()
        self.assertEqual(proc.returncode, 0)
        self.assertIn("HANDOFF REQUIRED: 1 abandoned item(s): GATES:G1", out["systemMessage"])
        self.assertNotIn("owner gone", out["systemMessage"])  # free-form reasons stay out

    def test_multiple_scopes_without_binding_do_not_block(self):
        self.write(".gatehouse/a/GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        self.write(".gatehouse/b/GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        _, out = self.hook()
        self.assertIn("none bound to this session", out["systemMessage"])

    def test_session_binding_selects_the_scope(self):
        self.write(".gatehouse/a/GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        self.write(".gatehouse/b/GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        self.assertEqual(self.check("--bind", "sess-a", "--scope", "a").returncode, 0)
        _, out = self.hook(session="sess-a")
        self.assertEqual(out["decision"], "block")
        self.assertIn("[scope a]", out["reason"])

    def test_open_dispatch_wave_blocks(self):
        self.write(".gatehouse/a/GATES.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        self.assertEqual(self.check("--approve").returncode, 0)
        self.write(".gatehouse/a/dispatch.json",
                   '{"schema":1,"waves":{"w1":{"state":"sealed","leaves":["l1"],'
                   '"openedAt":"2026-09-30T10:00:00.000Z","sealedAt":"2026-09-30T10:00:02.000Z",'
                   '"started":{"l1":{"handle":"h1","at":"2026-09-30T10:00:01.000Z"}},"returned":{}}}}')
        _, out = self.hook()
        self.assertEqual(out["decision"], "block")
        self.assertIn("dispatch:w1 sealed (0/1 returned)", out["reason"])


class LeaseTests(RepoCase):
    def leaf(self, name, owns):
        self.write(f".gatehouse/api/gates/{name}.md", f"# Gates\n\nOWNS: {owns}\n\n"
                   + gate("G1", "a", "echo one", "one"))

    def test_disjoint_leaves_claim_and_overlapping_leaf_is_refused(self):
        self.leaf("leaf-a", "src/api/**")
        self.leaf("leaf-b", "src/web/**")
        self.leaf("leaf-c", "src/api/routes/**")
        self.assertEqual(self.check("--claim", "--scope", "api", "--leaf", "leaf-a").returncode, 0)
        self.assertEqual(self.check("--claim", "--scope", "api", "--leaf", "leaf-b").returncode, 0)
        proc = self.check("--claim", "--scope", "api", "--leaf", "leaf-c")
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertIn("CONFLICT src/api/routes/** overlaps src/api/** held by api/leaf-a", proc.stdout)
        self.assertIn("CLAIM REFUSED (1 conflict(s))", proc.stdout)

    def test_release_frees_the_claim(self):
        self.leaf("leaf-a", "src/api/**")
        self.leaf("leaf-c", "src/api/routes/**")
        self.check("--claim", "--scope", "api", "--leaf", "leaf-a")
        self.assertEqual(self.check("--release", "--scope", "api", "--leaf", "leaf-a").returncode, 0)
        self.assertEqual(self.check("--claim", "--scope", "api", "--leaf", "leaf-c").returncode, 0)

    def test_double_claim_by_same_leaf_is_refused(self):
        self.leaf("leaf-a", "src/api/**")
        self.check("--claim", "--scope", "api", "--leaf", "leaf-a")
        proc = self.check("--claim", "--scope", "api", "--leaf", "leaf-a")
        self.assertEqual(proc.returncode, 3)
        self.assertIn("already holds a live lease", proc.stdout)

    def test_claim_without_owns_is_a_usage_error(self):
        self.write(".gatehouse/api/gates/leaf-a.md", "# Gates\n" + gate("G1", "a", "echo one", "one"))
        proc = self.check("--claim", "--scope", "api", "--leaf", "leaf-a")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("declares no OWNS paths", proc.stderr)

    def test_release_recovers_after_scope_directory_is_gone(self):
        self.leaf("leaf-a", "src/api/**")
        self.check("--claim", "--scope", "api", "--leaf", "leaf-a")
        import shutil
        shutil.rmtree(os.path.join(self.repo, ".gatehouse", "api"))
        proc = self.check("--release", "--scope", "api")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("released 1 lease(s) for api", proc.stdout)

    def test_glob_overlap_rules(self):
        from gatehouse.gates import globs_overlap
        self.assertFalse(globs_overlap("src/a/x.py", "src/b/x.py"))
        self.assertFalse(globs_overlap("src/api/**", "src/web/**"))
        self.assertTrue(globs_overlap("src/api/**", "src/api/routes/**"))
        self.assertTrue(globs_overlap("src/a*", "src/ab*"))
        self.assertTrue(globs_overlap("src/api", "src/api/x.py"))
        self.assertTrue(globs_overlap("src/x.py", "src/x.py"))


if __name__ == "__main__":
    unittest.main()
