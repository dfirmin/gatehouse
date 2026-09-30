import unittest

import helpers  # noqa: F401  (adds src/ to sys.path)
from gatehouse import gates as G


def parse(text, **kwargs):
    return G.parse_gates(text, **kwargs)


class ParserTests(unittest.TestCase):
    def test_minimal_runnable_and_manual_gates(self):
        doc = parse(
            "# Gates: x\n\nOWNS: src/**, tests/**\n\n"
            "- [ ] G1: does the thing\n  CHECK: true\n  EXPECT: ok\n  EVIDENCE: pending\n"
            "- [x] G2: reviewed by hand\n  EVIDENCE: looked at it\n"
        )
        self.assertEqual(doc.errors, [])
        self.assertEqual([g.id for g in doc.gates], ["G1", "G2"])
        self.assertEqual(doc.owns, ["src/**", "tests/**"])
        self.assertEqual(doc.gates[0].check, "true")
        self.assertIsNone(doc.gates[1].check)
        self.assertTrue(doc.gates[1].checked)

    def test_gate_needs_explicit_id(self):
        doc = parse("- [ ] just a title\n")
        self.assertTrue(any("explicit ID" in e for e in doc.errors))

    def test_duplicate_ids_reported_with_first_line(self):
        doc = parse("- [ ] G1: a\n- [ ] G1: b\n")
        self.assertTrue(any("duplicate gate id G1 (first declared on line 1)" in e for e in doc.errors))

    def test_zero_gates_is_an_error_unless_allowed(self):
        self.assertIn("ledger contains zero live gates", parse("# nothing\n").errors)
        self.assertEqual(parse("# nothing\n", require_gates=False).errors, [])

    def test_runnable_gate_needs_both_check_and_expect(self):
        doc = parse("- [ ] G1: a\n  CHECK: true\n")
        self.assertTrue(any("require both" in e for e in doc.errors))

    def test_blank_check_or_expect_rejected(self):
        doc = parse("- [ ] G1: a\n  CHECK:\n  EXPECT: ok\n")
        self.assertTrue(any("cannot be blank" in e for e in doc.errors))

    def test_unindented_attribute_is_diagnosed_not_ignored(self):
        doc = parse("- [ ] G1: a\nCHECK: true\n")
        self.assertTrue(any("unindented CHECK" in e for e in doc.errors))

    def test_orphan_attribute(self):
        doc = parse("# h\n  CHECK: true\n- [ ] G1: a\n")
        self.assertTrue(any("orphan CHECK" in e for e in doc.errors))

    def test_duplicate_attribute(self):
        doc = parse("- [ ] G1: a\n  EVIDENCE: pending\n  EVIDENCE: again\n")
        self.assertTrue(any("duplicate EVIDENCE" in e for e in doc.errors))

    def test_fenced_examples_are_ignored(self):
        doc = parse("```\n- [ ] BAD gate with no id\n  CHECK: rm -rf /\n```\n- [ ] G1: real\n")
        self.assertEqual(doc.errors, [])
        self.assertEqual([g.id for g in doc.gates], ["G1"])

    def test_longer_fence_needs_matching_close(self):
        doc = parse("````\n```\n- [ ] BAD\n```\n````\n- [ ] G1: real\n")
        self.assertEqual(doc.errors, [])

    def test_unclosed_fence(self):
        self.assertIn("unclosed fenced block", parse("```\n- [ ] G1: a\n").errors)

    def test_abandon_marks_gate_and_needs_reason(self):
        doc = parse("- [ ] G1: a\n  EVIDENCE: pending\nABANDON: G1 owner unavailable\n")
        self.assertEqual(doc.abandoned, {"G1": "owner unavailable"})
        self.assertEqual(G.gate_state(doc.gates[0], doc.abandoned), "abandoned")
        self.assertTrue(any("non-blank reason" in e for e in parse("- [ ] G1: a\nABANDON: G1\n").errors))

    def test_abandon_unknown_gate_is_error(self):
        self.assertTrue(any("unknown gate G9" in e for e in parse("- [ ] G1: a\nABANDON: G9 why\n").errors))

    def test_indented_abandon_is_diagnosed(self):
        doc = parse("- [ ] G1: a\n  ABANDON: G1 nope\n")
        self.assertTrue(any("indented ABANDON" in e for e in doc.errors))

    def test_duplicate_abandon(self):
        doc = parse("- [ ] G1: a\nABANDON: G1 x\nABANDON: G1 y\n")
        self.assertTrue(any("duplicate ABANDON" in e for e in doc.errors))

    def test_owns_rules(self):
        self.assertTrue(any("before the first gate" in e for e in parse("- [ ] G1: a\nOWNS: src/**\n").errors))
        self.assertTrue(any("relative" in e for e in parse("OWNS: /etc\n- [ ] G1: a\n").errors))
        self.assertTrue(any("traversal" in e for e in parse("OWNS: ../x\n- [ ] G1: a\n").errors))
        self.assertEqual(parse("OWNS: ./src//api/, tests/**\n- [ ] G1: a\n").owns, ["src/api", "tests/**"])

    def test_regex_expectation_validated(self):
        doc = parse("- [ ] G1: a\n  CHECK: true\n  EXPECT: /(unclosed/\n")
        self.assertTrue(any("invalid EXPECT regex" in e for e in doc.errors))
        doc = parse("- [ ] G1: a\n  CHECK: true\n  EXPECT: /ok/q\n")
        self.assertTrue(any("invalid EXPECT regex" in e for e in doc.errors))

    def test_regex_length_limit(self):
        doc = parse("- [ ] G1: a\n  CHECK: true\n  EXPECT: /" + "a" * 1001 + "/\n")
        self.assertTrue(any("longer than 1000" in e for e in doc.errors))

    def test_text_expectation_and_path_like_warning(self):
        doc = parse("- [ ] G1: a\n  CHECK: true\n  EXPECT: plain marker\n")
        self.assertEqual(doc.gates[0].expectation, {"kind": "text", "value": "plain marker"})
        self.assertEqual(doc.warnings, [])
        doc = parse("- [ ] G1: a\n  CHECK: true\n  EXPECT: /etc/app/conf/\n")
        self.assertTrue(any("read as a regular expression" in w for w in doc.warnings))

    def test_js_style_named_group_is_translated(self):
        pattern, flags = G.translate_regex(r"(?<n>\d+)-\k<n>", "i")
        self.assertEqual(pattern, r"(?P<n>\d+)-(?P=n)")
        self.assertTrue(flags & 2)  # re.IGNORECASE

    def test_lookbehind_is_not_mistaken_for_a_named_group(self):
        pattern, _ = G.translate_regex(r"(?<=a)b(?<!c)", "")
        self.assertEqual(pattern, r"(?<=a)b(?<!c)")

    def match(self, source, flags, text):
        import re
        pattern, reflags = G.translate_regex(source, flags)
        return re.compile(pattern, reflags).search(text) is not None

    def test_dollar_matches_only_at_true_end_without_m_flag(self):
        self.assertFalse(self.match("ok$", "", "ok\n"))
        self.assertTrue(self.match("ok$", "", "ok"))
        self.assertTrue(self.match("ok$", "m", "ok\n"))
        self.assertTrue(self.match("x$", "m", "x\r\ny"))
        self.assertTrue(self.match("^y", "m", "x\r\ny"))
        self.assertFalse(self.match("x$", "", "x\r\ny"))

    def test_dot_and_whitespace_follow_js_semantics(self):
        self.assertFalse(self.match("a.b", "", "a\rb"))
        self.assertTrue(self.match("a.b", "s", "a\rb"))
        self.assertTrue(self.match(r"a\sb", "", "a b"))
        self.assertTrue(self.match(r"a[\s]b", "", "a b"))
        self.assertFalse(self.match(r"\d", "", "٣"))

    def test_escapes_and_classes_are_left_alone(self):
        self.assertTrue(self.match(r"\$5", "", "cost $5"))
        self.assertTrue(self.match("a[$]b", "", "a$b"))
        self.assertTrue(self.match("a[.]b", "", "a.b"))
        self.assertFalse(self.match("a[.]b", "", "axb"))
        self.assertTrue(self.match(r"a\\$", "", "a\\"))

    def test_crlf_and_final_newline_round_trip(self):
        text = "- [ ] G1: a\r\n  CHECK: true\r\n  EXPECT: ok\r\n  EVIDENCE: pending\r\n"
        doc = parse(text)
        self.assertEqual(doc.eol, "\r\n")
        self.assertEqual(G.format_document(doc), text)
        self.assertEqual(G.format_document(parse("- [ ] G1: a\n  EVIDENCE: x")), "- [ ] G1: a\n  EVIDENCE: x")

    def test_qualify(self):
        self.assertEqual(G.qualify("/a/b/leaf-1.2.1.md", "G3"), "leaf-1.2.1:G3")
        self.assertEqual(G.qualify("GATES.MD", "G1"), "GATES:G1")


class StateTests(unittest.TestCase):
    def runnable(self, evidence, checked=True, check="true", expect="ok", cwd=None):
        extra = f"  CWD: {cwd}\n" if cwd else ""
        doc = parse(f"- [{'x' if checked else ' '}] G1: a\n  CHECK: {check}\n  EXPECT: {expect}\n{extra}"
                    f"  EVIDENCE: {evidence}\n")
        self.assertEqual(doc.errors, [])
        return doc.gates[0], doc.abandoned

    def good_evidence(self, gate):
        digest = G.gate_definition_digest(gate)
        return (G.automatic_evidence_prefix(digest)
                + " exit=0; EXPECT=matched; output-sha256=" + "a" * 64 + "; output-bytes=3; shell=/bin/sh")

    def test_unchecked_is_unmet(self):
        gate, ab = self.runnable("pending", checked=False)
        self.assertEqual(G.gate_state(gate, ab), "unmet")

    def test_checked_runnable_needs_current_automatic_evidence(self):
        gate, ab = self.runnable("pending")
        self.assertEqual(G.gate_state(gate, ab), "stale-unmet")
        gate, ab = self.runnable("I ran it and it passed")
        self.assertEqual(G.gate_state(gate, ab), "stale-unmet")
        gate, ab = self.runnable("x")
        gate.evidence = self.good_evidence(gate)
        self.assertEqual(G.gate_state(gate, ab), "met")

    def test_evidence_bound_to_definition(self):
        gate, ab = self.runnable("x")
        evidence = self.good_evidence(gate)
        other, _ = self.runnable(evidence, expect="different")
        self.assertEqual(G.gate_state(other, ab), "stale-unmet")
        moved, _ = self.runnable(evidence, cwd="sub")
        self.assertEqual(G.gate_state(moved, ab), "stale-unmet")

    def test_malformed_or_oversized_evidence_is_stale(self):
        gate, ab = self.runnable("x")
        good = self.good_evidence(gate)
        gate.evidence = good.replace("exit=0", "exit=1")
        self.assertEqual(G.gate_state(gate, ab), "stale-unmet")
        gate.evidence = good + "x" * 1000
        self.assertEqual(G.gate_state(gate, ab), "stale-unmet")
        gate.evidence = good.replace("output-bytes=3", "output-bytes=03")
        self.assertEqual(G.gate_state(gate, ab), "stale-unmet")

    def test_manual_gate_needs_human_evidence(self):
        doc = parse("- [x] G1: reviewed\n  EVIDENCE: pending\n")
        self.assertEqual(G.gate_state(doc.gates[0], doc.abandoned), "unmet-no-evidence")
        doc = parse("- [x] G1: reviewed\n  EVIDENCE: read the diff, ok\n")
        self.assertEqual(G.gate_state(doc.gates[0], doc.abandoned), "met")
        doc = parse("- [x] G1: reviewed\n  EVIDENCE: automatic-evidence=v1; whatever\n")
        self.assertEqual(G.gate_state(doc.gates[0], doc.abandoned), "stale-unmet")


class FileSafetyTests(unittest.TestCase):
    def test_reader_rejects_symlink_fifo_and_hardlink(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            real = os.path.join(tmp, "real.md")
            with open(real, "w") as handle:
                handle.write("hello")
            self.assertEqual(G.read_stable_regular_file(real), "hello")

            link = os.path.join(tmp, "link.md")
            os.symlink(real, link)
            with self.assertRaises(G.GateFileError):
                G.read_stable_regular_file(link)

            fifo = os.path.join(tmp, "fifo.md")
            os.mkfifo(fifo)
            with self.assertRaises(G.GateFileError):
                G.read_stable_regular_file(fifo)

            hard = os.path.join(tmp, "hard.md")
            os.link(real, hard)
            with self.assertRaises(G.GateFileError):
                G.read_stable_regular_file(real)

            with self.assertRaises(FileNotFoundError):
                G.read_stable_regular_file(os.path.join(tmp, "missing.md"))

    def test_reader_enforces_size_and_root(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as other:
            path = os.path.join(tmp, "big.md")
            with open(path, "w") as handle:
                handle.write("x" * 100)
            with self.assertRaises(G.GateFileError):
                G.read_stable_regular_file(path, max_bytes=50)
            outside = os.path.join(other, "o.md")
            with open(outside, "w") as handle:
                handle.write("x")
            with self.assertRaises(G.GateFileError):
                G.read_stable_regular_file(outside, root=tmp)

    def test_write_atomic_refuses_symlink_target(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            real = os.path.join(tmp, "real")
            open(real, "w").close()
            link = os.path.join(tmp, "link")
            os.symlink(real, link)
            with self.assertRaises(G.GateFileError):
                G.write_atomic(link, "x")


if __name__ == "__main__":
    unittest.main()
