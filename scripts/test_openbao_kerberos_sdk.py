#!/usr/bin/python3 -EsSB
"""Candidate-only Kerberos route and bounded execution regressions."""

from contextlib import redirect_stderr
import io
import subprocess
import sys
import unittest
from unittest.mock import patch

import openbao_kerberos_sdk as sdk


class CandidateTests(unittest.TestCase):
    def test_only_nine_kerberos_routes_are_opened_in_disposable_source(self):
        source = (sdk.fixture.ldap.ROOT / "src/plugin/compatibility.rs").read_text()
        result = sdk.candidate_source(source)
        self.assertIn("ExternalPluginKind::RadiusAuth => &[],", result)
        self.assertEqual(len(sdk.OPERATIONS), 9)
        self.assertEqual(len(set(sdk.OPERATIONS)), 9)
        for operation in sdk.OPERATIONS:
            self.assertIn(".auth.kerberos.", operation)
            self.assertEqual(result.count('"' + operation + '"'), 1)
        self.assertEqual(sdk.candidate_source(result), result)
        with self.assertRaises(sdk.fixture.harness.HarnessError):
            sdk.candidate_source(result.replace(sdk.OPERATIONS[0], "unreviewed"))
        with self.assertRaises(sdk.fixture.harness.HarnessError):
            sdk.candidate_source(source + source)

    def test_candidate_flag_is_explicit_at_frozen_execution_boundary(self):
        with patch.object(sys, "argv", ["runner", "--version", "2.7.0", "--test-binary", "/binary",
                                       "--acknowledge-unsigned-directory-image"]), patch.object(sdk, "run") as run:
            self.assertEqual(sdk.main(), 0)
            self.assertIs(run.call_args.kwargs["strict_candidate"], True)
        with patch.object(sys, "argv", ["runner", "--normal", "--version", "2.7.0", "--test-binary", "/binary"]), patch.object(sdk, "run") as run:
            self.assertEqual(sdk.main(), 0)
            self.assertIs(run.call_args.kwargs["strict_candidate"], False)

    def test_progress_does_not_forward_child_output(self):
        output, progress = io.StringIO(), sdk.Progress()
        with redirect_stderr(output):
            progress.feed(b"reflected disposable ticket\n")
            for name in sdk.STAGES:
                for byte in ("kerberos-sdk-stage:" + name + "\n").encode():
                    progress.feed(bytes([byte]))
        self.assertEqual(progress.count, len(sdk.STAGES))
        self.assertNotIn("ticket", output.getvalue())

    def test_reordered_duplicate_unknown_and_oversized_progress_fails(self):
        for raw in (b"kerberos-sdk-stage:complete\n", b"kerberos-sdk-stage:secret\n",
                    b"kerberos-sdk-stage:profile\nkerberos-sdk-stage:profile\n", b"x" * 1025, b"x\n" * 32769):
            with redirect_stderr(io.StringIO()), self.assertRaises(sdk.fixture.harness.HarnessError):
                sdk.Progress().feed(raw)

    def test_child_must_exit_successfully_after_every_stage_and_is_reaped(self):
        stages = ";".join("print(" + repr("kerberos-sdk-stage:" + stage) + ")" for stage in sdk.STAGES)
        for body, success in ((stages, True), (stages + "; sys.exit(1)", False), ("pass", False),
                              ("print('kerberos-sdk-stage:complete')", False)):
            script = "import sys; sys.stdin.buffer.read(); " + body
            process = subprocess.Popen([sys.executable, "-E", "-s", "-S", "-c", script],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
            with redirect_stderr(io.StringIO()):
                if success:
                    sdk.exchange(process, b"fixture-only", sdk.Progress())
                else:
                    with self.assertRaises(sdk.fixture.harness.HarnessError):
                        sdk.exchange(process, b"fixture-only", sdk.Progress())
            self.assertIsNotNone(process.poll())
            self.assertTrue(process.stdin.closed and process.stdout.closed)


if __name__ == "__main__":
    unittest.main()
