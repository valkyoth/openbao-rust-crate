#!/usr/bin/python3 -EsSB
"""Candidate RADIUS route inventory and bounded secret-safe execution tests."""

from contextlib import redirect_stderr
import io
import subprocess
import sys
import unittest
from unittest.mock import patch

import openbao_radius_sdk as sdk


class RadiusSdkTests(unittest.TestCase):
    def test_exact_six_operations_only_in_disposable_source(self):
        source = (sdk.fixture.ldap.ROOT / "src/plugin/compatibility.rs").read_text()
        changed = sdk.candidate_source(source)
        self.assertEqual(len(sdk.OPERATIONS), 6)
        self.assertEqual(len(set(sdk.OPERATIONS)), 6)
        self.assertEqual(changed, source)
        for operation in sdk.OPERATIONS:
            self.assertIn(".auth.radius.", operation)
            self.assertEqual(changed.count('"' + operation + '"'), 1)
        self.assertNotIn("openbao.post.auth.radius.login.ea2f3680af864d92", sdk.OPERATIONS)
        self.assertIn("radius-auth-acknowledged", sdk.FEATURES.split(","))
        for invalid in (source + source, changed.replace(sdk.OPERATIONS[0], "unreviewed")):
            with self.assertRaises(sdk.fixture.harness.HarnessError):
                sdk.candidate_source(invalid)

    def test_explicit_candidate_boundary_and_image_acknowledgements(self):
        with patch.object(sys, "argv", ["runner", "--version", "2.7.0", "--test-binary", "/binary",
            "--acknowledge-unsigned-directory-image", "--acknowledge-unsigned-radius-image"]), patch.object(sdk, "run") as run:
            self.assertEqual(sdk.main(), 0)
            self.assertIs(run.call_args.kwargs["strict_candidate"], True)
            self.assertEqual(run.call_args.args[2:], (True, True))
        with patch.object(sys, "argv", ["runner", "--normal", "--version", "2.7.0", "--test-binary", "/binary"]), patch.object(sdk, "run") as run:
            self.assertEqual(sdk.main(), 0)
            self.assertIs(run.call_args.kwargs["strict_candidate"], False)

    def test_progress_redacts_child_output_and_requires_order(self):
        output, progress = io.StringIO(), sdk.Progress()
        with redirect_stderr(output):
            progress.feed(b"reflected password\n")
            for stage in sdk.STAGES:
                progress.feed(("radius-sdk-stage:" + stage + "\n").encode())
        self.assertNotIn("password", output.getvalue())
        self.assertEqual(progress.count, len(sdk.STAGES))
        for raw in (b"radius-sdk-stage:complete\n", b"radius-sdk-stage:unknown\n",
                    b"radius-sdk-stage:profile\nradius-sdk-stage:profile\n", b"x" * 1025, b"x\n" * 32769):
            with redirect_stderr(io.StringIO()), self.assertRaises(sdk.fixture.harness.HarnessError):
                sdk.Progress().feed(raw)

    def test_child_must_complete_all_stages_and_exit_successfully(self):
        stages = ";".join("print(" + repr("radius-sdk-stage:" + stage) + ")" for stage in sdk.STAGES)
        for body, success in ((stages, True), (stages + "; sys.exit(1)", False), ("pass", False)):
            process = subprocess.Popen([sys.executable, "-E", "-s", "-S", "-c",
                "import sys; sys.stdin.buffer.read(); " + body], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
            with redirect_stderr(io.StringIO()):
                if success:
                    sdk.exchange(process, b"disposable-only", sdk.Progress())
                else:
                    with self.assertRaises(sdk.fixture.harness.HarnessError):
                        sdk.exchange(process, b"disposable-only", sdk.Progress())
            self.assertIsNotNone(process.poll())
            self.assertTrue(process.stdin.closed and process.stdout.closed)


if __name__ == "__main__":
    unittest.main()
