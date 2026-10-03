#!/usr/bin/python3 -EsSB
"""Candidate route restrictions and secret-safe LDAP progress regressions."""

from contextlib import redirect_stderr
import io
import subprocess
import sys
import unittest

import openbao_ldap_sdk as sdk


class CandidateTests(unittest.TestCase):
    def test_candidate_opens_only_explicit_ldap_operations(self):
        source = (sdk.fixture.ROOT / "src/plugin/ldap_contracts.rs").read_text()
        sdk.verify_contract_source(source)
        for operation in sdk.OPERATIONS:
            self.assertIn('"' + operation + '"', source)
            self.assertNotIn("kerberos", operation)
            self.assertNotIn("radius", operation)

    def test_candidate_refuses_unknown_or_already_modified_source(self):
        for source in ("", "fn reviewed_operations() {}"):
            with self.assertRaises(sdk.fixture.harness.HarnessError):
                sdk.verify_contract_source(source)

    def test_progress_emits_only_fixed_ordered_stages(self):
        progress = sdk.Progress()
        output = io.StringIO()
        with redirect_stderr(output):
            progress.feed(b"potential credential reflection discarded\n")
            for stage in sdk.STAGES:
                raw = ("ldap-sdk-stage:" + stage + "\n").encode()
                for byte in raw:
                    progress.feed(bytes([byte]))
        self.assertEqual(progress.count, len(sdk.STAGES))
        self.assertNotIn("reflection", output.getvalue())

    def test_progress_rejects_reordering_duplicates_unknown_and_overflow(self):
        for raw in (b"ldap-sdk-stage:login\n", b"ldap-sdk-stage:secret\n", b"x" * 1025,
                    b"ldap-sdk-stage:profile\nldap-sdk-stage:profile\n", b"x\n" * 32769):
            with redirect_stderr(io.StringIO()), self.assertRaises(sdk.fixture.harness.HarnessError):
                sdk.Progress().feed(raw)

    def test_failed_child_is_reaped_and_streams_closed(self):
        process = subprocess.Popen([sys.executable, "-E", "-s", "-S", "-c",
                                    "import sys; sys.stdin.buffer.read(); print('ldap-sdk-stage:login')"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        with self.assertRaises(sdk.fixture.harness.HarnessError):
            sdk.exchange(process, b"disposable-input", sdk.Progress())
        self.assertIsNotNone(process.poll())
        self.assertTrue(process.stdin.closed and process.stdout.closed)

    def test_complete_child_inventory_required(self):
        script = "import sys; sys.stdin.buffer.read(); " + ";".join(
            "print(" + repr("ldap-sdk-stage:" + stage) + ")" for stage in sdk.STAGES)
        process = subprocess.Popen([sys.executable, "-E", "-s", "-S", "-c", script],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        with redirect_stderr(io.StringIO()):
            sdk.exchange(process, b"disposable-input", sdk.Progress())
        self.assertEqual(process.returncode, 0)
        self.assertTrue(process.stdin.closed and process.stdout.closed)

    def test_incomplete_inventory_and_nonzero_exit_fail_closed(self):
        scripts = ("import sys; sys.stdin.buffer.read()",
                   "import sys; sys.stdin.buffer.read(); " + ";".join(
                       "print(" + repr("ldap-sdk-stage:" + stage) + ")" for stage in sdk.STAGES)
                   + "; sys.exit(1)")
        for script in scripts:
            process = subprocess.Popen([sys.executable, "-E", "-s", "-S", "-c", script],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, start_new_session=True)
            with redirect_stderr(io.StringIO()), self.assertRaises(sdk.fixture.harness.HarnessError):
                sdk.exchange(process, b"disposable-input", sdk.Progress())
            self.assertIsNotNone(process.poll())
            self.assertTrue(process.stdin.closed and process.stdout.closed)


if __name__ == "__main__":
    unittest.main()
