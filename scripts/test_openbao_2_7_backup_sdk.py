#!/usr/bin/python3 -EsSB
"""Offline checks for public SDK backup evidence and observer dispatch."""

import copy
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import openbao_2_7_backup_sdk as subject
import verify_openbao_2_7_backup_sdk as evidence


class BackupSdkTests(unittest.TestCase):
    def test_strict_normal_runner_selects_strict_test_and_normal_binary_directory(self):
        def server(*, backup_observer):
            backup_observer("https://127.0.0.1:12345", Path("/ca"), "fixture-only-token")
            return {}

        with patch.dict(os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}), \
             patch.object(subject.os, "geteuid", return_value=0), \
             patch.object(subject.pwd, "getpwuid", return_value=SimpleNamespace(pw_gid=1000)), \
             patch.object(subject, "input_hashes", return_value={"source": "a" * 64}), \
             patch.object(subject.sdk, "binary_hash", return_value="b" * 64) as binary, \
             patch.object(subject.recovery, "run", side_effect=server), \
             patch.object(subject.recovery, "validate_report"), \
             patch.object(subject.sdk, "run_test") as runner:
            result = subject.run(Path("/test"), strict=True)
            self.assertEqual(runner.call_args.kwargs, {"test": subject.STRICT_TEST})
            self.assertEqual(binary.call_count, 2)
            for call in binary.call_args_list:
                self.assertEqual(call.kwargs, {"candidate": False})
            self.assertIs(result["strict_profile_verified"], True)
            self.assertEqual(result["scope"], "public-sdk-strict-normal-build")

    def test_strict_normal_build_scope_is_distinct_and_fail_closed(self):
        inputs = {"src/sys.rs": "a" * 64}
        with patch.object(subject, "input_hashes", return_value=inputs):
            report = subject.report_for(inputs, "b" * 64, strict=True)
            subject.validate_report(report, "b" * 64, strict=True)
            self.assertIs(report["strict_profile_verified"], True)
            self.assertIs(report["backup_decryption_verified"], False)
            self.assertEqual(report["test"], subject.STRICT_TEST)
            with self.assertRaises(subject.recovery.harness.HarnessError):
                subject.validate_report(report, "b" * 64)
            for field, value in (("scope", "public-sdk-strict-disposable-candidate-build"),
                                 ("test", subject.TEST), ("strict_profile_verified", False),
                                 ("routable", False), ("backup_decryption_verified", True),
                                 ("inputs", {}), ("test_binary_sha256", "c" * 64),
                                 ("source_scope", "candidate")):
                with self.assertRaises(subject.recovery.harness.HarnessError):
                    subject.validate_report(dict(report, **{field: value}), "b" * 64, strict=True)
            with self.assertRaises(subject.recovery.harness.HarnessError):
                subject.report_for(inputs, "b" * 64, True, True)

    def test_strict_candidate_evidence_cannot_be_relabelled_as_public_promotion(self):
        import generate_openbao_2_7_candidate as candidate
        verified = candidate.verify()
        inputs = {"src/sys.rs": "a" * 64}
        with patch.object(candidate, "verify", return_value=verified), \
             patch.object(subject, "input_hashes", return_value=inputs):
            original = subject.report_for(inputs, "b" * 64, True)
            subject.validate_report(original, "b" * 64, True)
            self.assertTrue(original["strict_profile_verified"])
            self.assertFalse(original["routable"])
            self.assertEqual(original["test"], subject.STRICT_TEST)
            with self.assertRaises(subject.recovery.harness.HarnessError):
                subject.validate_report(original, "b" * 64)
            for field, value in (("routable", True), ("backup_decryption_verified", True),
                                 ("scope", "public-sdk-promoted"), ("test", subject.TEST),
                                 ("candidate_registry_sha256", "0" * 64),
                                 ("candidate_generated_rust_sha256", "0" * 64),
                                 ("source_scope", "unmodified-main")):
                with self.assertRaises(subject.recovery.harness.HarnessError):
                    subject.validate_report(dict(original, **{field: value}), "b" * 64, True)

    def test_retained_evidence_pins_and_every_source_input(self):
        original = evidence.verify()
        for field in ("EXPECTED_SHA256", "TEST_BINARY_SHA256"):
            with patch.object(evidence, field, "0" * 64):
                with self.assertRaises((subject.snapshots.SnapshotError, subject.recovery.harness.HarnessError)):
                    evidence.verify()
        for path in original["inputs"]:
            for omit in (True, False):
                changed = copy.deepcopy(original)
                if omit: del changed["inputs"][path]
                else: changed["inputs"][path] = "0" * 64
                with self.assertRaises(subject.recovery.harness.HarnessError):
                    subject.validate_report(changed, evidence.TEST_BINARY_SHA256)
        for field in ("routable", "strict_profile_verified", "backup_decryption_verified"):
            for value in (True, 0):
                changed = dict(original, **{field: value})
                with self.assertRaises(subject.recovery.harness.HarnessError):
                    subject.validate_report(changed, evidence.TEST_BINARY_SHA256)

    def test_report_rejects_source_binary_and_scope_changes(self):
        inputs = {"src/sys.rs": "a" * 64, "src/sys/backup_live.rs": "b" * 64}
        with patch.object(subject, "input_hashes", return_value=inputs):
            original = subject.report_for(inputs, "c" * 64)
            subject.validate_report(original, "c" * 64)
            for field, value in (("routable", True), ("strict_profile_verified", True),
                                 ("backup_decryption_verified", True), ("outcome", "failed"),
                                 ("scope", "strict-public-sdk"), ("test", "other"),
                                 ("test_binary_sha256", "d" * 64), ("checks", [])):
                changed = copy.deepcopy(original)
                changed[field] = value
                with self.assertRaises(subject.recovery.harness.HarnessError):
                    subject.validate_report(changed, "c" * 64)
            for path in inputs:
                for omit in (True, False):
                    changed = copy.deepcopy(original)
                    if omit: del changed["inputs"][path]
                    else: changed["inputs"][path] = "0" * 64
                    with self.assertRaises(subject.recovery.harness.HarnessError):
                        subject.validate_report(changed, "c" * 64)

    def test_root_invoking_user_rejected_before_server_or_binary(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(subject.os, "geteuid", return_value=0), \
             patch.object(subject.sdk, "binary_hash") as binary, patch.object(subject.recovery, "run") as server:
            with self.assertRaises(subject.recovery.harness.HarnessError): subject.run(Path("/test"))
            binary.assert_not_called()
            server.assert_not_called()

    def test_requires_exactly_one_successful_sdk_call_and_unchanged_inputs(self):
        for mode in ("success", "missing", "duplicate", "failed", "source-drift", "binary-drift", "server-failed"):
            inputs = [{"source": "a"}, {"source": "b" if mode == "source-drift" else "a"}]
            digest = ["c" * 64, ("d" if mode == "binary-drift" else "c") * 64]

            def server(*, backup_observer):
                if mode == "server-failed": raise subject.recovery.harness.HarnessError("fixture failed")
                if mode != "missing":
                    backup_observer("https://127.0.0.1:12345", Path("/ca"), "fixture-only-token")
                if mode == "duplicate":
                    backup_observer("https://127.0.0.1:12345", Path("/ca"), "fixture-only-token")
                return {"server": "report"}

            with patch.dict(os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}), \
                 patch.object(subject.os, "geteuid", return_value=0), \
                 patch.object(subject.pwd, "getpwuid", return_value=SimpleNamespace(pw_gid=1000)), \
                 patch.object(subject, "input_hashes", side_effect=inputs), \
                 patch.object(subject.sdk, "binary_hash", side_effect=digest), \
                 patch.object(subject.recovery, "run", side_effect=server), \
                 patch.object(subject.recovery, "validate_report"), \
                 patch.object(subject.sdk, "run_test") as runner:
                if mode == "failed": runner.side_effect = subject.recovery.harness.HarnessError("test failed")
                if mode == "success":
                    result = subject.run(Path("/test"))
                    self.assertFalse(result["strict_profile_verified"])
                    self.assertFalse(result["routable"])
                    self.assertEqual(runner.call_args.kwargs, {"test": subject.TEST})
                else:
                    with self.assertRaises(subject.recovery.harness.HarnessError): subject.run(Path("/test"))


if __name__ == "__main__":
    unittest.main()
