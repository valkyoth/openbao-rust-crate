#!/usr/bin/python3 -EsSB
"""Exact patch selection, failure cleanup and narrow upgrade evidence scope."""

from contextlib import ExitStack, redirect_stdout
import io
from pathlib import Path
import unittest
from unittest.mock import patch

import openbao_2_7_1_backup_upgrade as fixture


class UpgradeTests(unittest.TestCase):
    def test_only_reviewed_source_and_target_are_used(self):
        report = fixture.report_for(fixture.input_hashes())
        self.assertEqual(report["source_version"], "2.7.0")
        self.assertEqual(report["version"], "2.7.1")
        self.assertNotEqual(report["source_image"], report["target_image"])
        for key in ("routable", "unseal_backup_upgrade_verified", "general_upgrade_verified",
                    "backup_decryption_verified", "sdk_live_verified"):
            self.assertIs(report[key], False)
        for path in ("src/sys.rs", "scripts/openbao_2_7_backup_upgrade.py",
                     "scripts/openbao_2_7_1_backup_upgrade.py", "scripts/verify_openbao_2_7_1_image.py",
                     "compat/onboarding/2.7.1/image-provenance.json"):
            self.assertIn(path, report["inputs"])

    def test_non_root_refused_before_side_effects(self):
        with patch.object(fixture.os, "geteuid", return_value=1000), \
             patch.object(fixture.tempfile, "mkdtemp") as directory, \
             self.assertRaises(fixture.harness.HarnessError):
            fixture.run()
        directory.assert_not_called()

    def test_signature_failures_precede_container_creation(self):
        for obj, name in ((fixture.previous.staged, "verify_image_signature"),
                          (fixture.patch, "verify_signature"), (fixture.image_evidence, "verify")):
            with ExitStack() as stack:
                stack.enter_context(redirect_stdout(io.StringIO()))
                stack.enter_context(patch.object(fixture.os, "geteuid", return_value=0))
                stack.enter_context(patch.object(fixture.previous.staged, "verify"))
                stack.enter_context(patch.object(fixture.previous.staged, "verify_image_signature"))
                stack.enter_context(patch.object(fixture.image_evidence, "verify"))
                stack.enter_context(patch.object(fixture.patch, "verify_signature"))
                stack.enter_context(patch.object(obj, name, side_effect=fixture.harness.HarnessError("failed")))
                directory = stack.enter_context(patch.object(fixture.tempfile, "mkdtemp"))
                with self.assertRaises(fixture.harness.HarnessError): fixture.run()
                directory.assert_not_called()

    def test_same_storage_no_retry_and_cleanup_on_every_failure(self):
        for failure in (None, "network", "source-start", "target-start", "create", "stop",
                        "cluster", "verify", "source-drift", "seal-cleanup", "private-cleanup", "resource-cleanup"):
            removed = []
            with self.subTest(failure=failure), ExitStack() as stack:
                stack.enter_context(redirect_stdout(io.StringIO()))
                def mock(obj, name, **kwargs):
                    return stack.enter_context(patch.object(obj, name, **kwargs))
                mock(fixture.os, "geteuid", return_value=0)
                mock(fixture, "input_hashes", side_effect=[{"source": "a"}, {"source": "b" if failure == "source-drift" else "a"}])
                mock(fixture.previous.staged, "verify")
                mock(fixture.previous.staged, "verify_image_signature")
                mock(fixture.image_evidence, "verify")
                mock(fixture.patch, "verify_signature")
                mock(fixture.tls.evidence_tools, "protected_path", side_effect=lambda path: path)
                mock(fixture.harness, "generate_tls", side_effect=lambda root, *_: (root / "tls", root / "ca"))
                mock(fixture.previous, "configure", side_effect=lambda root, _: (root / "config", root / "storage"))
                image = mock(fixture.harness, "inspect_image", side_effect=["source-digest", "target-digest"])
                def command(argv, **_):
                    if failure == "network" and "create" in argv or failure == "stop" and "stop" in argv:
                        raise fixture.harness.HarnessError("failed")
                    return b""
                commands = mock(fixture.harness, "run_bounded", side_effect=command)
                def start(*args):
                    if failure == ("source-start" if args[2] == "2.7.0" else "target-start"):
                        raise fixture.harness.HarnessError("failed")
                    return "https://127.0.0.1:1234"
                starts = mock(fixture.previous, "start", side_effect=start)
                initialize = mock(fixture.previous, "initialize", return_value=("disposable", "share"))
                mock(fixture.previous, "cluster", side_effect=["original", "foreign" if failure == "cluster" else "original"])
                create = mock(fixture.previous, "create_backup", return_value=("nonce", "fingerprint", "ciphertext"),
                              side_effect=fixture.harness.HarnessError("failed") if failure == "create" else None)
                verify = mock(fixture.previous, "verify_backup",
                              side_effect=fixture.harness.HarnessError("failed") if failure == "verify" else None)
                def remove(podman, kind, *_):
                    removed.append(kind)
                    if failure == "resource-cleanup": raise OSError()
                mock(fixture.harness, "remove_owned_resource", side_effect=remove)
                sanitize = mock(fixture.harness, "sanitize_file", return_value=failure != "seal-cleanup")
                mock(fixture.harness, "cleanup_private_files", return_value=failure != "private-cleanup")
                if failure:
                    with self.assertRaises((fixture.harness.HarnessError, OSError)): fixture.run()
                else:
                    report = fixture.run()
                    self.assertEqual(report, fixture.report_for({"source": "a"}))
                    self.assertEqual([call.args[1] for call in image.call_args_list],
                                     [fixture.previous.staged.RELEASE, fixture.patch.RELEASE])
                    self.assertEqual([call.args[1:3] for call in starts.call_args_list],
                                     [("source-digest", "2.7.0"), ("target-digest", "2.7.1")])
                    self.assertEqual(starts.call_args_list[0].args[6:10], starts.call_args_list[1].args[6:10])
                    self.assertEqual(sum("stop" in call.args[0] for call in commands.call_args_list), 1)
                    initialize.assert_called_once()
                    create.assert_called_once()
                    verify.assert_called_once()
                self.assertLessEqual(create.call_count, 1)
                if failure == "cluster": verify.assert_not_called()
                sanitize.assert_called_once()
                self.assertEqual(removed[-1], "network")

    def test_failure_does_not_write_evidence_or_print_secret_error(self):
        with patch("sys.argv", ["fixture"]), \
             patch.object(fixture, "run", side_effect=fixture.harness.HarnessError("private-marker")), \
             patch.object(fixture.tempfile, "NamedTemporaryFile") as output, \
             redirect_stdout(io.StringIO()) as messages:
            self.assertEqual(fixture.main(), 1)
        output.assert_not_called()
        self.assertNotIn("private-marker", messages.getvalue())


if __name__ == "__main__":
    unittest.main()
