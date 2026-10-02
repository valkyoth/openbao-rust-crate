#!/usr/bin/python3 -EsSB
"""Backup scope, version isolation and fail-closed cleanup regressions."""

from contextlib import ExitStack, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import openbao_2_7_1_backups as fixture


class BackupTests(unittest.TestCase):
    def test_config_uses_static_seal_only_for_recovery(self):
        for suite in fixture.SUITES:
            with self.subTest(suite=suite), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                certs = root / "tls"
                certs.mkdir()
                config = fixture.configure(root, certs, suite).read_bytes()
                self.assertIn(b"raw_storage_endpoint = true", config)
                self.assertIn(b'tls_min_version = "tls13"', config)
                seal = certs / "fixture-seal.key"
                self.assertEqual(seal.exists(), suite == "recovery")
                if suite == "recovery":
                    self.assertEqual(seal.stat().st_size, 32)
                    self.assertEqual(seal.stat().st_mode & 0o777, 0o640)
                    self.assertNotIn(seal.read_bytes(), config)
                    self.assertIn(b'current_key = "file:///openbao/tls/fixture-seal.key"', config)
                else:
                    self.assertNotIn(b'seal "static"', config)

    def test_invalid_suite_refused_before_resources(self):
        with patch.object(fixture.os, "geteuid", return_value=0), \
             patch.object(fixture, "input_hashes") as inputs, \
             self.assertRaises(fixture.harness.HarnessError):
            fixture.run("unknown")
        inputs.assert_not_called()

    def run_mocked(self, suite="recovery", failure=None, observer=None):
        output = io.StringIO()
        module = fixture.recovery if suite == "recovery" else fixture.unseal
        with ExitStack() as stack:
            stack.enter_context(redirect_stdout(output))

            def mock(obj, name, **options):
                return stack.enter_context(patch.object(obj, name, **options))

            mock(fixture.os, "geteuid", return_value=0)
            mock(fixture, "input_hashes", side_effect=[{"source": "before"},
                 {"source": "changed" if failure == "inputs" else "before"}])
            mock(fixture.evidence, "verify")
            signature = mock(fixture.patch, "verify_signature")
            mock(fixture.tls.evidence_tools, "protected_path", side_effect=lambda value: value)
            mock(fixture.harness, "generate_tls", side_effect=lambda root, *_: (root / "tls", root / "ca"))
            mock(fixture, "configure", side_effect=lambda root, *_: root / "config")
            image = mock(fixture.harness, "inspect_image", return_value="pinned-image")
            mock(fixture.harness, "run_bounded", return_value=b"{}")
            limits = mock(fixture.base, "validate_container_resource_config")
            network = mock(fixture.tls, "verify_network")
            mock(fixture.harness, "parse_port", return_value=1234)
            health = mock(fixture.harness, "wait_for_exact_version")
            rejection = mock(fixture.tls, "probe_tls")
            mock(module, "initialize", return_value=("disposable-token", "disposable-share"))
            probe = mock(module, "probe", side_effect=
                         fixture.harness.HarnessError("disposable-marker") if failure == "probe" else None)
            wipe = mock(fixture.harness, "sanitize_file", return_value=failure != "seal-cleanup")
            mock(fixture.harness, "cleanup_private_files", return_value=True)
            remove = mock(fixture.harness, "remove_owned_resource", side_effect=
                          OSError("disposable-marker") if failure == "resource-cleanup" else None)
            if failure:
                with self.assertRaises(fixture.harness.HarnessError):
                    fixture.run(suite, observer)
            else:
                report = fixture.run(suite, observer)
                self.assertEqual(report["version"], "2.7.1")
                self.assertEqual(report["suite"], suite)
                self.assertEqual(report["scope"], "server-fixture-only-not-sdk-integration")
                self.assertFalse(report["routable"])
                self.assertFalse(report["backup_decryption_verified"])
                self.assertFalse(report["upgrade_verified"])
                self.assertEqual(report["checks"], module.CHECKS)
                signature.assert_called_once()
                self.assertEqual(image.call_args.args[1], fixture.patch.RELEASE)
                limits.assert_called_once()
                network.assert_called_once()
                self.assertEqual(health.call_args.args[2], "2.7.1")
                rejection.assert_called_once_with(1234, health.call_args.args[1])
                if observer:
                    self.assertIs(probe.call_args.args[-1], observer)
            self.assertEqual(wipe.call_count, int(suite == "recovery"))
            if suite == "recovery":
                self.assertEqual(wipe.call_args.args[0].name, "fixture-seal.key")
            self.assertEqual([call.args[1] for call in remove.call_args_list], ["container", "network"])
            for marker in ("disposable-token", "disposable-share", "disposable-marker"):
                self.assertNotIn(marker, output.getvalue())
            self.assertEqual(fixture.recovery.fixture.VERSION, "2.7.0")
            self.assertEqual(fixture.unseal.fixture.VERSION, "2.7.0")

    def test_both_backups_keep_exact_version_and_scope(self):
        for suite in fixture.SUITES:
            with self.subTest(suite=suite):
                self.run_mocked(suite)

    def test_recovery_observer_keeps_server_evidence_scope(self):
        self.run_mocked(observer=lambda *_: None)

    def test_failures_cannot_produce_success(self):
        for failure in ("probe", "seal-cleanup", "resource-cleanup", "inputs"):
            with self.subTest(failure=failure):
                self.run_mocked(failure=failure)


if __name__ == "__main__":
    unittest.main()
