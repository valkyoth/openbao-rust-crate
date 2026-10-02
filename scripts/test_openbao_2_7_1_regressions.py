#!/usr/bin/python3 -EsSB
"""Checks for reuse of server probes without relabeling them as SDK evidence."""

from contextlib import ExitStack, redirect_stdout
import io
from pathlib import Path
import unittest
from unittest.mock import patch

import openbao_2_7_1_regressions as fixture


class RegressionTests(unittest.TestCase):
    def test_each_established_probe_runs_without_version_monkeypatching(self):
        for suite, module in (("external-keys", fixture.external), ("transit", fixture.transit),
                              ("workflow-cas", fixture.workflow), ("system", fixture.system),
                              ("mfa-totp", fixture.mfa)):
            with patch.object(module, "probe") as probe:
                result = fixture.probe(suite, "https://127.0.0.1", None, "disposable", None)
            probe.assert_called_once_with("https://127.0.0.1", None, "disposable")
            self.assertEqual(result["checks"], module.CHECKS)
            self.assertEqual(fixture.tls.VERSION, "2.7.0")

    def test_pki_keeps_independent_crypto_verification(self):
        verifier = object()
        with patch.object(fixture.pki, "probe") as probe:
            fixture.probe("pki", "https://127.0.0.1", None, "disposable", verifier)
        probe.assert_called_once_with("https://127.0.0.1", None, "disposable", verifier)

    def test_replay_failure_cannot_be_reported_as_passed(self):
        with patch.object(fixture.control, "probe", return_value=False):
            result = fixture.probe("control-groups", "https://127.0.0.1", None, "disposable", None)
        self.assertIs(result["server_replay_rejected"], False)
        self.assertEqual(result["outcome"], "completed-with-known-upstream-replay-failure")
        with patch.object(fixture.control, "probe", return_value=None), self.assertRaises(fixture.harness.HarnessError):
            fixture.probe("control-groups", "https://127.0.0.1", None, "disposable", None)

    def test_api_requires_raw_routes(self):
        with patch.object(fixture, "excluded_plugins"), \
             patch.object(fixture.patch, "capture_api", return_value={"document": {"paths": {}}}), \
             self.assertRaises(fixture.harness.HarnessError):
            fixture.probe("api", "https://127.0.0.1", None, "disposable", None)

    def test_missing_plugin_requires_specific_failure_and_absent_mount(self):
        for response, mounts in (({"errors": ["permission denied"]}, {}),
                                 ({"errors": ["plugin not found in the catalog"]}, {"excluded-ldap/": {}})):
            with patch.object(fixture.patch, "call", side_effect=[{}, response, {"data": mounts}]), \
                 self.assertRaises(fixture.harness.HarnessError):
                fixture.excluded_plugins("https://127.0.0.1", None, "disposable")

    def run_mocked(self, fail_probe=False, fail_cleanup=False):
        output = io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(redirect_stdout(output))
            def mock(obj, name, **options):
                return stack.enter_context(patch.object(obj, name, **options))
            mock(fixture.os, "geteuid", return_value=0)
            mock(fixture, "input_hashes", return_value={"reviewed": "digest"})
            mock(fixture.evidence, "verify")
            mock(fixture.patch, "verify_signature")
            mock(fixture.tls.evidence_tools, "protected_path", side_effect=lambda path: path)
            mock(fixture.harness, "generate_tls", side_effect=lambda root, *_: (root / "tls", root / "ca"))
            mock(fixture.harness, "inspect_image", return_value="pinned-image")
            mock(fixture.harness, "run_bounded", return_value=b"{}")
            limits = mock(fixture.base, "validate_container_resource_config")
            network = mock(fixture.tls, "verify_network")
            mock(fixture.harness, "parse_port", return_value=1234)
            health = mock(fixture.harness, "wait_for_exact_version")
            tls = mock(fixture.tls, "probe_tls")
            mock(fixture.harness, "initialize_and_unseal", return_value="disposable-token")
            mock(fixture.harness, "cleanup_private_files", return_value=True)
            remove = mock(fixture.harness, "remove_owned_resource",
                          side_effect=OSError("disposable-marker") if fail_cleanup else None)
            mock(fixture, "probe", side_effect=fixture.harness.HarnessError("disposable-marker") if fail_probe else None,
                 return_value={"checks": ["raw-storage-enabled"], "openapi": {"document": {}}})
            write = mock(fixture.patch, "write_capture_output", return_value=Path("/tmp/mock-output"))
            if fail_probe or fail_cleanup:
                with self.assertRaises((fixture.harness.HarnessError, OSError)):
                    fixture.run("api")
                write.assert_not_called()
            else:
                report = fixture.run("api")
                self.assertIs(report["routable"], False)
                self.assertEqual(report["scope"], "server-fixture-only-not-sdk-integration")
                self.assertEqual(report["version"], "2.7.1")
                limits.assert_called_once()
                network.assert_called_once()
                self.assertEqual(health.call_args.args[2], "2.7.1")
                tls.assert_called_once_with(1234, health.call_args.args[1])
            self.assertEqual([call.args[1] for call in remove.call_args_list], ["container", "network"])
            self.assertNotIn("disposable", output.getvalue())

    def test_harness_verifies_exact_version_and_sanitized_report(self):
        self.run_mocked()

    def test_probe_failure_cleans_up_without_evidence(self):
        self.run_mocked(fail_probe=True)

    def test_cleanup_failure_cannot_publish_success(self):
        self.run_mocked(fail_cleanup=True)


if __name__ == "__main__":
    unittest.main()
