#!/usr/bin/python3 -EsSB
"""Patch SDK runner: no success evidence on execution or cleanup failure."""

from contextlib import ExitStack, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import openbao_2_7_2_sdk as fixture


class SdkRunnerTests(unittest.TestCase):
    def test_diagnostic_stages_are_fixed_and_secret_free(self):
        diagnostic = (b"secret-response-must-not-escape\npatch-stage:profile\n"
                      b"patch-stage:approle\npatch-stage:unknown\n")
        self.assertEqual(fixture.diagnostic_stages(diagnostic), ["profile", "approle"])

    def test_build_refuses_root(self):
        with patch.object(fixture.os, "geteuid", return_value=0), \
             self.assertRaises(fixture.harness.HarnessError):
            fixture.build()

    def test_execution_refuses_unprivileged_invocation(self):
        with patch.object(fixture.os, "geteuid", return_value=1000), \
             patch.object(fixture.execution, "FrozenBinary") as frozen, \
             self.assertRaises(fixture.harness.HarnessError):
            fixture.run(Path("/unused"), strict_candidate=True)
        frozen.assert_not_called()

    def run_mocked(self, failure=None, *, normal=False):
        output = io.StringIO()
        real_output = tempfile.NamedTemporaryFile
        with tempfile.TemporaryDirectory() as destination, ExitStack() as stack:
            stack.enter_context(redirect_stdout(output))
            stack.enter_context(patch.dict(fixture.os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}))

            def mock(obj, name, **options):
                return stack.enter_context(patch.object(obj, name, **options))

            mock(fixture.pwd, "getpwuid", return_value=SimpleNamespace(pw_gid=1000))
            binary_hash = mock(fixture.execution, "binary_hash", return_value="a" * 64)
            mock(fixture.normal_sdk, "verify", side_effect=[
                {"scope": "public-sdk-strict-normal-build", "routable": True},
                {"scope": "changed" if failure == "registry-drift"
                 else "public-sdk-strict-normal-build", "routable": True}])
            mock(fixture, "input_hashes", side_effect=[{"source": "before"},
                 {"source": "changed" if failure == "inputs" else "before"}])
            mock(fixture.candidate, "verify", return_value={})
            mock(fixture.candidate.registry, "rust_output", return_value=b"candidate")
            signature = mock(fixture.patch, "verify_signature")
            mock(fixture.tls.evidence_tools, "protected_path", side_effect=lambda value: value)
            mock(fixture.harness, "generate_tls", side_effect=lambda root, *_: (root / "tls", root / "ca"))
            mock(fixture.harness, "write_server_config", side_effect=lambda root, *_: root / "config")
            mock(fixture.harness, "inspect_image", return_value="pinned-image")
            mock(fixture.harness, "run_bounded", return_value=b"{}")
            limits = mock(fixture.base, "validate_container_resource_config")
            network = mock(fixture.tls, "verify_network")
            mock(fixture.harness, "parse_port", return_value=1234)
            health = mock(fixture.harness, "wait_for_exact_version")
            rejection = mock(fixture.tls, "probe_tls")
            mock(fixture.harness, "initialize_and_unseal", return_value="disposable-token")
            test = mock(fixture, "run_core_test", side_effect=
                        fixture.harness.HarnessError("disposable-marker") if failure == "execution" else None)
            mock(fixture.harness, "cleanup_private_files", return_value=failure != "private-cleanup")
            remove = mock(fixture.harness, "remove_owned_resource", side_effect=
                          OSError("disposable-marker") if failure == "resource-cleanup" else None)
            writer = mock(fixture.tempfile, "NamedTemporaryFile", side_effect=
                          lambda **kwargs: real_output(dir=destination, **kwargs))
            if failure:
                with self.assertRaises(fixture.harness.HarnessError):
                    fixture.run.__wrapped__(object(), strict_candidate=not normal, normal=normal)
                writer.assert_not_called()
            else:
                fixture.run.__wrapped__(object(), strict_candidate=not normal, normal=normal)
                reports = list(Path(destination).glob("*.json"))
                self.assertEqual(len(reports), 1)
                report = json.loads(reports[0].read_bytes())
                self.assertIs(report["routable"], normal)
                self.assertEqual(report["scope"], "public-sdk-strict-normal-build" if normal
                                 else "public-sdk-strict-disposable-candidate-build")
                self.assertEqual(report["version"], "2.7.2")
                self.assertEqual(report["test"], fixture.TEST)
                if normal:
                    self.assertNotIn("candidate_registry_sha256", report)
                else:
                    self.assertEqual(report["candidate_registry_sha256"],
                                     fixture.candidate.EXPECTED_SHA256)
                self.assertTrue(all(call.kwargs == {"candidate": not normal}
                                    for call in binary_hash.call_args_list))
                signature.assert_called_once()
                limits.assert_called_once()
                network.assert_called_once()
                self.assertEqual(health.call_args.args[2], "2.7.2")
                rejection.assert_called_once_with(1234, health.call_args.args[1])
                self.assertEqual(test.call_args.args[1:3], (1000, 1000))
            self.assertEqual([call.args[1] for call in remove.call_args_list], ["container", "network"])
            self.assertNotIn("disposable-token", output.getvalue())
            self.assertNotIn("disposable-marker", output.getvalue())

    def test_success_is_candidate_sdk_only(self):
        self.run_mocked()

    def test_normal_mode_preserves_checks_and_cleanup(self):
        self.run_mocked(normal=True)

    def test_ambiguous_modes_are_rejected_before_execution(self):
        for normal, candidate in ((False, False), (True, True), (1, False), (False, 1)):
            with self.assertRaises(fixture.harness.HarnessError):
                fixture.run.__wrapped__(object(), normal=normal, strict_candidate=candidate)

    def test_execution_failure_cleans_up_without_report(self):
        self.run_mocked("execution")

    def test_resource_cleanup_failure_prevents_report(self):
        self.run_mocked("resource-cleanup")

    def test_private_cleanup_failure_prevents_report(self):
        self.run_mocked("private-cleanup")

    def test_changed_sources_prevent_report(self):
        self.run_mocked("inputs")


if __name__ == "__main__":
    unittest.main()
