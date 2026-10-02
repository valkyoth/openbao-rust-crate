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

import openbao_2_6_4_sdk as fixture


class SdkRunnerTests(unittest.TestCase):
    def test_progress_emits_only_ordered_constant_labels(self):
        captured = io.StringIO()
        progress = fixture.Progress()
        data = b"private-marker\n" + b"".join(("patch-stage:" + name + "\n").encode() for name in fixture.STAGES)
        with redirect_stdout(captured):
            for offset in range(0, len(data), 3):
                progress.feed(data[offset:offset + 3])
        self.assertEqual(progress.count, len(fixture.STAGES))
        self.assertNotIn("private-marker", captured.getvalue())
        self.assertEqual(captured.getvalue().splitlines(), ["2.6.4 SDK stage: " + s for s in fixture.STAGES])

    def test_progress_rejects_injection_reordering_and_output_overflow(self):
        for data in (b"patch-stage:private-marker\n", b"patch-stage:complete\n",
                     b"x" * 1025, b"x\n" * 32769):
            captured = io.StringIO()
            with redirect_stdout(captured), self.assertRaises(fixture.harness.HarnessError):
                fixture.Progress().feed(data)
            self.assertEqual(captured.getvalue(), "")

    def test_exchange_requires_success_and_all_stages(self):
        # Exercise real bounded pipes without root, credentials or a server.
        for success, complete in ((True, True), (False, True), (True, False)):
            lines = "".join("patch-stage:" + s + "\n" for s in (fixture.STAGES if complete else fixture.STAGES[:1]))
            code = "import sys; sys.stdin.buffer.read(); sys.stdout.write(" + repr(lines) + "); sys.exit(" + ("0" if success else "1") + ")"
            process = fixture.subprocess.Popen(["/usr/bin/python3", "-E", "-s", "-S", "-c", code],
                       stdin=fixture.subprocess.PIPE, stdout=fixture.subprocess.PIPE,
                       stderr=fixture.subprocess.DEVNULL, start_new_session=True)
            with redirect_stdout(io.StringIO()):
                if success and complete:
                    fixture.exchange(process, b"disposable", fixture.Progress())
                else:
                    with self.assertRaises(fixture.harness.HarnessError):
                        fixture.exchange(process, b"disposable", fixture.Progress())
            self.assertIsNotNone(process.poll())
            self.assertTrue(process.stdin.closed and process.stdout.closed)

    def test_exchange_timeout_kills_and_reaps_child(self):
        process = fixture.subprocess.Popen(["/usr/bin/python3", "-E", "-s", "-S", "-c",
                   "import time; time.sleep(60)"], stdin=fixture.subprocess.PIPE,
                   stdout=fixture.subprocess.PIPE, stderr=fixture.subprocess.DEVNULL, start_new_session=True)
        with patch.object(fixture.time, "monotonic", side_effect=[0, 91]), \
             self.assertRaises(fixture.harness.HarnessError):
            fixture.exchange(process, b"disposable", fixture.Progress())
        self.assertIsNotNone(process.poll())
        self.assertTrue(process.stdin.closed and process.stdout.closed)

    def test_diagnostic_execution_keeps_privilege_drop_and_sealed_descriptor(self):
        binary = SimpleNamespace(fd=12)
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            ca = Path(temporary) / "ca.pem"
            ca.write_text("disposable")
            stack.enter_context(patch.object(fixture.tls.evidence_tools, "protected_path", side_effect=lambda p: p))
            stack.enter_context(patch.object(fixture.execution, "test_listing", return_value=
                                f"{fixture.TEST}: test\n\n1 test, 0 benchmarks\n".encode()))
            spawn = stack.enter_context(patch.object(fixture.subprocess, "Popen"))
            exchange = stack.enter_context(patch.object(fixture, "exchange"))
            fixture.run_test(binary, 1000, 1000, ["https://127.0.0.1:1"] * 3, ca, "private-marker", test=fixture.TEST)
            command = spawn.call_args.args[0]
            for flag in ("--reuid=1000", "--regid=1000", "--clear-groups", "--no-new-privs",
                         "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all"):
                self.assertIn(flag, command)
            self.assertNotIn("private-marker", str(command))
            self.assertEqual(spawn.call_args.kwargs["pass_fds"], (12,))
            self.assertEqual(spawn.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            self.assertEqual(spawn.call_args.kwargs["stderr"], fixture.subprocess.DEVNULL)
            exchange.assert_called_once()

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
                {"scope": "changed" if failure == "registry-drift" else "public-sdk-strict-normal-build", "routable": True}])
            mock(fixture, "input_hashes", side_effect=[{"source": "before"},
                 {"source": "changed" if failure == "inputs" else "before"}])
            mock(fixture.candidate, "verify", return_value={})
            mock(fixture.candidate.registry, "rust_output", return_value=b"candidate")
            signature = mock(fixture.patch, "verify_signature", side_effect=
                             fixture.harness.HarnessError("disposable-marker") if failure == "signature" else None)
            mock(fixture.tls.evidence_tools, "protected_path", side_effect=lambda value: value)
            mock(fixture.harness, "generate_tls", side_effect=lambda root, *_: (root / "tls", root / "ca"))
            mock(fixture.harness, "write_server_config", side_effect=lambda root, *_: root / "config")
            mock(fixture.harness, "inspect_image", return_value="pinned-image")
            mock(fixture.harness, "run_bounded", return_value=b"{}")
            limits = mock(fixture.base, "validate_container_resource_config", side_effect=
                          fixture.harness.HarnessError("disposable-marker") if failure == "limits" else None)
            network = mock(fixture.tls, "verify_network", side_effect=
                           fixture.harness.HarnessError("disposable-marker") if failure == "network" else None)
            mock(fixture.harness, "parse_port", return_value=1234)
            health = mock(fixture.harness, "wait_for_exact_version", side_effect=
                          fixture.harness.HarnessError("disposable-marker") if failure == "health" else None)
            rejection = mock(fixture.tls, "probe_tls", side_effect=
                             fixture.harness.HarnessError("disposable-marker") if failure == "tls" else None)
            mock(fixture.harness, "initialize_and_unseal", return_value="disposable-token")
            test = mock(fixture, "run_test", side_effect=
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
                self.assertEqual(report["scope"], "public-sdk-strict-normal-build" if normal else "public-sdk-strict-disposable-candidate-build")
                self.assertEqual(report["version"], "2.6.4")
                self.assertEqual(report["test"], fixture.TEST)
                if normal:
                    self.assertNotIn("candidate_registry_sha256", report)
                    self.assertNotIn("candidate_generated_rust_sha256", report)
                else:
                    self.assertEqual(report["candidate_registry_sha256"], fixture.candidate.EXPECTED_SHA256)
                self.assertTrue(all(call.kwargs == {"candidate": not normal} for call in binary_hash.call_args_list))
                signature.assert_called_once()
                limits.assert_called_once()
                network.assert_called_once()
                self.assertEqual(health.call_args.args[2], "2.6.4")
                rejection.assert_called_once_with(1234, health.call_args.args[1])
                self.assertEqual(test.call_args.kwargs["test"], fixture.TEST)
                self.assertEqual(test.call_args.args[1:3], (1000, 1000))
            self.assertEqual([call.args[1] for call in remove.call_args_list],
                             [] if failure == "signature" else ["container", "network"])
            if failure in ("signature", "limits", "network", "health", "tls"):
                test.assert_not_called()
            self.assertNotIn("disposable-token", output.getvalue())
            self.assertNotIn("disposable-marker", output.getvalue())

    def test_success_is_candidate_sdk_only(self):
        self.run_mocked()

    def test_normal_mode_preserves_security_checks_and_cleanup(self):
        for failure in (None, "inputs", "registry-drift", "signature", "limits", "network", "health", "tls",
                        "execution", "resource-cleanup", "private-cleanup"):
            with self.subTest(failure=failure):
                self.run_mocked(failure, normal=True)

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

    def test_security_preconditions_prevent_execution_and_report(self):
        for failure in ("signature", "limits", "network", "health", "tls"):
            with self.subTest(failure=failure):
                self.run_mocked(failure)

    def test_inputs_bind_capture_sources_and_public_sdk(self):
        inputs = fixture.input_hashes()
        for path in ("src/patch_264_live.rs", "src/patch_271_live.rs", "src/sys.rs",
                     "scripts/openbao_2_6_4.py", "scripts/openbao_2_6_4_sdk.py",
                     "scripts/verify_openbao_2_6_4.py", "scripts/openbao_2_7_consistency_sdk.py",
                     "compat/onboarding/2.6.4/openapi.json", "compat/onboarding/2.6.4/patch-tls.json",
                     "compat/onboarding/2.6.4/image-provenance.json", "Cargo.lock"):
            self.assertIn(path, inputs)
            self.assertEqual(inputs[path], fixture.base.sha256(
                fixture.base.read_regular_file(fixture.patch.ROOT / path, 2 * 1024 * 1024)))


if __name__ == "__main__":
    unittest.main()
