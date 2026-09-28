#!/usr/bin/python3 -EsSB
"""Offline security regressions for the unprivileged staged SDK runner."""

import contextlib
import copy
import io
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import openbao_2_7_consistency_sdk as subject
import verify_openbao_2_7_consistency_sdk as evidence


class SdkFixtureTests(unittest.TestCase):
    def test_retained_sdk_evidence_rejects_stale_sources_and_stronger_claims(self):
        original = evidence.verify()
        for field, value in (("routable", True), ("routable", 0),
                             ("controlled_replication_lag_verified", True),
                             ("scope", "public-sdk-dispatch"), ("test", "other"),
                             ("test_binary_sha256", "0" * 64)):
            changed = copy.deepcopy(original)
            changed[field] = value
            with self.assertRaises(subject.server.harness.HarnessError): evidence.validate_report(changed)
        for path in original["inputs"]:
            for omit in (True, False):
                changed = copy.deepcopy(original)
                if omit: del changed["inputs"][path]
                else: changed["inputs"][path] = "0" * 64
                with self.assertRaises(subject.server.harness.HarnessError): evidence.validate_report(changed)
        with patch.object(evidence, "EXPECTED_SHA256", "0" * 64):
            with self.assertRaises(subject.server.snapshots.SnapshotError): evidence.verify()

    def test_binary_location_type_and_permissions(self):
        binary = subject.ROOT / "target/debug/deps/openbao-0123456789abcdef"
        with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=0o100755, st_uid=1000)), \
             patch.object(subject.server.snapshots, "read_regular_file", return_value=b"test"):
            self.assertEqual(subject.binary_hash(binary, 1000), subject.server.snapshots.sha256(b"test"))
            for value in (Path("relative"), Path("/tmp/openbao-0123456789abcdef"), binary.with_name("other")):
                with self.assertRaises(subject.server.harness.HarnessError): subject.binary_hash(value, 1000)
        for mode, uid in ((0o120755, 1000), (0o100777, 1000), (0o100644, 1000), (0o100755, 0)):
            with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=mode, st_uid=uid)):
                with self.assertRaises(subject.server.harness.HarnessError): subject.binary_hash(binary, 1000)

    def test_child_drops_privileges_and_keeps_credentials_off_command_and_environment(self):
        for outcome in ("success", "failure", "timeout", "interrupt", "no-test"):
            process = MagicMock()
            process.pid = 12345
            process.returncode = 1 if outcome == "failure" else 0
            process.poll.return_value = None if outcome in ("timeout", "interrupt") else process.returncode
            if outcome == "timeout": process.communicate.side_effect = subprocess.TimeoutExpired("test", 90)
            if outcome == "interrupt": process.communicate.side_effect = subject.server.harness.HarnessError("interrupted")
            listing = b"0 tests, 0 benchmarks\n" if outcome == "no-test" else f"{subject.TEST}: test\n\n1 test, 0 benchmarks\n".encode()
            with tempfile.TemporaryDirectory() as directory:
                ca = Path(directory) / "ca"
                ca.write_text("public fixture CA", encoding="ascii")
                with patch.object(subject.server.evidence_tools, "protected_path", side_effect=lambda path: path), \
                     patch.object(subject.server.harness, "run_bounded", return_value=listing), \
                     patch.object(subject.subprocess, "Popen", return_value=process) as spawn, \
                     patch.object(subject.os, "killpg") as kill:
                    def run(): subject.run_test(Path("/test"), 1000, 1000, ["a", "b", "c"], ca, "synthetic-private-token")
                    if outcome == "success": run()
                    else:
                        with self.assertRaises((subject.server.harness.HarnessError, subprocess.TimeoutExpired)): run()
                    if outcome == "no-test":
                        spawn.assert_not_called()
                        continue
                    command = spawn.call_args.args[0]
                    for flag in ("--reuid=1000", "--regid=1000", "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all"):
                        self.assertIn(flag, command)
                    self.assertNotIn("synthetic-private-token", repr(spawn.call_args))
                    self.assertEqual(spawn.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
                    self.assertTrue(spawn.call_args.kwargs["close_fds"])
                    self.assertTrue(spawn.call_args.kwargs["start_new_session"])
                    self.assertIn(b"synthetic-private-token", process.communicate.call_args.args[0])
                    process.wait.assert_called_once()
                    if outcome in ("timeout", "interrupt"): kill.assert_called_once_with(12345, subject.signal.SIGKILL)
                    else: kill.assert_not_called()

    def test_root_or_missing_invoking_identity_is_rejected_before_setup(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(subject.os, "geteuid", return_value=0), \
             patch.object(subject, "binary_hash") as binary:
            with self.assertRaises(subject.server.harness.HarnessError): subject.run(Path("/test"))
            binary.assert_not_called()

    def test_all_resources_cleaned_up_when_sdk_fails(self):
        removed = []
        with contextlib.ExitStack() as stack:
            def mock(obj, name, **kwargs): return stack.enter_context(patch.object(obj, name, **kwargs))
            stack.enter_context(patch.dict(os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}))
            mock(subject.os, "geteuid", return_value=0)
            mock(subject.pwd, "getpwuid", return_value=SimpleNamespace(pw_gid=1000))
            mock(subject, "binary_hash", return_value="digest")
            mock(subject, "input_hashes", return_value={})
            mock(subject.server.staged, "verify")
            mock(subject.server.staged, "verify_image_signature")
            mock(subject.server.evidence_tools, "protected_path", side_effect=lambda path: path)
            mock(subject.server.harness, "generate_tls", side_effect=lambda root, *args: (root / "tls", root / "ca"))
            mock(subject.server.harness, "inspect_image", return_value="pinned-image")
            mock(subject.server.harness, "run_bounded", return_value=b'{"subnets":[{"subnet":"10.88.0.0/24","gateway":"10.88.0.1"}]}')
            mock(subject.server.snapshots, "validate_container_resource_config")
            mock(subject.server.fixture, "verify_network")
            mock(subject.server.harness, "parse_port", return_value=18200)
            mock(subject.server.fixture, "wait_for_health")
            mock(subject.server.fixture, "probe_tls")
            mock(subject.server, "initialize_cluster", return_value="synthetic-token")
            mock(subject.server, "probe")
            mock(subject.server, "ready_cluster", return_value=(0, "cluster"))
            mock(subject, "run_test", side_effect=subject.server.harness.HarnessError("synthetic-private-detail"))
            mock(subject.server.harness, "remove_owned_resource", side_effect=lambda p, kind, *args: removed.append(kind))
            mock(subject.server.harness, "cleanup_private_files", return_value=True)
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(subject.server.harness.HarnessError): subject.run(Path("/test"))
        self.assertEqual(removed, ["container"] * 3 + ["network"])

    def test_evidence_binds_all_rust_sources(self):
        hashes = subject.input_hashes()
        for path in ("src/client.rs", "src/client/consistency.rs", "src/client/consistency/live.rs", "src/consistency.rs", "Cargo.lock"):
            self.assertIn(path, hashes)


if __name__ == "__main__":
    unittest.main()
