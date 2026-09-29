#!/usr/bin/python3 -EsSB
"""Offline coordination, bounded-pipe and cleanup tests for SDK controlled lag."""

import contextlib
import copy
import io
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import openbao_2_7_consistency_sdk_lag as subject
import verify_openbao_2_7_consistency_sdk_lag as evidence


class CoordinatedSdkTests(unittest.TestCase):
    def test_retained_evidence_rejects_modified_sources_and_claims(self):
        original = evidence.verify()
        for field, value in (("routable", True), ("routable", 0), ("checks", []),
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

    @contextlib.contextmanager
    def child(self, code):
        with patch.object(subject.server.evidence_tools, "protected_path", side_effect=lambda path: path):
            session = subject.Session(Path("/test"), 1000, 1000)
        session.process = subprocess.Popen([sys.executable, "-I", "-c", code], stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        subject.os.set_blocking(session.process.stdin.fileno(), False)
        subject.os.set_blocking(session.process.stdout.fileno(), False)
        try:
            yield session
        finally:
            session.__exit__()
        self.assertIsNotNone(session.process.returncode)
        self.assertTrue(session.process.stdin.closed)
        self.assertTrue(session.process.stdout.closed)

    def test_pipe_protocol_accepts_only_ordered_events_and_never_echoes_child_output(self):
        code = "import sys; print('synthetic-private-detail'); print('prefix CONSISTENCY:scope-ready', flush=True); sys.stdin.readline(); print('CONSISTENCY:partition-ready', flush=True)"
        with self.child(code) as child, contextlib.redirect_stdout(io.StringIO()) as output:
            child.expect("scope-ready")
            child.send(b"scope\n")
            child.expect("partition-ready")
            with self.assertRaises(subject.server.harness.HarnessError): child.finish()
        self.assertNotIn("synthetic-private-detail", output.getvalue())
        for code in ("print('CONSISTENCY:complete')", "print('x' * 20000)", "pass"):
            with self.child(code) as child, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(subject.server.harness.HarnessError): child.expect("scope-ready")

    def test_stdin_and_deadline_are_bounded_and_hung_child_is_reaped(self):
        with self.child("import time; time.sleep(60)") as child:
            for data in (b"no-newline", b"x" * 65536 + b"\n", "not-bytes"):
                with self.assertRaises(subject.server.harness.HarnessError): child.send(data)
            with patch.object(subject.time, "monotonic", side_effect=[0, 100]):
                with self.assertRaises(subject.server.harness.HarnessError): child.expect("scope-ready")

    def test_expected_test_must_exist_before_spawn_and_privileges_are_dropped(self):
        with patch.object(subject.server.evidence_tools, "protected_path", side_effect=lambda path: path), \
             patch.object(subject.sdk, "test_listing", return_value=b"0 tests, 0 benchmarks\n"), \
             patch.object(subject.subprocess, "Popen") as spawn:
            child = subject.Session(Path("/test"), 1000, 1001)
            for flag in ("--reuid=1000", "--regid=1001", "--no-new-privs", "--clear-groups", "--bounding-set=-all"):
                self.assertIn(flag, child.command)
            with self.assertRaises(subject.server.harness.HarnessError): child.__enter__()
            spawn.assert_not_called()

    def test_coordination_requires_observation_no_retries_and_no_write_side_effects(self):
        for failure in (None, "scope-dispatch", "not-transmitted", "retry", "mutation", "early-failure", "cluster-dispatch", "missing-preflight"):
            actions, events = [], []
            class Relay:
                address = "https://127.0.0.1:1"
                def __init__(self, *args): pass
                def __enter__(self): return self
                def __exit__(self, *args): actions.append("relay-closed")
                def snapshot(self): return list(events)
                def switch_cluster(self, address): actions.append("switched-cluster")
                def wait_for(self, method, path, **kwargs):
                    actions.append(path)
                    return failure != "not-transmitted"
            class Session:
                def __init__(self, *args): pass
                def __enter__(self): return self
                def __exit__(self, *args): actions.append("child-closed")
                def send(self, data):
                    if data == b"scope\n" and failure == "scope-dispatch": events.append(("GET", "/v1/fixture-kv/data/sdk-lag"))
                    if data == b"switched\n":
                        if failure != "missing-preflight": events.append(("GET", "/v1/sys/health"))
                        if failure == "cluster-dispatch": events.append(("GET", "/v1/fixture-kv/data/sdk-lag"))
                def expect(self, stage):
                    if stage == "cancel-ready":
                        if failure == "early-failure": raise subject.server.harness.HarnessError("child failure")
                        events.append(("POST", "/v1/fixture-kv/data/sdk-cancel"))
                    if stage == "recovery-ready":
                        events.append(("POST", "/v1/fixture-kv/data/sdk-timeout"))
                        if failure == "retry": events.append(events[-1])
                def finish(self): actions.append("child-passed")
            class Partition:
                def __init__(self, *args): pass
                def __enter__(self): actions.append("partitioned")
                def __exit__(self, *args): actions.append("restored")
            def request(address, ca, token, method, path):
                if path.endswith("sdk-lag"):
                    return 200, {"data": {"data": {"marker": "lagged"}, "metadata": {"version": 2}}}, None, None
                return (200 if failure == "mutation" else 404), {}, None, None
            with patch.object(subject.server, "ready_cluster", return_value=(0, "cluster")), \
                 patch.object(subject.relay_module, "Relay", Relay), patch.object(subject, "Session", Session), \
                 patch.object(subject.lag, "RaftPartition", Partition), patch.object(subject.server, "request", side_effect=request), \
                 patch.object(Path, "read_text", return_value="public CA"):
                def run(): subject.probe(Path("/test"), 1000, 1000, ["a", "b", "c"], ["d", "e", "f"],
                                        ["n1", "n2", "n3"], Path("ca"), Path("tls"), "synthetic-token", "podman", "a" * 32, {}, "independent")
                if failure:
                    with self.assertRaises(subject.server.harness.HarnessError): run()
                else: run()
            self.assertIn("child-closed", actions)
            self.assertIn("relay-closed", actions)
            if "partitioned" in actions: self.assertIn("restored", actions)
            if not failure:
                self.assertLess(actions.index("/v1/fixture-kv/data/sdk-lag"), actions.index("restored"))

    def test_sources_bound_and_no_report_on_failure(self):
        inputs = subject.input_hashes()
        for path in ("scripts/consistency_tls_relay.py", "scripts/openbao_2_7_consistency_lag.py",
                     "src/client/consistency/live.rs", "src/client.rs", "Cargo.lock"):
            self.assertIn(path, inputs)
        with patch.object(subject, "run", side_effect=subject.server.harness.HarnessError("synthetic-private-detail")), \
             patch.object(subject.tempfile, "NamedTemporaryFile") as output, \
             patch("sys.argv", ["fixture", "--test-binary", "/test"]), contextlib.redirect_stdout(io.StringIO()) as messages:
            self.assertEqual(subject.main(), 1)
        output.assert_not_called()
        self.assertNotIn("synthetic-private-detail", messages.getvalue())

    def test_independent_node_requires_distinct_identity_and_registers_cleanup_before_start(self):
        for identity in ("independent", "original", "", None):
            resources = []
            with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
                def mock(obj, name, **kwargs): return stack.enter_context(patch.object(obj, name, **kwargs))
                def command(*args, **kwargs):
                    self.assertEqual(len(resources), 1)
                    return b"{}"
                mock(subject.server.harness, "run_bounded", side_effect=command)
                mock(subject.server.snapshots, "validate_container_resource_config")
                mock(subject.server.fixture, "verify_network")
                mock(subject.server.harness, "parse_port", return_value=18200)
                mock(subject.server.fixture, "wait_for_health")
                mock(subject.server.fixture, "probe_tls")
                initialize = mock(subject.server, "initialize_cluster")
                mock(subject.server, "request", return_value=(200, {"version": "2.7.0", "initialized": True,
                     "sealed": False, "standby": False, "cluster_id": identity}, None, None))
                def run():
                    return subject.independent_cluster("podman", "image", "network", "a" * 32,
                        Path(directory), Path("tls"), Path("ca"), ["10.88.0.10", "10.88.0.11", "10.88.0.12"],
                        {"subnets": [{"subnet": "10.88.0.0/24", "gateway": "10.88.0.1"}]}, {}, resources, "original")
                if identity == "independent":
                    self.assertEqual(run(), "https://127.0.0.1:18200")
                else:
                    with self.assertRaises(subject.server.harness.HarnessError): run()
                initialize.assert_called_once_with(["https://127.0.0.1:18200"], ["10.88.0.13"], Path("ca"))

    def test_runner_keeps_cleanup_and_captured_baseline_provenance(self):
        for fails in (False, True):
            removed = []
            with contextlib.ExitStack() as stack:
                def mock(obj, name, **kwargs): return stack.enter_context(patch.object(obj, name, **kwargs))
                stack.enter_context(patch.dict(subject.os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}))
                mock(subject.os, "geteuid", return_value=0)
                mock(subject.pwd, "getpwuid", return_value=SimpleNamespace(pw_gid=1000))
                mock(subject.sdk, "binary_hash", return_value="digest")
                mock(subject.sdk, "input_hashes", return_value={"baseline": "hash"})
                mock(subject, "input_hashes", return_value={"baseline": "hash", "controlled": "hash"})
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
                baseline = mock(subject.sdk, "run_test")
                def independent(*args):
                    args[-2].append(("container", "independent"))
                    return "https://127.0.0.1:18201"
                mock(subject, "independent_cluster", side_effect=independent)
                mock(subject, "probe", side_effect=subject.server.harness.HarnessError("probe failure") if fails else None)
                mock(subject.server.harness, "remove_owned_resource", side_effect=lambda p, kind, *args: removed.append(kind))
                mock(subject.server.harness, "cleanup_private_files", return_value=True)
                with contextlib.redirect_stdout(io.StringIO()):
                    if fails:
                        with self.assertRaises(subject.server.harness.HarnessError): subject.run.__wrapped__(Path("/test"))
                    else:
                        old, new = subject.run.__wrapped__(Path("/test"))
                        self.assertEqual(old["inputs"], {"baseline": "hash"})
                        self.assertIs(old["controlled_replication_lag_verified"], False)
                        self.assertIs(new["routable"], False)
                baseline.assert_called_once()
            self.assertEqual(removed, ["container"] * 4 + ["network"])


if __name__ == "__main__":
    unittest.main()
