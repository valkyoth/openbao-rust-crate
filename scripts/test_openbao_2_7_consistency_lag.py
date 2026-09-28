#!/usr/bin/python3 -EsSB
"""Offline regressions for scoped Raft fault injection and its evidence claims."""

import contextlib
import copy
import io
from pathlib import Path
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import openbao_2_7_consistency_lag as subject
import verify_openbao_2_7_consistency_lag as evidence

RUN = "a" * 32
ENV = {"PATH": "/usr/bin:/bin"}


class LagTests(unittest.TestCase):
    def test_retained_evidence_rejects_stale_inputs_and_inflated_claims(self):
        original = evidence.verify()
        for field, value in (("routable", True), ("routable", 0), ("sdk_controlled_lag_verified", True),
                             ("expiry_listener_wait_ms", 10000), ("recovery_listener_wait_ms", 250),
                             ("scope", "sdk-controlled-lag"), ("checks", [])):
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

    def test_distinct_bounded_recovery_listener_preserves_short_expiry_and_tls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = subject.write_config(root, 0, "10.88.0.10")
            text = config.read_text(encoding="ascii")
            self.assertIn('consistency_max_index_wait = "250ms"', text)
            self.assertIn('consistency_max_index_wait = "10s"', text)
            self.assertEqual(text.count('tls_min_version = "tls13"'), 2)
            self.assertEqual(text.count('consistency_fallback_behavior = "fail"'), 2)
            self.assertIn('address = "0.0.0.0:8202"', text)
            self.assertEqual(config.stat().st_mode & 0o777, 0o640)
            command = subject.container_command("podman", "image", "node", "network", RUN, config, root / "tls", "10.88.0.10")
            self.assertIn("127.0.0.1::8202", command)
            self.assertIn("127.0.0.1::8200", command)

    def test_namespace_requires_running_owned_container_and_confined_mount_path(self):
        info = {"Name": "fixture", "Config": {"Labels": {subject.server.harness.OWNER_LABEL: RUN}},
                "State": {"Running": True}, "NetworkSettings": {"SandboxKey": "/run/netns/netns-fixture"}}
        self.assertEqual(subject.namespace_path(info, "fixture", RUN), Path("/run/netns/netns-fixture"))
        for path in ("/proc/1/ns/net", "/run/netns/../host", "/run/netns/netns-a/extra", "/tmp/netns-fixture", None):
            changed = copy.deepcopy(info)
            changed["NetworkSettings"]["SandboxKey"] = path
            with self.assertRaises(subject.server.harness.HarnessError): subject.namespace_path(changed, "fixture", RUN)
        for key, value in (("Name", "other"), ("Name", None), ("Config", None), ("State", {"Running": 1}),
                           ("Config", {"Labels": {subject.server.harness.OWNER_LABEL: "other"}})):
            changed = copy.deepcopy(info)
            changed[key] = value
            with self.assertRaises(subject.server.harness.HarnessError): subject.namespace_path(changed, "fixture", RUN)

    def test_pinned_namespace_only_firewall_and_cleanup(self):
        for failure in (None, "body", "host", "parent", "changed", "install", "restore"):
            calls = []
            def run(command, **kwargs):
                calls.append((command, kwargs))
                if failure == "install" or (failure == "restore" and len(calls) == 2):
                    return SimpleNamespace(returncode=1)
                return SimpleNamespace(returncode=0)
            with contextlib.ExitStack() as stack:
                def mock(obj, name, **kwargs): return stack.enter_context(patch.object(obj, name, **kwargs))
                mock(subject.server.evidence_tools, "protected_path", side_effect=lambda path: path)
                mock(subject.RaftPartition, "inspect", return_value=Path("/run/netns/netns-fixture"))
                mock(Path, "lstat", return_value=SimpleNamespace(st_mode=0o40777 if failure == "parent" else 0o40755, st_uid=0))
                opened = mock(subject.os, "open", return_value=42)
                closed = mock(subject.os, "close")
                mock(subject.os, "fstat", return_value=SimpleNamespace(st_mode=0o100444, st_uid=0, st_dev=10, st_ino=20))
                mock(subject.os, "stat", return_value=SimpleNamespace(st_dev=10, st_ino=20 if failure == "host" else 21))
                mock(Path, "stat", return_value=SimpleNamespace(st_dev=10, st_ino=22 if failure == "changed" else 20))
                mock(subject.subprocess, "run", side_effect=run)
                def operation():
                    with subject.RaftPartition("podman", "fixture", RUN, ENV):
                        if failure == "body": raise subject.server.harness.HarnessError("test failure")
                if failure:
                    with self.assertRaises(subject.server.harness.HarnessError): operation()
                else: operation()
                if failure == "parent":
                    opened.assert_not_called()
                    closed.assert_not_called()
                else: closed.assert_called_once_with(42)
            if failure in ("host", "parent", "changed"):
                self.assertEqual(calls, [])
                continue
            command, options = calls[0]
            self.assertEqual(command, ["/usr/bin/nsenter", "--net=/proc/self/fd/42", "/usr/sbin/nft", "-f", "-"])
            self.assertEqual(options["pass_fds"], (42,))
            self.assertEqual(options["timeout"], 10)
            body = options["input"].decode()
            self.assertNotIn("flush", body)
            self.assertNotIn("8200", body)
            self.assertEqual(body.count("8201 drop"), 4)
            if failure != "install": self.assertEqual(calls[-1][1]["input"], f"delete table inet openbao_fixture_{RUN}\n".encode())

    def test_probe_requires_observed_staleness_and_successful_await_recovery(self):
        for failure in (None, "not-stale", "wrong-status", "recovery-timeout", "mutated"):
            restored = threading.Event()
            calls = []
            awaits = []
            class Partition:
                def __init__(self, *args): pass
                def __enter__(self): return self
                def restore(self): restored.set()
                def __exit__(self, *args): self.restore()
            def read(marker, version): return {"data": {"data": {"marker": marker}, "metadata": {"version": version}}}
            def request(address, ca, token, method, path, payload=None, index=None, policies=(), *, timeout=5):
                self.assertEqual(timeout, 15 if address == "recovery-follower" else 5)
                calls.append((address, method, index, policies))
                if method == "POST" and index is None: return 200, {"data": {"version": 2}}, "real-index", None
                if address == "leader": return 200, read("lagged", 3 if failure == "mutated" else 2), None, None
                if index is None:
                    return 200, read("lagged", 2) if failure == "not-stale" else read("initial", 1), None, None
                if policies == ("await-state", "fail"):
                    awaits.append(True)
                    if len(awaits) == 2:
                        self.assertEqual(address, "recovery-follower")
                        self.assertTrue(restored.wait(2))
                        return (429 if failure == "recovery-timeout" else 200), read("lagged", 2), None, None
                return (400 if failure == "wrong-status" else 429), {}, None, "1"
            with patch.object(subject.server, "ready_cluster", return_value=(0, "cluster")), \
                 patch.object(subject, "RaftPartition", Partition), \
                 patch.object(subject.server, "request", side_effect=request), \
                 patch.object(subject.server, "index_value"), \
                 patch.object(subject.time, "monotonic", side_effect=[0, 0.25]), \
                 contextlib.redirect_stdout(io.StringIO()):
                if failure:
                    with self.assertRaises(subject.server.harness.HarnessError):
                        subject.probe(["leader", "follower", "other"], ["a", "b", "c"], Path("ca"), "synthetic-token", "podman", RUN, ENV,
                                      ["recovery-leader", "recovery-follower", "recovery-other"])
                else:
                    subject.probe(["leader", "follower", "other"], ["a", "b", "c"], Path("ca"), "synthetic-token", "podman", RUN, ENV,
                                  ["recovery-leader", "recovery-follower", "recovery-other"])
            self.assertTrue(restored.is_set())
            self.assertEqual(sum(method == "POST" and index is None for _, method, index, _ in calls), 1)

    def test_failure_produces_no_evidence_or_private_diagnostics(self):
        with patch.object(subject, "run", side_effect=subject.server.harness.HarnessError("synthetic-private-detail")), \
             patch.object(subject.tempfile, "NamedTemporaryFile") as output, \
             patch("sys.argv", ["fixture"]), contextlib.redirect_stdout(io.StringIO()) as messages:
            self.assertEqual(subject.main(), 1)
        output.assert_not_called()
        self.assertNotIn("synthetic-private-detail", messages.getvalue())

    def test_runner_cleans_up_partial_setup_and_fault_injection_failure(self):
        for failure in (None, "network", "start", "probe", "cleanup", "changed-inputs"):
            removed = []
            def run(command, **kwargs):
                if failure == "network" and command[1:3] == ["network", "create"]:
                    raise subject.server.harness.HarnessError("network failure")
                if failure == "start" and command[1] == "run":
                    raise subject.server.harness.HarnessError("start failure")
                return b'{"subnets":[{"subnet":"10.88.0.0/24","gateway":"10.88.0.1"}]}'
            def remove(podman, kind, name, run_id, environment):
                removed.append(kind)
                self.assertTrue(name.endswith(run_id))
                if failure == "cleanup": raise subject.server.harness.HarnessError("cleanup failure")
            with contextlib.ExitStack() as stack:
                def mock(obj, name, **kwargs): return stack.enter_context(patch.object(obj, name, **kwargs))
                mock(subject.os, "geteuid", return_value=0)
                mock(subject, "input_hashes", side_effect=[{}, {"changed": "hash"}] if failure == "changed-inputs" else [{}, {}])
                mock(subject.server.staged, "verify")
                mock(subject.server.staged, "verify_image_signature")
                mock(subject.server.evidence_tools, "protected_path", side_effect=lambda path: path)
                mock(subject.server.harness, "generate_tls", side_effect=lambda root, *args: (root / "tls", root / "ca"))
                mock(subject.server.harness, "inspect_image", return_value="pinned-image")
                mock(subject.server.harness, "run_bounded", side_effect=run)
                mock(subject.server.snapshots, "validate_container_resource_config")
                mock(subject.server.fixture, "verify_network")
                mock(subject.server.harness, "parse_port", return_value=18200)
                mock(subject.server.fixture, "wait_for_health")
                mock(subject.server.fixture, "probe_tls")
                mock(subject.server, "initialize_cluster", return_value="synthetic-token")
                mock(subject.server, "probe")
                mock(subject.server, "ready_cluster", return_value=(0, "cluster"))
                mock(subject, "probe", side_effect=subject.server.harness.HarnessError("probe failure") if failure == "probe" else None)
                mock(subject.server.harness, "remove_owned_resource", side_effect=remove)
                mock(subject.server.harness, "cleanup_private_files", return_value=True)
                with contextlib.redirect_stdout(io.StringIO()):
                    if failure:
                        with self.assertRaises(subject.server.harness.HarnessError): subject.run()
                    else:
                        result = subject.run()
                        self.assertIs(result["routable"], False)
                        self.assertIs(result["sdk_controlled_lag_verified"], False)
            expected = ["network"] if failure == "network" else (["container", "network"] if failure == "start" else ["container"] * 3 + ["network"])
            self.assertEqual(removed, expected)


if __name__ == "__main__":
    unittest.main()
