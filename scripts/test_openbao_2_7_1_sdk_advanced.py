#!/usr/bin/python3 -EsSB
"""Fail-closed selection, coordination and cleanup for advanced patch evidence."""

from contextlib import ExitStack, redirect_stdout
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import openbao_2_7_1_sdk_advanced as fixture


class AdvancedTests(unittest.TestCase):
    def test_build_refuses_root(self):
        with patch.object(fixture.os, "geteuid", return_value=0), self.assertRaises(fixture.harness.HarnessError):
            fixture.build()

    def test_exact_test_required_before_privilege_dropped_spawn(self):
        with patch.object(fixture.tls.evidence_tools, "protected_path", side_effect=lambda path: path), \
             patch.object(fixture.execution, "test_listing", return_value=b"0 tests, 0 benchmarks\n"), \
             patch.object(fixture.subprocess, "Popen") as spawn:
            session = fixture.Session(Path("/test"), 1000, 1001)
            self.assertIn(fixture.LAG_TEST, session.command)
            self.assertNotIn(fixture.coordination.TEST, session.command)
            for flag in ("--reuid=1000", "--regid=1001", "--no-new-privs", "--clear-groups", "--bounding-set=-all"):
                self.assertIn(flag, session.command)
            with self.assertRaises(fixture.harness.HarnessError):
                session.__enter__()
            spawn.assert_not_called()

    def test_node_requires_limits_isolation_and_both_tls_listeners(self):
        for failure in (None, "start", "limits", "network", "version", "tls"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                root, resources, calls = Path(directory), [], []
                def mock(obj, name, **kwargs):
                    return stack.enter_context(patch.object(obj, name, **kwargs))
                def command(argv, **_):
                    self.assertEqual(resources, [("container", "openbao-271-advanced-0-owner")])
                    calls.append(argv)
                    if len(calls) == 1:
                        if failure == "start": raise fixture.harness.HarnessError("failed")
                        return b""
                    if argv[1] == "inspect": return b"{}"
                    self.assertEqual(argv[1], "port")
                    return b"127.0.0.1:1234\n" if argv[-1] == "8200/tcp" else b"127.0.0.1:1235\n"
                mock(fixture.server.lag, "write_config", return_value=root / "config")
                mock(fixture.server.lag, "container_command", return_value=["podman", "run"])
                mock(fixture.harness, "run_bounded", side_effect=command)
                limits = mock(fixture.base, "validate_container_resource_config",
                              side_effect=fixture.harness.HarnessError("failed") if failure == "limits" else None)
                network = mock(fixture.tls, "verify_network",
                               side_effect=fixture.harness.HarnessError("failed") if failure == "network" else None)
                version = mock(fixture.harness, "wait_for_exact_version",
                               side_effect=fixture.harness.HarnessError("failed") if failure == "version" else None)
                tls = mock(fixture.tls, "probe_tls",
                           side_effect=fixture.harness.HarnessError("failed") if failure == "tls" else None)
                def run():
                    return fixture.start_node("podman", "pinned", "network", "owner", root,
                                              root / "certs", root / "ca", 0, "10.88.0.10", {}, resources)
                if failure:
                    with self.assertRaises(fixture.harness.HarnessError): run()
                else:
                    self.assertEqual(run(), ("openbao-271-advanced-0-owner", "https://127.0.0.1:1234", "https://127.0.0.1:1235"))
                    limits.assert_called_once_with({})
                    network.assert_called_once()
                    self.assertEqual([call.args for call in version.call_args_list], [
                        ("https://127.0.0.1:1234", root / "ca", "2.7.1"),
                        ("https://127.0.0.1:1235", root / "ca", "2.7.1")])
                    self.assertEqual([call.args for call in tls.call_args_list], [(1234, root / "ca"), (1235, root / "ca")])
                self.assertEqual(len(resources), 1)

    def test_report_requires_all_phases_and_stable_source_and_binary(self):
        for mode in ("success", "missing", "duplicate", "test-failure", "cluster-failure", "source-drift", "binary-drift"):
            def server(suite, backup_observer):
                self.assertEqual(suite, "recovery")
                if mode != "missing":
                    backup_observer("https://127.0.0.1:1", Path("/ca"), "disposable")
                if mode == "duplicate":
                    backup_observer("https://127.0.0.1:1", Path("/ca"), "disposable")

            with self.subTest(mode=mode), redirect_stdout(io.StringIO()), \
                 patch.dict(fixture.os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}), \
                 patch.object(fixture.pwd, "getpwuid", return_value=SimpleNamespace(pw_gid=1000)), \
                 patch.object(fixture, "input_hashes", side_effect=[{"source": "a"}, {"source": "b" if mode == "source-drift" else "a"}]), \
                 patch.object(fixture.execution, "binary_hash", side_effect=["a" * 64, ("b" if mode == "binary-drift" else "a") * 64]), \
                 patch.object(fixture.candidate, "verify", return_value={}), \
                 patch.object(fixture.candidate.registry, "rust_output", return_value=b"candidate"), \
                 patch.object(fixture.backups, "run", side_effect=server), \
                 patch.object(fixture.execution, "run_test", side_effect=fixture.harness.HarnessError("failed") if mode == "test-failure" else None) as test, \
                 patch.object(fixture, "run_cluster", side_effect=fixture.harness.HarnessError("failed") if mode == "cluster-failure" else None) as cluster:
                if mode == "success":
                    report = fixture.run.__wrapped__(Path("/test"), strict_candidate=True)
                    self.assertEqual(report["tests"], fixture.TESTS)
                    self.assertEqual(report["features"], fixture.FEATURES)
                    self.assertEqual(report["version"], "2.7.1")
                    self.assertFalse(report["routable"])
                    self.assertFalse(report["backup_decryption_verified"])
                    self.assertEqual(report["executable_storage"], "sealed-memfd")
                    self.assertEqual([call.kwargs["test"] for call in test.call_args_list], [fixture.basic.TEST, fixture.BACKUP_TEST])
                    cluster.assert_called_once()
                else:
                    with self.assertRaises(fixture.harness.HarnessError):
                        fixture.run.__wrapped__(Path("/test"), strict_candidate=True)

    def test_coordination_enforces_transmission_no_retry_and_foreign_cluster_denial(self):
        for failure in (None, "scope-dispatch", "not-transmitted", "retry", "mutation", "child", "cluster-dispatch", "missing-preflight"):
            actions, events = [], []

            class Relay:
                address = "https://127.0.0.1:1"
                def __init__(self, *_): pass
                def __enter__(self): return self
                def __exit__(self, *_): actions.append("relay-closed")
                def snapshot(self): return list(events)
                def switch_cluster(self, _): actions.append("switched")
                def wait_for(self, method, path, **_):
                    actions.append(path)
                    return failure != "not-transmitted"

            class Session:
                def __init__(self, *_): pass
                def __enter__(self): return self
                def __exit__(self, *_): actions.append("child-closed")
                def send(self, data):
                    if data == b"scope\n" and failure == "scope-dispatch":
                        events.append(("GET", "/v1/fixture-kv/data/sdk-lag"))
                    if data == b"switched\n":
                        if failure != "missing-preflight": events.append(("GET", "/v1/sys/health"))
                        if failure == "cluster-dispatch": events.append(("GET", "/v1/fixture-kv/data/sdk-lag"))
                def expect(self, stage):
                    if stage == "cancel-ready":
                        if failure == "child": raise fixture.harness.HarnessError("failed")
                        events.append(("POST", "/v1/fixture-kv/data/sdk-cancel"))
                    if stage == "recovery-ready":
                        events.append(("POST", "/v1/fixture-kv/data/sdk-timeout"))
                        if failure == "retry": events.append(events[-1])
                def finish(self): actions.append("passed")

            class Partition:
                def __init__(self, *_): pass
                def __enter__(self): actions.append("partitioned")
                def __exit__(self, *_): actions.append("restored")

            def request(address, ca, token, method, path):
                if path.endswith("sdk-lag"):
                    return 200, {"data": {"data": {"marker": "lagged"}, "metadata": {"version": 2}}}, None, None
                return (200 if failure == "mutation" else 404), {}, None, None

            with self.subTest(failure=failure), \
                 patch.object(fixture.server, "ready_cluster", return_value=(0, "cluster")), \
                 patch.object(fixture.coordination.relay_module, "Relay", Relay), patch.object(fixture, "Session", Session), \
                 patch.object(fixture.server.lag, "RaftPartition", Partition), \
                 patch.object(fixture.server.protocol, "request", side_effect=request), \
                 patch.object(Path, "read_text", return_value="public CA"):
                def run():
                    fixture.probe(Path("/test"), 1000, 1000, ["a", "b", "c"], ["d", "e", "f"],
                                  ["n1", "n2", "n3"], Path("ca"), Path("tls"), "disposable", "podman", "a" * 32, {}, "independent")
                if failure:
                    with self.assertRaises(fixture.harness.HarnessError): run()
                else: run()
            self.assertIn("child-closed", actions)
            self.assertIn("relay-closed", actions)
            if "partitioned" in actions: self.assertIn("restored", actions)
            if not failure:
                self.assertLess(actions.index("/v1/fixture-kv/data/sdk-lag"), actions.index("restored"))

    def test_cluster_identity_and_cleanup_cannot_be_skipped(self):
        for failure in (None, "same-cluster", "wrong-version", "probe", "cleanup"):
            resources = []
            with self.subTest(failure=failure), ExitStack() as stack:
                stack.enter_context(redirect_stdout(io.StringIO()))
                def mock(obj, name, **kwargs):
                    return stack.enter_context(patch.object(obj, name, **kwargs))
                mock(fixture.server.image_evidence, "verify")
                mock(fixture.patch, "verify_signature")
                mock(fixture.tls.evidence_tools, "protected_path", side_effect=lambda path: path)
                mock(fixture.harness, "generate_tls", side_effect=lambda root, *_: (root / "tls", root / "ca"))
                mock(fixture.harness, "inspect_image", return_value="pinned")
                mock(fixture.harness, "run_bounded", return_value=b'{"subnets":[{"subnet":"10.88.0.0/24","gateway":"10.88.0.1"}]}')
                def start(*args):
                    number, owned = args[7], args[-1]
                    owned.append(("container", f"node-{number}"))
                    return f"node-{number}", f"https://127.0.0.1:{1230 + number}", f"https://127.0.0.1:{1240 + number}"
                nodes = mock(fixture, "start_node", side_effect=start)
                initialize = mock(fixture.server.protocol, "initialize_cluster", return_value="disposable")
                mock(fixture.server, "probe")
                mock(fixture.server, "ready_cluster", return_value=(0, "original"))
                mock(fixture.execution, "run_test")
                mock(fixture.server.protocol, "request", return_value=(200, {"version": "2.7.0" if failure == "wrong-version" else "2.7.1",
                    "initialized": True, "sealed": False, "standby": False, "cluster_id": "original" if failure == "same-cluster" else "other"}, None, None))
                mock(fixture, "probe", side_effect=fixture.harness.HarnessError("failed") if failure == "probe" else None)
                def remove(podman, kind, *_):
                    resources.append(kind)
                    if failure == "cleanup": raise OSError()
                mock(fixture.harness, "remove_owned_resource", side_effect=remove)
                mock(fixture.harness, "cleanup_private_files", return_value=True)
                if failure:
                    with self.assertRaises(fixture.harness.HarnessError): fixture.run_cluster(Path("/test"), 1000, 1000)
                else:
                    fixture.run_cluster(Path("/test"), 1000, 1000)
                self.assertEqual(nodes.call_count, 4)
                self.assertEqual(initialize.call_args.args[1], ["10.88.0.13"])
            self.assertEqual(resources, ["container"] * 4 + ["network"])


if __name__ == "__main__":
    unittest.main()
