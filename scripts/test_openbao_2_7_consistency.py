#!/usr/bin/python3 -EsSB
"""Offline tests for the staged three-node consistency protocol fixture."""

import contextlib
import copy
from email.message import Message
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import openbao_2_7_consistency as subject
import verify_openbao_2_7_consistency as evidence


class ConsistencyFixtureTests(unittest.TestCase):
    def test_retained_evidence_rejects_changed_inputs_and_overstated_claims(self):
        original = evidence.verify()
        for field, value in (("sdk_live_verified", True), ("controlled_replication_lag_verified", True),
                             ("routable", True), ("routable", 0), ("nodes", 1),
                             ("checks", []), ("scope", "sdk-integration")):
            changed = copy.deepcopy(original)
            changed[field] = value
            with self.assertRaises(subject.harness.HarnessError):
                evidence.validate_report(changed)
        for path in subject.INPUTS:
            for omit in (True, False):
                changed = copy.deepcopy(original)
                if omit:
                    del changed["inputs"][path]
                else:
                    changed["inputs"][path] = "0" * 64
                with self.assertRaises(subject.harness.HarnessError):
                    evidence.validate_report(changed)
        with patch.object(evidence, "EXPECTED_SHA256", "0" * 64):
            with self.assertRaises(subject.snapshots.SnapshotError):
                evidence.verify()

    def test_only_exact_kv_initialization_errors_allow_setup_retry(self):
        for message in subject.KV_INITIALIZING_ERRORS:
            response = {"errors": [message]}
            self.assertTrue(subject.kv_initializing(400, response))
            self.assertEqual(subject.failure_category(response), "kv-initializing")
            for status in (200, 403, 429, 500):
                self.assertFalse(subject.kv_initializing(status, response))
            for body in ({"errors": [message + " extra"]}, {"errors": [message, "other"]},
                         {"errors": [message], "extra": True}, {"errors": message}, None, []):
                self.assertFalse(subject.kv_initializing(400, body))

    def test_kv_initialization_cannot_retry_forever_or_produce_success(self):
        real = subject.base64.b64encode(b'{"cluster":"fixture","value":"100"}').decode()
        reads = []
        def request(address, ca, token, method, path, payload=None, index=None, policies=()):
            if path.endswith("/configuration"):
                return 200, {"data": {"config": {"servers": [{"node_id": f"fixture-{i}", "voter": True} for i in range(3)]}}}, None, None
            if path == "/v1/sys/mounts/fixture-kv": return 204, {}, None, None
            if method == "POST": return 200, {"data": {"version": 1}}, real, None
            reads.append((address, method, index, policies))
            return 400, {"errors": [subject.KV_INITIALIZING_ERRORS[0]]}, None, None
        with patch.object(subject, "ready_cluster", return_value=(0, "fixture")), \
             patch.object(subject, "request", side_effect=request), \
             patch.object(subject.time, "sleep") as sleep, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(subject.harness.HarnessError, "standby did not apply"):
                subject.probe(["leader", "standby-a", "standby-b"], Path("ca"), "synthetic-token")
        self.assertEqual(reads, [("standby-a", "GET", real, ("await-state", "fail"))] * 120)
        self.assertEqual(sleep.call_count, 120)

    def test_failure_classification_never_returns_server_content(self):
        for message, expected in (
            ('failed to decode "X-Vault-Index": synthetic-private-detail', "index-decode"),
            ('unknown second value for "X-Vault-Inconsistent": synthetic-private-detail', "policy-fallback"),
            ('unknown value for "X-Vault-Inconsistent" header', "policy-first-value"),
            ('unsupported path: synthetic-private-detail', "unsupported-route"),
            ('synthetic-private-detail', "unclassified"),
        ):
            self.assertEqual(subject.failure_category({"errors": [message]}), expected)
        for response in (None, [], {}, {"errors": "secret"}, {"errors": [None]}, {"errors": ["x"] * 9}):
            self.assertEqual(subject.failure_category(response), "unclassified")

    def test_network_addresses_are_bounded_private_and_do_not_use_gateway(self):
        config = {"subnets": [{"subnet": "10.88.0.0/24", "gateway": "10.88.0.1"}]}
        self.assertEqual(subject.node_addresses(config), ["10.88.0.10", "10.88.0.11", "10.88.0.12"])
        for subnet in ("127.0.0.0/24", "8.8.8.0/24", "10.88.0.0/30", "::/0", "invalid"):
            with self.assertRaises((subject.harness.HarnessError, ValueError)):
                subject.node_addresses({"subnets": [{"subnet": subnet}]})
        for config in ({}, {"subnets": []}, {"subnets": [{"subnet": "10.88.0.0/24", "gateway": "10.88.0.10"}]}):
            with self.assertRaises(subject.harness.HarnessError):
                subject.node_addresses(config)

    def test_config_and_command_preserve_isolation_and_raft_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = subject.write_config(root, 0, "10.88.0.10")
            text = config.read_text()
            self.assertIn('disable_standby_reads = false', text)
            self.assertIn('consistency_max_index_wait = "250ms"', text)
            self.assertIn('tls_min_version = "tls13"', text)
            self.assertEqual(config.stat().st_mode & 0o777, 0o640)
            command = subject.container_command("podman", "pinned-image", "node", "network", "id", config, root / "tls", "10.88.0.10")
            for value in ("--read-only", "no-new-privileges", "--cap-drop", "all", "--memory", "--cpus", "127.0.0.1::8200"):
                self.assertIn(value, command)
            self.assertIn("/raft:rw,noexec,nosuid,nodev,size=128m,mode=0770", command)
            self.assertEqual(command[command.index("--user") + 1], "100:0")
            raft = next(value for value in command if value.startswith("/raft:"))
            self.assertNotIn("uid=", raft)
            self.assertNotIn("gid=", raft)
            self.assertIn(f"{root / 'tls'}:/openbao/tls:ro,z", command)

    def test_headers_are_separate_no_proxy_redirect_and_reads_bounded(self):
        calls = []
        headers = Message()
        headers["Content-Type"] = "application/json"
        class Response:
            status = 200
            def __init__(self): self.headers = headers
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size):
                calls.append(("read", size))
                return b"{}"
            def getheader(self, key): return None
        class Connection:
            def putrequest(self, *args, **kwargs): calls.append(("request", args))
            def putheader(self, *args): calls.append(("header", args))
            def endheaders(self, body): calls.append(("body", body))
            def getresponse(self): return Response()
            def close(self): calls.append(("close",))
        with patch.object(subject.fixture, "context", return_value="verified-context"), \
             patch.object(subject.http.client, "HTTPSConnection", return_value=Connection()) as factory:
            result = subject.request("https://127.0.0.1:18200", Path("ca"), "synthetic-token", "GET", "/v1/fixture",
                                     policies=("await-state", "fail"))
        factory.assert_called_once_with("127.0.0.1", 18200, timeout=5, context="verified-context")
        self.assertEqual(result, (200, {}, None, None))
        self.assertIn(("header", ("X-Vault-Inconsistent", "await-state")), calls)
        self.assertIn(("header", ("X-Vault-Inconsistent", "fail")), calls)
        self.assertIn(("read", subject.fixture.MAX_BODY + 1), calls)
        self.assertEqual(calls[-1], ("close",))

    def test_invalid_target_or_header_rejected_before_connecting(self):
        with patch.object(subject.http.client, "HTTPSConnection") as connection:
            for address in ("http://127.0.0.1:18200", "https://example.org", "https://user@127.0.0.1:18200", "https://127.0.0.1:18200/path"):
                with self.assertRaises(subject.harness.HarnessError):
                    subject.request(address, Path("ca"), "", "GET", "/v1/test")
            with self.assertRaises(subject.harness.HarnessError):
                subject.request("https://127.0.0.1:18200", Path("ca"), "bad\r\nvalue", "GET", "/v1/test")
            connection.assert_not_called()

    def test_timeout_bounds_and_timeout_diagnostics(self):
        with patch.object(subject.http.client, "HTTPSConnection") as connection:
            for timeout in (0, 31, -1, True, 1.5, "30"):
                with self.assertRaises(subject.harness.HarnessError):
                    subject.request("https://127.0.0.1:18200", Path("ca"), "", "GET", "/v1/test", timeout=timeout)
            connection.assert_not_called()
        with patch.object(subject.fixture, "context", return_value=None), \
             patch.object(subject.http.client, "HTTPSConnection") as connection, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            connection.return_value.getresponse.side_effect = TimeoutError("synthetic-private-detail")
            with self.assertRaises(subject.harness.HarnessError):
                subject.request("https://127.0.0.1:18200", Path("ca"), "", "PUT", "/v1/sys/init", timeout=30)
            self.assertEqual(connection.call_args.kwargs["timeout"], 30)
            connection.return_value.close.assert_called_once()
        self.assertEqual(output.getvalue(), "Consistency fixture: request diagnostic=timeout\n")

    def test_initialization_order_and_long_timeouts_are_limited_to_ceremony(self):
        calls = []
        def request(address, ca, token, method, path, payload=None, **kwargs):
            calls.append((address, path, kwargs.get("timeout", 5)))
            if path == "/v1/sys/init":
                return 200, {"keys_base64": ["synthetic-share"], "root_token": "synthetic-token"}, None, None
            if path.endswith("/join"):
                self.assertFalse(payload["retry"])
                self.assertEqual(payload["leader_tls_servername"], "127.0.0.1")
                return 200, {"joined": True}, None, None
            if path.endswith("/unseal"):
                self.assertEqual(payload["key"], "synthetic-share")
                return 200, {"sealed": False}, None, None
            return 200, {}, None, None
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca"
            ca.write_text("public fixture certificate", encoding="ascii")
            with patch.object(subject, "request", side_effect=request), contextlib.redirect_stdout(io.StringIO()):
                result = subject.initialize_cluster(["a", "b", "c"], ["10.0.0.10", "10.0.0.11", "10.0.0.12"], ca)
        self.assertEqual(result, "synthetic-token")
        self.assertEqual(calls, [
            ("a", "/v1/sys/init", 30), ("a", "/v1/sys/unseal", 30), ("a", "/v1/sys/health", 5),
            ("b", "/v1/sys/storage/raft/join", 30), ("b", "/v1/sys/unseal", 30),
            ("c", "/v1/sys/storage/raft/join", 30), ("c", "/v1/sys/unseal", 30),
        ])

    def test_raft_index_schema_cluster_and_uint64_are_checked(self):
        def encode(data):
            return subject.base64.b64encode(subject.json.dumps(data).encode()).decode()
        subject.index_value(encode({"cluster": "fixture", "value": str(2**64 - 1)}), "fixture")
        for data in ({}, {"cluster": "other", "value": "1"}, {"cluster": "fixture", "value": str(2**64)},
                     {"cluster": "fixture", "value": "-1"}, {"cluster": "fixture", "value": 1},
                     {"cluster": "fixture", "value": "1", "extra": 0}):
            with self.assertRaises(subject.harness.HarnessError):
                subject.index_value(encode(data), "fixture")

    def test_protocol_probe_distinguishes_real_propagation_from_synthetic_failure(self):
        calls = []
        initializing = list(subject.KV_INITIALIZING_ERRORS)
        real = subject.base64.b64encode(b'{"cluster":"fixture","value":"100"}').decode()
        read = {"data": {"data": {"marker": "initial"}, "metadata": {"version": 1}}}
        def request(address, ca, token, method, path, payload=None, index=None, policies=()):
            calls.append((address, method, path, index, policies))
            if path == "/v1/sys/storage/raft/configuration":
                return 200, {"data": {"config": {"servers": [{"node_id": f"fixture-{i}", "voter": True} for i in range(3)]}}}, None, None
            if path == "/v1/sys/mounts/fixture-kv": return 204, {}, None, None
            if method == "POST" and index is None: return 200, {"data": {"version": 1}}, real, None
            if address == "standby-a" and index == real and initializing:
                return 400, {"errors": [initializing.pop()]}, None, None
            if policies == ("await-state,fail",): return 400, {}, None, None
            if index and index != real and policies in (("fail",), ("await-state", "fail")):
                return 429, {}, None, "1"
            return 200, read, None, None
        with patch.object(subject, "ready_cluster", return_value=(0, "fixture")), \
             patch.object(subject, "request", side_effect=request), \
             patch.object(subject.time, "sleep"), \
             patch.object(subject.time, "monotonic", side_effect=[0, 0.25]), \
             contextlib.redirect_stdout(io.StringIO()):
            subject.probe(["leader", "standby-a", "standby-b"], Path("ca"), "synthetic-token")
        self.assertTrue(any(call[0] == "standby-b" and call[3] == real for call in calls))
        self.assertEqual(initializing, [])
        self.assertEqual(sum(call[1] == "POST" and call[3] is not None for call in calls), 1)
        self.assertEqual(calls[-1][0:2], ("leader", "GET"))

    def test_no_report_or_error_detail_on_failure(self):
        with patch.object(subject, "run", side_effect=subject.harness.HarnessError("synthetic-sensitive-detail")), \
             patch.object(subject.tempfile, "NamedTemporaryFile") as output, \
             patch("sys.argv", ["fixture"]), contextlib.redirect_stdout(io.StringIO()) as text:
            self.assertEqual(subject.main(), 1)
        output.assert_not_called()
        self.assertNotIn("synthetic-sensitive-detail", text.getvalue())

    def test_real_index_failure_remains_failure_after_read_only_diagnostics(self):
        real = subject.base64.b64encode(b'{"cluster":"fixture","value":"100"}').decode()
        calls = []
        def request(address, ca, token, method, path, payload=None, index=None, policies=()):
            calls.append((address, method, path))
            if path.endswith("/configuration"):
                return 200, {"data": {"config": {"servers": [{"node_id": f"fixture-{i}", "voter": True} for i in range(3)]}}}, None, None
            if path == "/v1/sys/mounts/fixture-kv": return 204, {}, None, None
            if method == "POST": return 200, {"data": {"version": 1}}, real, None
            return 400, {"errors": ['unknown value for "X-Vault-Inconsistent" header: synthetic-sensitive-detail']}, None, None
        with patch.object(subject, "ready_cluster", return_value=(0, "fixture")), \
             patch.object(subject, "request", side_effect=request), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(subject.harness.HarnessError):
                subject.probe(["leader", "standby-a", "standby-b"], Path("ca"), "synthetic-token")
        self.assertEqual([call[:2] for call in calls[-3:]], [("standby-a", "GET"), ("leader", "GET"), ("standby-a", "GET")])
        self.assertIn("real-index diagnostic=policy-first-value", output.getvalue())
        self.assertNotIn("synthetic-sensitive-detail", output.getvalue())

    def test_run_attempts_all_cleanup_and_never_promotes_or_claims_lag_proof(self):
        for failure in (None, "network", "start", "probe", "cleanup", "changed-inputs"):
            removed = []
            def run(command, **kwargs):
                if failure == "network" and command[1:3] == ["network", "create"]:
                    raise subject.harness.HarnessError("network failure")
                if failure == "start" and command[1] == "run":
                    raise subject.harness.HarnessError("start failure")
                if command[1:3] == ["network", "inspect"]:
                    return b'{"subnets":[{"subnet":"10.88.0.0/24","gateway":"10.88.0.1"}]}'
                return b"{}"
            def remove(podman, kind, name, run_id, environment):
                removed.append(kind)
                self.assertTrue(name.endswith(run_id))
                self.assertNotIn("CONTAINER_HOST", environment)
                if failure == "cleanup": raise subject.harness.HarnessError("cleanup failure")
            with contextlib.ExitStack() as stack:
                def mock(obj, name, **kwargs): return stack.enter_context(patch.object(obj, name, **kwargs))
                mock(subject.staged, "verify")
                mock(subject.staged, "verify_image_signature")
                mock(subject.evidence_tools, "protected_path", side_effect=lambda path: path)
                mock(subject.harness, "generate_tls", side_effect=lambda root, *args: (root / "tls", root / "ca"))
                mock(subject.harness, "inspect_image", return_value="pinned-image")
                mock(subject.harness, "run_bounded", side_effect=run)
                mock(subject.snapshots, "validate_container_resource_config")
                mock(subject.fixture, "verify_network")
                mock(subject.harness, "parse_port", return_value=18200)
                mock(subject.fixture, "wait_for_health")
                mock(subject.fixture, "probe_tls")
                mock(subject, "initialize_cluster", return_value="synthetic-token")
                mock(subject, "probe", side_effect=subject.harness.HarnessError("probe failure") if failure == "probe" else None)
                mock(subject.harness, "remove_owned_resource", side_effect=remove)
                mock(subject.harness, "cleanup_private_files", return_value=True)
                mock(subject, "input_hashes", side_effect=[{}, {"changed": "hash"}] if failure == "changed-inputs" else [{}, {}])
                with contextlib.redirect_stdout(io.StringIO()):
                    if failure:
                        with self.assertRaises(subject.harness.HarnessError): subject.run()
                    else:
                        result = subject.run()
                        self.assertIs(result["routable"], False)
                        self.assertIs(result["sdk_live_verified"], False)
                        self.assertIs(result["controlled_replication_lag_verified"], False)
                        self.assertEqual(result["nodes"], 3)
            expected = ["network"] if failure == "network" else (["container", "network"] if failure == "start" else ["container"] * 3 + ["network"])
            self.assertEqual(removed, expected)


if __name__ == "__main__":
    unittest.main()
