#!/usr/bin/python3 -EsSB
"""Offline regression tests for the staged external-key fixture."""

import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import openbao_2_7_external_keys as subject
import verify_openbao_2_7_external_keys as retained


class ExternalKeyFixtureTests(unittest.TestCase):
    def test_retained_report_rejects_scope_changes_omissions_and_stale_inputs(self):
        report = retained.verify()
        for field, value in (("version", "2.6.3"), ("outcome", "failed"), ("routable", True),
                             ("routable", 0), ("pkcs11_verified", True), ("pkcs11_verified", 0),
                             ("scope", "sdk-integration"), ("tls", "TLSv1.2"),
                             ("checks", report["checks"][:-1]), ("inputs", {}),
                             ("image_linux_amd64_digest", "sha256:" + "0" * 64)):
            changed = dict(report, **{field: value})
            with self.assertRaises(subject.snapshots.SnapshotError):
                retained.validate_report(changed, subject.input_hashes())
        for field in report:
            changed = dict(report)
            del changed[field]
            with self.assertRaises(subject.snapshots.SnapshotError):
                retained.validate_report(changed, subject.input_hashes())
        with self.assertRaises(subject.snapshots.SnapshotError):
            retained.validate_report(dict(report, unexpected="field"), subject.input_hashes())

    def test_retained_file_rejects_reencoded_or_modified_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(subject.snapshots.read_regular_file(retained.RESULT, 64 * 1024) + b" ")
            with patch.object(retained, "RESULT", path), self.assertRaises(subject.snapshots.SnapshotError):
                retained.verify()

    def test_denial_requires_specific_grant_error(self):
        for status in (400, 403, 500):
            subject.require_grant_denial(status, {"errors": ['mount "denied/" is missing grant for key "provider:key"']})
        for status, body in ((200, {"errors": ["missing grant for key"]}),
                             (404, {"errors": ["missing grant for key"]}),
                             (500, {"errors": ["provider unavailable"]}),
                             (403, {"errors": ["permission denied"]}),
                             (400, {"errors": []}), (400, {"errors": [1]}), (400, {})):
            with self.assertRaises(subject.harness.HarnessError):
                subject.require_grant_denial(status, body)

    def test_request_uses_merge_patch_and_no_ambient_proxy(self):
        captured = []

        class Response:
            status = 204
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, limit):
                self.limit = limit
                return b""

        class Opener:
            def open(self, request, timeout):
                captured.append((request, timeout))
                return Response()

        with patch.object(subject.fixture, "context", return_value=None), \
             patch.object(subject.urllib.request, "build_opener", return_value=Opener()) as build:
            subject.request("https://localhost", Path("ca"), "fixture-credential", "PATCH", "/v1/example", {"value": None})
        request, timeout = captured[0]
        self.assertEqual(request.get_header("Content-type"), "application/merge-patch+json")
        self.assertEqual(request.data, b'{"value":null}')
        self.assertEqual(timeout, 5)
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], subject.harness.RejectRedirect)

    def test_missing_resource_requires_exact_error_contract(self):
        for kind, name in (("key", "key"), ("config", "fixture-provider")):
            body = {"errors": [f'{kind} "{name}" not found']}
            subject.require_missing(400, body, kind, name)
            for status, response in ((404, body), (200, body), (400, {}),
                                     (400, {"errors": ["permission denied"]}),
                                     (400, {"errors": ['key "another" not found']})):
                with self.assertRaises(subject.harness.HarnessError):
                    subject.require_missing(status, response, kind, name)

    def test_probe_exercises_lifecycle_and_grant_removal(self):
        calls = []
        config = {"plugin": "transit", "token": "(redacted)"}
        key = {"name": "key", "version": 1}
        plaintext = subject.base64.b64encode(b"checkpoint-four-fixture").decode("ascii")

        def request(address, ca, token, method, path, payload=None):
            calls.append((method, path, payload))
            config_path = "/v1/sys/external-keys/configs/fixture-provider"
            key_path = config_path + "/keys/key"
            if path == "/v1/auth/token/create":
                return 200, {"auth": {"client_token": "fixture-token", "policies": ["fixture-kms-source"]}}
            if path == "/v1/sys/mounts": return 403, {}
            if path in (config_path, key_path):
                target = config if path == config_path else key
                if method == "GET":
                    if target: return 200, {"data": dict(target)}
                    kind, name = ("config", "fixture-provider") if path == config_path else ("key", "key")
                    return 400, {"errors": [f'{kind} "{name}" not found']}
                if method == "PATCH":
                    for name, value in payload.items():
                        if name == "verify": continue
                        if value is None: target.pop(name, None)
                        else: target[name] = value
                if method == "DELETE": target.clear()
                return 204, {}
            if method == "LIST":
                keys = ["fixture-provider"] if path.endswith("configs") else (["key"] if path.endswith("keys") else ["fixture-allowed/"])
                return 200, {"data": {"keys": keys}}
            if path == "/v1/fixture-denied/keys/delegated":
                return 400, {"errors": ["missing grant for key"]}
            if path == "/v1/fixture-allowed/encrypt/delegated":
                if any(m == "DELETE" and p.endswith("grants/fixture-allowed") for m, p, _ in calls):
                    return 500, {"errors": ["missing grant for key"]}
                return 200, {"data": {"ciphertext": "vault:v1:fixture"}}
            if path == "/v1/fixture-allowed/decrypt/delegated": return 200, {"data": {"plaintext": plaintext}}
            if path == "/v1/fixture-source/keys/key" or path == "/v1/fixture-allowed/keys/delegated":
                return 200, {"data": {"name": "key"}}
            return 204, {}

        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca"
            ca.write_text("public fixture CA", encoding="ascii")
            with patch.object(subject, "request", side_effect=request), contextlib.redirect_stdout(io.StringIO()):
                subject.probe("https://localhost", ca, "fixture-root")
        self.assertTrue(any(m == "DELETE" and p.endswith("grants/fixture-allowed") for m, p, _ in calls))
        self.assertTrue(any(m == "PATCH" and body.get("tls_server_name", "absent") is None for m, _, body in calls if body))

    def test_main_never_prints_nested_errors_or_writes_success_on_failure(self):
        output = io.StringIO()
        with patch.object(subject, "run", side_effect=subject.harness.HarnessError("fixture-private-value")), \
             patch.object(subject.tempfile, "NamedTemporaryFile") as write, \
             patch("sys.argv", ["fixture"]), contextlib.redirect_stdout(output):
            self.assertEqual(subject.main(), 1)
        write.assert_not_called()
        self.assertNotIn("fixture-private-value", output.getvalue())

    def test_inputs_bind_current_and_reused_fixture_sources(self):
        hashes = subject.input_hashes()
        self.assertIn("scripts/openbao_2_7_external_keys.py", hashes)
        self.assertIn("scripts/openbao_2_7_tls.py", hashes)
        self.assertIn("scripts/openbao_test_harness.py", hashes)
        self.assertTrue(all(len(value) == 64 for value in hashes.values()))

    def test_run_cleans_resources_and_rejects_failures_or_changed_inputs(self):
        for failure in (None, "network", "container", "health", "probe", "cleanup", "changed-inputs"):
            removed = []
            calls = 0

            def command(*args, **kwargs):
                nonlocal calls
                calls += 1
                if (failure == "network" and calls == 1) or (failure == "container" and calls == 2):
                    raise subject.harness.HarnessError("fixture private detail")
                return b"{}"

            def remove(podman, kind, name, owner, environment):
                removed.append(kind)
                self.assertTrue(name.endswith(owner))
                self.assertNotIn("CONTAINER_HOST", environment)
                if failure == "cleanup":
                    raise subject.harness.HarnessError("cleanup failed")

            def fail_at(stage):
                if failure == stage:
                    raise subject.harness.HarnessError("fixture private detail")

            with contextlib.ExitStack() as stack:
                def mock(obj, name, **kwargs):
                    return stack.enter_context(patch.object(obj, name, **kwargs))
                mock(subject.staged, "verify")
                mock(subject.staged, "verify_image_signature")
                mock(subject.evidence_tools, "protected_path", side_effect=lambda path: path)
                mock(subject.harness, "generate_tls", side_effect=lambda root, *args: (root / "tls", root / "ca"))
                mock(subject.harness, "write_server_config", side_effect=lambda root, *args: root / "config")
                mock(subject.harness, "inspect_image", return_value="pinned-fixture-image")
                mock(subject.harness, "run_bounded", side_effect=command)
                mock(subject.snapshots, "validate_container_resource_config")
                mock(subject.fixture, "verify_network")
                mock(subject.harness, "parse_port", return_value=18200)
                mock(subject.fixture, "wait_for_health", side_effect=lambda *args: fail_at("health"))
                mock(subject.fixture, "probe_tls")
                mock(subject.harness, "initialize_and_unseal", return_value="fixture-token")
                mock(subject, "probe", side_effect=lambda *args: fail_at("probe"))
                mock(subject.harness, "remove_owned_resource", side_effect=remove)
                mock(subject.harness, "cleanup_private_files", return_value=True)
                mock(subject, "input_hashes", side_effect=[{}, {"changed": "hash"}] if failure == "changed-inputs" else [{}, {}])
                with contextlib.redirect_stdout(io.StringIO()):
                    if failure:
                        with self.assertRaises(subject.harness.HarnessError):
                            subject.run()
                    else:
                        result = subject.run()
                        self.assertFalse(result["routable"])
                        self.assertFalse(result["pkcs11_verified"])
                        self.assertEqual(result["checks"], subject.CHECKS)
            self.assertEqual(removed, ["network"] if failure == "network" else ["container", "network"])


if __name__ == "__main__":
    unittest.main()
