#!/usr/bin/python3 -EsSB
"""Staged fixture regressions; mocks never count as live OpenBao evidence."""

import copy
import socket
import threading
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import openbao_2_7_tls as fixture


class FixtureTests(unittest.TestCase):
    def test_network_keeps_publication_without_default_routes_or_dns(self):
        command = fixture.network_command("podman", "fixture", "owner")
        self.assertNotIn("--internal", command)
        self.assertIn("--disable-dns", command)
        self.assertIn("no_default_route=true", command)
        self.assertIn("isolate=strict", command)
        self.assertIn("--label", command)
        connected = b"Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 0000580A 00000000 0001 0 0 0 00FFFFFF 0 0 0\n"
        rejected_ipv6_default = b"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000000 00000000 00200200 lo\n"
        fixture.validate_routes(connected, rejected_ipv6_default)
        for v4, v6 in ((connected.replace(b"0000580A", b"00000000").replace(b"00FFFFFF", b"00000000"), b""),
                       (connected, rejected_ipv6_default.replace(b"00200200", b"00000001")),
                       (b"", b""), (connected + b"bad row\n", b""), (connected, b"bad row")):
            with self.assertRaises(fixture.harness.HarnessError):
                fixture.validate_routes(v4, v6)
        config = b'{"driver":"bridge","dns_enabled":false,"options":{"no_default_route":"true","isolate":"strict"}}'
        with patch.object(fixture.harness, "run_bounded", side_effect=[config, connected, rejected_ipv6_default]):
            fixture.verify_network("podman", "network", "container", {})
        for invalid in (config.replace(b'false', b'true'), config.replace(b'"true"', b'"false"'),
                        config.replace(b'"strict"', b'"false"'), b'{"options":null}'):
            with patch.object(fixture.harness, "run_bounded", return_value=invalid):
                with self.assertRaises(fixture.harness.HarnessError):
                    fixture.verify_network("podman", "network", "container", {})

    def test_startup_diagnostics_do_not_echo_logs(self):
        import contextlib
        import io
        marker = b"test-only-private-marker"
        self.assertEqual(fixture.classify_startup_logs(marker), [])
        self.assertEqual(fixture.classify_startup_logs(marker + b": fatal error: out of memory"), ["allocation-failure"])
        with patch.object(fixture.evidence_tools, "protected_path", return_value=Path("/usr/bin/sh")), \
             patch.object(fixture.harness, "run_bounded", return_value=marker + b": permission denied") as command:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                fixture.startup_diagnostic("/usr/bin/podman", "fixture", {})
            self.assertIn("permission-denied", output.getvalue())
            self.assertNotIn(marker.decode(), output.getvalue())
            self.assertEqual(command.call_args.kwargs["maximum"], 64 * 1024)
            self.assertEqual(command.call_args.args[0][:4], ["/usr/bin/sh", "-c", 'exec "$@" 2>&1', "fixture-logs"])

    def test_readiness_exited_server_fails_immediately(self):
        with patch.object(fixture.harness, "run_bounded", return_value=b'{"Running":false}'), \
             patch.object(fixture, "startup_diagnostic") as diagnostic, \
             patch.object(fixture.harness, "https_json") as http, \
             patch.object(fixture.time, "sleep") as sleep:
            with self.assertRaises(fixture.harness.HarnessError):
                fixture.wait_for_health("podman", "fixture", {}, "address", Path("ca"))
            diagnostic.assert_called_once()
            http.assert_not_called()
            sleep.assert_not_called()

    def test_readiness_version_mismatch_never_retries(self):
        with patch.object(fixture.harness, "run_bounded", return_value=b'{"Running":true}'), \
             patch.object(fixture.harness, "https_json", return_value={"version": "2.6.3"}), \
             patch.object(fixture.time, "sleep") as sleep:
            with self.assertRaises(fixture.harness.VersionMismatch):
                fixture.wait_for_health("podman", "fixture", {}, "address", Path("ca"))
            sleep.assert_not_called()

    def test_container_security_options(self):
        command = fixture.container_command("/usr/bin/podman", "image@sha256:locked", "container", "network", "owner", Path("/tmp/config"), Path("/tmp/tls"))
        for option, value in (("--network", "network"), ("--user", "100:0"), ("--cap-drop", "all"), ("--security-opt", "no-new-privileges"), ("--publish", "127.0.0.1::8200"), ("--pull", "never"), ("--memory", "1g"), ("--memory-swap", "2g"), ("--cpus", "1"), ("--pids-limit", "256")):
            self.assertEqual(command[command.index(option) + 1], value)
        self.assertIn("--read-only", command)
        self.assertNotIn("-dev", command)
        self.assertEqual(command.count("--pids-limit"), 1)

    def test_config_preserves_storage_and_tls(self):
        with tempfile.TemporaryDirectory() as root:
            config = fixture.harness.write_server_config(Path(root), "2.7.0").read_text()
            self.assertIn('storage "inmem"', config)
            self.assertIn('tls_min_version = "tls13"', config)
            self.assertNotIn('tls_disable', config)
            self.assertNotIn('storage "file"', config)

    def test_context_has_only_explicit_roots_and_tls13(self):
        with patch.object(ssl.SSLContext, "load_verify_locations") as load:
            context = fixture.context(Path("/fixture/ca.crt"))
            self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(context.get_ca_certs(), [])
            load.assert_called_once_with(cafile="/fixture/ca.crt")

    @staticmethod
    def responses():
        replies = [(200, {"version": "2.7.0", "initialized": True, "sealed": False}), (403, {}), (204, {}),
                   (200, {"data": {"name": "fixture", "type": "aes256-gcm96", "latest_version": 1}})]
        for _ in range(4):
            replies.extend([(404, {}), (400, {"errors": ["plugin not found in the catalog: fixture"]}), (200, {"data": {}})])
        return replies

    def test_plugin_absence_is_not_a_skipped_success(self):
        with patch.object(fixture, "request", side_effect=self.responses()) as request:
            fixture.probe_server("address", Path("ca"), "test-only-token")
            self.assertEqual(request.call_count, 16)
            paths = [call.args[4] for call in request.call_args_list]
            self.assertIn("/v1/sys/plugins/catalog/auth/kerberos", paths)
            self.assertIn("/v1/sys/plugins/catalog/secret/ldap", paths)

    def test_unexpected_plugin_and_failure_states_fail_closed(self):
        for index, replacement in ((0, (200, {"version": "2.6.3", "initialized": True, "sealed": False})),
                                   (1, (204, {})), (4, (200, {})), (5, (204, {})),
                                   (5, (400, {"errors": ["permission denied"]})),
                                   (5, (400, {"errors": "plugin not found in the catalog"})),
                                   (6, (200, {"data": {"fixture-ldap/": {}}})),
                                   (6, (200, {"data": []}))):
            responses = copy.deepcopy(self.responses())
            responses[index] = replacement
            with self.subTest(index=index, replacement=replacement), patch.object(fixture, "request", side_effect=responses):
                with self.assertRaises(fixture.harness.HarnessError):
                    fixture.probe_server("address", Path("ca"), "test-only-token")

    def test_transit_creation_requires_metadata_not_empty_success(self):
        for replacement in ((204, {}), (200, {}), (200, {"data": None}),
                            (200, {"data": {"name": "other", "type": "aes256-gcm96", "latest_version": 1}}),
                            (200, {"data": {"name": "fixture", "type": "rsa-2048", "latest_version": 1}}),
                            (200, {"data": {"name": "fixture", "type": "aes256-gcm96", "latest_version": True}}),
                            (200, {"data": {"name": "fixture", "type": "aes256-gcm96", "latest_version": 2}})):
            responses = self.responses()
            responses[3] = replacement
            with patch.object(fixture, "request", side_effect=responses):
                with self.assertRaises(fixture.harness.HarnessError):
                    fixture.probe_server("address", Path("ca"), "test-only-token")

    def test_response_bounds_content_type_and_duplicate_keys(self):
        for data, content_type in ((b"x" * (fixture.MAX_BODY + 1), "application/json"),
                                   (b'{}', "text/html"), (b'{"a":1,"a":2}', "application/json")):
            response = MagicMock()
            response.__enter__.return_value = response
            response.status = 200
            response.read.return_value = data
            response.headers.get_content_type.return_value = content_type
            with patch.object(fixture, "context"), patch.object(fixture.urllib.request, "build_opener") as opener:
                opener.return_value.open.return_value = response
                with self.assertRaises((fixture.harness.HarnessError, fixture.base.SnapshotError)):
                    fixture.request("https://127.0.0.1:1234", Path("ca"), "", "GET", "/v1/sys/health")
                response.read.assert_called_once_with(fixture.MAX_BODY + 1)

    def test_tls_probe_rejects_wrong_failure_reason_and_false_success(self):
        for failure in (None, OSError("connection refused"), ssl.SSLError("unrelated TLS failure")):
            verified = MagicMock()
            verified.wrap_socket.return_value.__enter__.return_value.version.return_value = "TLSv1.3"
            candidate = MagicMock()
            candidate.wrap_socket.side_effect = failure
            with patch.object(fixture, "context", return_value=verified), \
                 patch.object(fixture.ssl, "SSLContext", return_value=candidate), \
                 patch.object(fixture.socket, "create_connection"):
                with self.assertRaises((fixture.harness.HarnessError, OSError)):
                    fixture.probe_tls(1234, Path("ca"))

    def test_tls_probe_against_real_local_tls_server(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tls, ca = fixture.harness.generate_tls(root, "/usr/bin/openssl", {"PATH": "/usr/bin:/bin", "HOME": directory})
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.minimum_version = ssl.TLSVersion.TLSv1_3
            server_context.load_cert_chain(tls / "server.crt", tls / "server.key")
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(4)
                listener.settimeout(5)
                attempts = []
                def serve():
                    for _ in range(4):
                        try:
                            raw, _ = listener.accept()
                            with raw:
                                raw.settimeout(5)
                                with server_context.wrap_socket(raw, server_side=True):
                                    attempts.append("accepted")
                        except ssl.SSLError:
                            attempts.append("rejected")
                        except OSError:
                            return
                server = threading.Thread(target=serve)
                server.start()
                try:
                    fixture.probe_tls(listener.getsockname()[1], ca)
                finally:
                    server.join(timeout=10)
                    self.assertFalse(server.is_alive())
                    self.assertTrue(fixture.harness.cleanup_private_files(root))
                self.assertEqual(attempts, ["accepted", "rejected", "rejected", "rejected"])

    def test_sensitive_errors_are_not_printed(self):
        import contextlib
        import io
        with patch.object(fixture, "run", side_effect=fixture.harness.HarnessError("test-only-private-marker")), \
             patch.object(fixture.signal, "signal"), patch("sys.argv", ["fixture"]):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(fixture.main(), 1)
            self.assertNotIn("test-only-private-marker", output.getvalue())

    def test_cleanup_runs_after_start_failure_and_checks_both_resources(self):
        self.check_failed_start_cleanup(fixture.harness.HarnessError("start failed"))
        self.check_failed_start_cleanup(fixture.harness.HarnessInterrupted("interrupted"))
        self.check_failed_start_cleanup(fixture.harness.HarnessError("start failed"), cleanup_failure=True)

    def check_failed_start_cleanup(self, failure, cleanup_failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "fixture"
            root.mkdir()
            with patch.object(fixture.staged, "verify"), patch.object(fixture.staged, "verify_image_signature"), \
                 patch.object(fixture.evidence_tools, "protected_path", side_effect=lambda p: p), \
                 patch.object(fixture.tempfile, "mkdtemp", return_value=str(root)), \
                 patch.object(fixture.harness, "generate_tls", return_value=(root / "tls", root / "ca")), \
                 patch.object(fixture.harness, "inspect_image", return_value="pinned"), \
                 patch.object(fixture.harness, "run_bounded", side_effect=[b"network", failure]), \
                 patch.object(fixture.harness, "remove_owned_resource", side_effect=[fixture.harness.HarnessError("cleanup failed") if cleanup_failure else None, None]) as remove, \
                 patch.object(fixture.harness, "cleanup_private_files", return_value=True) as cleanup:
                with self.assertRaises(fixture.harness.HarnessError):
                    fixture.run()
                self.assertEqual([c.args[1] for c in remove.call_args_list], ["container", "network"])
                environment = remove.call_args.args[-1]
                self.assertEqual(set(environment), {"PATH", "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "LANG"})
                self.assertEqual(environment["PATH"], "/usr/bin:/bin")
                cleanup.assert_called_once_with(root)
                self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
