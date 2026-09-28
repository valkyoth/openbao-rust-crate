#!/usr/bin/python3 -EsSB
"""Real TLS regressions for the private consistency test relay, not OpenBao proof."""

import contextlib
import http.client
import http.server
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest

import consistency_tls_relay as subject
import openbao_test_harness as harness


class RelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        cls.addClassCleanup(harness.cleanup_private_files, root)
        cls.tls, cls.ca = harness.generate_tls(root, "/usr/bin/openssl", {"PATH": "/usr/bin:/bin", "HOME": str(root)})

    @contextlib.contextmanager
    def upstream(self, label, response_headers=None):
        calls = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self): self.reply()
            def do_POST(self): self.reply()
            def reply(self):
                self.connection.settimeout(3)
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                calls.append((self.command, self.path, self.headers.get_all("X-Vault-Inconsistent", [])))
                body = json.dumps({"node": label}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for name, value in response_headers if response_headers is not None else [("X-Vault-Index", "synthetic-index")]:
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(str(self.tls / "server.crt"), str(self.tls / "server.key"))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        try:
            yield f"https://127.0.0.1:{server.server_port}", calls
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    def request(self, address, method="GET", path="/v1/fixture-kv/data/sdk-lag", headers=None, body=b""):
        connection = http.client.HTTPSConnection("127.0.0.1", subject.port_for(address), timeout=3,
                                                context=subject.tls_fixture.context(self.ca))
        try:
            connection.putrequest(method, path)
            for key, value in headers if headers is not None else [("X-Vault-Token", "synthetic-token")]:
                connection.putheader(key, value)
            connection.endheaders(body)
            with connection.getresponse() as response:
                return response.status, response.read(2048)
        finally:
            connection.close()

    def test_routes_one_endpoint_without_merging_policy_headers_or_logging_secrets(self):
        with self.upstream("leader") as (leader, leader_calls), self.upstream("follower") as (follower, follower_calls):
            with subject.Relay(leader, follower, self.ca, self.tls, "synthetic-token") as relay:
                status, body = self.request(relay.address, "POST")
                self.assertEqual((status, json.loads(body)["node"]), (200, "leader"))
                headers = [("X-Vault-Token", "synthetic-token"), ("X-Vault-Index", "synthetic-index"),
                           ("X-Vault-Inconsistent", "await-state"), ("X-Vault-Inconsistent", "fail")]
                status, body = self.request(relay.address, headers=headers)
                self.assertEqual((status, json.loads(body)["node"]), (200, "follower"))
                self.assertEqual(self.request(relay.address, "POST", headers=headers)[0], 200)
                self.assertTrue(relay.wait_for("POST", "/v1/fixture-kv/data/sdk-lag", count=2))
                self.assertEqual(len(leader_calls), 1)
                self.assertEqual(len(follower_calls), 2)
                self.assertEqual(follower_calls[0][2], ["await-state", "fail"])
                self.assertNotIn("synthetic-token", repr(relay.snapshot()))
                self.assertNotIn("synthetic-index", repr(relay.snapshot()))
            self.assertEqual(relay.token, "")

    def test_rejected_paths_credentials_framing_and_limit_never_reach_upstream(self):
        with self.upstream("node") as (node, calls), subject.Relay(node, node, self.ca, self.tls, "synthetic-token") as relay:
            auth = [("X-Vault-Token", "synthetic-token")]
            for headers in ([], [("X-Vault-Token", "wrong")], auth * 2,
                            auth + [("Content-Length", "1"), ("Content-Length", "2")],
                            auth + [("Transfer-Encoding", "chunked")], auth + [("Expect", "100-continue")],
                            auth + [("Content-Length", "65537")], auth + [("Content-Length", "-1")],
                            auth + [("X-Vault-Index", "a"), ("X-Vault-Index", "b")]):
                self.assertIn(self.request(relay.address, headers=headers)[0], (400, 403, 413))
            for path in ("/v1/sys/raw/test", "/v1/fixture-kv/data/sdk-lag?extra=1", "https://example.org/"):
                self.assertEqual(self.request(relay.address, path=path)[0], 404)
            self.assertEqual(calls, [])
            self.assertEqual(relay.snapshot(), [])
            relay.accepted = subject.MAX_EVENTS
            self.assertEqual(self.request(relay.address)[0], 503)
            self.assertEqual(calls, [])

    def test_health_is_unauthenticated_and_observation_is_bounded(self):
        with self.upstream("node") as (node, calls), subject.Relay(node, node, self.ca, self.tls, "synthetic-token") as relay:
            self.assertEqual(self.request(relay.address, path="/v1/sys/health")[0], 403)
            self.assertEqual(self.request(relay.address, path="/v1/sys/health", headers=[])[0], 200)
            self.assertEqual(len(calls), 1)
            self.assertFalse(relay.wait_for("GET", "/v1/fixture-kv/data/sdk-lag", timeout=0.01))
            for args in (("DELETE", "/v1/fixture-kv/data/sdk-lag"), ("GET", "/secret")):
                with self.assertRaises(ValueError): relay.wait_for(*args)

    def test_cluster_switch_preserves_endpoint_and_validates_destination(self):
        with self.upstream("original") as (original, original_calls), self.upstream("independent") as (independent, independent_calls):
            with subject.Relay(original, original, self.ca, self.tls, "synthetic-token") as relay:
                address = relay.address
                for invalid in ("http://127.0.0.1:1", "https://example.org:1"):
                    with self.assertRaises(ValueError): relay.switch_cluster(invalid)
                self.assertEqual(json.loads(self.request(address)[1])["node"], "original")
                relay.switch_cluster(independent)
                self.assertEqual(relay.address, address)
                self.assertEqual(self.request(address, path="/v1/sys/health")[0], 403)
                self.assertEqual(json.loads(self.request(address, path="/v1/sys/health", headers=[])[1])["node"], "independent")
                self.assertEqual(len(original_calls), 1)
                self.assertEqual(independent_calls, [("GET", "/v1/sys/health", [])])

    def test_tls_rejects_untrusted_ca_and_tls12(self):
        with self.upstream("node") as (node, calls), subject.Relay(node, node, self.ca, self.tls, "synthetic-token") as relay:
            for trusted in (False, True):
                context = subject.tls_fixture.context(self.ca) if trusted else ssl.create_default_context()
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                if trusted:
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.maximum_version = ssl.TLSVersion.TLSv1_2
                with socket.create_connection(("127.0.0.1", subject.port_for(relay.address)), timeout=3) as stream:
                    with self.assertRaises(ssl.SSLError): context.wrap_socket(stream, server_hostname="127.0.0.1")
            self.assertEqual(calls, [])

    def test_response_metadata_rejects_controls_duplicates_and_oversize(self):
        for name in ("X-Vault-Index", "Retry-After"):
            for values in (("safe\r\n folded",), ("safe\tvalue",), ("safe\x00value",),
                           ("safe\x7fvalue",), ("x" * 4097,), ("one", "two")):
                with self.subTest(name=name, values=values):
                    with self.upstream("node", [(name, value) for value in values]) as (node, calls):
                        with subject.Relay(node, node, self.ca, self.tls, "synthetic-token") as relay:
                            with self.assertRaises((OSError, http.client.HTTPException)):
                                self.request(relay.address)
                            self.assertEqual(len(calls), 1)

    def test_destinations_reject_non_loopback_plaintext_or_url_overrides(self):
        for value in ("http://127.0.0.1:1", "https://example.org:1", "https://user@127.0.0.1:1",
                      "https://127.0.0.1:1/path", "https://127.0.0.1:1?x=1", "https://127.0.0.1:1#fragment"):
            with self.assertRaises(ValueError): subject.port_for(value)

    def test_connection_capacity_and_event_budget_are_bounded(self):
        with self.upstream("node") as (node, calls), subject.Relay(node, node, self.ca, self.tls, "synthetic-token") as relay:
            for _ in range(4): self.assertTrue(relay.connections.acquire(blocking=False))
            try:
                with self.assertRaises((OSError, http.client.HTTPException)):
                    self.request(relay.address)
            finally:
                for _ in range(4): relay.connections.release()
            self.assertEqual(calls, [])
            for _ in range(subject.MAX_EVENTS): relay.record("GET", "/v1/fixture-kv/data/sdk-lag")
            with self.assertRaises(ValueError): relay.record("GET", "/v1/fixture-kv/data/sdk-lag")
            with self.assertRaises(ValueError): relay.record("GET", "/v1/private")


if __name__ == "__main__":
    unittest.main()
