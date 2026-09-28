"""Test-only, bounded loopback TLS relay for one immutable SDK cluster endpoint.

No arbitrary destinations, redirects, path rewriting, credential logging, or
plaintext listener. This is not a production proxy or an SDK feature.
"""

import hmac
import http.client
import http.server
import socket
import ssl
import threading
import urllib.parse

import openbao_2_7_tls as tls_fixture

PATHS = frozenset({"/v1/fixture-kv/data/sdk-lag", "/v1/fixture-kv/data/sdk-cancel",
                   "/v1/fixture-kv/data/sdk-timeout"})
MAX_REQUEST = 65536
MAX_EVENTS = 128


def port_for(address):
    parsed = urllib.parse.urlsplit(address)
    if (parsed.scheme != "https" or parsed.hostname != "127.0.0.1" or not parsed.port
            or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
        raise ValueError("relay requires an exact loopback HTTPS endpoint")
    return parsed.port


def visible(value, maximum):
    return isinstance(value, str) and 0 < len(value) <= maximum and all(0x21 <= ord(c) <= 0x7e for c in value)


class Relay:
    def __init__(self, leader, follower, ca, tls, token):
        self.leader_port, self.follower_port = port_for(leader), port_for(follower)
        if not visible(token, 8192):
            raise ValueError("invalid relay credential")
        self.token = token
        self.upstream_context = tls_fixture.context(ca)
        self.listener_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.listener_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.listener_context.load_cert_chain(str(tls / "server.crt"), str(tls / "server.key"))
        self.events = []
        self.accepted = 0
        self.condition = threading.Condition()
        self.connections = threading.BoundedSemaphore(4)
        self.httpd = None
        self.thread = None

    def record(self, method, path):
        if method not in ("GET", "POST") or (path not in PATHS and (method, path) != ("GET", "/v1/sys/health")):
            raise ValueError("invalid relay event")
        with self.condition:
            if len(self.events) >= MAX_EVENTS:
                raise ValueError("relay event limit exceeded")
            # Only allowlisted method/path pairs, never bodies, tokens or indices.
            self.events.append((method, path))
            self.condition.notify_all()

    def snapshot(self):
        with self.condition:
            return list(self.events)

    def switch_cluster(self, address):
        port = port_for(address)
        with self.condition:
            self.leader_port = port
            self.follower_port = port

    def wait_for(self, method, path, count=1, timeout=5):
        if method not in ("GET", "POST") or path not in PATHS or not 1 <= count <= MAX_EVENTS or not 0 < timeout <= 20:
            raise ValueError("invalid relay observation")
        with self.condition:
            return self.condition.wait_for(lambda: self.events.count((method, path)) >= count, timeout)

    def __enter__(self):
        relay = self

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = False
            block_on_close = True
            request_queue_size = 4

            def process_request(self, request, client_address):
                if not relay.connections.acquire(blocking=False):
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, client_address)
                except BaseException:
                    relay.connections.release()
                    raise

            def process_request_thread(self, request, client_address):
                live = [request]
                def expire():
                    try:
                        live[0].shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    live[0].close()
                deadline = threading.Timer(20, expire)
                deadline.daemon = True
                deadline.start()
                try:
                    request.settimeout(3)
                    secured = relay.listener_context.wrap_socket(request, server_side=True)
                    live[0] = secured
                    super().process_request_thread(secured, client_address)
                except (OSError, ValueError):
                    self.shutdown_request(request)
                finally:
                    deadline.cancel()
                    relay.connections.release()

            def handle_error(self, request, client_address):
                # BaseServer otherwise prints tracebacks that can include metadata.
                pass

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *_):
                pass

            def reject(self, status=400):
                self.send_response_only(status)
                self.send_header("Content-Length", "2")
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"{}")

            def send_error(self, code, message=None, explain=None):
                self.reject(code)

            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def forward(self):
                connection = None
                try:
                    health = self.path == "/v1/sys/health" and self.command == "GET"
                    if not health and self.path not in PATHS:
                        self.reject(404)
                        return
                    headers = list(self.headers.raw_items())
                    if len(headers) > 16 or any(len(name) > 64 or len(value) > 8192 for name, value in headers):
                        self.reject()
                        return
                    lengths = self.headers.get_all("Content-Length", [])
                    if self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Expect") or len(lengths) > 1:
                        self.reject()
                        return
                    length = lengths[0] if lengths else "0"
                    if not length.isascii() or not length.isdecimal() or len(length) > 6 or int(length) > MAX_REQUEST:
                        self.reject(413)
                        return
                    size = int(length)
                    if self.command == "GET" and size:
                        self.reject()
                        return
                    tokens = self.headers.get_all("X-Vault-Token", [])
                    if (health and tokens) or (not health and (len(tokens) != 1 or not visible(tokens[0], 8192)
                            or not hmac.compare_digest(tokens[0], relay.token))):
                        self.reject(403)
                        return
                    forwarded = []
                    for name, limit, count in (("X-Vault-Token", 8192, 1), ("X-Vault-Index", 4096, 1),
                                                ("X-Vault-Inconsistent", 64, 2), ("X-Vault-Namespace", 256, 1)):
                        values = self.headers.get_all(name, [])
                        if len(values) > count or any(not visible(value, limit) for value in values):
                            self.reject()
                            return
                        forwarded.extend((name, value) for value in values)
                    if health and forwarded:
                        self.reject()
                        return
                    body = self.rfile.read(size)
                    if len(body) != size:
                        self.reject()
                        return
                    with relay.condition:
                        if relay.accepted >= MAX_EVENTS:
                            self.reject(503)
                            return
                        relay.accepted += 1
                    with relay.condition:
                        port = relay.leader_port if self.command == "POST" and not self.headers.get_all("X-Vault-Index") else relay.follower_port
                    connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=15, context=relay.upstream_context)
                    connection.putrequest(self.command, self.path, skip_accept_encoding=True)
                    for name, value in forwarded:
                        connection.putheader(name, value)
                    connection.putheader("Content-Type", "application/json")
                    connection.putheader("Content-Length", str(size))
                    connection.endheaders(body)
                    relay.record(self.command, self.path)
                    with connection.getresponse() as response:
                        data = response.read(tls_fixture.MAX_BODY + 1)
                        if len(data) > tls_fixture.MAX_BODY:
                            raise ValueError("relay response limit exceeded")
                        if data and response.headers.get_content_type() != "application/json":
                            raise ValueError("invalid relay response content type")
                        metadata = []
                        for name in ("X-Vault-Index", "Retry-After"):
                            values = response.headers.get_all(name, [])
                            if len(values) > 1 or any(not visible(value, 4096) for value in values):
                                raise ValueError("invalid relay response metadata")
                            metadata.extend((name, value) for value in values)
                        self.send_response_only(response.status)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(data)))
                        for name, value in metadata:
                            self.send_header(name, value)
                        self.end_headers()
                        self.wfile.write(data)
                except (OSError, ValueError, http.client.HTTPException):
                    # Closing the connection is fail-closed, not a synthetic success.
                    self.close_connection = True
                finally:
                    if connection is not None:
                        connection.close()

        self.httpd = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05})
        try:
            self.thread.start()
        except BaseException:
            self.httpd.server_close()
            raise
        return self

    @property
    def address(self):
        if self.httpd is None:
            raise ValueError("relay is not running")
        return f"https://127.0.0.1:{self.httpd.server_port}"

    def __exit__(self, *_):
        try:
            self.httpd.shutdown()
            self.thread.join()
        finally:
            self.httpd.server_close()
            self.token = ""
