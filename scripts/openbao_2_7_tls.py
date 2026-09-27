#!/usr/bin/python3 -EsSB
"""Exercise the staged server over TLS without promoting an SDK profile."""

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.request

import evidence_tools
import openbao_api_snapshots as base
import openbao_2_7_api as staged
import openbao_test_harness as harness


VERSION = "2.7.0"
MAX_BODY = 1024 * 1024
ROOT = Path(__file__).resolve().parents[1]
INPUTS = ("scripts/openbao_2_7_tls.py", "scripts/openbao_test_harness.py",
          "scripts/evidence_tools.py", "scripts/openbao_api_snapshots.py",
          "scripts/openbao_2_7_api.py", "compat/onboarding/2.7.0/api-evidence.lock.json")


def input_hashes():
    return {path: base.sha256(base.read_regular_file(ROOT / path, 2 * 1024 * 1024)) for path in INPUTS}


def context(ca: Path) -> ssl.SSLContext:
    result = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    result.minimum_version = ssl.TLSVersion.TLSv1_3
    result.load_verify_locations(cafile=str(ca))
    return result


def request(address, ca, token, method, path, payload=None):
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    if body is not None and len(body) > MAX_BODY:
        raise harness.HarnessError("staged request exceeds limit")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    outgoing = urllib.request.Request(address + path, data=body, method=method, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), harness.RejectRedirect(),
                                        urllib.request.HTTPSHandler(context=context(ca)))
    try:
        response = opener.open(outgoing, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    except (OSError, urllib.error.URLError) as error:
        raise harness.HarnessError("staged TLS request failed") from error
    with response:
        status = response.status
        data = response.read(MAX_BODY + 1)
        if len(data) > MAX_BODY:
            raise harness.HarnessError("staged response exceeds limit")
        if data and response.headers.get_content_type() != "application/json":
            raise harness.HarnessError("staged response is not JSON")
    return status, base.parse_json(data, MAX_BODY) if data else {}


def require_status(actual, expected):
    if actual != expected:
        if type(actual) is int and type(expected) is int and 100 <= actual <= 599 and 100 <= expected <= 599:
            print(f"Staged TLS fixture: status diagnostic=received-{actual}-expected-{expected}", flush=True)
        raise harness.HarnessError("staged operation returned unexpected status")


def probe_tls(port, ca):
    # Successful verified handshake first: connectivity failures must not count
    # as evidence of certificate rejection in the negative checks below.
    with socket.create_connection(("127.0.0.1", port), timeout=5) as transport:
        with context(ca).wrap_socket(transport, server_hostname="127.0.0.1") as tls:
            if tls.version() != "TLSv1.3":
                raise harness.HarnessError("staged server did not negotiate TLS 1.3")
    for label in ("untrusted-ca", "wrong-hostname", "tls12"):
        candidate = context(ca)
        if label == "untrusted-ca":
            candidate = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            candidate.minimum_version = ssl.TLSVersion.TLSv1_3
        if label == "tls12":
            candidate.minimum_version = ssl.TLSVersion.TLSv1_2
            candidate.maximum_version = ssl.TLSVersion.TLSv1_2
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as transport:
                with candidate.wrap_socket(transport, server_hostname="invalid.example" if label == "wrong-hostname" else "127.0.0.1"):
                    pass
        except ssl.SSLCertVerificationError:
            if label == "tls12":
                raise harness.HarnessError("TLS floor probe failed for the wrong reason")
        except ssl.SSLError as error:
            if label != "tls12" or error.reason != "TLSV1_ALERT_PROTOCOL_VERSION":
                raise harness.HarnessError("TLS probe failed for the wrong reason") from error
        else:
            raise harness.HarnessError("staged server accepted forbidden TLS configuration")


def probe_server(address, ca, token):
    status, health = request(address, ca, "", "GET", "/v1/sys/health")
    require_status(status, 200)
    harness.verify_reported_version(health.get("version"), VERSION)
    if health.get("initialized") is not True or health.get("sealed") is not False:
        raise harness.HarnessError("staged server is not initialized and unsealed")
    require_status(request(address, ca, "", "POST", "/v1/sys/mounts/fixture-transit", {"type": "transit"})[0], 403)
    require_status(request(address, ca, token, "POST", "/v1/sys/mounts/fixture-transit", {"type": "transit"})[0], 204)
    # The tagged pathPolicyWrite returns formatKeyPolicy, not an empty response.
    status, key = request(address, ca, token, "POST", "/v1/fixture-transit/keys/fixture", {"type": "aes256-gcm96"})
    require_status(status, 200)
    data = key.get("data")
    if (not isinstance(data, dict) or data.get("name") != "fixture"
        or data.get("type") != "aes256-gcm96" or type(data.get("latest_version")) is not int
        or data["latest_version"] != 1):
        raise harness.HarnessError("staged Transit key response does not match the created key")
    # A catalog lookup plus a failed mount and absent mount entry distinguish
    # server installation state from an SDK route/field compatibility rejection.
    for kind, name in (("auth", "ldap"), ("auth", "kerberos"), ("auth", "radius"), ("secret", "ldap")):
        print(f"Staged TLS fixture: checking absent {kind}/{name}", flush=True)
        require_status(request(address, ca, token, "GET", f"/v1/sys/plugins/catalog/{kind}/{name}")[0], 404)
        prefix = "auth" if kind == "auth" else "mounts"
        mount = "fixture-" + name
        status, failure = request(address, ca, token, "POST", f"/v1/sys/{prefix}/{mount}", {"type": name})
        require_status(status, 400)
        errors = failure.get("errors")
        if not isinstance(errors, list) or not errors or not all(isinstance(e, str) for e in errors):
            raise harness.HarnessError("missing-plugin response is malformed")
        if not any("plugin not found in the catalog" in e for e in errors):
            raise harness.HarnessError("plugin mount failed for an unreviewed reason")
        status, mounts = request(address, ca, token, "GET", f"/v1/sys/{prefix}")
        require_status(status, 200)
        if not isinstance(mounts.get("data"), dict) or mount + "/" in mounts["data"]:
            raise harness.HarnessError("missing-plugin mount was unexpectedly installed")


def container_command(podman, image, container, network, run_id, config, tls):
    command = harness.container_command(podman, image, container, network, run_id, config, tls)
    index = command.index("--pids-limit")
    command[index:index + 2] = list(base.CONTAINER_RESOURCE_OPTIONS)
    return command


def network_command(podman, network, run_id):
    # Internal bridges suppress forwarding on some Netavark versions, including
    # published host ports. No default route provides egress isolation without
    # disabling the fixture's loopback-only port publication.
    return [podman, "network", "create", "--driver", "bridge", "--disable-dns",
            "--opt", "no_default_route=true", "--opt", "isolate=strict",
            "--label", f"{harness.OWNER_LABEL}={run_id}", network]


def validate_routes(ipv4, ipv6):
    try:
        rows = ipv4.decode("ascii").splitlines()
        if not rows or rows[0].split()[:3] != ["Iface", "Destination", "Gateway"] or len(rows) > 65:
            raise ValueError("invalid IPv4 route table")
        for row in rows[1:]:
            fields = row.split()
            if len(fields) != 11 or len(fields[1]) != 8 or len(fields[7]) != 8:
                raise ValueError("invalid IPv4 route")
            destination, mask = int(fields[1], 16), int(fields[7], 16)
            if destination == 0 and mask == 0:
                raise ValueError("IPv4 default route")
        rows = ipv6.decode("ascii").splitlines()
        if len(rows) > 64:
            raise ValueError("IPv6 route table exceeds limit")
        for row in rows:
            fields = row.split()
            if len(fields) != 10 or len(fields[0]) != 32 or len(fields[1]) != 2:
                raise ValueError("invalid IPv6 route")
            destination, prefix, flags = int(fields[0], 16), int(fields[1], 16), int(fields[8], 16)
            # Linux can expose an unreachable default route on lo (RTF_REJECT).
            if destination == 0 and prefix == 0 and not flags & 0x200:
                raise ValueError("IPv6 default route")
    except (UnicodeError, ValueError, IndexError) as error:
        raise harness.HarnessError("staged network route isolation was not applied") from error


def verify_network(podman, network, container, environment):
    output = harness.run_bounded([podman, "network", "inspect", "--format", "{{json .}}", network],
                                 maximum=16 * 1024, timeout=10, environment=environment)
    config = base.parse_json(output, 16 * 1024)
    options = config.get("options")
    if (config.get("driver") != "bridge" or config.get("dns_enabled") is not False
        or not isinstance(options, dict)
        or options.get("no_default_route") != "true"
        or options.get("isolate") != "strict"):
        raise harness.HarnessError("staged network configuration was not applied")
    routes = [harness.run_bounded([podman, "exec", container, "/bin/cat", path],
                                 maximum=16 * 1024, timeout=10, environment=environment)
              for path in ("/proc/net/route", "/proc/net/ipv6_route")]
    validate_routes(*routes)


def classify_startup_logs(output):
    lowered = output.lower()
    patterns = {
        "allocation-failure": (b"out of memory", b"cannot allocate memory", b"failed to reserve"),
        "permission-denied": (b"permission denied",),
        "unknown-storage": (b"unknown storage type",),
        "listener-configuration": (b"error parsing listener", b"error initializing listener"),
        "address-in-use": (b"address already in use",),
        "configuration-error": (b"error loading configuration", b"error parsing config"),
    }
    return [label for label, markers in patterns.items() if any(marker in lowered for marker in markers)]


def startup_diagnostic(podman, container, environment):
    try:
        shell = str(evidence_tools.protected_path(Path("/usr/bin/sh")))
        # Fixed shell program only redirects stderr into the bounded stdout
        # reader. All executable/argument values are separate quoted argv.
        output = harness.run_bounded([shell, "-c", 'exec "$@" 2>&1', "fixture-logs", podman, "logs", "--tail", "50", container],
                                     maximum=64 * 1024, timeout=10, environment=environment)
        categories = classify_startup_logs(output)
        print("Staged TLS fixture: startup diagnostic=" + (",".join(categories) or "unclassified"), flush=True)
    except (harness.HarnessError, OSError, ValueError):
        print("Staged TLS fixture: startup diagnostic=unavailable", flush=True)


def wait_for_health(podman, container, environment, address, ca):
    last_failure = "unknown"
    for _ in range(120):
        state = base.parse_json(harness.run_bounded(
            [podman, "inspect", "--format", "{{json .State}}", container],
            maximum=16 * 1024, timeout=10, environment=environment), 16 * 1024)
        if state.get("Running") is not True:
            print("Staged TLS fixture: server exited before readiness", flush=True)
            startup_diagnostic(podman, container, environment)
            raise harness.HarnessError("OpenBao did not become reachable before the preflight deadline")
        try:
            health = harness.https_json(address, ca, "GET", "/v1/sys/health", None, {200, 429, 472, 473, 501, 503})
            harness.verify_reported_version(health.get("version"), VERSION)
            return
        except harness.VersionMismatch:
            raise
        except harness.HarnessError as error:
            cause = error.__cause__
            if isinstance(cause, urllib.error.URLError):
                cause = cause.reason
            if isinstance(cause, ssl.SSLCertVerificationError):
                last_failure = "certificate-verification"
            elif isinstance(cause, ssl.SSLError):
                last_failure = "tls-handshake"
            elif isinstance(cause, ConnectionRefusedError):
                last_failure = "connection-refused"
            elif isinstance(cause, TimeoutError):
                last_failure = "connection-timeout"
            else:
                last_failure = "health-response"
            time.sleep(0.25)
    print("Staged TLS fixture: readiness diagnostic=" + last_failure, flush=True)
    startup_diagnostic(podman, container, environment)
    raise harness.HarnessError("OpenBao did not become reachable before the preflight deadline")


def run():
    inputs = input_hashes()
    print("Staged TLS fixture: verifying image evidence", flush=True)
    staged.verify()
    staged.verify_image_signature()
    podman = str(evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-270-tls-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root), "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    run_id = secrets.token_hex(16)
    container = "openbao-270-tls-" + run_id
    network = "openbao-270-net-" + run_id
    network_attempted = container_attempted = False
    token = ""
    try:
        print("Staged TLS fixture: preparing TLS and container", flush=True)
        tls, ca = harness.generate_tls(root, openssl, environment)
        config = harness.write_server_config(root, VERSION)
        print("Staged TLS fixture: preparing pinned image", flush=True)
        image = harness.inspect_image(podman, staged.RELEASE, environment)
        print("Staged TLS fixture: creating isolated no-default-route network", flush=True)
        network_attempted = True
        harness.run_bounded(network_command(podman, network, run_id), timeout=60, environment=environment)
        container_attempted = True
        print("Staged TLS fixture: starting constrained server", flush=True)
        harness.run_bounded(container_command(podman, image, container, network, run_id, config, tls), timeout=120, environment=environment)
        print("Staged TLS fixture: verifying resource limits and loopback port", flush=True)
        limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", container], maximum=64 * 1024, timeout=30, environment=environment)
        base.validate_container_resource_config(base.parse_json(limits, 64 * 1024))
        verify_network(podman, network, container, environment)
        port = harness.parse_port(harness.run_bounded([podman, "port", container, "8200/tcp"], maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        print("Staged TLS fixture: waiting for exact-version TLS health", flush=True)
        wait_for_health(podman, container, environment, address, ca)
        print("Staged TLS fixture: checking TLS rejection cases", flush=True)
        probe_tls(port, ca)
        token = harness.initialize_and_unseal(address, ca)
        print("Staged TLS fixture: checking built-in and absent-plugin behavior", flush=True)
        probe_server(address, ca, token)
    finally:
        token = ""
        failed = False
        for attempted, kind, name in ((container_attempted, "container", container), (network_attempted, "network", network)):
            if attempted:
                try:
                    harness.remove_owned_resource(podman, kind, name, run_id, environment)
                except (harness.HarnessError, OSError):
                    failed = True
        if not harness.cleanup_private_files(root):
            failed = True
        try:
            shutil.rmtree(root)
        except OSError:
            failed = True
        if failed:
            raise harness.HarnessError("staged TLS fixture cleanup incomplete")
    if inputs != input_hashes():
        raise harness.HarnessError("staged fixture inputs changed during execution")
    return {"schema": "openbao-staged-tls/v1", "version": VERSION, "image_linux_amd64_digest": staged.AMD64,
            "inputs": inputs,
            "scope": "server-fixture-only-not-sdk-integration", "tls": "TLSv1.3", "outcome": "passed",
            "checks": ["exact-version", "resource-limits", "network-isolation", "initialize-unseal", "untrusted-ca-rejected", "wrong-hostname-rejected", "tls12-rejected", "unauthenticated-mount-rejected", "builtin-transit", "external-plugins-not-installed", "cleanup"],
            "plugin_contracts_verified": False, "routable": False}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        result = run()
        with tempfile.NamedTemporaryFile(prefix="openbao-270-tls-result-", suffix=".json", delete=False) as output:
            output.write(base.canonical_json(result))
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            print(f"Staged TLS fixture passed; result: {output.name}")
        return 0
    except (harness.HarnessError, base.SnapshotError, OSError, ValueError) as error:
        # Never print response bodies, token material or nested exception chains.
        reasons = {
            "subprocess failed": "command-failed",
            "subprocess timed out": "command-timeout",
            "locked image preparation failed": "image-preparation",
            "pulled image does not match the locked Linux amd64 digest": "image-identity",
            "OpenBao did not become reachable before the preflight deadline": "tls-readiness",
            "staged TLS fixture cleanup incomplete": "cleanup",
            "staged operation returned unexpected status": "http-status",
            "plugin mount failed for an unreviewed reason": "plugin-error-contract",
        }
        reason = reasons.get(str(error), "unclassified")
        print(f"Staged TLS fixture failed ({reason}); no compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
