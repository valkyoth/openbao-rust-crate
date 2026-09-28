#!/usr/bin/python3 -EsSB
"""Staged three-node Raft consistency protocol fixture; never promote routing."""

import argparse
import base64
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile
import time
import urllib.parse

import evidence_tools
import openbao_2_7_api as staged
import openbao_2_7_tls as fixture
import openbao_api_snapshots as snapshots
import openbao_test_harness as harness

ROOT = Path(__file__).resolve().parents[1]
INPUTS = (*fixture.INPUTS, "scripts/openbao_2_7_consistency.py")
CHECKS = ["three-node-raft", "exact-version-tls13", "tls-rejections",
          "resource-limits", "network-isolation", "one-active-two-standby",
          "real-write-index-propagation", "synthetic-unseen-index-429",
          "await-expiry-fail", "forward-active", "await-expiry-forward",
          "separate-policy-headers", "malformed-policy-rejected",
          "write-429-without-mutation", "cleanup"]

# Exact v2.7.0 KV upgradeCheck responses, not general retryable HTTP errors.
KV_INITIALIZING_ERRORS = (
    "Waiting for the primary to upgrade from non-versioned to versioned data. "
    "This backend will be unavailable for a brief period and will resume service when the primary is finished.",
    "Upgrading from non-versioned to versioned data. "
    "This backend will be unavailable for a brief period and will resume service shortly.",
)


def kv_initializing(status, response):
    return status == 400 and any(response == {"errors": [message]} for message in KV_INITIALIZING_ERRORS)


def require(value):
    if not value:
        raise harness.HarnessError("consistency fixture contract assertion failed")


def failure_category(response):
    # Return fixed labels only; server errors can reflect credentials or indices.
    if kv_initializing(400, response):
        return "kv-initializing"
    errors = response.get("errors") if isinstance(response, dict) else None
    if not isinstance(errors, list) or not errors or len(errors) > 8:
        return "unclassified"
    patterns = (
        ("index-decode", 'failed to decode "X-Vault-Index"'),
        ("index-cardinality", 'expected at most one value for "X-Vault-Index"'),
        ("policy-cardinality", 'expected at most two values for "X-Vault-Inconsistent"'),
        ("policy-first-value", 'unknown value for "X-Vault-Inconsistent" header'),
        ("policy-fallback", 'unknown second value for "X-Vault-Inconsistent"'),
        ("policy-multiple-values", "cannot be used with more than one value"),
        ("unsupported-route", "unsupported path"),
        ("missing-route", "no handler for route"),
        ("permission-denied", "permission denied"),
        ("missing-token", "missing client token"),
    )
    for error in errors:
        if isinstance(error, str) and len(error) <= 4096:
            for label, marker in patterns:
                if marker in error:
                    return label
    return "unclassified"


def input_hashes():
    return {path: snapshots.sha256(snapshots.read_regular_file(ROOT / path, 2 * 1024 * 1024))
            for path in INPUTS}


def request(address, ca, token, method, path, payload=None, index=None, policies=(), *, timeout=5):
    require(type(timeout) is int and 1 <= timeout <= 30)
    parsed = urllib.parse.urlsplit(address)
    require(parsed.scheme == "https" and parsed.hostname == "127.0.0.1"
            and parsed.port is not None and not parsed.username and not parsed.password
            and not parsed.path and not parsed.query and not parsed.fragment)
    require(path.startswith("/v1/") and all(0x21 <= ord(c) <= 0x7e for c in path))
    headers = [("Content-Type", "application/json")]
    if token:
        headers.append(("X-Vault-Token", token))
    if index is not None:
        headers.append(("X-Vault-Index", index))
    headers.extend(("X-Vault-Inconsistent", value) for value in policies)
    require(len(headers) <= 8 and all(isinstance(value, str) and len(value) <= 4096
            and all(0x21 <= ord(c) <= 0x7e for c in value) for _, value in headers))
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    require(body is None or len(body) <= fixture.MAX_BODY)
    connection = http.client.HTTPSConnection("127.0.0.1", parsed.port, timeout=timeout,
                                             context=fixture.context(ca))
    try:
        connection.putrequest(method, path, skip_accept_encoding=True)
        for name, value in headers:
            # Repeated occurrences are required; a comma-separated value is not equivalent.
            connection.putheader(name, value)
        if body is not None:
            connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body)
        with connection.getresponse() as response:
            content = response.read(fixture.MAX_BODY + 1)
            require(len(content) <= fixture.MAX_BODY)
            if content:
                require(response.headers.get_content_type() == "application/json")
            indices = response.headers.get_all("X-Vault-Index", [])
            require(len(indices) <= 1 and all(len(value) <= 4096 for value in indices))
            return (response.status, snapshots.parse_json(content, fixture.MAX_BODY) if content else {},
                    indices[0] if indices else None, response.getheader("Retry-After"))
    except TimeoutError as error:
        print("Consistency fixture: request diagnostic=timeout", flush=True)
        raise harness.HarnessError("consistency TLS request timed out") from error
    except (OSError, http.client.HTTPException) as error:
        raise harness.HarnessError("consistency TLS request failed") from error
    finally:
        connection.close()


def node_addresses(config):
    require(isinstance(config, dict) and isinstance(config.get("subnets"), list)
            and len(config["subnets"]) == 1)
    subnet = config["subnets"][0]
    require(isinstance(subnet, dict) and isinstance(subnet.get("subnet"), str))
    network = ipaddress.ip_network(subnet["subnet"])
    require(network.version == 4 and network.is_private and not network.is_loopback
            and 16 <= network.prefixlen <= 28)
    addresses = [str(network.network_address + offset) for offset in (10, 11, 12)]
    require(subnet.get("gateway") not in addresses)
    return addresses


def write_config(root, number, address):
    require(type(number) is int and 0 <= number < 3)
    require(str(ipaddress.IPv4Address(address)) == address)
    config = root / f"node-{number}.hcl"
    body = (f'ui = false\ndisable_mlock = true\ndisable_standby_reads = false\n'
            f'storage "raft" {{\n  path = "/raft"\n  node_id = "fixture-{number}"\n}}\n'
            'listener "tcp" {\n  address = "0.0.0.0:8200"\n'
            '  cluster_address = "0.0.0.0:8201"\n'
            '  tls_cert_file = "/openbao/tls/server.crt"\n'
            '  tls_key_file = "/openbao/tls/server.key"\n  tls_min_version = "tls13"\n'
            '  consistency_max_index_wait = "250ms"\n'
            '  consistency_fallback_behavior = "fail"\n}\n'
            f'api_addr = "https://{address}:8200"\ncluster_addr = "https://{address}:8201"\n')
    harness.write_private(config, body.encode(), 0o640)
    return config


def container_command(podman, image, container, network, run_id, config, tls, address):
    command = fixture.container_command(podman, image, container, network, run_id, config, tls)
    # Podman's --tmpfs parser rejects uid/gid options. The existing 100:0
    # server identity writes via group 0; mode 0770 keeps other users out.
    command[2:2] = ["--ip", address, "--tmpfs", "/raft:rw,noexec,nosuid,nodev,size=128m,mode=0770"]
    # These three nodes intentionally share one disposable listener certificate.
    command[command.index(f"{tls}:/openbao/tls:ro,Z")] = f"{tls}:/openbao/tls:ro,z"
    return command


def ready_cluster(addresses, ca):
    for _ in range(120):
        health = [request(address, ca, "", "GET", "/v1/sys/health") for address in addresses]
        for _, body, _, _ in health:
            harness.verify_reported_version(body.get("version"), fixture.VERSION)
        if (all(status in (200, 429) and body.get("initialized") is True
                and body.get("sealed") is False and type(body.get("standby")) is bool
                for status, body, _, _ in health)
                and sum(body["standby"] is False for _, body, _, _ in health) == 1):
            clusters = [body.get("cluster_id") for _, body, _, _ in health]
            require(all(isinstance(value, str) and 0 < len(value) <= 256 for value in clusters))
            require(len(set(clusters)) == 1)
            active = next(i for i, (_, body, _, _) in enumerate(health) if not body["standby"])
            return active, clusters[0]
        time.sleep(0.25)
    raise harness.HarnessError("three-node cluster did not become ready")


def initialize_cluster(addresses, internal, ca):
    print("Consistency fixture: initializing first Raft node", flush=True)
    status, initialized, _, _ = request(addresses[0], ca, "", "PUT", "/v1/sys/init",
                                      {"secret_shares": 1, "secret_threshold": 1}, timeout=30)
    fixture.require_status(status, 200)
    keys, token = initialized.get("keys_base64"), initialized.get("root_token")
    require(isinstance(keys, list) and len(keys) == 1 and isinstance(keys[0], str) and keys[0]
            and isinstance(token, str) and token)
    try:
        for number, address in enumerate(addresses):
            if number:
                print(f"Consistency fixture: joining Raft node {number + 1}", flush=True)
                status, joined, _, _ = request(address, ca, "", "POST", "/v1/sys/storage/raft/join",
                    {"leader_api_addr": f"https://{internal[0]}:8200", "leader_tls_servername": "127.0.0.1",
                     "leader_ca_cert": ca.read_text(encoding="ascii"), "retry": False}, timeout=30)
                fixture.require_status(status, 200)
                require(joined.get("joined") is True)
            print(f"Consistency fixture: unsealing Raft node {number + 1}", flush=True)
            status, unsealed, _, _ = request(address, ca, "", "POST", "/v1/sys/unseal", {"key": keys[0]}, timeout=30)
            fixture.require_status(status, 200)
            # Raft join/unseal may finish asynchronously. Health is checked below.
            require(isinstance(unsealed.get("sealed"), bool))
            if not number:
                print("Consistency fixture: waiting for initial Raft leader", flush=True)
                for _ in range(120):
                    if request(address, ca, "", "GET", "/v1/sys/health")[0] == 200:
                        break
                    time.sleep(0.25)
                else:
                    raise harness.HarnessError("initial Raft leader unavailable")
    finally:
        keys[0] = ""
        initialized.clear()
    return token


def index_value(encoded, cluster):
    require(isinstance(encoded, str) and 0 < len(encoded) <= 4096)
    try:
        decoded = base64.b64decode(encoded, validate=True)
        data = snapshots.parse_json(decoded, 4096)
    except (ValueError, snapshots.SnapshotError) as error:
        raise harness.HarnessError("invalid fixture storage index") from error
    require(isinstance(data, dict) and set(data) == {"cluster", "value"}
            and data["cluster"] == cluster and isinstance(data["value"], str)
            and data["value"].isascii() and data["value"].isdigit() and len(data["value"]) <= 20
            and int(data["value"]) < 2**64)
    return data


def probe(addresses, ca, token):
    print("Consistency fixture: checking shared cluster identity and standby health", flush=True)
    active, cluster = ready_cluster(addresses, ca)
    leader = addresses[active]
    standbys = [address for i, address in enumerate(addresses) if i != active]
    print("Consistency fixture: checking three voting members", flush=True)
    for _ in range(120):
        status, configuration, _, _ = request(leader, ca, token, "GET", "/v1/sys/storage/raft/configuration")
        fixture.require_status(status, 200)
        servers = configuration.get("data", {}).get("config", {}).get("servers")
        require(isinstance(servers, list) and len(servers) <= 3)
        if (len(servers) == 3 and all(isinstance(server, dict) and server.get("voter") is True for server in servers)
                and {server.get("node_id") for server in servers} == {"fixture-0", "fixture-1", "fixture-2"}):
            break
        time.sleep(0.25)
    else:
        raise harness.HarnessError("three Raft voting members were not established")
    print("Consistency fixture: three ready Raft nodes; checking real write indices", flush=True)
    fixture.require_status(request(leader, ca, token, "POST", "/v1/sys/mounts/fixture-kv",
                                   {"type": "kv", "options": {"version": "2"}})[0], 204)
    path = "/v1/fixture-kv/data/check"
    status, written, real_index, _ = request(leader, ca, token, "POST", path,
                                           {"data": {"marker": "initial"}})
    fixture.require_status(status, 200)
    require(written.get("data", {}).get("version") == 1)
    index_value(real_index, cluster)
    for number, standby in enumerate(standbys, 1):
        print(f"Consistency fixture: reading real index on standby {number}", flush=True)
        for attempt in range(120):
            status, read, _, _ = request(standby, ca, token, "GET", path, index=real_index,
                                        policies=("await-state", "fail"))
            if status == 200:
                require(read.get("data", {}).get("data") == {"marker": "initial"})
                break
            if kv_initializing(status, read):
                # Standby KV initialization polls once a second, independently of
                # the applied Raft index. Only retry this exact setup response;
                # success still requires the indexed read to return the value.
                if attempt == 0:
                    print("Consistency fixture: waiting for standby KV initialization", flush=True)
                time.sleep(0.025)
                continue
            if status != 429:
                print("Consistency fixture: real-index diagnostic=" + failure_category(read), flush=True)
                # Read-only comparisons help distinguish policy parsing from standby handling.
                # Neither comparison can turn the original failed assertion into success.
                for label, target, policy in (("active-await", leader, ("await-state", "fail")),
                                               ("standby-fail", standby, ("fail",))):
                    observed, detail, _, _ = request(target, ca, token, "GET", path,
                                                     index=real_index, policies=policy)
                    print(f"Consistency fixture: {label} diagnostic=status-{observed}-"
                          + failure_category(detail), flush=True)
            fixture.require_status(status, 429)
            time.sleep(0.025)
        else:
            raise harness.HarnessError("standby did not apply real write index")
    future = base64.b64encode(json.dumps({"cluster": cluster, "value": str(2**64 - 1)},
                                       separators=(",", ":")).encode()).decode("ascii")
    index_value(future, cluster)
    standby = standbys[0]
    print("Consistency fixture: synthetic unseen index and explicit policies", flush=True)
    status, _, _, retry_after = request(standby, ca, token, "GET", path, index=future, policies=("fail",))
    fixture.require_status(status, 429)
    require(retry_after == "1")
    started = time.monotonic()
    fixture.require_status(request(standby, ca, token, "GET", path, index=future,
                                   policies=("await-state", "fail"))[0], 429)
    require(0.15 <= time.monotonic() - started < 5)
    for policy in (("forward-active-node",), ("await-state", "forward-active-node")):
        status, read, _, _ = request(standby, ca, token, "GET", path, index=future, policies=policy)
        fixture.require_status(status, 200)
        require(read.get("data", {}).get("data") == {"marker": "initial"})
    fixture.require_status(request(standby, ca, token, "GET", path, index=real_index,
                                   policies=("await-state,fail",))[0], 400)
    print("Consistency fixture: rejected write has no KV2 version side effect", flush=True)
    fixture.require_status(request(standby, ca, token, "POST", path, {"data": {"marker": "forbidden"}},
                                   index=future, policies=("fail",))[0], 429)
    status, read, _, _ = request(leader, ca, token, "GET", path)
    fixture.require_status(status, 200)
    require(read.get("data", {}).get("metadata", {}).get("version") == 1
            and read.get("data", {}).get("data") == {"marker": "initial"})


def run():
    inputs = input_hashes()
    print("Consistency fixture: verifying signed image", flush=True)
    staged.verify()
    staged.verify_image_signature()
    podman = str(evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-270-consistency-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    run_id = secrets.token_hex(16)
    network = "openbao-270-consnet-" + run_id
    resources = []
    token = ""
    try:
        tls, ca = harness.generate_tls(root, openssl, environment)
        image = harness.inspect_image(podman, staged.RELEASE, environment)
        resources.append(("network", network))
        harness.run_bounded(fixture.network_command(podman, network, run_id), timeout=60, environment=environment)
        info = snapshots.parse_json(harness.run_bounded([podman, "network", "inspect", "--format", "{{json .}}", network],
            maximum=16 * 1024, timeout=10, environment=environment), 16 * 1024)
        internal = node_addresses(info)
        addresses = []
        for number, address in enumerate(internal):
            print(f"Consistency fixture: starting constrained Raft node {number + 1}", flush=True)
            name = f"openbao-270-cons-{number}-{run_id}"
            config = write_config(root, number, address)
            resources.append(("container", name))
            print("Consistency fixture: creating node container", flush=True)
            harness.run_bounded(container_command(podman, image, name, network, run_id, config, tls, address),
                                 timeout=120, environment=environment)
            print("Consistency fixture: checking node resource limits", flush=True)
            limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", name],
                                         maximum=64 * 1024, timeout=30, environment=environment)
            snapshots.validate_container_resource_config(snapshots.parse_json(limits, 64 * 1024))
            print("Consistency fixture: checking node routes", flush=True)
            fixture.verify_network(podman, network, name, environment)
            print("Consistency fixture: checking node loopback publication", flush=True)
            port = harness.parse_port(harness.run_bounded([podman, "port", name, "8200/tcp"],
                                      maximum=1024, timeout=30, environment=environment))
            public = f"https://127.0.0.1:{port}"
            print("Consistency fixture: waiting for exact-version TLS health", flush=True)
            fixture.wait_for_health(podman, name, environment, public, ca)
            fixture.probe_tls(port, ca)
            addresses.append(public)
        print("Consistency fixture: initializing and joining Raft cluster", flush=True)
        token = initialize_cluster(addresses, internal, ca)
        probe(addresses, ca, token)
    finally:
        token = ""
        failed = False
        for kind, name in reversed(resources):
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
            raise harness.HarnessError("consistency fixture cleanup incomplete")
    require(inputs == input_hashes())
    return {"schema": "openbao-consistency-protocol-tls/v1", "version": fixture.VERSION,
            "image_linux_amd64_digest": staged.AMD64, "inputs": inputs, "outcome": "passed",
            "scope": "multi-node-server-protocol-only", "nodes": 3, "tls": "TLSv1.3",
            "checks": CHECKS, "routable": False, "sdk_live_verified": False,
            "controlled_replication_lag_verified": False}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        result = run()
        with tempfile.NamedTemporaryFile(prefix="openbao-270-consistency-result-", suffix=".json", delete=False) as output:
            output.write(snapshots.canonical_json(result))
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            print(f"Consistency protocol fixture passed; result: {output.name}")
        return 0
    except (harness.HarnessError, snapshots.SnapshotError, OSError, ValueError, TypeError):
        print("Consistency fixture failed; no compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
