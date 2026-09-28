#!/usr/bin/python3 -EsSB
"""Coordinate the unprivileged SDK test with a scoped Raft partition and TLS relay."""

import argparse
import ipaddress
import os
from pathlib import Path
import pwd
import secrets
import selectors
import shutil
import signal
import subprocess
import tempfile
import time

import consistency_tls_relay as relay_module
import openbao_2_7_consistency_lag as lag
import openbao_2_7_consistency_sdk as sdk

server = sdk.server
TEST = "client::consistency::live::staged_consistency_lag_tls"
STAGES = ("scope-ready", "partition-ready", "cancel-ready", "recovery-ready", "isolation-ready", "complete")


def input_hashes():
    inputs = sdk.input_hashes()
    for path in ("scripts/openbao_2_7_consistency_sdk_lag.py", "scripts/openbao_2_7_consistency_lag.py",
                 "scripts/consistency_tls_relay.py"):
        inputs[path] = server.snapshots.sha256(server.snapshots.read_regular_file(server.ROOT / path, 2 * 1024 * 1024))
    return inputs


class Session:
    def __init__(self, binary, uid, gid):
        tool = str(server.evidence_tools.protected_path(Path("/usr/bin/setpriv")))
        self.command = [tool, f"--reuid={uid}", f"--regid={gid}", "--clear-groups", "--no-new-privs",
                        "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", str(binary),
                        "--ignored", "--exact", TEST, "--test-threads=1", "--nocapture"]
        self.environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
        self.process = None
        self.buffer = b""
        self.total = 0
        self.stage = 0

    def __enter__(self):
        listing = server.harness.run_bounded(self.command + ["--list"], maximum=1024, timeout=10, environment=self.environment)
        server.require(listing == f"{TEST}: test\n\n1 test, 0 benchmarks\n".encode())
        self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=self.environment, cwd=server.ROOT,
                                        close_fds=True, start_new_session=True)
        try:
            os.set_blocking(self.process.stdin.fileno(), False)
            os.set_blocking(self.process.stdout.fileno(), False)
        except BaseException:
            self.__exit__()
            raise
        return self

    def send(self, data):
        server.require(isinstance(data, bytes) and len(data) <= 65536 and data.endswith(b"\n"))
        deadline = time.monotonic() + 5
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdin, selectors.EVENT_WRITE)
            while data:
                remaining = deadline - time.monotonic()
                server.require(remaining > 0 and selector.select(remaining))
                try:
                    size = os.write(self.process.stdin.fileno(), data)
                except BlockingIOError:
                    continue
                server.require(size > 0)
                data = data[size:]

    def expect(self, stage):
        server.require(self.stage < len(STAGES) and stage == STAGES[self.stage])
        deadline = time.monotonic() + 25
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while True:
                while b"\n" in self.buffer:
                    line, self.buffer = self.buffer.split(b"\n", 1)
                    if b"CONSISTENCY:" in line:
                        server.require(line.split(b"CONSISTENCY:", 1)[1] == stage.encode("ascii"))
                        self.stage += 1
                        print(f"Consistency SDK lag fixture: {stage}", flush=True)
                        return
                remaining = deadline - time.monotonic()
                server.require(remaining > 0 and selector.select(remaining))
                chunk = os.read(self.process.stdout.fileno(), 4096)
                server.require(bool(chunk))
                self.total += len(chunk)
                server.require(self.total <= 16384)
                # Never echo child output; only fixed, validated stage labels.
                self.buffer += chunk

    def finish(self):
        server.require(self.stage == len(STAGES))
        self.process.stdin.close()
        server.require(self.process.wait(timeout=10) == 0)

    def __exit__(self, *_):
        if self.process is not None:
            try:
                if self.process.poll() is None:
                    os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
            finally:
                self.process.stdin.close()
                self.process.stdout.close()


def probe(binary, uid, gid, addresses, recovery, names, ca, tls, token, podman, run_id, environment, independent):
    active, _ = server.ready_cluster(addresses, ca)
    follower = next(i for i in range(3) if i != active)
    with relay_module.Relay(addresses[active], recovery[follower], ca, tls, token) as relay:
        with Session(binary, uid, gid) as child:
            child.send(server.snapshots.canonical_json({"addresses": [relay.address] * 3,
                       "ca_pem": ca.read_text(encoding="ascii"), "token": token}))
            child.expect("scope-ready")
            before = [event for event in relay.snapshot() if event[1] in relay_module.PATHS]
            child.send(b"scope\n")
            child.expect("partition-ready")
            server.require(before == [event for event in relay.snapshot() if event[1] in relay_module.PATHS])
            with lag.RaftPartition(podman, names[follower], run_id, environment):
                child.send(b"partitioned\n")
                child.expect("cancel-ready")
                server.require(relay.wait_for("POST", "/v1/fixture-kv/data/sdk-cancel"))
                child.send(b"cancel\n")
                child.expect("recovery-ready")
                server.require(relay.wait_for("POST", "/v1/fixture-kv/data/sdk-timeout"))
                reads = relay.snapshot().count(("GET", "/v1/fixture-kv/data/sdk-lag"))
                child.send(b"await\n")
                server.require(relay.wait_for("GET", "/v1/fixture-kv/data/sdk-lag", count=reads + 1))
                # Leaving the context restores Raft only after the SDK awaited
                # request has been transmitted through verified upstream TLS.
            child.expect("isolation-ready")
            before = relay.snapshot()
            relay.switch_cluster(independent)
            child.send(b"switched\n")
            child.expect("complete")
            server.require(relay.snapshot()[len(before):] == [("GET", "/v1/sys/health")])
            child.finish()
    # Relay exit drains its upstream handlers; late replay cannot hide behind
    # the client timeout or cancellation when inspecting final server state.
    events = relay.snapshot()
    for path in ("sdk-cancel", "sdk-timeout"):
        server.require(events.count(("POST", "/v1/fixture-kv/data/" + path)) == 1)
    for path in ("sdk-cancel", "sdk-timeout"):
        server.fixture.require_status(server.request(addresses[active], ca, token, "GET", "/v1/fixture-kv/data/" + path)[0], 404)
    status, read, _, _ = server.request(addresses[active], ca, token, "GET", "/v1/fixture-kv/data/sdk-lag")
    server.fixture.require_status(status, 200)
    lag.marker(read, "lagged", 2)


def independent_cluster(podman, image, network, run_id, root, tls, ca, internal, info, environment, resources, cluster):
    address = str(ipaddress.IPv4Address(internal[-1]) + 1)
    subnet = ipaddress.ip_network(info["subnets"][0]["subnet"])
    server.require(ipaddress.IPv4Address(address) in subnet and address not in internal
                   and address != info["subnets"][0].get("gateway")
                   and ipaddress.IPv4Address(address) != subnet.broadcast_address)
    print("Consistency SDK lag fixture: starting independent cluster for isolation", flush=True)
    directory = root / "independent"
    directory.mkdir(mode=0o700)
    config = server.write_config(directory, 0, address)
    name = "openbao-270-independent-" + run_id
    resources.append(("container", name))
    server.harness.run_bounded(server.container_command(podman, image, name, network, run_id, config, tls, address),
                               timeout=120, environment=environment)
    limits = server.harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", name],
                                       maximum=65536, timeout=30, environment=environment)
    server.snapshots.validate_container_resource_config(server.snapshots.parse_json(limits, 65536))
    server.fixture.verify_network(podman, network, name, environment)
    port = server.harness.parse_port(server.harness.run_bounded([podman, "port", name, "8200/tcp"],
                                     maximum=1024, timeout=30, environment=environment))
    public = f"https://127.0.0.1:{port}"
    server.fixture.wait_for_health(podman, name, environment, public, ca)
    server.fixture.probe_tls(port, ca)
    # A one-element list initializes/unseals but never joins the original cluster.
    server.initialize_cluster([public], [address], ca)
    status, health, _, _ = server.request(public, ca, "", "GET", "/v1/sys/health")
    server.fixture.require_status(status, 200)
    server.harness.verify_reported_version(health.get("version"), server.fixture.VERSION)
    identity = health.get("cluster_id")
    server.require(health.get("initialized") is True and health.get("sealed") is False
                   and health.get("standby") is False and isinstance(identity, str)
                   and 0 < len(identity) <= 256 and identity != cluster)
    return public


def run(binary):
    server.require(os.geteuid() == 0)
    uid, gid = int(os.environ.get("SUDO_UID", "0")), int(os.environ.get("SUDO_GID", "0"))
    server.require(uid > 0 and gid > 0 and pwd.getpwuid(uid).pw_gid == gid)
    digest = sdk.binary_hash(binary, uid)
    baseline_inputs = sdk.input_hashes()
    inputs = input_hashes()
    server.require(all(inputs.get(path) == digest for path, digest in baseline_inputs.items()))
    print("Consistency SDK lag fixture: verifying signed image", flush=True)
    server.staged.verify()
    server.staged.verify_image_signature()
    podman = str(server.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(server.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-270-sdk-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    run_id = secrets.token_hex(16)
    network = "openbao-270-sdknet-" + run_id
    resources = []
    try:
        tls, ca = server.harness.generate_tls(root, openssl, environment)
        image = server.harness.inspect_image(podman, server.staged.RELEASE, environment)
        resources.append(("network", network))
        server.harness.run_bounded(server.fixture.network_command(podman, network, run_id), timeout=60, environment=environment)
        info = server.snapshots.parse_json(server.harness.run_bounded(
            [podman, "network", "inspect", "--format", "{{json .}}", network],
            maximum=16384, timeout=10, environment=environment), 16384)
        internal = server.node_addresses(info)
        addresses, recovery, names = [], [], []
        for number, address in enumerate(internal):
            print(f"Consistency SDK lag fixture: starting constrained node {number + 1}", flush=True)
            name = f"openbao-270-sdk-{number}-{run_id}"
            config = lag.write_config(root, number, address)
            resources.append(("container", name))
            server.harness.run_bounded(lag.container_command(podman, image, name, network, run_id, config, tls, address),
                                       timeout=120, environment=environment)
            limits = server.harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", name],
                                               maximum=65536, timeout=30, environment=environment)
            server.snapshots.validate_container_resource_config(server.snapshots.parse_json(limits, 65536))
            server.fixture.verify_network(podman, network, name, environment)
            port = server.harness.parse_port(server.harness.run_bounded([podman, "port", name, "8200/tcp"],
                                            maximum=1024, timeout=30, environment=environment))
            public = f"https://127.0.0.1:{port}"
            server.fixture.wait_for_health(podman, name, environment, public, ca)
            server.fixture.probe_tls(port, ca)
            recovery_port = server.harness.parse_port(server.harness.run_bounded([podman, "port", name, "8202/tcp"],
                maximum=1024, timeout=30, environment=environment))
            recovery_public = f"https://127.0.0.1:{recovery_port}"
            server.fixture.wait_for_health(podman, name, environment, recovery_public, ca)
            server.fixture.probe_tls(recovery_port, ca)
            recovery.append(recovery_public)
            names.append(name)
            addresses.append(public)
        token = server.initialize_cluster(addresses, internal, ca)
        server.probe(addresses, ca, token)
        active, cluster = server.ready_cluster(addresses, ca)
        ordered = [addresses[active], *[address for i, address in enumerate(addresses) if i != active]]
        print("Consistency SDK lag fixture: running unprivileged Rust TLS transport test", flush=True)
        sdk.run_test(binary, uid, gid, ordered, ca, token)
        server.require(server.ready_cluster(addresses, ca) == server.ready_cluster(recovery, ca))
        independent = independent_cluster(podman, image, network, run_id, root, tls, ca, internal, info,
                                          environment, resources, cluster)
        probe(binary, uid, gid, addresses, recovery, names, ca, tls, token, podman, run_id, environment, independent)
        token = ""
    finally:
        failed = False
        for kind, name in reversed(resources):
            try:
                server.harness.remove_owned_resource(podman, kind, name, run_id, environment)
            except (server.harness.HarnessError, OSError):
                failed = True
        if not server.harness.cleanup_private_files(root):
            failed = True
        try:
            shutil.rmtree(root)
        except OSError:
            failed = True
        server.require(not failed)
    server.require(inputs == input_hashes() and digest == sdk.binary_hash(binary, uid))
    baseline = {"schema": "openbao-consistency-sdk-tls/v1", "version": server.fixture.VERSION,
                "inputs": baseline_inputs, "test_binary_sha256": digest, "test": sdk.TEST, "outcome": "passed",
                "image_linux_amd64_digest": server.staged.AMD64, "routable": False,
                "scope": "sdk-production-transport-beneath-profile-gate", "controlled_replication_lag_verified": False}
    combined = {"schema": "openbao-consistency-sdk-lag-tls/v2", "version": server.fixture.VERSION,
                "inputs": inputs, "test_binary_sha256": digest, "test": TEST, "outcome": "passed",
                "image_linux_amd64_digest": server.staged.AMD64, "routable": False,
                "scope": "sdk-controlled-lag-beneath-profile-gate",
                "checks": ["stale-read", "real-index-429", "rejected-write-no-mutation",
                           "foreign-namespace-index-no-dispatch", "cancel-after-upstream-transmission",
                           "timeout-after-upstream-transmission", "no-retry", "await-recovery",
                           "independent-cluster-preflight-no-authenticated-dispatch", "cleanup"]}
    return baseline, combined


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", required=True, type=Path)
    args = parser.parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, server.harness.interrupted)
    try:
        baseline, combined = run(args.test_binary)
        for label, result in (("sdk-baseline", baseline), ("sdk-lag", combined)):
            with tempfile.NamedTemporaryFile(prefix=f"openbao-270-{label}-result-", suffix=".json", delete=False) as output:
                output.write(server.snapshots.canonical_json(result))
                output.flush()
                os.fchmod(output.fileno(), 0o644)
                print(f"Consistency {label} fixture passed; result: {output.name}")
        return 0
    except (server.harness.HarnessError, server.snapshots.SnapshotError, OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("Consistency SDK lag fixture failed; no compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
