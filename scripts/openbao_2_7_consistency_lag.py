#!/usr/bin/python3 -EsSB
"""Controlled Raft lag in one disposable container network namespace only."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import tempfile
import time

import openbao_2_7_consistency as server

INPUTS = (*server.INPUTS, "scripts/openbao_2_7_consistency_lag.py")
CHECKS = ["three-node-protocol-baseline", "container-only-raft-partition", "real-write-index",
          "stale-read-observed", "unseen-real-index-429", "unseen-write-no-mutation",
          "await-expiry", "replication-restored", "await-recovery", "cleanup"]


def input_hashes():
    return {path: server.snapshots.sha256(server.snapshots.read_regular_file(server.ROOT / path, 2 * 1024 * 1024))
            for path in INPUTS}


def write_config(root, number, address):
    config = server.write_config(root, number, address)
    # Keep the original 250 ms listener for expiry checks. Recovery has a
    # distinct bounded window so TCP/Raft retry latency is not confused with
    # failure of consistency enforcement.
    recovery = ('listener "tcp" {\n  address = "0.0.0.0:8202"\n'
                '  cluster_address = "0.0.0.0:8203"\n'
                '  tls_cert_file = "/openbao/tls/server.crt"\n'
                '  tls_key_file = "/openbao/tls/server.key"\n'
                '  tls_min_version = "tls13"\n'
                '  consistency_max_index_wait = "10s"\n'
                '  consistency_fallback_behavior = "fail"\n}\n')
    combined = root / f"node-{number}-recovery.hcl"
    server.harness.write_private(combined, (config.read_text(encoding="ascii") + recovery).encode("ascii"), 0o640)
    return combined


def container_command(*args):
    command = server.container_command(*args)
    command[2:2] = ["--publish", "127.0.0.1::8202"]
    return command


def namespace_path(info, name, run_id):
    server.require(isinstance(info, dict) and isinstance(info.get("Name"), str)
                   and info["Name"].lstrip("/") == name)
    config, state, network = info.get("Config"), info.get("State"), info.get("NetworkSettings")
    server.require(isinstance(config, dict) and isinstance(state, dict) and isinstance(network, dict))
    labels = config.get("Labels")
    server.require(isinstance(labels, dict) and labels.get(server.harness.OWNER_LABEL) == run_id
                   and state.get("Running") is True)
    value = network.get("SandboxKey")
    server.require(isinstance(value, str) and re.fullmatch(r"/run/netns/netns-[a-zA-Z0-9-]+", value) is not None)
    return Path(value)


class RaftPartition:
    """Pin a verified non-host namespace before installing a private nft table."""

    def __init__(self, podman, name, run_id, environment):
        server.require(re.fullmatch(r"[0-9a-f]{32}", run_id) is not None)
        self.podman, self.name, self.run_id = podman, name, run_id
        self.environment = environment
        self.table = "openbao_fixture_" + run_id
        self.fd = None
        self.installed = False
        self.nsenter = str(server.evidence_tools.protected_path(Path("/usr/bin/nsenter")))
        self.nft = str(server.evidence_tools.protected_path(Path("/usr/sbin/nft")))

    def inspect(self):
        raw = server.harness.run_bounded([self.podman, "inspect", "--format", "{{json .}}", self.name],
                                         maximum=65536, timeout=10, environment=self.environment)
        return namespace_path(server.snapshots.parse_json(raw, 65536), self.name, self.run_id)

    def command(self, body):
        server.require(self.fd is not None)
        # Pass a pinned namespace FD, never a PID that can be recycled. No shell,
        # host firewall command, config files or inherited proxy/loader settings.
        result = subprocess.run([self.nsenter, f"--net=/proc/self/fd/{self.fd}", self.nft, "-f", "-"],
                                input=body.encode("ascii"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=10, check=False, close_fds=True, pass_fds=(self.fd,), env=self.environment)
        server.require(result.returncode == 0)

    def __enter__(self):
        print("Consistency lag fixture: pinning owned non-host network namespace", flush=True)
        path = self.inspect()
        # The mount and its parent must be protected against workspace replacement.
        parent = path.parent.lstat()
        server.require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o022)
        self.fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata = os.fstat(self.fd)
            host = os.stat("/proc/self/ns/net")
            server.require(metadata.st_uid == 0 and not metadata.st_mode & 0o022
                           and (metadata.st_dev, metadata.st_ino) != (host.st_dev, host.st_ino))
            server.require(path == self.inspect())
            current = path.stat(follow_symlinks=False)
            server.require((current.st_dev, current.st_ino) == (metadata.st_dev, metadata.st_ino))
            body = f"add table inet {self.table}\n"
            for direction in ("input", "output"):
                body += f"add chain inet {self.table} {direction} {{ type filter hook {direction} priority -100; policy accept; }}\n"
                for port in ("sport", "dport"):
                    body += f"add rule inet {self.table} {direction} tcp {port} 8201 drop\n"
            print("Consistency lag fixture: installing container-local Raft filter", flush=True)
            self.command(body)
            self.installed = True
            return self
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise

    def restore(self):
        if self.installed:
            print("Consistency lag fixture: removing container-local Raft filter", flush=True)
            self.command(f"delete table inet {self.table}\n")
            self.installed = False

    def __exit__(self, *_):
        try:
            self.restore()
        finally:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None


def marker(response, expected, version):
    server.require(response.get("data", {}).get("data") == {"marker": expected}
                   and response.get("data", {}).get("metadata", {}).get("version") == version)


def probe(addresses, names, ca, token, podman, run_id, environment, recovery_addresses):
    active, cluster = server.ready_cluster(addresses, ca)
    standby = next(i for i in range(3) if i != active)
    leader, follower = addresses[active], addresses[standby]
    path = "/v1/fixture-kv/data/check"
    print("Consistency lag fixture: isolating one standby's Raft port", flush=True)
    with RaftPartition(podman, names[standby], run_id, environment) as partition:
        status, written, index, _ = server.request(leader, ca, token, "POST", path,
                                                 {"data": {"marker": "lagged"}, "options": {"cas": 1}})
        server.fixture.require_status(status, 200)
        server.require(written.get("data", {}).get("version") == 2)
        server.index_value(index, cluster)
        print("Consistency lag fixture: proving stale HTTPS read and real-index rejection", flush=True)
        status, stale, _, _ = server.request(follower, ca, token, "GET", path, policies=("fail",))
        server.fixture.require_status(status, 200)
        marker(stale, "initial", 1)
        status, _, _, retry = server.request(follower, ca, token, "GET", path, index=index, policies=("fail",))
        server.fixture.require_status(status, 429)
        server.require(retry == "1")
        status, _, _, _ = server.request(follower, ca, token, "POST", path, {"data": {"marker": "forbidden"}},
                                         index=index, policies=("fail",))
        server.fixture.require_status(status, 429)
        start = time.monotonic()
        status, _, _, _ = server.request(follower, ca, token, "GET", path, index=index, policies=("await-state", "fail"))
        server.fixture.require_status(status, 429)
        server.require(0.15 <= time.monotonic() - start < 5)
        print("Consistency lag fixture: restoring replication during an awaited read", flush=True)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(server.request, recovery_addresses[standby], ca, token, "GET", path,
                                  index=index, policies=("await-state", "fail"), timeout=15)
            time.sleep(0.05)
            server.require(not pending.done())
            partition.restore()
            status, read, _, _ = pending.result(timeout=16)
            # No fallback to retries or forwarding: this same awaited read must
            # succeed within the recovery listener's bounded wait.
            server.fixture.require_status(status, 200)
            marker(read, "lagged", 2)
    status, read, _, _ = server.request(leader, ca, token, "GET", path)
    server.fixture.require_status(status, 200)
    marker(read, "lagged", 2)
    server.ready_cluster(addresses, ca)


def run():
    server.require(os.geteuid() == 0)
    inputs = input_hashes()
    print("Consistency lag fixture: verifying signed image", flush=True)
    server.staged.verify()
    server.staged.verify_image_signature()
    podman = str(server.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(server.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-270-lag-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    run_id = secrets.token_hex(16)
    network = "openbao-270-lagnet-" + run_id
    resources = []
    try:
        tls, ca = server.harness.generate_tls(root, openssl, environment)
        image = server.harness.inspect_image(podman, server.staged.RELEASE, environment)
        resources.append(("network", network))
        server.harness.run_bounded(server.fixture.network_command(podman, network, run_id), timeout=60, environment=environment)
        info = server.snapshots.parse_json(server.harness.run_bounded(
            [podman, "network", "inspect", "--format", "{{json .}}", network], maximum=16384,
            timeout=10, environment=environment), 16384)
        internal = server.node_addresses(info)
        addresses, names, recovery_addresses = [], [], []
        for number, address in enumerate(internal):
            print(f"Consistency lag fixture: starting constrained node {number + 1}", flush=True)
            name = f"openbao-270-lag-{number}-{run_id}"
            config = write_config(root, number, address)
            resources.append(("container", name))
            server.harness.run_bounded(container_command(podman, image, name, network, run_id, config, tls, address),
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
            addresses.append(public)
            recovery_addresses.append(recovery_public)
            names.append(name)
        token = server.initialize_cluster(addresses, internal, ca)
        server.probe(addresses, ca, token)
        recovery_active, recovery_cluster = server.ready_cluster(recovery_addresses, ca)
        active, cluster = server.ready_cluster(addresses, ca)
        server.require((recovery_active, recovery_cluster) == (active, cluster))
        probe(addresses, names, ca, token, podman, run_id, environment, recovery_addresses)
        token = ""
    finally:
        failed = False
        for kind, name in reversed(resources):
            try:
                server.harness.remove_owned_resource(podman, kind, name, run_id, environment)
            except (server.harness.HarnessError, OSError):
                failed = True
        if not server.harness.cleanup_private_files(root): failed = True
        try:
            shutil.rmtree(root)
        except OSError:
            failed = True
        server.require(not failed)
    server.require(inputs == input_hashes())
    return {"schema": "openbao-consistency-controlled-lag/v1", "version": server.fixture.VERSION,
            "inputs": inputs, "outcome": "passed", "checks": CHECKS, "routable": False,
            "image_linux_amd64_digest": server.staged.AMD64, "scope": "controlled-lag-server-protocol-only",
            "sdk_controlled_lag_verified": False, "expiry_listener_wait_ms": 250,
            "recovery_listener_wait_ms": 10000}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for number in (signal.SIGINT, signal.SIGTERM): signal.signal(number, server.harness.interrupted)
    try:
        result = run()
        with tempfile.NamedTemporaryFile(prefix="openbao-270-lag-result-", suffix=".json", delete=False) as output:
            output.write(server.snapshots.canonical_json(result))
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            print(f"Consistency controlled-lag fixture passed; result: {output.name}")
        return 0
    except (server.harness.HarnessError, server.snapshots.SnapshotError, OSError, ValueError, subprocess.SubprocessError):
        print("Consistency lag fixture failed; no compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
