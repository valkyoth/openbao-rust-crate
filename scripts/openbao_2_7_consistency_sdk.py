#!/usr/bin/python3 -EsSB
"""Run staged SDK TLS transport tests as the invoking non-root user."""

import argparse
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import signal
import stat
import subprocess
import tempfile

import openbao_2_7_consistency as server

ROOT = server.ROOT
TEST = "client::consistency::live::staged_consistency_tls"
INPUTS = (*server.INPUTS, "scripts/openbao_2_7_consistency_sdk.py", "Cargo.toml", "Cargo.lock",
          "build.rs", "rust-toolchain.toml")


def input_hashes():
    paths = (*INPUTS, *(str(path.relative_to(ROOT)) for path in sorted((ROOT / "src").rglob("*.rs"))))
    return {path: server.snapshots.sha256(server.snapshots.read_regular_file(ROOT / path, 2 * 1024 * 1024))
            for path in paths}


def binary_hash(binary, uid, *, candidate=False):
    binary = Path(binary)
    directory = "target/candidate-sdk/debug/deps" if candidate else "target/debug/deps"
    server.require(binary.is_absolute() and binary.parent == ROOT / directory
                   and re.fullmatch(r"openbao-[0-9a-f]{16}", binary.name) is not None)
    metadata = binary.lstat()
    server.require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == uid
                   and metadata.st_mode & 0o111 and not metadata.st_mode & 0o022)
    return server.snapshots.sha256(server.snapshots.read_regular_file(binary, 256 * 1024 * 1024))


def run_test(binary, uid, gid, addresses, ca, token, *, test=TEST):
    tool = str(server.evidence_tools.protected_path(Path("/usr/bin/setpriv")))
    command = [tool, f"--reuid={uid}", f"--regid={gid}", "--clear-groups", "--no-new-privs",
               "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
               str(binary), "--ignored", "--exact", test, "--test-threads=1"]
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    listing = server.harness.run_bounded(command + ["--list"], maximum=1024, timeout=10, environment=environment)
    # libtest exits successfully even when a filter selects zero tests.
    server.require(listing == f"{test}: test\n\n1 test, 0 benchmarks\n".encode())
    payload = server.snapshots.canonical_json({"addresses": addresses, "ca_pem": ca.read_text(encoding="ascii"),
                                               "token": token})
    server.require(len(payload) < 65536)
    # Never execute a workspace-built program as root or inherit credentials,
    # loader overrides, proxies, extra descriptors, or a root-readable output file.
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, cwd=ROOT, close_fds=True,
                               start_new_session=True, env=environment)
    try:
        process.communicate(payload, timeout=90)
        server.require(process.returncode == 0)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def run(binary):
    server.require(os.geteuid() == 0)
    uid, gid = int(os.environ.get("SUDO_UID", "0")), int(os.environ.get("SUDO_GID", "0"))
    server.require(uid > 0 and gid > 0 and pwd.getpwuid(uid).pw_gid == gid)
    digest = binary_hash(binary, uid)
    inputs = input_hashes()
    print("Consistency SDK fixture: verifying signed image", flush=True)
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
        addresses = []
        for number, address in enumerate(internal):
            print(f"Consistency SDK fixture: starting constrained node {number + 1}", flush=True)
            name = f"openbao-270-sdk-{number}-{run_id}"
            config = server.write_config(root, number, address)
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
            addresses.append(public)
        token = server.initialize_cluster(addresses, internal, ca)
        server.probe(addresses, ca, token)
        active, _ = server.ready_cluster(addresses, ca)
        ordered = [addresses[active], *[address for i, address in enumerate(addresses) if i != active]]
        print("Consistency SDK fixture: running unprivileged Rust TLS transport test", flush=True)
        run_test(binary, uid, gid, ordered, ca, token)
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
    server.require(inputs == input_hashes() and digest == binary_hash(binary, uid))
    return {"schema": "openbao-consistency-sdk-tls/v1", "version": server.fixture.VERSION,
            "inputs": inputs, "test_binary_sha256": digest, "test": TEST, "outcome": "passed",
            "image_linux_amd64_digest": server.staged.AMD64, "routable": False,
            "scope": "sdk-production-transport-beneath-profile-gate", "controlled_replication_lag_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", required=True, type=Path)
    args = parser.parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, server.harness.interrupted)
    try:
        result = run(args.test_binary)
        with tempfile.NamedTemporaryFile(prefix="openbao-270-sdk-result-", suffix=".json", delete=False) as output:
            output.write(server.snapshots.canonical_json(result))
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            print(f"Consistency SDK transport fixture passed; result: {output.name}")
        return 0
    except (server.harness.HarnessError, server.snapshots.SnapshotError, OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("Consistency SDK fixture failed; no compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
