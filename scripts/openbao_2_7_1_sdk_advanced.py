#!/usr/bin/python3 -EsSB
"""Public SDK patch, backup and controlled-lag checks in one candidate build."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import signal
import subprocess
import tempfile

import openbao_2_7_1_sdk as basic
import openbao_2_7_1_backups as backups
import openbao_2_7_1_consistency as server
import openbao_2_7_consistency_sdk_lag as coordination
import openbao_patch_normal_sdk as normal_sdk

patch, base, harness, tls = basic.patch, basic.base, basic.harness, basic.tls
execution, builder, candidate = basic.execution, basic.builder, basic.candidate
FEATURES = "sys,approle,transit,transit-bytes,consistency,raw-api,raw-api-acknowledged,operator-ops,operator-ops-acknowledged,rustls-tls"
BACKUP_TEST = "sys::backup_live::public_patch_rotation_backup_strict_tls"
BASELINE_TEST = "client::consistency::patch_live::public_consistency_tls"
LAG_TEST = "client::consistency::patch_live::public_consistency_lag_tls"
TESTS = [basic.TEST, BACKUP_TEST, BASELINE_TEST, LAG_TEST]
CHECKS = ["exact-public-sdk-profile", "approle-expiry", "transit-version-and-aad",
          "workflow-cas-create-update", "workflow-cas-rejected-write-preserves-state", "sdk-grouped-backup-read",
          "sdk-singleton-backup-read", "sdk-hex-base64-equivalence", "three-node-public-sdk-baseline",
          "stale-read", "real-index-429", "rejected-write-no-mutation", "foreign-namespace-index-no-dispatch",
          "cancel-after-upstream-transmission", "timeout-after-upstream-transmission", "no-retry",
          "await-recovery", "independent-cluster-preflight-no-authenticated-dispatch", "cleanup"]


def input_hashes(*, normal=False):
    values = {**basic.input_hashes(), **backups.input_hashes(), **server.input_hashes()}
    for path in ("scripts/openbao_2_7_1_sdk_advanced.py", "scripts/openbao_2_7_consistency_sdk_lag.py",
                 "scripts/consistency_tls_relay.py"):
        values[path] = base.sha256(base.read_regular_file(patch.ROOT / path, 2 * 1024 * 1024))
    if normal:
        values.update(normal_sdk.input_hashes())
    return dict(sorted(values.items()))


def build():
    patch.require(os.geteuid() != 0)
    before = input_hashes()
    verified = candidate.verify()
    inputs = builder.backup_inputs(builder.source_inputs())
    with tempfile.TemporaryDirectory(prefix="openbao-271-advanced-build-") as temporary:
        root = Path(temporary)
        builder.prepare(root, inputs, verified)
        env = builder.build_environment(root)
        messages = builder.run(["cargo", "test", "--locked", "--offline", "--no-default-features", "--features", FEATURES,
                                "--lib", "--no-run", "--message-format=json-render-diagnostics"], root, env, capture=True)
        artifacts = [json.loads(line) for line in messages.splitlines() if line.strip()]
        binaries = [Path(item["executable"]) for item in artifacts if item.get("reason") == "compiler-artifact"
                    and item.get("executable") and item.get("target", {}).get("name") == "openbao"
                    and item.get("profile", {}).get("test") is True]
        patch.require(len(binaries) == 1 and before == input_hashes())
    print(f"2.7.1 advanced candidate SDK binary: {binaries[0]}")
    print("Build only; no live verification or normal profile promotion")


class Session(coordination.Session):
    """Reuse bounded coordination without changing the historical test selector."""

    def __init__(self, binary, uid, gid):
        super().__init__(binary, uid, gid)
        self.command[self.command.index(coordination.TEST)] = LAG_TEST

    def __enter__(self):
        listing = execution.test_listing(self.command, self.environment, self.binary)
        patch.require(listing == f"{LAG_TEST}: test\n\n1 test, 0 benchmarks\n".encode())
        self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=self.environment, cwd=patch.ROOT,
                                        close_fds=True, pass_fds=(self.binary.fd,), start_new_session=True)
        try:
            os.set_blocking(self.process.stdin.fileno(), False)
            os.set_blocking(self.process.stdout.fileno(), False)
        except BaseException:
            self.__exit__()
            raise
        return self


def probe(binary, uid, gid, addresses, recovery, names, ca, certs, token, podman, owner, environment, independent):
    active, _ = server.ready_cluster(addresses, ca)
    follower = next(i for i in range(3) if i != active)
    with coordination.relay_module.Relay(addresses[active], recovery[follower], ca, certs, token) as relay:
        with Session(binary, uid, gid) as child:
            child.send(base.canonical_json({"addresses": [relay.address] * 3,
                       "ca_pem": ca.read_text(encoding="ascii"), "token": token}))
            child.expect("scope-ready")
            before = [event for event in relay.snapshot() if event[1] in coordination.relay_module.PATHS]
            child.send(b"scope\n")
            child.expect("partition-ready")
            patch.require(before == [event for event in relay.snapshot() if event[1] in coordination.relay_module.PATHS])
            with server.lag.RaftPartition(podman, names[follower], owner, environment):
                child.send(b"partitioned\n")
                child.expect("cancel-ready")
                patch.require(relay.wait_for("POST", "/v1/fixture-kv/data/sdk-cancel"))
                child.send(b"cancel\n")
                child.expect("recovery-ready")
                patch.require(relay.wait_for("POST", "/v1/fixture-kv/data/sdk-timeout"))
                reads = relay.snapshot().count(("GET", "/v1/fixture-kv/data/sdk-lag"))
                child.send(b"await\n")
                patch.require(relay.wait_for("GET", "/v1/fixture-kv/data/sdk-lag", count=reads + 1))
            child.expect("isolation-ready")
            before = relay.snapshot()
            relay.switch_cluster(independent)
            child.send(b"switched\n")
            child.expect("complete")
            patch.require(relay.snapshot()[len(before):] == [("GET", "/v1/sys/health")])
            child.finish()
    events = relay.snapshot()
    for path in ("sdk-cancel", "sdk-timeout"):
        patch.require(events.count(("POST", "/v1/fixture-kv/data/" + path)) == 1)
        tls.require_status(server.protocol.request(addresses[active], ca, token, "GET", "/v1/fixture-kv/data/" + path)[0], 404)
    status, read, _, _ = server.protocol.request(addresses[active], ca, token, "GET", "/v1/fixture-kv/data/sdk-lag")
    tls.require_status(status, 200)
    server.lag.marker(read, "lagged", 2)


def start_node(podman, image, network, owner, root, certs, ca, number, address, environment, resources):
    name = f"openbao-271-advanced-{number}-{owner}"
    directory = root / f"node-{number}"
    directory.mkdir(mode=0o700)
    config = server.lag.write_config(directory, number if number < 3 else 0, address)
    resources.append(("container", name))
    harness.run_bounded(server.lag.container_command(podman, image, name, network, owner, config, certs, address),
                        timeout=120, environment=environment)
    limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", name],
                                 maximum=65536, timeout=30, environment=environment)
    base.validate_container_resource_config(base.parse_json(limits, 65536))
    tls.verify_network(podman, network, name, environment)
    endpoints = []
    for port_name in ("8200/tcp", "8202/tcp"):
        port = harness.parse_port(harness.run_bounded([podman, "port", name, port_name],
                                  maximum=1024, timeout=30, environment=environment))
        public = f"https://127.0.0.1:{port}"
        harness.wait_for_exact_version(public, ca, patch.VERSION)
        tls.probe_tls(port, ca)
        endpoints.append(public)
    return name, *endpoints


def run_cluster(binary, uid, gid):
    server.image_evidence.verify()
    print("2.7.1 advanced SDK: verifying signed image", flush=True)
    patch.verify_signature()
    podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-271-advanced-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    owner = secrets.token_hex(16)
    network = "openbao-271-advancednet-" + owner
    resources = []
    token = ""
    try:
        certs, ca = harness.generate_tls(root, openssl, environment)
        image = harness.inspect_image(podman, patch.RELEASE, environment)
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, owner), timeout=60, environment=environment)
        info = base.parse_json(harness.run_bounded([podman, "network", "inspect", "--format", "{{json .}}", network],
                               maximum=16384, timeout=10, environment=environment), 16384)
        internal = server.protocol.node_addresses(info)
        nodes = []
        for number, address in enumerate(internal):
            print(f"2.7.1 advanced SDK: starting constrained node {number + 1}", flush=True)
            nodes.append(start_node(podman, image, network, owner, root, certs, ca, number, address, environment, resources))
        names, addresses, recovery = ([node[i] for node in nodes] for i in range(3))
        token = server.protocol.initialize_cluster(addresses, internal, ca)
        server.probe(addresses, recovery, names, ca, token, podman, owner, environment)
        active, cluster = server.ready_cluster(addresses, ca)
        ordered = [addresses[active], *[address for i, address in enumerate(addresses) if i != active]]
        print("2.7.1 advanced SDK: public consistency baseline", flush=True)
        execution.run_test(binary, uid, gid, ordered, ca, token, test=BASELINE_TEST)
        independent_ip = ipaddress.IPv4Address(internal[-1]) + 1
        subnet = ipaddress.ip_network(info["subnets"][0]["subnet"])
        patch.require(independent_ip in subnet and independent_ip not in (subnet.network_address, subnet.broadcast_address)
                      and str(independent_ip) not in internal and str(independent_ip) != info["subnets"][0].get("gateway"))
        print("2.7.1 advanced SDK: starting independent cluster", flush=True)
        _, independent, _ = start_node(podman, image, network, owner, root, certs, ca, 3,
                                       str(independent_ip), environment, resources)
        server.protocol.initialize_cluster([independent], [str(independent_ip)], ca)
        status, health, _, _ = server.protocol.request(independent, ca, "", "GET", "/v1/sys/health")
        tls.require_status(status, 200)
        harness.verify_reported_version(health.get("version"), patch.VERSION)
        identity = health.get("cluster_id")
        patch.require(health.get("initialized") is True and health.get("sealed") is False and health.get("standby") is False
                      and isinstance(identity, str) and 0 < len(identity) <= 256 and identity != cluster)
        print("2.7.1 advanced SDK: public controlled lag, cancellation and isolation", flush=True)
        probe(binary, uid, gid, addresses, recovery, names, ca, certs, token, podman, owner, environment, independent)
    finally:
        token = ""
        failed = False
        for kind, name in reversed(resources):
            try:
                harness.remove_owned_resource(podman, kind, name, owner, environment)
            except (harness.HarnessError, OSError):
                failed = True
        if not harness.cleanup_private_files(root):
            failed = True
        try:
            shutil.rmtree(root)
        except OSError:
            failed = True
        patch.require(not failed)


@execution.frozen_runner
def run(binary, strict_candidate=False, normal=False):
    patch.require(type(normal) is bool and type(strict_candidate) is bool and normal != strict_candidate)
    uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    patch.require(uid > 0 and gid > 0 and pwd.getpwuid(uid).pw_gid == gid)
    digest = execution.binary_hash(binary, uid, candidate=strict_candidate)
    inputs = input_hashes(normal=True) if normal else input_hashes()
    provenance = normal_sdk.verify() if normal else None
    verified = None if normal else candidate.verify()
    calls = 0

    def observe(address, ca, token):
        nonlocal calls
        patch.require(calls == 0)
        for test, label in ((basic.TEST, "AppRole, Transit and workflow CAS"), (BACKUP_TEST, "public backup decoding")):
            print(f"2.7.1 advanced SDK: {label}", flush=True)
            execution.run_test(binary, uid, gid, [address] * 3, ca, token, test=test)
        calls += 1

    backups.run("recovery", backup_observer=observe)
    patch.require(calls == 1)
    run_cluster(binary, uid, gid)
    patch.require(inputs == (input_hashes(normal=True) if normal else input_hashes())
                  and digest == execution.binary_hash(binary, uid, candidate=strict_candidate))
    report = {**execution.EXECUTION_ASSURANCE, "schema": "openbao-patch-sdk-advanced-tls/v1",
            "version": patch.VERSION, "inputs": inputs, "test_binary_sha256": digest,
            "tests": TESTS, "features": FEATURES, "checks": CHECKS,
            "scope": "public-sdk-strict-disposable-candidate-build", "image_linux_amd64_digest": patch.AMD64,
            "image_index_digest": patch.INDEX, "routable": False, "outcome": "passed",
            "backup_decryption_verified": False, "synthetic_indices": "test-only-never-observable-cancellation-and-timeout"}
    if normal:
        patch.require(provenance == normal_sdk.verify())
        report.update(provenance)
    else:
        report.update(candidate_registry_sha256=candidate.EXPECTED_SHA256,
                      candidate_generated_rust_sha256=base.sha256(candidate.registry.rust_output(verified, verification_candidate=True)),
                      source_scope="repository-inputs-with-explicit-generated-candidate-override")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--build", action="store_true")
    action.add_argument("--test-binary", type=Path)
    parser.add_argument("--normal", action="store_true", help="Verify the checked-in normal build, without a candidate override")
    args = parser.parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        if args.build:
            if args.normal:
                normal_sdk.build(FEATURES, lambda: input_hashes(normal=True))
            else:
                build()
        else:
            result = run(args.test_binary, strict_candidate=not args.normal, normal=args.normal)
            with tempfile.NamedTemporaryFile(prefix="openbao-271-sdk-advanced-result-", suffix=".json", delete=False) as output:
                output.write(base.canonical_json(result))
                output.flush()
                os.fsync(output.fileno())
                os.fchmod(output.fileno(), 0o644)
                print(f"2.7.1 advanced public SDK fixture passed; result: {output.name}", flush=True)
    except (harness.HarnessError, base.SnapshotError, candidate.registry.RegistryError,
            OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("2.7.1 advanced SDK fixture failed; no compatibility promotion")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
