#!/usr/bin/python3 -EsSB
"""Exact patch Raft protocol and controlled-lag evidence, not SDK promotion."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import tempfile
import time

import openbao_2_7_1 as patch
import openbao_2_7_consistency as protocol
import openbao_2_7_consistency_lag as lag
import verify_openbao_2_7_1_image as image_evidence

base, harness, tls = patch.base, patch.harness, patch.tls
CHECKS = [*protocol.CHECKS[:-1], *lag.CHECKS]


def input_hashes():
    paths = {*patch.INPUTS, *lag.INPUTS, "scripts/openbao_2_7_1_consistency.py",
             "scripts/verify_openbao_2_7_1_image.py",
             *("compat/onboarding/2.7.1/" + name for name in image_evidence.ARTIFACTS)}
    return {path: base.sha256(base.read_regular_file(patch.ROOT / path, 2 * 1024 * 1024))
            for path in sorted(paths)}


def ready_cluster(addresses, ca):
    patch.require(len(addresses) == 3 and len(set(addresses)) == 3)
    for _ in range(120):
        health = [protocol.request(address, ca, "", "GET", "/v1/sys/health") for address in addresses]
        for _, body, _, _ in health:
            harness.verify_reported_version(body.get("version"), patch.VERSION)
        if (all(status in (200, 429) and body.get("initialized") is True
                and body.get("sealed") is False and type(body.get("standby")) is bool
                for status, body, _, _ in health)
                and sum(body["standby"] is False for _, body, _, _ in health) == 1):
            clusters = [body.get("cluster_id") for _, body, _, _ in health]
            patch.require(all(isinstance(value, str) and 0 < len(value) <= 256 for value in clusters))
            patch.require(len(set(clusters)) == 1)
            return next(i for i, (_, body, _, _) in enumerate(health) if not body["standby"]), clusters[0]
        time.sleep(0.25)
    raise harness.HarnessError("exact patch cluster did not become ready")


def probe(addresses, recovery_addresses, names, ca, token, podman, owner, environment):
    active, cluster = ready_cluster(addresses, ca)
    patch.require(ready_cluster(recovery_addresses, ca) == (active, cluster))
    leader = addresses[active]
    follower_number = next(i for i in range(3) if i != active)
    follower = addresses[follower_number]
    request = protocol.request
    print("2.7.1 consistency: checking three voting members", flush=True)
    for _ in range(120):
        status, result, _, _ = request(leader, ca, token, "GET", "/v1/sys/storage/raft/configuration")
        tls.require_status(status, 200)
        members = result.get("data", {}).get("config", {}).get("servers")
        patch.require(isinstance(members, list) and len(members) <= 3)
        if (len(members) == 3 and all(isinstance(member, dict) and member.get("voter") is True for member in members)
                and {member.get("node_id") for member in members} == {"fixture-0", "fixture-1", "fixture-2"}):
            break
        time.sleep(0.25)
    else:
        raise harness.HarnessError("three voting members unavailable")
    tls.require_status(request(leader, ca, token, "POST", "/v1/sys/mounts/fixture-kv",
                              {"type": "kv", "options": {"version": "2"}})[0], 204)
    path = "/v1/fixture-kv/data/check"
    status, written, index, _ = request(leader, ca, token, "POST", path, {"data": {"marker": "initial"}})
    tls.require_status(status, 200)
    patch.require(written.get("data", {}).get("version") == 1)
    protocol.index_value(index, cluster)
    print("2.7.1 consistency: real index propagation on both standbys", flush=True)
    for number, standby in enumerate(addresses):
        if number == active:
            continue
        for _ in range(120):
            status, read, _, _ = request(standby, ca, token, "GET", path, index=index, policies=("await-state", "fail"))
            if status == 200:
                lag.marker(read, "initial", 1)
                break
            patch.require(status == 429 or protocol.kv_initializing(status, read))
            time.sleep(0.025)
        else:
            raise harness.HarnessError("standby did not apply write index")
    future = base64.b64encode(base.canonical_json({"cluster": cluster, "value": str(2**64 - 1)})).decode("ascii")
    protocol.index_value(future, cluster)
    print("2.7.1 consistency: explicit policies and rejected-write side effects", flush=True)
    status, _, _, retry = request(follower, ca, token, "GET", path, index=future, policies=("fail",))
    tls.require_status(status, 429)
    patch.require(retry == "1")
    started = time.monotonic()
    tls.require_status(request(follower, ca, token, "GET", path, index=future, policies=("await-state", "fail"))[0], 429)
    patch.require(0.15 <= time.monotonic() - started < 5)
    for policy in (("forward-active-node",), ("await-state", "forward-active-node")):
        status, read, _, _ = request(follower, ca, token, "GET", path, index=future, policies=policy)
        tls.require_status(status, 200)
        lag.marker(read, "initial", 1)
    tls.require_status(request(follower, ca, token, "GET", path, index=index, policies=("await-state,fail",))[0], 400)
    tls.require_status(request(follower, ca, token, "POST", path, {"data": {"marker": "forbidden"}},
                              index=future, policies=("fail",))[0], 429)
    status, read, _, _ = request(leader, ca, token, "GET", path)
    tls.require_status(status, 200)
    lag.marker(read, "initial", 1)

    print("2.7.1 consistency: isolating one standby's Raft port", flush=True)
    with lag.RaftPartition(podman, names[follower_number], owner, environment) as partition:
        status, written, index, _ = request(leader, ca, token, "POST", path,
                                            {"data": {"marker": "lagged"}, "options": {"cas": 1}})
        tls.require_status(status, 200)
        patch.require(written.get("data", {}).get("version") == 2)
        protocol.index_value(index, cluster)
        status, stale, _, _ = request(follower, ca, token, "GET", path, policies=("fail",))
        tls.require_status(status, 200)
        lag.marker(stale, "initial", 1)
        status, _, _, retry = request(follower, ca, token, "GET", path, index=index, policies=("fail",))
        tls.require_status(status, 429)
        patch.require(retry == "1")
        tls.require_status(request(follower, ca, token, "POST", path, {"data": {"marker": "forbidden"}},
                                  index=index, policies=("fail",))[0], 429)
        started = time.monotonic()
        tls.require_status(request(follower, ca, token, "GET", path, index=index, policies=("await-state", "fail"))[0], 429)
        patch.require(0.15 <= time.monotonic() - started < 5)
        print("2.7.1 consistency: restoring replication during an awaited read", flush=True)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(request, recovery_addresses[follower_number], ca, token, "GET", path,
                                  index=index, policies=("await-state", "fail"), timeout=15)
            time.sleep(0.05)
            patch.require(not pending.done())
            partition.restore()
            status, read, _, _ = pending.result(timeout=16)
            tls.require_status(status, 200)
            lag.marker(read, "lagged", 2)
    status, read, _, _ = request(leader, ca, token, "GET", path)
    tls.require_status(status, 200)
    lag.marker(read, "lagged", 2)
    ready_cluster(addresses, ca)


def run():
    patch.require(os.geteuid() == 0)
    inputs = input_hashes()
    image_evidence.verify()
    print("2.7.1 consistency: verifying signed image", flush=True)
    patch.verify_signature()
    podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-271-consistency-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    owner = secrets.token_hex(16)
    network = "openbao-271-consnet-" + owner
    resources = []
    token = ""
    try:
        certs, ca = harness.generate_tls(root, openssl, environment)
        image = harness.inspect_image(podman, patch.RELEASE, environment)
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, owner), timeout=60, environment=environment)
        info = base.parse_json(harness.run_bounded([podman, "network", "inspect", "--format", "{{json .}}", network],
                                                  maximum=16384, timeout=10, environment=environment), 16384)
        internal = protocol.node_addresses(info)
        addresses, recovery_addresses, names = [], [], []
        for number, address in enumerate(internal):
            print(f"2.7.1 consistency: starting constrained node {number + 1}", flush=True)
            name = f"openbao-271-cons-{number}-{owner}"
            config = lag.write_config(root, number, address)
            resources.append(("container", name))
            harness.run_bounded(lag.container_command(podman, image, name, network, owner, config, certs, address),
                                timeout=120, environment=environment)
            limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", name],
                                         maximum=65536, timeout=30, environment=environment)
            base.validate_container_resource_config(base.parse_json(limits, 65536))
            tls.verify_network(podman, network, name, environment)
            for port_name, collection in (("8200/tcp", addresses), ("8202/tcp", recovery_addresses)):
                port = harness.parse_port(harness.run_bounded([podman, "port", name, port_name],
                                           maximum=1024, timeout=30, environment=environment))
                public = f"https://127.0.0.1:{port}"
                harness.wait_for_exact_version(public, ca, patch.VERSION)
                tls.probe_tls(port, ca)
                collection.append(public)
            names.append(name)
        token = protocol.initialize_cluster(addresses, internal, ca)
        probe(addresses, recovery_addresses, names, ca, token, podman, owner, environment)
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
    patch.require(inputs == input_hashes())
    return {"schema": "openbao-patch-consistency-tls/v1", "version": patch.VERSION, "inputs": inputs,
            "image_linux_amd64_digest": patch.AMD64, "image_index_digest": patch.INDEX,
            "outcome": "passed", "scope": "controlled-lag-server-protocol-only", "checks": CHECKS,
            "nodes": 3, "routable": False, "sdk_live_verified": False,
            "expiry_listener_wait_ms": 250, "recovery_listener_wait_ms": 10000}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        report = run()
        with tempfile.NamedTemporaryFile(prefix="openbao-271-consistency-result-", suffix=".json", delete=False) as output:
            output.write(base.canonical_json(report))
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o644)
            print(f"2.7.1 consistency protocol and controlled lag passed; result: {output.name}", flush=True)
    except (harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"2.7.1 consistency failed ({patch.failure_category(error)}); no compatibility promotion")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
