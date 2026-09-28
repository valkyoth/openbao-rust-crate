#!/usr/bin/python3 -EsSB
"""Test a real recovery backup across a pinned 2.6.3 -> 2.7.0 restart."""

import argparse
import base64
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile
import time

import openbao_2_7_recovery_backup as recovery
import openbao_2_7_consistency as raft
import validate_openbao_release_lock as releases

system = recovery.system
fixture, harness, snapshots, staged = recovery.fixture, recovery.harness, recovery.snapshots, recovery.staged
ROOT = recovery.ROOT
INPUTS = (*recovery.INPUTS, "scripts/openbao_2_7_backup_upgrade.py",
          "scripts/openbao_2_7_consistency.py",
          "scripts/validate_openbao_release_lock.py", "compat/releases.lock.json",
          "compat/image-signatures.lock.json")
CHECKS = ["signed-pinned-images", "exact-source-and-target-versions", "tls13-and-rejections",
          "resource-limits", "network-isolation", "real-source-recovery-backup",
          "persistent-storage-restart", "same-cluster", "raw-before-dedicated-read",
          "raw-base64-preserved-across-dedicated-read", "dedicated-backup-equivalence", "protected-paths",
          "unprivileged-raw-read-denied", "dedicated-delete-removes-backup", "cleanup"]


def require(condition):
    if not condition:
        raise harness.HarnessError("backup upgrade assertion failed")


def predecessor():
    return harness.select_release(releases.validate_lock_files(), "2.6.3")


def verify_predecessor_signature(release):
    image = release["image"]
    _, output = snapshots.run_bounded([
        "cosign", "verify", "--certificate-identity", image["certificate_identity"],
        "--certificate-oidc-issuer", image["certificate_oidc_issuer"],
        "docker.io/openbao/openbao@" + image["index_digest"],
    ], 1024 * 1024, timeout=180)
    signed = snapshots.parse_json(b'{"signatures":' + output + b'}', 1024 * 1024 + 32)["signatures"]
    require(isinstance(signed, list) and 0 < len(signed) <= 32)
    for entry in signed:
        require(isinstance(entry, dict) and isinstance(entry.get("critical"), dict))
        require(entry["critical"].get("image") == {"docker-manifest-digest": image["index_digest"]}
                and entry["critical"].get("type") == "https://sigstore.dev/cosign/sign/v1")


def input_hashes():
    return {path: snapshots.sha256(snapshots.read_regular_file(ROOT / path, 2 * 1024 * 1024))
            for path in INPUTS}


def configure(root, tls):
    original = recovery.configure_static_seal(root, tls)
    data = snapshots.read_regular_file(original, 8192)
    require(data.count(b'storage "inmem" {}') == 1)
    data = data.replace(b'storage "inmem" {}',
                        b'storage "raft" {\n path = "/openbao/data"\n node_id = "fixture-upgrade"\n}\n')
    config = root / "upgrade.hcl"
    harness.write_private(config, data, 0o640)
    storage = root / "storage"
    storage.mkdir(mode=0o700)
    os.chown(storage, 100, 0)
    return config, storage


def call(address, ca, token, method, path, payload=None, status=200):
    actual, response = system.request(address, ca, token, method, path, payload)
    fixture.require_status(actual, status)
    return response


def initialize(address, ca):
    # Initialization is a single write; only subsequent health reads may poll.
    status, response, _, _ = raft.request(address, ca, "", "PUT", "/v1/sys/init",
                                        {"recovery_shares": 1, "recovery_threshold": 1}, timeout=30)
    fixture.require_status(status, 200)
    token = system.credential(response.get("root_token"))
    shares = response.get("recovery_keys_base64")
    require(isinstance(shares, list) and len(shares) == 1)
    return token, system.credential(shares[0])


def create_backup(address, ca, token, share):
    public = snapshots.read_regular_file(ROOT / recovery.PUBLIC_KEY, 8192).decode("ascii").strip()
    require(0 < len(base64.b64decode(public, validate=True)) <= 6144)
    started = call(address, ca, token, "POST", "sys/rotate/recovery/init",
                   {"secret_shares": 1, "secret_threshold": 1, "backup": True, "pgp_keys": [public]})["data"]
    nonce = system.credential(started.get("nonce"))
    require(started.get("started") is True and started.get("backup") is True)
    result = call(address, ca, token, "POST", "sys/rotate/recovery/update",
                  {"key": share, "nonce": nonce})["data"]
    require(result.get("complete") is True and result.get("backup") is True)
    fingerprints, keys = result.get("pgp_fingerprints"), result.get("keys")
    require(isinstance(fingerprints, list) and len(fingerprints) == 1
            and isinstance(keys, list) and len(keys) == 1)
    fingerprint, encrypted = fingerprints[0], keys[0]
    require(isinstance(fingerprint, str) and len(fingerprint) == 40
            and all(c in "0123456789abcdef" for c in fingerprint)
            and isinstance(encrypted, str) and 0 < len(encrypted) <= 16384)
    require(bool(bytes.fromhex(encrypted)))
    # Do not call the source backup-read handler: it can migrate storage.
    return nonce, fingerprint, encrypted


def verify_backup(address, ca, token, expected):
    nonce, fingerprint, encrypted = expected
    # The predecessor used barrier.Put; physical raw bytes remain ciphertext.
    # Default string encoding is lossy for binary data, so use base64 only.
    def raw_bytes():
        encoded = call(address, ca, token, "GET", recovery.RAW + "?encoding=base64")["data"]["value"]
        require(isinstance(encoded, str) and 0 < len(encoded) <= 131072)
        try:
            value = base64.b64decode(encoded, validate=True)
        except ValueError:
            raise harness.HarnessError("backup raw encoding is malformed") from None
        require(0 < len(value) <= 65536 and base64.b64encode(value).decode("ascii") == encoded)
        return value

    print("Backup upgrade fixture: reading preserved physical backup bytes", flush=True)
    before = raw_bytes()
    print("Backup upgrade fixture: checking dedicated backup contents", flush=True)
    dedicated = call(address, ca, token, "GET", "sys/rotate/recovery/backup")["data"]
    require(dedicated.get("nonce") == nonce and dedicated.get("keys") == {fingerprint: [encrypted]})
    require(raw_bytes() == before)
    print("Backup upgrade fixture: checking restricted access and protected paths", flush=True)
    policy = "fixture-upgrade-deny"
    call(address, ca, token, "POST", "sys/policies/acl/" + policy,
         {"policy": 'path "*" { capabilities = ["deny"] }'}, 204)
    issued = call(address, ca, token, "POST", "auth/token/create",
                  {"policies": [policy], "no_default_policy": True, "ttl": "5m",
                   "explicit_max_ttl": "5m", "renewable": False})["auth"]
    require(issued.get("policies") == [policy])
    restricted = system.credential(issued.get("client_token"))
    system.denied(*system.request(address, ca, restricted, "GET", recovery.RAW), "permission denied")
    for path in ("core/keyring", "core/cluster/local/info"):
        recovery.protected(*system.request(address, ca, token, "GET", "sys/raw/" + path), path)
    print("Backup upgrade fixture: deleting preserved backup", flush=True)
    call(address, ca, token, "DELETE", "sys/rotate/recovery/backup", status=204)
    call(address, ca, token, "GET", recovery.RAW, status=404)


def cluster(address, ca, version):
    for _ in range(120):
        health = harness.https_json(address, ca, "GET", "/v1/sys/health", None, {200, 429, 503})
        harness.verify_reported_version(health.get("version"), version)
        require(health.get("initialized") is True)
        if health.get("sealed") is False and health.get("standby") is False:
            return system.credential(health.get("cluster_id"))
        require(health.get("sealed") is True or
                (health.get("sealed") is False and health.get("standby") is True))
        time.sleep(0.25)
    print("Backup upgrade fixture: auto-unseal deadline exceeded", flush=True)
    raise harness.HarnessError("backup upgrade auto-unseal deadline exceeded")


def start(podman, image, version, name, network, run_id, config, tls, storage, ca, environment):
    command = fixture.container_command(podman, image, name, network, run_id, config, tls)
    offset = command.index("--entrypoint")
    command[offset:offset] = ["--volume", f"{storage}:/openbao/data:rw,Z"]
    print("Backup upgrade fixture: starting constrained container", flush=True)
    harness.run_bounded(command, timeout=120, environment=environment)
    print("Backup upgrade fixture: checking resource limits", flush=True)
    limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", name],
                                maximum=65536, timeout=30, environment=environment)
    snapshots.validate_container_resource_config(snapshots.parse_json(limits, 65536))
    print("Backup upgrade fixture: checking network isolation", flush=True)
    try:
        fixture.verify_network(podman, network, name, environment)
    except harness.HarnessError:
        fixture.startup_diagnostic(podman, name, environment)
        raise
    print("Backup upgrade fixture: checking loopback publication", flush=True)
    port = harness.parse_port(harness.run_bounded([podman, "port", name, "8200/tcp"],
                             maximum=1024, timeout=30, environment=environment))
    address = f"https://127.0.0.1:{port}"
    print("Backup upgrade fixture: waiting for exact-version TLS health", flush=True)
    try:
        harness.wait_for_exact_version(address, ca, version)
    except harness.HarnessError:
        fixture.startup_diagnostic(podman, name, environment)
        raise
    print("Backup upgrade fixture: checking TLS rejection cases", flush=True)
    fixture.probe_tls(port, ca)
    return address


def report_for(inputs):
    return {"schema": "openbao-backup-upgrade/v1", "source_version": "2.6.3", "version": "2.7.0",
            "inputs": inputs, "source_image": predecessor()["image"]["linux_amd64_digest"],
            "target_image": staged.AMD64, "outcome": "passed", "checks": CHECKS,
            "scope": "server-recovery-backup-single-node-raft-upgrade-only", "tls": "TLSv1.3",
            "routable": False, "unseal_backup_upgrade_verified": False,
            "general_upgrade_verified": False, "backup_decryption_verified": False}


def validate_report(report):
    require(snapshots.canonical_json(report) == snapshots.canonical_json(report_for(input_hashes())))


def run():
    require(os.geteuid() == 0)
    inputs = input_hashes()
    print("Backup upgrade fixture: verifying both signed images", flush=True)
    old = predecessor()
    staged.verify()
    staged.verify_image_signature()
    verify_predecessor_signature(old)
    podman = str(recovery.transport.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(recovery.transport.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-backup-upgrade-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    run_id = secrets.token_hex(16)
    network = "openbao-upgrade-net-" + run_id
    resources = []
    token = share = ""
    expected = None
    try:
        tls, ca = harness.generate_tls(root, openssl, environment)
        config, storage = configure(root, tls)
        images = [harness.inspect_image(podman, release, environment) for release in (old, staged.RELEASE)]
        resources.append(("network", network))
        harness.run_bounded(fixture.network_command(podman, network, run_id), timeout=60, environment=environment)
        name = "openbao-upgrade-old-" + run_id
        resources.append(("container", name))
        print("Backup upgrade fixture: creating backup on 2.6.3", flush=True)
        address = start(podman, images[0], "2.6.3", name, network, run_id, config, tls, storage, ca, environment)
        print("Backup upgrade fixture: initializing recovery shares on Raft", flush=True)
        token, share = initialize(address, ca)
        print("Backup upgrade fixture: waiting for source auto-unseal and leadership", flush=True)
        identity = cluster(address, ca, "2.6.3")
        print("Backup upgrade fixture: creating encrypted recovery backup", flush=True)
        expected = create_backup(address, ca, token, share)
        harness.run_bounded([podman, "stop", "--time", "20", name], timeout=60, environment=environment)
        harness.remove_owned_resource(podman, "container", name, run_id, environment)
        resources.pop()
        name = "openbao-upgrade-new-" + run_id
        resources.append(("container", name))
        print("Backup upgrade fixture: restarting same storage on 2.7.0", flush=True)
        address = start(podman, images[1], "2.7.0", name, network, run_id, config, tls, storage, ca, environment)
        print("Backup upgrade fixture: waiting for auto-unseal and checking cluster identity", flush=True)
        try:
            target_identity = cluster(address, ca, "2.7.0")
        except harness.HarnessError:
            fixture.startup_diagnostic(podman, name, environment)
            raise
        if target_identity != identity:
            print("Backup upgrade fixture: cluster identity mismatch", flush=True)
            require(False)
        print("Backup upgrade fixture: verifying migrated backup and access controls", flush=True)
        verify_backup(address, ca, token, expected)
    finally:
        token = share = ""
        expected = None
        failed = False
        for kind, name in reversed(resources):
            try:
                harness.remove_owned_resource(podman, kind, name, run_id, environment)
            except (harness.HarnessError, OSError):
                failed = True
        if not harness.sanitize_file(root / "tls" / "fixture-seal.key"):
            failed = True
        if not harness.cleanup_private_files(root):
            failed = True
        try:
            shutil.rmtree(root)
        except OSError:
            failed = True
        require(not failed)
    require(inputs == input_hashes())
    return report_for(inputs)


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        report = run()
        with tempfile.NamedTemporaryFile(prefix="openbao-backup-upgrade-result-", suffix=".json", delete=False) as output:
            output.write(snapshots.canonical_json(report))
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            print(f"Backup upgrade fixture passed; result: {output.name}")
        return 0
    except (harness.HarnessError, snapshots.SnapshotError, releases.LockValidationError,
            OSError, ValueError, TypeError, KeyError, TimeoutError):
        print("Backup upgrade fixture failed; no compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
