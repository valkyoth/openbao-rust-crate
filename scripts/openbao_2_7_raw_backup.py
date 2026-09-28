#!/usr/bin/python3 -EsSB
"""Probe real disposable unseal backup raw reads; no recovery/upgrade claims."""

import argparse
import base64
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile

import openbao_2_7_system_behavior as system

transport = system.transport
fixture, harness, snapshots, staged = system.fixture, system.harness, system.snapshots, system.staged
ROOT = Path(__file__).resolve().parents[1]
PUBLIC_KEY = "compat/onboarding/2.7.0/rekey-test-public.b64"
INPUTS = (*system.INPUTS, "scripts/openbao_2_7_raw_backup.py", PUBLIC_KEY)
RAW = "sys/raw/core/unseal-keys-backup"
CHECKS = ["exact-version-tls13", "tls-rejections", "resource-limits", "network-isolation",
          "real-pgp-backup", "raw-backup-matches-rekey-result", "raw-base64-equivalence",
          "dedicated-backup-equivalence", "unprivileged-raw-read-denied",
          "keyring-and-cluster-info-protected", "deleted-backup-absent", "cleanup"]


def require(condition):
    if not condition:
        raise harness.HarnessError("raw backup fixture assertion failed")


def input_hashes():
    return {path: snapshots.sha256(snapshots.read_regular_file(ROOT / path, 2 * 1024 * 1024)) for path in INPUTS}


def initialize(address, ca):
    result = harness.https_json(address, ca, "PUT", "/v1/sys/init",
                               {"secret_shares": 1, "secret_threshold": 1}, {200})
    token = system.credential(result.get("root_token"))
    keys = result.get("keys_base64")
    require(isinstance(keys, list) and len(keys) == 1)
    key = system.credential(keys[0])
    response = harness.https_json(address, ca, "POST", "/v1/sys/unseal", {"key": key}, {200})
    require(response.get("sealed") is False)
    return token, key


def backup_matches(value, nonce, fingerprint, encrypted):
    require(isinstance(value, str) and len(value) <= 65536)
    decoded = snapshots.parse_json(value.encode(), 65536)
    require(decoded == {"Nonce": nonce, "Keys": {fingerprint: [encrypted]}})


def protected(status, response, path):
    require(type(status) is int and status == 400 and isinstance(response, dict)
            and response.get("errors") == [f'cannot access "{path}"'])


def probe(address, ca, token, key):
    def call(method, path, payload=None, status=200):
        actual, response = system.request(address, ca, token, method, path, payload)
        fixture.require_status(actual, status)
        return response

    print("Raw backup fixture: creating disposable PGP-encrypted unseal backup", flush=True)
    call("GET", RAW, status=404)
    public = snapshots.read_regular_file(ROOT / PUBLIC_KEY, 8192).decode("ascii").strip()
    require(0 < len(base64.b64decode(public, validate=True)) <= 6144)
    print("Raw backup fixture: starting authenticated root rotation", flush=True)
    started = call("POST", "sys/rotate/root/init", {"secret_shares": 1, "secret_threshold": 1,
                   "pgp_keys": [public], "backup": True})["data"]
    nonce = system.credential(started.get("nonce"))
    require(started.get("started") is True and started.get("backup") is True)
    print("Raw backup fixture: submitting disposable share", flush=True)
    result = call("POST", "sys/rotate/root/update", {"key": key, "nonce": nonce})["data"]
    require(result.get("complete") is True and result.get("backup") is True)
    fingerprints, encrypted = result.get("pgp_fingerprints"), result.get("keys")
    require(isinstance(fingerprints, list) and len(fingerprints) == 1
            and isinstance(encrypted, list) and len(encrypted) == 1)
    fingerprint, ciphertext = fingerprints[0], encrypted[0]
    require(isinstance(fingerprint, str) and len(fingerprint) == 40
            and all(c in "0123456789abcdef" for c in fingerprint)
            and isinstance(ciphertext, str) and 0 < len(ciphertext) <= 16384)
    require(len(bytes.fromhex(ciphertext)) > 0)
    print("Raw backup fixture: raw and dedicated backup equivalence", flush=True)
    raw = call("GET", RAW)["data"]["value"]
    backup_matches(raw, nonce, fingerprint, ciphertext)
    encoded = call("GET", RAW + "?encoding=base64")["data"]["value"]
    require(isinstance(encoded, str) and len(encoded) <= 131072)
    require(base64.b64decode(encoded, validate=True) == raw.encode())
    dedicated = call("GET", "sys/rotate/root/backup")["data"]
    require(dedicated.get("nonce") == nonce and dedicated.get("keys") == {fingerprint: [ciphertext]})
    # Recheck storage after the dedicated backup handler reads it.
    backup_matches(call("GET", RAW)["data"]["value"], nonce, fingerprint, ciphertext)
    print("Raw backup fixture: denied read and protected storage paths", flush=True)
    policy = "fixture-raw-deny"
    call("POST", "sys/policies/acl/" + policy, {"policy": 'path "*" { capabilities = ["deny"] }'}, 204)
    issued = call("POST", "auth/token/create", {"policies": [policy], "no_default_policy": True,
                  "ttl": "5m", "explicit_max_ttl": "5m", "renewable": False})["auth"]
    require(issued.get("policies") == [policy])
    restricted = system.credential(issued.get("client_token"))
    system.denied(*system.request(address, ca, restricted, "GET", RAW), "permission denied")
    for path in ("core/keyring", "core/cluster/local/info"):
        protected(*system.request(address, ca, token, "GET", "sys/raw/" + path), path)
    print("Raw backup fixture: deleting backup through dedicated API", flush=True)
    call("DELETE", "sys/rotate/root/backup", status=204)
    call("GET", RAW, status=404)


def report_for(inputs):
    return {"schema": "openbao-raw-backup-tls/v1", "version": fixture.VERSION,
            "inputs": inputs, "image_linux_amd64_digest": staged.AMD64, "outcome": "passed",
            "scope": "server-fixture-only-not-sdk-integration", "tls": "TLSv1.3",
            "checks": CHECKS, "recovery_backup_verified": False, "upgrade_verified": False,
            "backup_decryption_verified": False, "routable": False}


def validate_report(report):
    require(snapshots.canonical_json(report) == snapshots.canonical_json(report_for(input_hashes())))


def run():
    require(os.geteuid() == 0)
    inputs = input_hashes()
    print("Raw backup fixture: verifying signed image", flush=True)
    staged.verify()
    staged.verify_image_signature()
    podman = str(transport.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(transport.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-270-raw-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    run_id = secrets.token_hex(16)
    container, network = "openbao-270-raw-" + run_id, "openbao-270-rawnet-" + run_id
    resources = []
    token = key = ""
    try:
        tls, ca = harness.generate_tls(root, openssl, environment)
        config = harness.write_server_config(root, fixture.VERSION)
        configuration = snapshots.read_regular_file(config, 8192) + b"raw_storage_endpoint = true\n"
        config = root / "raw-enabled.hcl"
        harness.write_private(config, configuration, 0o640)
        image = harness.inspect_image(podman, staged.RELEASE, environment)
        resources.append(("network", network))
        harness.run_bounded(fixture.network_command(podman, network, run_id), timeout=60, environment=environment)
        resources.append(("container", container))
        harness.run_bounded(fixture.container_command(podman, image, container, network, run_id, config, tls),
                            timeout=120, environment=environment)
        limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", container],
                                     maximum=65536, timeout=30, environment=environment)
        snapshots.validate_container_resource_config(snapshots.parse_json(limits, 65536))
        fixture.verify_network(podman, network, container, environment)
        port = harness.parse_port(harness.run_bounded([podman, "port", container, "8200/tcp"],
                                  maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        fixture.wait_for_health(podman, container, environment, address, ca)
        fixture.probe_tls(port, ca)
        token, key = initialize(address, ca)
        probe(address, ca, token, key)
    finally:
        token = key = ""
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
        require(not failed)
    require(inputs == input_hashes())
    return report_for(inputs)


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        result = run()
        with tempfile.NamedTemporaryFile(prefix="openbao-270-raw-result-", suffix=".json", delete=False) as output:
            output.write(snapshots.canonical_json(result))
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            print(f"Raw backup fixture passed; result: {output.name}")
        return 0
    except (harness.HarnessError, snapshots.SnapshotError, OSError, ValueError, TypeError,
            KeyError, TimeoutError):
        print("Raw backup fixture failed; no security-block or compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
