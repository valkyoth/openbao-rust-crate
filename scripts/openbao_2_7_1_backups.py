#!/usr/bin/python3 -EsSB
"""Exercise real PGP rotation backups on exact 2.7.1 without promotion."""

import argparse
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile

import openbao_2_7_1 as patch
import openbao_2_7_raw_backup as unseal
import openbao_2_7_recovery_backup as recovery
import verify_openbao_2_7_1 as evidence

base, harness, tls = patch.base, patch.harness, patch.tls
SUITES = ("unseal", "recovery")


def input_hashes():
    paths = {*patch.INPUTS, *unseal.INPUTS, *recovery.INPUTS,
             "scripts/openbao_2_7_1_backups.py", "scripts/verify_openbao_2_7_1.py",
             "compat/onboarding/2.7.1/initial-patch-tls.json", "compat/onboarding/2.7.1/initial-openapi.json"}
    return {path: base.sha256(base.read_regular_file(patch.ROOT / path, 2 * 1024 * 1024))
            for path in sorted(paths)}


def configure(root, certs, suite):
    patch.require(suite in SUITES)
    config = harness.write_server_config(root, patch.VERSION)
    content = base.read_regular_file(config, 8192) + b"raw_storage_endpoint = true\n"
    if suite == "recovery":
        harness.write_private(certs / "fixture-seal.key", secrets.token_bytes(32), 0o640)
        content += (b'seal "static" {\n'
                    b' current_key_id = "fixture-only"\n'
                    b' current_key = "file:///openbao/tls/fixture-seal.key"\n'
                    b'}\n')
    config = root / "backup-enabled.hcl"
    harness.write_private(config, content, 0o640)
    return config


def run(suite, backup_observer=None):
    patch.require(os.geteuid() == 0 and suite in SUITES)
    patch.require(backup_observer is None or (suite == "recovery" and callable(backup_observer)))
    inputs = input_hashes()
    evidence.verify()
    print(f"2.7.1 {suite} backup: verifying signed image", flush=True)
    patch.verify_signature()
    podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-271-backup-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    owner = secrets.token_hex(16)
    container, network = "openbao-271-backup-" + owner, "openbao-271-backupnet-" + owner
    resources = []
    token = key = ""
    module = unseal if suite == "unseal" else recovery
    try:
        certs, ca = harness.generate_tls(root, openssl, environment)
        config = configure(root, certs, suite)
        image = harness.inspect_image(podman, patch.RELEASE, environment)
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, owner), timeout=60, environment=environment)
        resources.append(("container", container))
        print(f"2.7.1 {suite} backup: starting constrained TLS server", flush=True)
        harness.run_bounded(tls.container_command(podman, image, container, network, owner, config, certs),
                            timeout=120, environment=environment)
        limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", container],
                                     maximum=65536, timeout=30, environment=environment)
        base.validate_container_resource_config(base.parse_json(limits, 65536))
        tls.verify_network(podman, network, container, environment)
        port = harness.parse_port(harness.run_bounded([podman, "port", container, "8200/tcp"],
                                  maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        harness.wait_for_exact_version(address, ca, patch.VERSION)
        tls.probe_tls(port, ca)
        token, key = module.initialize(address, ca)
        if backup_observer is None:
            module.probe(address, ca, token, key)
        else:
            module.probe(address, ca, token, key, backup_observer)
    finally:
        token = key = ""
        failed = False
        for kind, name in reversed(resources):
            try:
                harness.remove_owned_resource(podman, kind, name, owner, environment)
            except (harness.HarnessError, OSError):
                failed = True
        if suite == "recovery" and not harness.sanitize_file(root / "tls" / "fixture-seal.key"):
            failed = True
        if not harness.cleanup_private_files(root):
            failed = True
        try:
            shutil.rmtree(root)
        except OSError:
            failed = True
        patch.require(not failed)
    patch.require(inputs == input_hashes())
    return {"schema": "openbao-patch-backup-tls/v1", "version": patch.VERSION, "suite": suite,
            "inputs": inputs, "image_linux_amd64_digest": patch.AMD64, "image_index_digest": patch.INDEX,
            "scope": "server-fixture-only-not-sdk-integration", "tls": "TLSv1.3",
            "checks": module.CHECKS, "outcome": "passed", "routable": False,
            "upgrade_verified": False, "backup_decryption_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("all", *SUITES), default="all")
    args = parser.parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        for suite in SUITES if args.suite == "all" else (args.suite,):
            report = run(suite)
            with tempfile.NamedTemporaryFile(prefix="openbao-271-" + suite + "-backup-", suffix=".json", delete=False) as output:
                output.write(base.canonical_json(report))
                output.flush()
                os.fsync(output.fileno())
                os.fchmod(output.fileno(), 0o644)
                print(f"2.7.1 {suite} backup passed; result: {output.name}", flush=True)
    except (harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"2.7.1 backup fixture failed ({patch.failure_category(error)}); no compatibility promotion")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
