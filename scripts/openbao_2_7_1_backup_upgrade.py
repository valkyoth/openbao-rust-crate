#!/usr/bin/python3 -EsSB
"""Check a real recovery backup across a signed 2.7.0 -> 2.7.1 restart."""

import argparse
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile

import openbao_2_7_backup_upgrade as previous
import openbao_2_7_1 as patch
import verify_openbao_2_7_1_image as image_evidence

base, harness, tls = patch.base, patch.harness, patch.tls
SOURCE_VERSION = "2.7.0"


def input_hashes():
    paths = {*previous.INPUTS, *patch.INPUTS, "scripts/openbao_2_7_1_backup_upgrade.py",
             "scripts/verify_openbao_2_7_1_image.py", "scripts/verify_openbao_2_7_1.py",
             *("compat/onboarding/2.7.1/" + name for name in image_evidence.ARTIFACTS)}
    return {path: base.sha256(base.read_regular_file(patch.ROOT / path, 2 * 1024 * 1024)) for path in sorted(paths)}


def report_for(inputs):
    return {"schema": "openbao-patch-backup-upgrade/v1", "source_version": SOURCE_VERSION,
            "version": patch.VERSION, "inputs": inputs,
            "source_image": previous.staged.AMD64, "source_image_index": previous.staged.INDEX,
            "target_image": patch.AMD64, "target_image_index": patch.INDEX,
            "outcome": "passed", "checks": previous.CHECKS,
            "scope": "server-recovery-backup-single-node-raft-upgrade-only", "tls": "TLSv1.3",
            "routable": False, "unseal_backup_upgrade_verified": False,
            "general_upgrade_verified": False, "backup_decryption_verified": False,
            "sdk_live_verified": False}


def run():
    patch.require(os.geteuid() == 0)
    inputs = input_hashes()
    print("2.7.1 backup upgrade: verifying both signed images", flush=True)
    previous.staged.verify()
    previous.staged.verify_image_signature()
    image_evidence.verify()
    patch.verify_signature()
    patch.require(previous.staged.RELEASE["version"] == SOURCE_VERSION and patch.RELEASE["version"] == "2.7.1")
    podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-271-backup-upgrade-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    owner = secrets.token_hex(16)
    network = "openbao-271-upgrade-net-" + owner
    resources = []
    token = share = ""
    expected = None
    try:
        certs, ca = harness.generate_tls(root, openssl, environment)
        config, storage = previous.configure(root, certs)
        images = [harness.inspect_image(podman, release, environment)
                  for release in (previous.staged.RELEASE, patch.RELEASE)]
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, owner), timeout=60, environment=environment)
        name = "openbao-271-upgrade-old-" + owner
        resources.append(("container", name))
        print("2.7.1 backup upgrade: creating backup on 2.7.0", flush=True)
        address = previous.start(podman, images[0], SOURCE_VERSION, name, network, owner,
                                 config, certs, storage, ca, environment)
        token, share = previous.initialize(address, ca)
        identity = previous.cluster(address, ca, SOURCE_VERSION)
        expected = previous.create_backup(address, ca, token, share)
        harness.run_bounded([podman, "stop", "--time", "20", name], timeout=60, environment=environment)
        harness.remove_owned_resource(podman, "container", name, owner, environment)
        resources.pop()
        name = "openbao-271-upgrade-new-" + owner
        resources.append(("container", name))
        print("2.7.1 backup upgrade: restarting the same storage on 2.7.1", flush=True)
        address = previous.start(podman, images[1], patch.VERSION, name, network, owner,
                                 config, certs, storage, ca, environment)
        patch.require(previous.cluster(address, ca, patch.VERSION) == identity)
        print("2.7.1 backup upgrade: checking preserved backup and access controls", flush=True)
        previous.verify_backup(address, ca, token, expected)
    finally:
        token = share = ""
        expected = None
        failed = False
        for kind, name in reversed(resources):
            try:
                harness.remove_owned_resource(podman, kind, name, owner, environment)
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
        patch.require(not failed)
    patch.require(inputs == input_hashes())
    return report_for(inputs)


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        report = run()
        with tempfile.NamedTemporaryFile(prefix="openbao-271-backup-upgrade-result-", suffix=".json", delete=False) as output:
            output.write(base.canonical_json(report))
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o644)
            print(f"2.7.1 recovery backup upgrade passed; result: {output.name}", flush=True)
    except (harness.HarnessError, base.SnapshotError, previous.releases.LockValidationError,
            OSError, ValueError, TypeError, KeyError, TimeoutError):
        print("2.7.1 backup upgrade failed; no compatibility promotion")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
