#!/usr/bin/python3 -EsSB
"""Check a real recovery backup across a signed 2.7.2 -> 2.7.3 restart."""

import argparse
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile

import openbao_2_7_backup_upgrade as previous
import openbao_2_7_2 as source
import openbao_maintenance_capture as candidate
import verify_openbao_2_7_2_image as source_image_evidence


base, harness, tls = candidate.base, candidate.harness, candidate.tls
VERSION = "2.7.3"
INDEX, AMD64 = candidate.PINS[VERSION]
RELEASE = {"version": VERSION, "image": {"index_digest": INDEX, "linux_amd64_digest": AMD64}}
SOURCE_VERSION = "2.7.2"


def input_hashes():
    paths = {*previous.INPUTS, *source.INPUTS, *candidate.input_hashes(),
             "scripts/openbao_2_7_3_backup_upgrade.py",
             "scripts/verify_openbao_2_7_2_image.py",
             *("compat/onboarding/2.7.2/" + name for name in source_image_evidence.ARTIFACTS),
             "compat/onboarding/2.7.3/report.json"}
    return {path: base.sha256(base.read_regular_file(source.ROOT / path, 2 * 1024 * 1024)) for path in sorted(paths)}


def report_for(inputs):
    return {"schema": "openbao-patch-backup-upgrade/v1", "source_version": SOURCE_VERSION,
            "version": VERSION, "inputs": inputs,
            "source_image": source.AMD64, "source_image_index": source.INDEX,
            "target_image": AMD64, "target_image_index": INDEX,
            "outcome": "passed", "checks": previous.CHECKS,
            "scope": "server-recovery-backup-single-node-raft-upgrade-only", "tls": "TLSv1.3",
            "routable": False, "unseal_backup_upgrade_verified": False,
            "general_upgrade_verified": False, "backup_decryption_verified": False,
            "sdk_live_verified": False}


def run():
    candidate.require(os.geteuid() == 0)
    inputs = input_hashes()
    print("2.7.3 backup upgrade: verifying both signed images", flush=True)
    source_image_evidence.verify()
    source.verify_signature()
    candidate.verify_signature(VERSION)
    candidate.require(source.RELEASE["version"] == SOURCE_VERSION and RELEASE["version"] == "2.7.3")
    podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-273-backup-upgrade-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    owner = secrets.token_hex(16)
    network = "openbao-273-upgrade-net-" + owner
    resources = []
    token = share = ""
    expected = None
    try:
        certs, ca = harness.generate_tls(root, openssl, environment)
        config, storage = previous.configure(root, certs)
        images = [harness.inspect_image(podman, release, environment)
                  for release in (source.RELEASE, RELEASE)]
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, owner), timeout=60, environment=environment)
        name = "openbao-273-upgrade-old-" + owner
        resources.append(("container", name))
        print("2.7.3 backup upgrade: creating backup on 2.7.2", flush=True)
        address = previous.start(podman, images[0], SOURCE_VERSION, name, network, owner,
                                 config, certs, storage, ca, environment)
        token, share = previous.initialize(address, ca)
        identity = previous.cluster(address, ca, SOURCE_VERSION)
        expected = previous.create_backup(address, ca, token, share)
        harness.run_bounded([podman, "stop", "--time", "20", name], timeout=60, environment=environment)
        harness.remove_owned_resource(podman, "container", name, owner, environment)
        resources.pop()
        name = "openbao-273-upgrade-new-" + owner
        resources.append(("container", name))
        print("2.7.3 backup upgrade: restarting the same storage on 2.7.3", flush=True)
        address = previous.start(podman, images[1], VERSION, name, network, owner,
                                 config, certs, storage, ca, environment)
        candidate.require(previous.cluster(address, ca, VERSION) == identity)
        print("2.7.3 backup upgrade: checking preserved backup and access controls", flush=True)
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
        candidate.require(not failed)
    candidate.require(inputs == input_hashes())
    return report_for(inputs)


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        report = run()
        with tempfile.NamedTemporaryFile(prefix="openbao-273-backup-upgrade-result-", suffix=".json", delete=False) as output:
            output.write(base.canonical_json(report))
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o644)
            print(f"2.7.3 recovery backup upgrade passed; result: {output.name}", flush=True)
    except (harness.HarnessError, base.SnapshotError, previous.releases.LockValidationError,
            OSError, ValueError, TypeError, KeyError, TimeoutError):
        print("2.7.3 backup upgrade failed; no compatibility promotion")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
