#!/usr/bin/python3 -EsSB
"""Build and exercise the exact patch candidate with the public SDK over TLS."""

import argparse
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import signal
import subprocess
import tempfile

import check_openbao_2_7_candidate_sdk as builder
import generate_openbao_2_7_1_candidate as candidate
import openbao_2_7_consistency_sdk as execution

evidence = candidate.evidence
patch, base, harness, tls = evidence.patch, evidence.base, evidence.runner.harness, evidence.runner.tls
TEST = "patch_271_live::public_patch_tls"
FEATURES = "sys,approle,transit,transit-bytes,rustls-tls"
CHECKS = ["exact-version", "tls13", "tls-rejections", "resource-limits", "network-isolation",
          "strict-sdk-profile", "approle-login", "expired-secret-id-denied-without-tidy",
          "transit-encrypt-decrypt", "transit-version-selection", "associated-data-binding",
          "workflow-cas-create-update", "workflow-cas-rejected-write-preserves-state", "cleanup"]


def input_hashes():
    values = builder.backup_inputs(builder.source_inputs())
    paths = {"scripts/openbao_2_7_1_sdk.py", "scripts/check_openbao_2_7_candidate_sdk.py",
             "scripts/generate_openbao_2_7_1_candidate.py", "scripts/generate_openbao_capability_registry.py",
             "scripts/openbao_2_7_consistency_sdk.py", "scripts/verify_openbao_2_7_1_regressions.py",
             "compat/onboarding/2.7.1/candidate-capability-registry-v2.json", *execution.INPUTS}
    values.update({path: base.read_regular_file(patch.ROOT / path, 2 * 1024 * 1024) for path in paths})
    return {path: base.sha256(data) for path, data in sorted(values.items())}


def build():
    patch.require(os.geteuid() != 0)
    before = input_hashes()
    verified = candidate.verify()
    inputs = builder.backup_inputs(builder.source_inputs())
    with tempfile.TemporaryDirectory(prefix="openbao-271-sdk-build-") as temporary:
        root = Path(temporary)
        builder.prepare(root, inputs, verified)
        env = builder.build_environment(root)
        messages = builder.run(["cargo", "test", "--locked", "--offline", "--no-default-features",
            "--features", FEATURES, "--lib", "--no-run", "--message-format=json-render-diagnostics"], root, env, capture=True)
        artifacts = [json.loads(line) for line in messages.splitlines() if line.strip()]
        binaries = [Path(item["executable"]) for item in artifacts if item.get("reason") == "compiler-artifact"
                    and item.get("executable") and item.get("target", {}).get("name") == "openbao"
                    and item.get("profile", {}).get("test") is True]
        patch.require(len(binaries) == 1)
    patch.require(before == input_hashes())
    print(f"2.7.1 strict candidate SDK binary: {binaries[0]}")
    print("Build only; no live verification or normal profile promotion")


@execution.frozen_runner
def run(binary, strict_candidate=False):
    patch.require(strict_candidate is True)
    uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    patch.require(uid > 0 and gid > 0 and pwd.getpwuid(uid).pw_gid == gid)
    digest = execution.binary_hash(binary, uid, candidate=True)
    inputs = input_hashes()
    candidate.verify()
    print("2.7.1 SDK fixture: verifying signed image", flush=True)
    patch.verify_signature()
    podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-271-sdk-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    owner = secrets.token_hex(16)
    container, network = "openbao-271-sdk-" + owner, "openbao-271-sdknet-" + owner
    resources = []
    token = ""
    try:
        certs, ca = harness.generate_tls(root, openssl, environment)
        config = harness.write_server_config(root, patch.VERSION)
        image = harness.inspect_image(podman, patch.RELEASE, environment)
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, owner), timeout=60, environment=environment)
        resources.append(("container", container))
        print("2.7.1 SDK fixture: starting constrained TLS server", flush=True)
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
        token = harness.initialize_and_unseal(address, ca)
        print("2.7.1 SDK fixture: running unprivileged strict SDK test", flush=True)
        execution.run_test(binary, uid, gid, [address] * 3, ca, token, test=TEST)
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
    patch.require(inputs == input_hashes() and digest == execution.binary_hash(binary, uid, candidate=True))
    report = {**execution.EXECUTION_ASSURANCE, "schema": "openbao-patch-sdk-tls/v1", "version": patch.VERSION,
              "inputs": inputs, "test_binary_sha256": digest, "test": TEST, "features": FEATURES,
              "candidate_registry_sha256": candidate.EXPECTED_SHA256,
              "candidate_generated_rust_sha256": base.sha256(candidate.registry.rust_output(candidate.verify(), verification_candidate=True)),
              "source_scope": "repository-inputs-with-explicit-generated-candidate-override",
              "image_linux_amd64_digest": patch.AMD64, "image_index_digest": patch.INDEX,
              "scope": "public-sdk-strict-disposable-candidate-build", "outcome": "passed", "routable": False,
              "checks": CHECKS}
    with tempfile.NamedTemporaryFile(prefix="openbao-271-sdk-result-", suffix=".json", delete=False) as output:
        output.write(base.canonical_json(report))
        output.flush()
        os.fsync(output.fileno())
        os.fchmod(output.fileno(), 0o644)
        print(f"2.7.1 strict candidate SDK fixture passed; result: {output.name}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--build", action="store_true")
    action.add_argument("--test-binary", type=Path)
    args = parser.parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        if args.build:
            build()
        else:
            run(args.test_binary, strict_candidate=True)
    except (harness.HarnessError, base.SnapshotError, candidate.registry.RegistryError,
            OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        print("2.7.1 SDK fixture failed; no compatibility promotion")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
