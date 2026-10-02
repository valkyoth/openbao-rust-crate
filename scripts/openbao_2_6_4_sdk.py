#!/usr/bin/python3 -EsSB
"""Build and exercise the exact patch candidate with the public SDK over TLS."""

import argparse
import json
import os
from pathlib import Path
import pwd
import secrets
import selectors
import shutil
import signal
import subprocess
import tempfile
import time

import check_openbao_2_7_candidate_sdk as builder
import generate_openbao_2_6_4_candidate as candidate
import openbao_2_7_consistency_sdk as execution
import openbao_patch_normal_sdk as normal_sdk

evidence = candidate.evidence
patch, base, harness, tls = evidence.patch, evidence.base, evidence.patch.harness, evidence.patch.tls
TEST = "patch_264_live::public_patch_tls"
FEATURES = "sys,approle,transit,transit-bytes,kv1,kv2,token,ldap-auth,kerberos-auth,radius-auth,radius-auth-acknowledged,ldap,rustls-tls"
STAGES = ("profile", "approle", "expiry", "transit", "token", "kv", "wrapping", "legacy-mounts",
          "ldap-auth", "kerberos", "radius", "ldap-secrets", "cleanup", "complete")


class Progress:
    """Only fixed, ordered labels may leave the bounded child-output buffer."""

    def __init__(self):
        self.buffer = bytearray()
        self.total = 0
        self.count = 0

    def feed(self, chunk):
        self.total += len(chunk)
        patch.require(self.total <= 65536)
        self.buffer.extend(chunk)
        while b"\n" in self.buffer:
            line, _, rest = self.buffer.partition(b"\n")
            self.buffer = bytearray(rest)
            if line.startswith(b"patch-stage:"):
                patch.require(self.count < len(STAGES)
                              and line == ("patch-stage:" + STAGES[self.count]).encode())
                print("2.6.4 SDK stage: " + STAGES[self.count], flush=True)
                self.count += 1
        patch.require(len(self.buffer) <= 1024)


def exchange(process, payload, progress):
    deadline = time.monotonic() + 90
    offset = 0
    try:
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdin, selectors.EVENT_WRITE)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                patch.require(remaining > 0)
                events = selector.select(remaining)
                patch.require(bool(events))
                for key, _ in events:
                    if key.fileobj is process.stdin:
                        offset += os.write(process.stdin.fileno(), payload[offset:offset + 4096])
                        if offset == len(payload):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        chunk = os.read(process.stdout.fileno(), 4096)
                        if not chunk:
                            selector.unregister(process.stdout)
                        else:
                            progress.feed(chunk)
        patch.require(process.wait(timeout=max(0.001, deadline - time.monotonic())) == 0
                      and progress.count == len(STAGES))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        process.stdin.close()
        process.stdout.close()


def run_test(binary, uid, gid, addresses, ca, token, *, test):
    patch.require(test == TEST)
    tool = str(tls.evidence_tools.protected_path(Path("/usr/bin/setpriv")))
    command = [tool, f"--reuid={uid}", f"--regid={gid}", "--clear-groups", "--no-new-privs",
               "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
               str(binary), "--ignored", "--exact", test, "--test-threads=1"]
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    patch.require(execution.test_listing(command, environment, binary) == f"{test}: test\n\n1 test, 0 benchmarks\n".encode())
    payload = base.canonical_json({"addresses": addresses, "ca_pem": ca.read_text(encoding="ascii"), "token": token})
    patch.require(len(payload) < 65536)
    process = subprocess.Popen(command + ["--nocapture", "--format=terse"], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=patch.ROOT,
                               close_fds=True, pass_fds=(binary.fd,), start_new_session=True, env=environment)
    exchange(process, payload, Progress())


def input_hashes(*, normal=False):
    values = builder.backup_inputs(builder.source_inputs())
    paths = {"scripts/openbao_2_6_4_sdk.py", "scripts/check_openbao_2_7_candidate_sdk.py",
             "scripts/generate_openbao_2_6_4_candidate.py", "scripts/generate_openbao_capability_registry.py",
             "scripts/openbao_2_7_consistency_sdk.py", "scripts/verify_openbao_2_6_4.py",
             "compat/onboarding/2.6.4/candidate-capability-registry.json",
             "compat/onboarding/2.6.4/openapi.json", "compat/onboarding/2.6.4/patch-tls.json",
             *patch.input_hashes(), *execution.INPUTS}
    values.update({path: base.read_regular_file(patch.ROOT / path, 2 * 1024 * 1024) for path in paths})
    hashes = {path: base.sha256(data) for path, data in sorted(values.items())}
    return {**hashes, **normal_sdk.input_hashes()} if normal else hashes


def build():
    patch.require(os.geteuid() != 0)
    before = input_hashes()
    verified = candidate.verify()
    inputs = builder.backup_inputs(builder.source_inputs())
    with tempfile.TemporaryDirectory(prefix="openbao-264-sdk-build-") as temporary:
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
    print(f"2.6.4 strict candidate SDK binary: {binaries[0]}")
    print("Build only; no live verification or normal profile promotion")


@execution.frozen_runner
def run(binary, strict_candidate=False, normal=False):
    patch.require(type(normal) is bool and type(strict_candidate) is bool and normal != strict_candidate)
    uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    patch.require(uid > 0 and gid > 0 and pwd.getpwuid(uid).pw_gid == gid)
    digest = execution.binary_hash(binary, uid, candidate=strict_candidate)
    inputs = input_hashes(normal=True) if normal else input_hashes()
    provenance = normal_sdk.verify() if normal else None
    if not normal:
        candidate.verify()
    print("2.6.4 SDK fixture: verifying signed image", flush=True)
    patch.verify_signature()
    podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-264-sdk-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    owner = secrets.token_hex(16)
    container, network = "openbao-264-sdk-" + owner, "openbao-264-sdknet-" + owner
    resources = []
    token = ""
    try:
        certs, ca = harness.generate_tls(root, openssl, environment)
        config = harness.write_server_config(root, patch.VERSION)
        image = harness.inspect_image(podman, patch.RELEASE, environment)
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, owner), timeout=60, environment=environment)
        resources.append(("container", container))
        print("2.6.4 SDK fixture: starting constrained TLS server", flush=True)
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
        print("2.6.4 SDK fixture: running unprivileged strict SDK test", flush=True)
        run_test(binary, uid, gid, [address] * 3, ca, token, test=TEST)
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
    patch.require(inputs == (input_hashes(normal=True) if normal else input_hashes())
                  and digest == execution.binary_hash(binary, uid, candidate=strict_candidate))
    report = {**execution.EXECUTION_ASSURANCE, "schema": "openbao-patch-sdk-tls/v1", "version": patch.VERSION,
              "inputs": inputs, "test_binary_sha256": digest, "test": TEST, "features": FEATURES,
              "image_linux_amd64_digest": patch.AMD64, "image_index_digest": patch.INDEX,
              "scope": "public-sdk-strict-disposable-candidate-build", "outcome": "passed", "routable": False,
              "checks": ["exact-version", "tls13", "tls-rejections", "resource-limits", "network-isolation",
                         "strict-sdk-profile", "approle-login", "expired-secret-id-denied-without-tidy",
                         "transit-encrypt-decrypt", "transit-version-selection", "associated-data-binding",
                         "kv1-roundtrip", "kv2-write-patch-read", "token-lookup", "wrapping-one-use",
                         "ldap-auth-mapping", "kerberos-group-mapping", "radius-user-mapping",
                         "ldap-dynamic-role-administration", "cleanup"]}
    if normal:
        patch.require(provenance == normal_sdk.verify())
        report.update(provenance)
    else:
        report.update(candidate_registry_sha256=candidate.EXPECTED_SHA256,
                      candidate_generated_rust_sha256=base.sha256(candidate.registry.rust_output(candidate.verify(), verification_candidate=True)),
                      source_scope="repository-inputs-with-explicit-generated-candidate-override")
    with tempfile.NamedTemporaryFile(prefix="openbao-264-sdk-result-", suffix=".json", delete=False) as output:
        output.write(base.canonical_json(report))
        output.flush()
        os.fsync(output.fileno())
        os.fchmod(output.fileno(), 0o644)
        mode = "normal-build" if normal else "candidate"
        print(f"2.6.4 strict {mode} SDK fixture passed; result: {output.name}", flush=True)


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
            run(args.test_binary, strict_candidate=not args.normal, normal=args.normal)
    except (harness.HarnessError, base.SnapshotError, candidate.registry.RegistryError,
            OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        print("2.6.4 SDK fixture failed; no compatibility promotion")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
