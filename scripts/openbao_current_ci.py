#!/usr/bin/python3 -EsSB
"""Supplement the immutable historical matrix with current-profile SDK TLS jobs."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

import openbao_2_6_4 as legacy
import openbao_2_7_1 as modern
import openbao_2_7_api as initial
import openbao_2_7_tls as tls

base, harness = tls.base, tls.harness
ROOT = modern.ROOT
VERSIONS = ("2.6.4", "2.7.0", "2.7.1")
RELEASES = {"2.6.4": legacy, "2.7.0": initial, "2.7.1": modern}
FEATURES = "kv1,kv2,sys,token,rustls-tls"
TEST = "real_openbao_default_feature_flow"
OPERATIONS = harness.CORE_OPERATION_IDS[:8]
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


def require(condition):
    if not condition:
        raise harness.HarnessError("current-profile CI validation failed")


def coverage(historical, supported, supplemental=VERSIONS):
    require(len(historical) == len(set(historical)) and len(supported) == len(set(supported))
            and len(supplemental) == len(set(supplemental))
            and not set(historical).intersection(supplemental)
            and set(historical).union(supplemental) == set(supported))


def check_coverage():
    from validate_openbao_release_lock import validate_lock_files
    import generate_openbao_patch_registry as registry
    import openbao_patch_normal_sdk as normal
    normal.verify()
    historical = [row["version"] for row in validate_lock_files()["records"]]
    supported = registry.verify()["versions"]
    coverage(historical, supported)
    workflow = (ROOT / ".github/workflows/openbao-current-compatibility.yml").read_text()
    matrices = re.findall(r"^        version: (\[[^\n]+\])$", workflow, re.M)
    require(len(matrices) == 1 and json.loads(matrices[0]) == list(VERSIONS))
    print("All 28 supported profiles covered by historical and supplemental CI")


def build():
    require(os.geteuid() != 0)
    with tempfile.TemporaryDirectory(prefix="openbao-current-build-") as directory:
        output = harness.run_bounded(["cargo", "test", "--locked", "--no-default-features",
            "--features", FEATURES, "--test", "openbao_integration", "--no-run",
            "--message-format=json-render-diagnostics"], maximum=harness.MAX_CARGO_OUTPUT,
            timeout=1200, environment=harness.cargo_build_environment(Path(directory)))
    artifacts = [json.loads(line) for line in output.splitlines() if line]
    paths = [item["executable"] for item in artifacts if item.get("reason") == "compiler-artifact"
             and item.get("executable") and item.get("target", {}).get("name") == "openbao_integration"
             and item.get("profile", {}).get("test") is True]
    require(len(paths) == 1)
    binary = harness.validate_test_binary(Path(paths[0]))
    if "GITHUB_OUTPUT" in os.environ:
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            output.write(f"test_binary={binary}\n")
    print(f"Current-profile CI test binary: {binary}")


def freeze_binary(path, uid):
    require(path.is_absolute() and path.parent == ROOT / "target/debug/deps"
            and re.fullmatch(r"openbao_integration-[0-9a-f]{16}", path.name) is not None)
    source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    descriptor = None
    try:
        metadata = os.fstat(source)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == uid
                and metadata.st_mode & 0o100 and not metadata.st_mode & 0o022
                and 0 < metadata.st_size <= 256 * 1024 * 1024)
        descriptor = os.memfd_create("openbao-current-ci", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        total = 0
        while chunk := os.read(source, 65536):
            total += len(chunk)
            require(total <= 256 * 1024 * 1024)
            remaining = memoryview(chunk)
            while remaining:
                count = os.write(descriptor, remaining)
                require(count > 0)
                remaining = remaining[count:]
        require(total == metadata.st_size)
        os.fchmod(descriptor, 0o555)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, SEALS)
        require(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & SEALS == SEALS)
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 65536):
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, digest.hexdigest()
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(source)


def run_sdk(binary, uid, gid, address, ca, token, version):
    descriptors = []
    try:
        for value in (token, ca.read_text(encoding="ascii"), ""):
            descriptors.append(harness.create_secret_fd(value))
            os.fchown(descriptors[-1], uid, gid)
            os.fchmod(descriptors[-1], 0o600)
        token_fd, ca_fd, result_fd = descriptors
        setpriv = str(tls.evidence_tools.protected_path(Path("/usr/bin/setpriv")))
        command = [setpriv, f"--reuid={uid}", f"--regid={gid}", "--clear-groups", "--no-new-privs",
                   "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                   f"/proc/self/fd/{binary}", "--exact", TEST, "--test-threads=1"]
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "OPENBAO_INTEGRATION": "1",
                       "OPENBAO_EXPECTED_VERSION": version, "BAO_ADDR": address,
                       "BAO_CACERT": f"/proc/self/fd/{ca_fd}", "BAO_TOKEN_FILE": f"/proc/self/fd/{token_fd}",
                       "OPENBAO_RESULT_FILE": f"/proc/self/fd/{result_fd}"}
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=environment, close_fds=True,
                                   pass_fds=(binary, *descriptors), start_new_session=True, cwd=ROOT)
        try:
            require(process.wait(timeout=180) == 0)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        attestation = harness.parse_json(harness.read_descriptor(result_fd, 65536))
        require(attestation == {"schema": "openbao-core-flow-attestation/v1", "version": version,
                                "executed": list(OPERATIONS), "skipped": list(harness.OPENBAO_2_6_OPERATION_IDS)})
        return attestation
    finally:
        sanitized = True
        for descriptor in descriptors:
            if not harness.sanitize_secret_fd(descriptor):
                sanitized = False
        require(sanitized)


def run(version, binary):
    require(os.geteuid() == 0 and version in RELEASES)
    uid, gid = int(os.environ.get("SUDO_UID", "0")), int(os.environ.get("SUDO_GID", "0"))
    require(uid > 0 and gid > 0 and pwd.getpwuid(uid).pw_gid == gid)
    inputs = input_hashes()
    descriptor, digest = freeze_binary(binary, uid)
    root = None
    resources = []
    owner = secrets.token_hex(16)
    try:
        podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
        release = RELEASES[version]
        print(f"Current-profile CI: signed OpenBao {version}", file=sys.stderr, flush=True)
        if version == "2.7.0":
            release.verify_image_signature()
        else:
            release.verify_signature()
        root = Path(tempfile.mkdtemp(prefix="openbao-current-ci-", dir="/tmp"))
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(root),
                       "XDG_CONFIG_HOME": str(root), "XDG_CACHE_HOME": str(root)}
        openssl = str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl")))
        certs, ca = harness.generate_tls(root, openssl, environment)
        config = harness.write_server_config(root, version)
        image = harness.inspect_image(podman, release.RELEASE, environment)
        network, container = "openbao-ci-net-" + owner, "openbao-ci-" + owner
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, owner), timeout=60, environment=environment)
        resources.append(("container", container))
        harness.run_bounded(tls.container_command(podman, image, container, network, owner, config, certs),
                            timeout=120, environment=environment)
        limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", container],
                                     maximum=65536, timeout=30, environment=environment)
        base.validate_container_resource_config(base.parse_json(limits, 65536))
        tls.verify_network(podman, network, container, environment)
        port = harness.parse_port(harness.run_bounded([podman, "port", container, "8200/tcp"],
                                  maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        harness.wait_for_exact_version(address, ca, version)
        tls.probe_tls(port, ca)
        token = harness.initialize_and_unseal(address, ca)
        print("Current-profile CI: public SDK core operations", file=sys.stderr, flush=True)
        attestation = run_sdk(descriptor, uid, gid, address, ca, token, version)
        token = ""
    finally:
        os.close(descriptor)
        failed = False
        for kind, name in reversed(resources):
            try:
                harness.remove_owned_resource(podman, kind, name, owner, environment)
            except (harness.HarnessError, OSError):
                failed = True
        if root is not None:
            if not harness.cleanup_private_files(root):
                failed = True
            shutil.rmtree(root)
        require(not failed)
    require(inputs == input_hashes())
    return {"schema": "openbao-current-ci/v1", "version": version, "outcome": "passed",
            "image_linux_amd64_digest": release.AMD64, "test_binary_sha256": digest,
            "inputs": inputs, "build_provenance": "local-trusted-builder-not-attested",
            "tls": "TLSv1.3", "executable_storage": "sealed-memfd", "attestation": attestation,
            "scope": "eight-public-sdk-core-operations-not-full-endpoint-or-advanced-coverage",
            "cleanup": "passed"}


def input_hashes():
    paths = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "build.rs", "README.md",
             "scripts/openbao_current_ci.py", ".github/workflows/openbao-current-compatibility.yml",
             "tests/openbao_integration.rs"]
    paths.extend(str(path.relative_to(ROOT)) for path in sorted((ROOT / "src").rglob("*.rs")))
    local = {path: base.sha256(base.read_regular_file(ROOT / path, 2 * 1024 * 1024)) for path in paths}
    return {**legacy.input_hashes(), **modern.input_hashes(), **local}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check-coverage", action="store_true")
    action.add_argument("--build", action="store_true")
    action.add_argument("--version", choices=VERSIONS)
    parser.add_argument("--test-binary", type=Path)
    args = parser.parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        if args.check_coverage:
            check_coverage()
        elif args.build:
            build()
        else:
            require(args.test_binary is not None)
            result = run(args.version, args.test_binary)
            # The unprivileged invoking shell owns the artifact destination.
            # The root fixture never opens a workspace output pathname.
            sys.stdout.buffer.write(base.canonical_json(result))
    except (harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError,
            subprocess.TimeoutExpired):
        print("Current-profile CI failed; no compatibility success recorded", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
