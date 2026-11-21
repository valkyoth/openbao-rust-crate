#!/usr/bin/python3 -EsSB
"""Exercise maintenance contracts with explicit normal or candidate provenance."""

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
import generate_openbao_patch_registry as parent
import openbao_2_6_5_sdk as legacy
import openbao_2_7_consistency_sdk as execution
import openbao_maintenance_capture as capture
import openbao_patch_normal_sdk as normal_sdk
import openbao_maintenance_profiles as profiles

patch = capture.previous
base, harness, tls = capture.base, capture.harness, capture.tls
registry = parent.registry
FEATURES = legacy.FEATURES
TESTS = {"2.6.6": "patch_264_live::public_patch_266_tls", "2.7.3": "patch_271_live::public_patch_273_tls"}
STAGES = {"2.6.6": legacy.STAGES, "2.7.3": ("profile", "approle", "expiry", "transit", "workflow-cas")}
ARTIFACTS = profiles.ARTIFACTS


def input_hashes():
    values = builder.backup_inputs(builder.source_inputs())
    paths = {*capture.input_hashes(), *execution.INPUTS, "scripts/openbao_maintenance_sdk.py",
             "scripts/openbao_2_6_5_sdk.py", "scripts/openbao_maintenance_profiles.py", "scripts/check_openbao_2_7_candidate_sdk.py",
             "scripts/generate_openbao_capability_registry.py", "scripts/generate_openbao_patch_registry.py",
             str(parent.OUTPUT.relative_to(patch.ROOT))}
    for version in ARTIFACTS:
        paths.update(f"compat/onboarding/{version}/{name}.json" for name in ("openapi", "report"))
    values.update({path: base.read_regular_file(patch.ROOT / path, 2 * 1024 * 1024) for path in paths})
    return {p: base.sha256(data) for p, data in sorted(values.items())}


class MissingNormalProfiles(registry.RegistryError):
    pass


def normal_provenance():
    proof = normal_sdk.verify_build()
    reviewed = profiles.normal_registry()
    missing = sorted(set(TESTS) - set(reviewed["versions"]))
    if missing:
        raise MissingNormalProfiles("normal SDK profiles not present: " + ", ".join(missing))
    return proof


def normal_hashes():
    return {**input_hashes(), **normal_sdk.input_hashes()}


candidate = profiles.candidate


def build(*, prepare_inputs=None, features=FEATURES, tests=None, hashes=input_hashes):
    patch.require(os.geteuid() != 0)
    before = hashes()
    with tempfile.TemporaryDirectory(prefix="openbao-maintenance-sdk-build-") as temporary:
        root = Path(temporary)
        inputs = builder.backup_inputs(builder.source_inputs())
        builder.prepare(root, prepare_inputs(inputs) if prepare_inputs else inputs, candidate())
        messages = builder.run(["cargo", "test", "--locked", "--offline", "--no-default-features",
            "--features", features, "--lib", "--no-run", "--message-format=json-render-diagnostics"],
            root, builder.build_environment(root), capture=True)
        binaries = [Path(item["executable"]) for item in map(json.loads, messages.splitlines())
                    if item.get("reason") == "compiler-artifact" and item.get("executable")
                    and item.get("target", {}).get("name") == "openbao" and item.get("profile", {}).get("test")]
        patch.require(len(binaries) == 1)
    patch.require(before == hashes())
    # Cargo artifact layouts vary. Publish a content-addressed copy without
    # replacing another build; the privileged runner still freezes and checks it.
    binary = binaries[0]
    directory = patch.ROOT / "target/candidate-sdk/debug/deps"
    patch.require(binary.resolve().is_relative_to(directory.parent.resolve()))
    directory.mkdir(exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=directory) as stage:
        with binary.open("rb") as source:
            shutil.copyfileobj(source, stage)
        stage.flush()
        os.fchmod(stage.fileno(), 0o555)
        digest = base.sha256(base.read_regular_file(Path(stage.name), 256 * 1024 * 1024))
        target = directory / ("openbao-" + digest[:16])
        try:
            os.link(stage.name, target)
        except FileExistsError:
            pass
    patch.require(execution.binary_hash(target, os.getuid(), candidate=True) == digest)
    listing = subprocess.check_output([str(target), "--list"], timeout=15, text=True).splitlines()
    patch.require(all(listing.count(name + ": test") == 1 for name in (tests or TESTS.values())))
    print(target)


class Progress(legacy.Progress):
    def __init__(self, version):
        super().__init__()
        self.stages = STAGES[version]

    def feed(self, chunk):
        self.total += len(chunk)
        patch.require(self.total <= 65536)
        self.buffer.extend(chunk)
        while b"\n" in self.buffer:
            line, _, rest = self.buffer.partition(b"\n")
            self.buffer = bytearray(rest)
            if line.startswith(b"patch-stage:"):
                patch.require(self.count < len(self.stages)
                              and line == ("patch-stage:" + self.stages[self.count]).encode())
                print("SDK stage: " + self.stages[self.count], flush=True)
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
                      and progress.count == len(progress.stages))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        process.stdin.close()
        process.stdout.close()


def run_test(binary, uid, gid, addresses, ca, token, *, version):
    test = TESTS[version]
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
    exchange(process, payload, Progress(version))


@execution.frozen_runner
def run(binary, *, version, strict_candidate):
    patch.require(type(strict_candidate) is bool)
    uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    patch.require(uid > 0 and gid > 0 and pwd.getpwuid(uid).pw_gid == gid)
    digest = execution.binary_hash(binary, uid, candidate=strict_candidate)
    hashes = input_hashes if strict_candidate else normal_hashes
    inputs = hashes()
    proof = ({"candidate_generated_rust_sha256": base.sha256(registry.rust_output(candidate(), verification_candidate=True)),
              "scope": "strict-candidate-only", "routable": False} if strict_candidate else normal_provenance())
    index, platform = capture.PINS[version]
    release = {"version": version, "image": {"index_digest": index, "linux_amd64_digest": platform}}
    print("Maintenance SDK fixture: verifying signed image", flush=True)
    capture.verify_signature(version)
    podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-maintenance-sdk-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    owner = secrets.token_hex(16)
    container, network = "openbao-maintenance-sdk-" + owner, "openbao-maintenance-sdknet-" + owner
    resources = []
    token = ""
    try:
        certs, ca = harness.generate_tls(root, openssl, environment)
        config = harness.write_server_config(root, version)
        image = harness.inspect_image(podman, release, environment)
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, owner), timeout=60, environment=environment)
        resources.append(("container", container))
        print("Maintenance SDK fixture: starting constrained TLS server", flush=True)
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
        mount = "/v1/sys/auth/maintenance-alias"
        patch.call(address, ca, token, "POST", mount, {"type": "userpass"}, status=204)
        tune = mount + "/tune"
        settings = patch.call(address, ca, token, "GET", tune)["data"]
        alias_default = settings.get("case_sensitive_alias")
        patch.require(type(alias_default) is bool or "case_sensitive_alias" not in settings)
        patch.call(address, ca, token, "POST", tune, {"case_sensitive_alias": True}, status=204)
        patch.require(patch.call(address, ca, token, "GET", tune)["data"].get("case_sensitive_alias") is True)
        patch.call(address, ca, token, "DELETE", mount, status=204)
        print("Maintenance SDK fixture: running unprivileged strict SDK test", flush=True)
        run_test(binary, uid, gid, [address] * 3, ca, token, version=version)
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
    patch.require(inputs == hashes() and digest == execution.binary_hash(binary, uid, candidate=strict_candidate))
    if not strict_candidate:
        patch.require(proof == normal_provenance())
    mode = "candidate" if strict_candidate else "normal"
    report = {**execution.EXECUTION_ASSURANCE, **proof, "schema": f"openbao-maintenance-{mode}-sdk/v1",
              "version": version, "inputs": inputs, "test_binary_sha256": digest, "test": TESTS[version],
              "features": FEATURES,
              "image_linux_amd64_digest": platform, "image_index_digest": index, "stages": STAGES[version],
              "new_auth_mount_reported_case_sensitive_alias": alias_default,
              "explicit_case_sensitive_alias_verified": True,
              "outcome": "passed"}
    with tempfile.NamedTemporaryFile(prefix="openbao-maintenance-sdk-", suffix=".json", delete=False) as out:
        out.write(base.canonical_json(report))
        out.flush()
        os.fsync(out.fileno())
        os.fchmod(out.fileno(), 0o644)
    print(f"{version} {mode} SDK passed; result: {out.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--build", action="store_true")
    action.add_argument("--version", choices=TESTS)
    parser.add_argument("--normal", action="store_true")
    parser.add_argument("--test-binary", type=Path)
    args = parser.parse_args()
    if bool(args.version) != bool(args.test_binary):
        parser.error("--version and --test-binary must be supplied together")
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        if args.normal and args.build:
            normal_provenance()
            normal_sdk.build(FEATURES, normal_hashes)
        elif args.build:
            build()
        else:
            run(args.test_binary, version=args.version, strict_candidate=not args.normal)
        return 0
    except MissingNormalProfiles as error:
        print(error)
        return 1
    except (harness.HarnessError, base.SnapshotError, registry.RegistryError, OSError, ValueError, KeyError):
        print("Maintenance SDK fixture failed; no compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
