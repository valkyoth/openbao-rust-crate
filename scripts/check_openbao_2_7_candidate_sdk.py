#!/usr/bin/python3 -EsSB
"""Run strict SDK mocks in a disposable candidate build, without promoting main."""

import argparse
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import tempfile
import tomllib

import generate_openbao_2_7_candidate as candidate

registry = candidate.registry
ROOT = registry.ROOT
TEST = "candidate_dispatch"
MAX_TOTAL_BYTES = 16 * 1024 * 1024
EXPECTED_TESTS = {
    "strict_workflow_list_and_scan_preserve_distinct_methods",
    "strict_transit_rotation_keeps_legacy_empty_body_and_external_reference_separate",
    "strict_inspection_routes_are_version_specific",
    "historical_profiles_keep_legacy_rotation_and_reject_new_fields",
    "rolling_range_uses_detected_routes_but_does_not_relax_cas_policy",
    "strict_external_key_administration_covers_all_thirteen_routes",
    "strict_control_group_review_and_authorization_do_not_execute",
    "strict_pki_mldsa_and_kms_fields_use_registered_custom_mount_routes",
}


def run(command, destination, env, *, capture=False):
    process = subprocess.Popen(command, cwd=destination, env=env, start_new_session=True,
                               stdout=subprocess.PIPE if capture else None, text=True)
    try:
        stdout, _ = process.communicate(timeout=900)
    except BaseException:
        # On interruption, reap the owned group before releasing its temporary sources.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    if process.returncode:
        raise registry.RegistryError("candidate SDK command failed")
    return stdout


def source_inputs():
    paths = ["Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml", "README.md",
             f"tests/{TEST}.rs"]
    paths.extend(str(path.relative_to(ROOT)) for path in sorted((ROOT / "src").rglob("*.rs")))
    values = {}
    total = 0
    for relative in paths:
        path = ROOT / relative
        if any(parent.is_symlink() for parent in path.parents if parent != ROOT.parent):
            raise registry.RegistryError("candidate input parent is a symlink")
        value = registry.read_regular_file(path, 2 * 1024 * 1024)
        total += len(value)
        if total > MAX_TOTAL_BYTES:
            raise registry.RegistryError("candidate input total exceeds limit")
        values[relative] = value
    return values


def backup_inputs(inputs):
    result = dict(inputs)
    for relative in ("docs/OPENBAO_REQUEST_FIELD_COMPATIBILITY.md",
                     "compat/onboarding/2.7.0/control-group-policy.hcl",
                     "tests/fixtures/tls_test_ca.pem", "tests/fixtures/tls_test_ca.crl.pem"):
        result[relative] = registry.read_regular_file(ROOT / relative, 2 * 1024 * 1024)
    return result


def prepare(destination, inputs, verified_candidate):
    for relative, value in inputs.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(value)
    generated = destination / registry.RUST_PATH.relative_to(ROOT)
    generated.write_bytes(registry.rust_output(verified_candidate, verification_candidate=True))


def build_environment(destination):
    """Exclude ambient compiler wrappers, Cargo config, flags and loader overrides.

    Installed toolchains and cached dependency sources remain trusted inputs;
    this local build is not independently signed source-to-binary provenance.
    """
    for directory in (destination, *destination.parents):
        for name in ("config", "config.toml"):
            config = directory / ".cargo" / name
            if config.exists() or config.is_symlink():
                raise registry.RegistryError("ambient ancestor Cargo configuration is forbidden")
    home = Path.home()
    channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    lookup = {"HOME": str(home), "PATH": f"{home / '.cargo/bin'}:/usr/bin:/bin", "LANG": "C.UTF-8"}
    rustup = shutil.which("rustup", path=lookup["PATH"])
    if rustup is None:
        raise registry.RegistryError("rustup unavailable in trusted tool locations")
    cargo = Path(subprocess.check_output(
        [rustup, "which", "--toolchain", channel, "cargo"],
        env=lookup, cwd=destination, timeout=30, text=True).strip())
    if not cargo.is_absolute() or not cargo.is_file() or not (cargo.parent / "rustc").is_file():
        raise registry.RegistryError("pinned candidate toolchain unavailable")
    cargo_home = destination / "cargo-home"
    cargo_home.mkdir(mode=0o700)
    # Only the offline registry cache is shared, never config.toml or credentials.
    (cargo_home / "registry").symlink_to(home / ".cargo/registry", target_is_directory=True)
    return {"HOME": str(destination), "CARGO_HOME": str(cargo_home),
            "PATH": f"{cargo.parent}:/usr/bin:/bin", "LANG": "C.UTF-8",
            "RUSTC": str(cargo.parent / "rustc"), "RUSTDOC": str(cargo.parent / "rustdoc"),
            "RUSTUP_TOOLCHAIN": channel, "CARGO_INCREMENTAL": "0",
            "CARGO_TARGET_DIR": str(ROOT / "target/candidate-sdk")}


def main(build_backup=False):
    if os.geteuid() == 0:
        print("Candidate SDK verification must run without root")
        return 1
    try:
        registry.verify_outputs()
        verified = candidate.verify()
        inputs = source_inputs()
        if build_backup:
            inputs = backup_inputs(inputs)
        with tempfile.TemporaryDirectory(prefix="openbao-candidate-sdk-") as temporary:
            destination = Path(temporary)
            prepare(destination, inputs, verified)
            env = build_environment(destination)
            if build_backup:
                messages = run(["cargo", "test", "--locked", "--offline", "--no-default-features",
                                "--features", "sys,operator-ops,operator-ops-acknowledged,rustls-tls",
                                "--lib", "--no-run", "--message-format=json-render-diagnostics"], destination, env, capture=True)
                artifacts = [json.loads(line) for line in messages.splitlines() if line.strip()]
                binaries = [Path(item["executable"]) for item in artifacts
                            if item.get("reason") == "compiler-artifact" and item.get("executable")
                            and item.get("target", {}).get("name") == "openbao"
                            and item.get("profile", {}).get("test") is True]
                if len(binaries) != 1:
                    raise registry.RegistryError("candidate backup binary inventory changed")
                binary = binaries[0]
            else:
                command = ["cargo", "test", "--locked", "--offline", "--all-features", "--test", TEST,
                           "--", "--ignored"]
                listing = run([*command, "--list"], destination, env, capture=True)
                listed = {line.removesuffix(": test") for line in listing.splitlines() if line.endswith(": test")}
                if listed != EXPECTED_TESTS:
                    raise registry.RegistryError("candidate SDK test inventory changed")
                run(command, destination, env)
        current = backup_inputs(source_inputs()) if build_backup else source_inputs()
        if current != inputs:
            raise registry.RegistryError("candidate SDK inputs changed during verification")
        registry.verify_outputs()
    except (OSError, ValueError, registry.RegistryError, registry.SnapshotError,
            subprocess.TimeoutExpired):
        print("Candidate SDK verification failed; public promotion unchanged")
        return 1
    if build_backup:
        print(f"Strict candidate backup test binary: {binary}")
        print("Build only; live TLS verification and public promotion remain pending")
    else:
        print("Strict candidate SDK mocks passed; no live TLS or public promotion claim")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-backup-test", action="store_true")
    raise SystemExit(main(parser.parse_args().build_backup_test))
