#!/usr/bin/python3 -EsSB
"""Capture server-only evidence for the two maintenance candidates."""

import argparse
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile

import openbao_2_7_2 as previous

base, harness, tls = previous.base, previous.harness, previous.tls
require, call = previous.require, previous.call
PINS = {
    "2.6.6": ("sha256:91f37e006ca5a1ea274b146c5406e2abfb67e5338267ce56c0874285879d9e2d",
              "sha256:1a76758b261a78549fd310be6043d6d973dd7565b9b2663f01942e9110b03bdf"),
    "2.7.3": ("sha256:ba4b133eb9586630024e71a617e66f37f29cc3534cdd46a6233e098ceded8dc9",
              "sha256:b9418c63e2185157d8ee8689a8a93265d5aadad677d6320156172bd42ad3b10b"),
}


def input_hashes():
    paths = {*tls.INPUTS, "scripts/openbao_2_7_2.py", "scripts/openbao_maintenance_capture.py"}
    return {p: base.sha256(base.read_regular_file(previous.ROOT / p, 2 * 1024 * 1024)) for p in sorted(paths)}


def verify_signature(version):
    index, platform = PINS[version]
    ref = "docker.io/openbao/openbao@" + index
    _, raw = base.run_bounded(["skopeo", "inspect", "--raw", "docker://" + ref], 1024 * 1024, timeout=120)
    require("sha256:" + base.sha256(raw) == index)
    manifests = base.parse_json(raw, 1024 * 1024)["manifests"]
    require([m["digest"] for m in manifests if m.get("platform") == {"os": "linux", "architecture": "amd64"}]
            == [platform])
    identity = "https://github.com/openbao/openbao/.github/workflows/release-images.yml@refs/tags/v" + version
    _, output = base.run_bounded(["cosign", "verify", "--certificate-identity", identity,
                                  "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
                                  ref], 1024 * 1024, timeout=180)
    signatures = base.parse_json(b'{"signatures":' + output + b'}', 1024 * 1024 + 32)["signatures"]
    require(isinstance(signatures, list) and 0 < len(signatures) <= 32)
    for entry in signatures:
        require(entry["critical"]["image"] == {"docker-manifest-digest": index}
                and entry["critical"]["type"] == "https://sigstore.dev/cosign/sign/v1")


def normalize_api(document, mounts, version):
    index, amd64 = PINS[version]
    # handleOpenAPI returns HTTPRawBody. The CLI wraps this document in data,
    # but direct HTTPS capture must validate the unwrapped wire response.
    require(isinstance(document, dict))
    base.validate_json_tree(document)
    require(str(document.get("openapi", "")).startswith("3.")
            and document.get("info", {}).get("version") == version)
    paths = document.get("paths")
    schemas = document.get("components", {}).get("schemas")
    require(isinstance(paths, dict) and bool(paths) and isinstance(schemas, dict))
    return {"schema": "openbao-normalized-openapi/v2", "generator_version": base.GENERATOR_VERSION,
            "version": version, "image_index_digest": index, "image_linux_amd64_digest": amd64,
            "mounts": mounts, "path_count": len(paths), "schema_count": len(schemas),
            "operation_count": sum(1 for item in paths.values() for method in item if method in base.HTTP_METHODS),
            "document": base.contract_only(document)}


def capture_api(address, ca, token, version):
    secret_mounts, auth_mounts = ((base.SECRET_MOUNTS, base.AUTH_MOUNTS) if version == "2.6.6"
                                  else (previous.SECRET_MOUNTS, previous.AUTH_MOUNTS))
    mounts = []
    for path, kind, options in secret_mounts:
        payload = {"type": kind}
        if options:
            require(options in (("-version=1",), ("-version=2",)))
            payload["options"] = {"version": options[0][-1]}
        call(address, ca, token, "POST", "/v1/sys/mounts/" + path, payload, status=204)
        mounts.append({"kind": "secret", "path": path, "type": kind})
    for path, kind in auth_mounts:
        call(address, ca, token, "POST", "/v1/sys/auth/" + path, {"type": kind}, status=204)
        mounts.append({"kind": "auth", "path": path, "type": kind})
    print("Maintenance fixture: requesting raw OpenAPI document", flush=True)
    return normalize_api(call(address, ca, token, "POST", "/v1/sys/internal/specs/openapi",
                              {"generic_mount_paths": True}, openapi=True), mounts, version)


def write_capture_output(api_data, report):
    # The repository's immutable writer deliberately rejects paths outside the
    # repository. Capture output instead lives in a newly allocated private dir.
    output = Path(tempfile.mkdtemp(prefix="openbao-maintenance-evidence-", dir="/tmp"))
    try:
        for name, data in (("openapi.json", api_data), ("report.json", base.canonical_json(report))):
            with (output / name).open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
                os.fchmod(handle.fileno(), 0o644)
        output.chmod(0o755)
    except BaseException:
        shutil.rmtree(output)
        raise
    return output


def capture(version):
    index, amd64 = PINS[version]
    release = {"version": version, "image": {"index_digest": index, "linux_amd64_digest": amd64}}
    require(os.geteuid() == 0)
    inputs = input_hashes()
    print("Maintenance fixture: verifying signed image", flush=True)
    verify_signature(version)
    print("Maintenance fixture: verifying protected tools", flush=True)
    podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-maintenance-private-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    run_id = secrets.token_hex(16)
    container, network = "openbao-maintenance-" + run_id, "openbao-maintenance-net-" + run_id
    resources = []
    token = ""
    try:
        print("Maintenance fixture: preparing TLS certificates", flush=True)
        certs, ca = harness.generate_tls(root, openssl, environment)
        print("Maintenance fixture: preparing server configuration", flush=True)
        config = harness.write_server_config(root, version)
        config.write_bytes(base.read_regular_file(config, 65536) + b"raw_storage_endpoint = true\n")
        print("Maintenance fixture: preparing pinned image", flush=True)
        image = harness.inspect_image(podman, release, environment)
        print("Maintenance fixture: creating isolated network", flush=True)
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, run_id), timeout=60, environment=environment)
        print("Maintenance fixture: starting constrained server", flush=True)
        resources.append(("container", container))
        harness.run_bounded(tls.container_command(podman, image, container, network, run_id, config, certs),
                            timeout=120, environment=environment)
        print("Maintenance fixture: checking resource limits", flush=True)
        limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", container],
                                     maximum=64 * 1024, timeout=30, environment=environment)
        base.validate_container_resource_config(base.parse_json(limits, 64 * 1024))
        print("Maintenance fixture: checking server state", flush=True)
        state = base.parse_json(harness.run_bounded(
            [podman, "inspect", "--format", "{{json .State}}", container],
            maximum=16 * 1024, timeout=10, environment=environment), 16 * 1024)
        if state.get("Running") is not True:
            raise harness.HarnessError("maintenance server exited before network verification")
        print("Maintenance fixture: checking network isolation", flush=True)
        tls.verify_network(podman, network, container, environment)
        print("Maintenance fixture: checking loopback publication", flush=True)
        port = harness.parse_port(harness.run_bounded([podman, "port", container, "8200/tcp"],
                                  maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        print("Maintenance fixture: exact-version TLS health and rejection checks", flush=True)
        harness.wait_for_exact_version(address, ca, version)
        tls.probe_tls(port, ca)
        token = harness.initialize_and_unseal(address, ca)
        print("Maintenance fixture: capturing built-in runtime OpenAPI", flush=True)
        api = capture_api(address, ca, token, version)
    finally:
        token = ""
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
    api_data = base.canonical_json(api)
    report = {"schema": "openbao-patch-capture/v1", "version": version,
              "image_linux_amd64_digest": amd64, "image_index_digest": index,
              "inputs": inputs, "openapi_sha256": base.sha256(api_data),
              "scope": "server-fixture-only-not-sdk-integration", "routable": False,
              "checks": ["exact-version", "tls-rejections", "resource-limits", "network-isolation", "built-in-openapi", "cleanup"]}
    output = write_capture_output(api_data, report)
    print(f"{version} server API capture passed; result directory: {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", choices=PINS, required=True)
    parser.add_argument("--verify-image-only", action="store_true")
    args = parser.parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        if args.verify_image_only:
            verify_signature(args.version)
        else:
            capture(args.version)
        return 0
    except (harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("Maintenance fixture failed; no compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
