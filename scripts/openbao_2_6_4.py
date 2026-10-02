#!/usr/bin/python3 -EsSB
"""Capture the exact 2.6 maintenance patch without inheriting 2.7 contracts."""

import argparse
import base64
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile
import time

import openbao_2_7_1 as wire

base, harness, tls, documentation = wire.base, wire.harness, wire.tls, wire.documentation
ROOT = wire.ROOT
OUTPUT = ROOT / "compat/onboarding/2.6.4"
VERSION = "2.6.4"
SOURCE = "8206bc114009a0e468bbdae143f292922e1dbe27"
INDEX = "sha256:cf2340fc9a22cb9358ca0defd1f39b65673836bd23fe2bb8984a07e11fe13ef4"
AMD64 = "sha256:bd3e8b6b67b5c4c3fc1064cd0f86eb8063d9ed92a7af608b6408d6748e6eef64"
ATTESTATION = "sha256:b9f9c417f81c1f44e6a59b625f7e5b1780e044b3c62f27e5c0f960762196d172"
PROVENANCE = "sha256:5042d06a394d3e1d216d3ac0363830b75cf1605e691f925ff7f46a3c90004e8d"
BUNDLE_SHA256 = "42ac5a85572e74660a49ee40ba9463ab73dc27202edc4cb5192cc12ee7d2aa11"
IDENTITY = "https://github.com/openbao/openbao/.github/workflows/release-images.yml@refs/tags/v2.6.4"
DOCUMENTATION_SHA256 = "ee2284a895483dd93f4745e0b1e2ac2898cef17f04823d8af0464e3e22ad7576"
PREDECESSOR_DOC = "compat/onboarding/2.7.0/predecessor-2.6.3-documentation-v2.json"
PREDECESSOR_DOC_SHA256 = "7a8bd3a2fe483a1f3ff7dd9bc8ef4861ff31a04bf847d3f64111aadcac570b47"
RELEASE = {"version": VERSION, "source": {"peeled_commit_sha1": SOURCE},
           "documentation": {"source_path": "website/content/docs/api"},
           "image": {"index_digest": INDEX, "linux_amd64_digest": AMD64}}
IMAGE_ARTIFACTS = {"image-index.json": INDEX, "image-attestation-manifest.json": ATTESTATION,
                   "image-provenance.json": PROVENANCE, "signature-bundle.json": BUNDLE_SHA256}
LIMIT = 2 * 1024 * 1024
LEGACY_ROUTES = {"/auth/{ldap_mount_path}/config", "/auth/{kerberos_mount_path}/config",
                 "/auth/{radius_mount_path}/config", "/{ldap_mount_path}/config"}
CHECKS = ["exact-version", "tls13-and-rejections", "resource-limits", "network-isolation",
          "eab-mac-redacted", "approle-json-and-form-login", "expired-secret-id-denied-without-tidy",
          "full-2.6-built-in-openapi", "legacy-plugins-mounted", "raw-storage-enabled", "cleanup"]


def require(condition):
    if not condition:
        raise harness.HarnessError("2.6.4 fixture assertion failed")


def pinned(data, digest):
    require(base.sha256(data) == digest.removeprefix("sha256:"))
    return data


def input_hashes():
    paths = {*wire.INPUTS, "scripts/openbao_2_6_4.py", "scripts/openbao_documentation_v2.py",
             PREDECESSOR_DOC, "compat/onboarding/2.6.4/documentation.json",
             *("compat/onboarding/2.6.4/" + name for name in IMAGE_ARTIFACTS)}
    return {path: base.sha256(base.read_regular_file(ROOT / path, LIMIT)) for path in sorted(paths)}


def validate_documentation(data):
    document = base.parse_json(pinned(data, DOCUMENTATION_SHA256), base.MAX_SNAPSHOT_BYTES)
    documentation.validate(document, RELEASE)
    before = base.parse_json(pinned(base.read_regular_file(ROOT / PREDECESSOR_DOC, base.MAX_SNAPSHOT_BYTES),
                                   PREDECESSOR_DOC_SHA256), base.MAX_SNAPSHOT_BYTES)
    require(document["files"] == before["files"] and document["operations"] == before["operations"])
    return document


def verify_source():
    return validate_documentation(base.read_regular_file(OUTPUT / "documentation.json", base.MAX_SNAPSHOT_BYTES))


def source_review(repository_text):
    repository = base.validate_source_repository(repository_text)
    require(base.git_output(repository, ["rev-parse", "--verify", "refs/tags/v2.6.4^{commit}"], 128).strip() == SOURCE.encode())
    data = base.canonical_json(documentation.extract(repository, RELEASE))
    validate_documentation(data)
    base.write_immutable(OUTPUT / "documentation.json", data)


def validate_signature(data):
    signatures = base.parse_json(b'{"signatures":' + data + b'}', LIMIT)["signatures"]
    require(isinstance(signatures, list) and 0 < len(signatures) <= 32)
    for item in signatures:
        require(isinstance(item, dict) and isinstance(item.get("critical"), dict))
        require(item["critical"].get("image") == {"docker-manifest-digest": INDEX}
                and item["critical"].get("type") == "https://sigstore.dev/cosign/sign/v1")


def verify_signature():
    _, data = base.run_bounded(["cosign", "verify", "--certificate-identity", IDENTITY,
                               "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
                               "docker.io/openbao/openbao@" + INDEX], 1024 * 1024, timeout=180)
    validate_signature(data)


def validate_image(artifacts):
    require(set(artifacts) == set(IMAGE_ARTIFACTS))
    values = {name: base.parse_json(pinned(data, IMAGE_ARTIFACTS[name]), LIMIT)
              for name, data in artifacts.items() if name != "signature-bundle.json"}
    manifests = values["image-index.json"]["manifests"]
    require([m["digest"] for m in manifests if m.get("platform") == {"architecture": "amd64", "os": "linux"}] == [AMD64])
    require([m["digest"] for m in manifests if m.get("annotations", {}).get("vnd.docker.reference.digest") == AMD64] == [ATTESTATION])
    attestation = values["image-attestation-manifest.json"]
    require(attestation["subject"]["digest"] == AMD64)
    require(len(attestation["layers"]) == 1 and attestation["layers"][0]["digest"] == PROVENANCE
            and attestation["layers"][0]["size"] == len(artifacts["image-provenance.json"]))
    provenance = values["image-provenance.json"]
    require(provenance.get("predicateType") == "https://slsa.dev/provenance/v1")
    subjects = provenance.get("subject")
    require(isinstance(subjects, list) and bool(subjects)
            and all(s.get("digest") == {"sha256": AMD64.removeprefix("sha256:")} for s in subjects))
    args = provenance["predicate"]["buildDefinition"]["externalParameters"]["request"]["root"]["request"]["args"]
    require(args.get("vcs:revision") == SOURCE and args.get("vcs:source") == "https://github.com/openbao/openbao")
    lines = pinned(artifacts["signature-bundle.json"], BUNDLE_SHA256).splitlines()
    require(0 < len(lines) <= 32)
    for line in lines:
        bundle = base.parse_json(line, LIMIT)
        require(bundle.get("mediaType") == "application/vnd.dev.sigstore.bundle.v0.3+json")
        payload = base.parse_json(base64.b64decode(bundle["dsseEnvelope"]["payload"], validate=True), LIMIT)
        require(payload.get("_type") == "https://in-toto.io/Statement/v1"
                and payload.get("predicateType") == "https://sigstore.dev/cosign/sign/v1")
        subjects = payload.get("subject")
        require(isinstance(subjects, list) and len(subjects) == 1
                and subjects[0].get("digest") == {"sha256": INDEX.removeprefix("sha256:")})


def verify_image():
    validate_image({name: base.read_regular_file(OUTPUT / name, LIMIT) for name in IMAGE_ARTIFACTS})


def retain_image(directory):
    verify_signature()
    artifacts = {name: base.read_regular_file(directory / name, LIMIT) for name in IMAGE_ARTIFACTS}
    validate_image(artifacts)
    for name, data in artifacts.items():
        base.write_immutable(OUTPUT / name, data)


def call(address, ca, token, method, path, payload=None, *, status=200, **options):
    actual, body = wire.request(address, ca, token, method, path, payload, **options)
    tls.require_status(actual, status)
    return body


def prepare_config(root):
    original = harness.write_server_config(root, VERSION)
    data = base.read_regular_file(original, 65536)
    require(data.count(b'listener "tcp" {') == 1)
    marker = secrets.token_hex(32)
    data = data.replace(b'listener "tcp" {', b'listener "tcp" {\n  tls_acme_eab_key_id = "'
                        + wire.EAB_KEY_ID.encode() + b'"\n  tls_acme_eab_mac_key = "' + marker.encode() + b'"')
    config = root / "patch.hcl"
    harness.write_private(config, data + b"raw_storage_endpoint = true\n", 0o640)
    return config, marker


def patch_probes(address, ca, token, marker):
    print("2.6.4 fixture: sanitized configuration", flush=True)
    wire.check_sanitized(call(address, ca, token, "GET", "/v1/sys/config/state/sanitized"), marker)
    print("2.6.4 fixture: AppRole JSON/form login and expiry without tidy", flush=True)
    call(address, ca, token, "POST", "/v1/sys/auth/patch-approle", {"type": "approle"}, status=204)
    role = "/v1/auth/patch-approle/role/fixture"
    call(address, ca, token, "POST", role, {"secret_id_ttl": "5s", "secret_id_num_uses": 0}, status=204)
    credentials = {"role_id": call(address, ca, token, "GET", role + "/role-id")["data"]["role_id"],
                   "secret_id": call(address, ca, token, "POST", role + "/secret-id", {})["data"]["secret_id"]}
    for form in (False, True):
        response = call(address, ca, "", "POST", "/v1/auth/patch-approle/login", credentials, form=form)
        require(isinstance(response.get("auth"), dict) and bool(response["auth"].get("client_token")))
    time.sleep(6)
    for form in (False, True):
        status, response = wire.request(address, ca, "", "POST", "/v1/auth/patch-approle/login", credentials, form=form)
        require(status in (400, 403) and response.get("auth") is None
                and response.get("errors") == ["invalid role or secret ID"])
    call(address, ca, token, "DELETE", "/v1/sys/auth/patch-approle", status=204)


def normalize_api(document, mounts):
    require(isinstance(document, dict))
    base.validate_json_tree(document)
    require(str(document.get("openapi", "")).startswith("3.") and document.get("info", {}).get("version") == VERSION)
    paths, schemas = document.get("paths"), document.get("components", {}).get("schemas")
    require(isinstance(paths, dict) and bool(paths) and isinstance(schemas, dict))
    require("/sys/raw" in paths and "/sys/raw/{path}" in paths)
    require(LEGACY_ROUTES <= set(paths))
    expected = [{"kind": "secret", "path": path, "type": kind} for path, kind, _ in base.SECRET_MOUNTS]
    expected += [{"kind": "auth", "path": path, "type": kind} for path, kind in base.AUTH_MOUNTS]
    require(mounts == expected)
    return {"schema": "openbao-normalized-openapi/v2", "generator_version": base.GENERATOR_VERSION,
            "version": VERSION, "image_index_digest": INDEX, "image_linux_amd64_digest": AMD64,
            "mounts": mounts, "path_count": len(paths), "schema_count": len(schemas),
            "operation_count": sum(1 for item in paths.values() for method in item if method in base.HTTP_METHODS),
            "document": base.contract_only(document)}


def capture_api(address, ca, token):
    mounts = []
    for path, kind, options in base.SECRET_MOUNTS:
        payload = {"type": kind}
        if options:
            require(options in (("-version=1",), ("-version=2",)))
            payload["options"] = {"version": options[0][-1]}
        call(address, ca, token, "POST", "/v1/sys/mounts/" + path, payload, status=204)
        mounts.append({"kind": "secret", "path": path, "type": kind})
    for path, kind in base.AUTH_MOUNTS:
        call(address, ca, token, "POST", "/v1/sys/auth/" + path, {"type": kind}, status=204)
        mounts.append({"kind": "auth", "path": path, "type": kind})
    return normalize_api(call(address, ca, token, "POST", "/v1/sys/internal/specs/openapi",
                              {"generic_mount_paths": True}, openapi=True), mounts)


def capture():
    require(os.geteuid() == 0)
    inputs = input_hashes()
    verify_source()
    verify_image()
    print("2.6.4 fixture: verifying signed image", flush=True)
    verify_signature()
    podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-264-private-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    owner = secrets.token_hex(16)
    container, network = "openbao-264-" + owner, "openbao-264-net-" + owner
    resources = []
    token = ""
    try:
        certs, ca = harness.generate_tls(root, openssl, environment)
        config, marker = prepare_config(root)
        image = harness.inspect_image(podman, RELEASE, environment)
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, owner), timeout=60, environment=environment)
        resources.append(("container", container))
        print("2.6.4 fixture: starting constrained TLS server", flush=True)
        harness.run_bounded(tls.container_command(podman, image, container, network, owner, config, certs), timeout=120, environment=environment)
        limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", container], maximum=65536, timeout=30, environment=environment)
        base.validate_container_resource_config(base.parse_json(limits, 65536))
        tls.verify_network(podman, network, container, environment)
        port = harness.parse_port(harness.run_bounded([podman, "port", container, "8200/tcp"], maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        harness.wait_for_exact_version(address, ca, VERSION)
        tls.probe_tls(port, ca)
        token = harness.initialize_and_unseal(address, ca)
        patch_probes(address, ca, token, marker)
        print("2.6.4 fixture: capturing all 2.6 engines including legacy plugins", flush=True)
        api = capture_api(address, ca, token)
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
        require(not failed)
    require(inputs == input_hashes())
    data = base.canonical_json(api)
    report = {"schema": "openbao-patch-capture/v1", "version": VERSION, "inputs": inputs,
              "image_index_digest": INDEX, "image_linux_amd64_digest": AMD64,
              "scope": "server-fixture-only-not-sdk-integration", "routable": False,
              "openapi_sha256": base.sha256(data), "checks": CHECKS}
    output = write_capture_output(data, report)
    print(f"2.6.4 API and patch fixture passed; result directory: {output}", flush=True)


def write_capture_output(data, report):
    output = Path(tempfile.mkdtemp(prefix="openbao-264-evidence-", dir="/tmp"))
    try:
        for name, value in (("openapi.json", data), ("report.json", base.canonical_json(report))):
            with (output / name).open("xb") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
                os.fchmod(handle.fileno(), 0o644)
        output.chmod(0o755)
    except BaseException:
        shutil.rmtree(output)
        raise
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--source-repository")
    action.add_argument("--retain-image-directory", type=Path)
    action.add_argument("--verify-source", action="store_true")
    action.add_argument("--verify-image", action="store_true")
    action.add_argument("--capture", action="store_true")
    args = parser.parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        if args.source_repository:
            source_review(args.source_repository)
        elif args.retain_image_directory:
            retain_image(args.retain_image_directory)
        elif args.verify_source:
            verify_source()
        elif args.verify_image:
            verify_image()
        else:
            capture()
    except (harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("2.6.4 evidence failed; no compatibility promotion")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
