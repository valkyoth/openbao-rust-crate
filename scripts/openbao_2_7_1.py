#!/usr/bin/python3 -EsSB
"""Capture exact 2.7.1 patch evidence; never enable an SDK profile implicitly."""

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import openbao_2_7_tls as tls
import openbao_documentation_v2 as documentation

base, harness = tls.base, tls.harness
ROOT = Path(__file__).resolve().parents[1]
VERSION = "2.7.1"
SOURCE = "a5db72cef75c24b920ade02065b18dd8eb666bac"
DOCUMENTATION_SHA256 = "be731f6fe2db675a93e8c61852345b6ce6f640e3524ccdb8bf558dba20b4480c"
DOCUMENTATION_PATH = ROOT / "compat/onboarding/2.7.1/documentation.json"
INDEX = "sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf"
AMD64 = "sha256:a36ea8c27f0dcff5757664ad080425f96d3b6b2f33db3e76c4e2d3112fb17005"
IDENTITY = "https://github.com/openbao/openbao/.github/workflows/release-images.yml@refs/tags/v2.7.1"
RELEASE = {"version": VERSION, "source": {"peeled_commit_sha1": SOURCE},
           "documentation": {"source_path": "website/content/docs/api"},
           "image": {"index_digest": INDEX, "linux_amd64_digest": AMD64}}
SECRET_MOUNTS = tuple(row for row in base.SECRET_MOUNTS if row[1] != "ldap")
AUTH_MOUNTS = tuple(row for row in base.AUTH_MOUNTS if row[1] not in {"ldap", "radius", "kerberos"})
INPUTS = (*tls.INPUTS, "scripts/openbao_2_7_1.py")
CHECKS = ["exact-version", "tls13", "tls-rejections", "resource-limits", "network-isolation",
          "eab-mac-key-redacted", "approle-json-and-form-login", "expired-secret-id-denied-without-tidy", "cleanup"]
EAB_KEY_ID = "disposable-eab-fixture"


def require(condition):
    if not condition:
        raise harness.HarnessError("2.7.1 fixture assertion failed")


def input_hashes():
    return {path: base.sha256(base.read_regular_file(ROOT / path, 2 * 1024 * 1024)) for path in INPUTS}


def validate_documentation(data):
    require(base.sha256(data) == DOCUMENTATION_SHA256)
    document = base.parse_json(data, base.MAX_SNAPSHOT_BYTES)
    documentation.validate(document, RELEASE)
    return document


def verify_source():
    return validate_documentation(base.read_regular_file(DOCUMENTATION_PATH, base.MAX_SNAPSHOT_BYTES))


def validate_signature(output):
    signatures = base.parse_json(b'{"signatures":' + output + b'}', 1024 * 1024 + 32)["signatures"]
    require(isinstance(signatures, list) and 0 < len(signatures) <= 32)
    for entry in signatures:
        require(isinstance(entry, dict) and isinstance(entry.get("critical"), dict))
        critical = entry["critical"]
        require(critical.get("image") == {"docker-manifest-digest": INDEX}
                and critical.get("type") == "https://sigstore.dev/cosign/sign/v1")


def verify_signature():
    _, output = base.run_bounded([
        "cosign", "verify", "--certificate-identity", IDENTITY,
        "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
        f"docker.io/openbao/openbao@{INDEX}",
    ], 1024 * 1024, timeout=180)
    validate_signature(output)


def request(address, ca, token, method, path, payload=None, *, form=False, openapi=False):
    require(path.startswith("/v1/") and len(path) <= 4096)
    body = None if payload is None else (
        urllib.parse.urlencode(payload).encode() if form else base.canonical_json(payload))
    require(body is None or len(body) <= tls.MAX_BODY)
    headers = {"Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    outgoing = urllib.request.Request(address + path, data=body, method=method, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), harness.RejectRedirect(),
                                        urllib.request.HTTPSHandler(context=tls.context(ca)))
    maximum = base.MAX_OPENAPI_BYTES if openapi else tls.MAX_BODY
    try:
        response = opener.open(outgoing, timeout=30 if openapi else 5)
    except urllib.error.HTTPError as error:
        response = error
    except (OSError, urllib.error.URLError) as error:
        raise harness.HarnessError("2.7.1 TLS request failed") from error
    with response:
        status = response.status
        data = response.read(maximum + 1)
        require(len(data) <= maximum)
        require(not data or response.headers.get_content_type() == "application/json")
    return status, base.parse_json(data, maximum) if data else {}


def call(address, ca, token, method, path, payload=None, *, status=200, **options):
    actual, response = request(address, ca, token, method, path, payload, **options)
    tls.require_status(actual, status)
    return response


def prepare_config(root):
    config = harness.write_server_config(root, VERSION)
    marker = secrets.token_hex(32)
    data = base.read_regular_file(config, 64 * 1024)
    require(data.count(b'listener "tcp" {') == 1)
    # OpenBao validates the EAB pair even when using static TLS certificates.
    # Do not enable ACME issuance or contact a CA; only test config sanitization.
    config.write_bytes(data.replace(b'listener "tcp" {',
        b'listener "tcp" {\n  tls_acme_eab_key_id = "' + EAB_KEY_ID.encode()
        + b'"\n  tls_acme_eab_mac_key = "' + marker.encode() + b'"'))
    return config, marker


def check_sanitized(response, marker):
    require(isinstance(response.get("data"), dict))
    listeners = response["data"].get("listeners")
    require(isinstance(listeners, list) and len(listeners) == 1)
    require(isinstance(listeners[0], dict) and isinstance(listeners[0].get("config"), dict))
    require(listeners[0]["config"].get("tls_acme_eab_key_id") == EAB_KEY_ID)
    require("tls_acme_eab_mac_key" not in listeners[0]["config"])
    require(marker.encode() not in base.canonical_json(response))


def patch_probes(address, ca, token, marker):
    print("2.7.1 fixture: sanitized configuration", flush=True)
    check_sanitized(call(address, ca, token, "GET", "/v1/sys/config/state/sanitized"), marker)
    print("2.7.1 fixture: AppRole JSON/form login and expiry without tidy", flush=True)
    call(address, ca, token, "POST", "/v1/sys/auth/patch-approle", {"type": "approle"}, status=204)
    role = "/v1/auth/patch-approle/role/fixture"
    call(address, ca, token, "POST", role, {"secret_id_ttl": "5s", "secret_id_num_uses": 0}, status=204)
    role_id = call(address, ca, token, "GET", role + "/role-id")["data"]["role_id"]
    secret_id = call(address, ca, token, "POST", role + "/secret-id", {})["data"]["secret_id"]
    credentials = {"role_id": role_id, "secret_id": secret_id}
    for form in (False, True):
        response = call(address, ca, "", "POST", "/v1/auth/patch-approle/login", credentials, form=form)
        require(isinstance(response.get("auth"), dict) and bool(response["auth"].get("client_token")))
    time.sleep(6)
    for form in (False, True):
        status, response = request(address, ca, "", "POST", "/v1/auth/patch-approle/login", credentials, form=form)
        require(status in (400, 403) and response.get("auth") is None
                and response.get("errors") == ["invalid role or secret ID"])
    call(address, ca, token, "DELETE", "/v1/sys/auth/patch-approle", status=204)


def normalize_api(document, mounts):
    # handleOpenAPI returns HTTPRawBody. The CLI wraps this document in data,
    # but direct HTTPS capture must validate the unwrapped wire response.
    require(isinstance(document, dict))
    base.validate_json_tree(document)
    require(str(document.get("openapi", "")).startswith("3.")
            and document.get("info", {}).get("version") == VERSION)
    paths = document.get("paths")
    schemas = document.get("components", {}).get("schemas")
    require(isinstance(paths, dict) and bool(paths) and isinstance(schemas, dict))
    return {"schema": "openbao-normalized-openapi/v2", "generator_version": base.GENERATOR_VERSION,
            "version": VERSION, "image_index_digest": INDEX, "image_linux_amd64_digest": AMD64,
            "mounts": mounts, "path_count": len(paths), "schema_count": len(schemas),
            "operation_count": sum(1 for item in paths.values() for method in item if method in base.HTTP_METHODS),
            "document": base.contract_only(document)}


def capture_api(address, ca, token):
    mounts = []
    for path, kind, options in SECRET_MOUNTS:
        payload = {"type": kind}
        if options:
            require(options in (("-version=1",), ("-version=2",)))
            payload["options"] = {"version": options[0][-1]}
        call(address, ca, token, "POST", "/v1/sys/mounts/" + path, payload, status=204)
        mounts.append({"kind": "secret", "path": path, "type": kind})
    for path, kind in AUTH_MOUNTS:
        call(address, ca, token, "POST", "/v1/sys/auth/" + path, {"type": kind}, status=204)
        mounts.append({"kind": "auth", "path": path, "type": kind})
    print("2.7.1 fixture: requesting raw OpenAPI document", flush=True)
    return normalize_api(call(address, ca, token, "POST", "/v1/sys/internal/specs/openapi",
                              {"generic_mount_paths": True}, openapi=True), mounts)


def write_capture_output(api_data, report):
    # The repository's immutable writer deliberately rejects paths outside the
    # repository. Capture output instead lives in a newly allocated private dir.
    output = Path(tempfile.mkdtemp(prefix="openbao-271-evidence-", dir="/tmp"))
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


def failure_category(error):
    # Fixed labels only: exceptions from transport/configuration can contain
    # credentials. Never interpolate the error itself or its cause.
    messages = {
        "evidence command failed without exposing its output": "verification-command-failed",
        "bounded command timed out": "verification-command-timeout",
        "evidence tool and its parents must be root-owned and not group/world writable": "tool-permissions",
        "locked image preparation failed": "image-preparation",
        "pulled image does not match the locked Linux amd64 digest": "image-identity",
        "subprocess failed": "command-failed",
        "subprocess timed out": "command-timeout",
        "OpenBao did not become reachable before the preflight deadline": "tls-readiness",
        "staged operation returned unexpected status": "http-status",
        "2.7.1 fixture assertion failed": "assertion",
        "2.7.1 server exited before network verification": "server-exited",
    }
    return messages.get(str(error), "unclassified")


def capture():
    require(os.geteuid() == 0)
    inputs = input_hashes()
    print("2.7.1 fixture: verifying signed image", flush=True)
    verify_signature()
    print("2.7.1 fixture: verifying protected tools", flush=True)
    podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-271-private-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    run_id = secrets.token_hex(16)
    container, network = "openbao-271-" + run_id, "openbao-271-net-" + run_id
    resources = []
    token = ""
    try:
        print("2.7.1 fixture: preparing TLS certificates", flush=True)
        certs, ca = harness.generate_tls(root, openssl, environment)
        print("2.7.1 fixture: preparing server configuration", flush=True)
        config, marker = prepare_config(root)
        print("2.7.1 fixture: preparing pinned image", flush=True)
        image = harness.inspect_image(podman, RELEASE, environment)
        print("2.7.1 fixture: creating isolated network", flush=True)
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, run_id), timeout=60, environment=environment)
        print("2.7.1 fixture: starting constrained server", flush=True)
        resources.append(("container", container))
        harness.run_bounded(tls.container_command(podman, image, container, network, run_id, config, certs),
                            timeout=120, environment=environment)
        print("2.7.1 fixture: checking resource limits", flush=True)
        limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", container],
                                     maximum=64 * 1024, timeout=30, environment=environment)
        base.validate_container_resource_config(base.parse_json(limits, 64 * 1024))
        print("2.7.1 fixture: checking server state", flush=True)
        state = base.parse_json(harness.run_bounded(
            [podman, "inspect", "--format", "{{json .State}}", container],
            maximum=16 * 1024, timeout=10, environment=environment), 16 * 1024)
        if state.get("Running") is not True:
            raise harness.HarnessError("2.7.1 server exited before network verification")
        print("2.7.1 fixture: checking network isolation", flush=True)
        tls.verify_network(podman, network, container, environment)
        print("2.7.1 fixture: checking loopback publication", flush=True)
        port = harness.parse_port(harness.run_bounded([podman, "port", container, "8200/tcp"],
                                  maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        print("2.7.1 fixture: exact-version TLS health and rejection checks", flush=True)
        harness.wait_for_exact_version(address, ca, VERSION)
        tls.probe_tls(port, ca)
        token = harness.initialize_and_unseal(address, ca)
        patch_probes(address, ca, token, marker)
        print("2.7.1 fixture: capturing built-in runtime OpenAPI", flush=True)
        api = capture_api(address, ca, token)
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
    report = {"schema": "openbao-patch-capture/v1", "version": VERSION,
              "image_linux_amd64_digest": AMD64, "image_index_digest": INDEX,
              "inputs": inputs, "openapi_sha256": base.sha256(api_data),
              "scope": "server-fixture-only-not-sdk-integration", "routable": False,
              "checks": CHECKS}
    output = write_capture_output(api_data, report)
    print(f"2.7.1 API and patch fixture passed; result directory: {output}")


def source_review(repository_text):
    repository = base.validate_source_repository(repository_text)
    commit = base.git_output(repository, ["rev-parse", "--verify", "refs/tags/v2.7.1^{commit}"], 128).strip()
    require(commit == SOURCE.encode())
    docs = documentation.extract(repository, RELEASE)
    documentation.validate(docs, RELEASE)
    data = base.canonical_json(docs)
    validate_documentation(data)
    base.write_immutable(DOCUMENTATION_PATH, data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--capture", action="store_true")
    action.add_argument("--source-repository")
    action.add_argument("--verify-source", action="store_true")
    args = parser.parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        if args.capture:
            capture()
        elif args.verify_source:
            verify_source()
        else:
            source_review(args.source_repository)
        return 0
    except (harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"2.7.1 evidence failed ({failure_category(error)}); no compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
