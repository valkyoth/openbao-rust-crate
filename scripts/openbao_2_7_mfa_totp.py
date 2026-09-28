#!/usr/bin/python3 -EsSB
"""Probe MFA TOTP enrollment lifecycle, not storage erasure or SDK promotion."""

import argparse
import base64
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile
import urllib.parse
import uuid

import openbao_2_7_system_behavior as system

transport = system.transport
fixture, harness, snapshots, staged = system.fixture, system.harness, system.snapshots, system.staged
ROOT = Path(__file__).resolve().parents[1]
INPUTS = (*system.INPUTS, "scripts/openbao_2_7_mfa_totp.py", "src/secrets/identity.rs")
METHOD_NAME = "fixture-totp"
ISSUER = "fixture-openbao"
DENY_POLICY = "fixture-totp-deny"
BASE = "identity/mfa/method/totp"
CHECKS = ["exact-version-tls13", "tls-rejections", "resource-limits", "network-isolation",
          "totp-url-and-png-response", "duplicate-generation-no-secret",
          "unprivileged-generation-and-removal-denied", "entity-association-removal",
          "regeneration-new-secret", "other-entity-unaffected", "cleanup"]


def require(condition):
    if not condition:
        raise harness.HarnessError("MFA TOTP fixture assertion failed")


def input_hashes():
    return {path: snapshots.sha256(snapshots.read_regular_file(ROOT / path, 2 * 1024 * 1024)) for path in INPUTS}


def identifier(value):
    require(isinstance(value, str) and len(value) == 36)
    try:
        require(str(uuid.UUID(value)) == value)
    except ValueError:
        raise harness.HarnessError("MFA identifier invalid") from None
    return value


def enrollment(response, entity):
    require(isinstance(response, dict) and isinstance(response.get("data"), dict))
    data = response["data"]
    url, barcode = data.get("url"), data.get("barcode")
    require(isinstance(url, str) and 0 < len(url) <= 8192
            and isinstance(barcode, str) and 0 < len(barcode) <= 65536)
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "otpauth" and parsed.netloc == "totp" and not parsed.fragment
            and urllib.parse.unquote(parsed.path) == "/" + ISSUER + ":" + entity)
    fields = urllib.parse.parse_qs(parsed.query, strict_parsing=True, max_num_fields=8)
    require(set(fields) == {"issuer", "secret", "algorithm", "digits", "period"}
            and fields["issuer"] == [ISSUER] and fields["algorithm"] == ["SHA256"]
            and fields["digits"] == ["6"] and fields["period"] == ["30"]
            and len(fields["secret"]) == 1)
    secret = fields["secret"][0]
    require(len(secret) == 32 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in secret))
    image = base64.b64decode(barcode, validate=True)
    # Check a bounded PNG signature and IHDR dimensions, not QR decoding.
    require(len(image) >= 33 and image[:8] == b"\x89PNG\r\n\x1a\n"
            and image[8:16] == b"\x00\x00\x00\x0dIHDR"
            and int.from_bytes(image[16:20], "big") == 200
            and int.from_bytes(image[20:24], "big") == 200)
    return secret


def duplicate(response):
    require(isinstance(response, dict) and response.get("data") is None
            and response.get("warnings") == [f'Entity already has a secret for MFA method "{METHOD_NAME}"'])


def probe(address, ca, token):
    def call(method, path, payload=None, status=200):
        actual, response = system.request(address, ca, token, method, path, payload)
        fixture.require_status(actual, status)
        return response

    print("MFA TOTP fixture: method and disposable entities", flush=True)
    response = call("POST", BASE, {"method_name": METHOD_NAME, "issuer": ISSUER,
                    "algorithm": "SHA256", "digits": 6, "period": 30, "key_size": 20, "qr_size": 200})
    method = identifier(response["data"]["method_id"])
    entities = [identifier(call("POST", "identity/entity", {"name": name})["data"]["id"])
                for name in ("fixture-totp-first", "fixture-totp-control")]
    bodies = [{"method_id": method, "entity_id": entity} for entity in entities]
    print("MFA TOTP fixture: enrollment response and duplicate suppression", flush=True)
    first = enrollment(call("POST", BASE + "/admin-generate", bodies[0]), entities[0])
    enrollment(call("POST", BASE + "/admin-generate", bodies[1]), entities[1])
    for body in bodies:
        duplicate(call("POST", BASE + "/admin-generate", body))
    print("MFA TOTP fixture: least-privilege denial", flush=True)
    # Empty policies inherit the root parent's policies; request an explicit
    # deny-only policy and verify it before using the child for negative tests.
    call("POST", "sys/policies/acl/" + DENY_POLICY,
         {"policy": 'path "*" { capabilities = ["deny"] }'}, 204)
    response = call("POST", "auth/token/create", {"policies": [DENY_POLICY], "no_default_policy": True,
                    "ttl": "5m", "explicit_max_ttl": "5m", "renewable": False})
    restricted = system.credential(response["auth"]["client_token"])
    require(response["auth"].get("policies") == [DENY_POLICY])
    for action in ("admin-generate", "admin-destroy"):
        print("MFA TOTP fixture: checking denied " + action, flush=True)
        system.denied(*system.request(address, ca, restricted, "POST", BASE + "/" + action, bodies[0]),
                      "permission denied")
    duplicate(call("POST", BASE + "/admin-generate", bodies[0]))
    print("MFA TOTP fixture: removal and fresh enrollment; control entity unchanged", flush=True)
    call("POST", BASE + "/admin-destroy", bodies[0], 204)
    second = enrollment(call("POST", BASE + "/admin-generate", bodies[0]), entities[0])
    require(first != second)
    duplicate(call("POST", BASE + "/admin-generate", bodies[1]))
    for body in bodies:
        call("POST", BASE + "/admin-destroy", body, 204)
    for entity in entities:
        call("DELETE", "identity/entity/id/" + entity, status=204)
    call("DELETE", BASE + "/" + method, status=204)


def report_for(inputs):
    return {"schema": "openbao-mfa-totp-tls/v1", "version": fixture.VERSION,
            "inputs": inputs, "image_linux_amd64_digest": staged.AMD64, "outcome": "passed",
            "scope": "server-fixture-only-not-sdk-integration", "tls": "TLSv1.3",
            "checks": CHECKS, "storage_erasure_verified": False, "qr_decode_verified": False,
            "login_enforcement_verified": False, "routable": False}


def validate_report(report):
    require(snapshots.canonical_json(report) == snapshots.canonical_json(report_for(input_hashes())))


def run():
    require(os.geteuid() == 0)
    inputs = input_hashes()
    print("MFA TOTP fixture: verifying signed image", flush=True)
    staged.verify()
    staged.verify_image_signature()
    podman = str(transport.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(transport.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-270-mfa-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    run_id = secrets.token_hex(16)
    container, network = "openbao-270-mfa-" + run_id, "openbao-270-mfanet-" + run_id
    resources = []
    token = ""
    try:
        tls, ca = harness.generate_tls(root, openssl, environment)
        config = harness.write_server_config(root, fixture.VERSION)
        image = harness.inspect_image(podman, staged.RELEASE, environment)
        resources.append(("network", network))
        harness.run_bounded(fixture.network_command(podman, network, run_id), timeout=60, environment=environment)
        resources.append(("container", container))
        harness.run_bounded(fixture.container_command(podman, image, container, network, run_id, config, tls),
                            timeout=120, environment=environment)
        limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", container],
                                     maximum=65536, timeout=30, environment=environment)
        snapshots.validate_container_resource_config(snapshots.parse_json(limits, 65536))
        fixture.verify_network(podman, network, container, environment)
        port = harness.parse_port(harness.run_bounded([podman, "port", container, "8200/tcp"],
                                  maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        fixture.wait_for_health(podman, container, environment, address, ca)
        fixture.probe_tls(port, ca)
        token = harness.initialize_and_unseal(address, ca)
        probe(address, ca, token)
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
    return report_for(inputs)


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        result = run()
        with tempfile.NamedTemporaryFile(prefix="openbao-270-mfa-result-", suffix=".json", delete=False) as output:
            output.write(snapshots.canonical_json(result))
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            print(f"MFA TOTP fixture passed; result: {output.name}")
        return 0
    except (harness.HarnessError, snapshots.SnapshotError, OSError, ValueError, TypeError,
            KeyError, TimeoutError):
        print("MFA TOTP fixture failed; no security-block or compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
