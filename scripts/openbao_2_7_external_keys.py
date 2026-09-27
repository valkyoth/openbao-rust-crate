#!/usr/bin/python3 -EsSB
"""Test staged external-key delegation over TLS without promoting SDK routing."""

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile
import urllib.error
import urllib.request

import evidence_tools
import openbao_2_7_api as staged
import openbao_2_7_tls as fixture
import openbao_api_snapshots as snapshots
import openbao_test_harness as harness

ROOT = Path(__file__).resolve().parents[1]
INPUTS = (*fixture.INPUTS, "scripts/openbao_2_7_external_keys.py")
CHECKS = ["exact-version-tls13", "tls-rejections", "resource-limits", "network-isolation",
          "least-privilege-provider-token", "config-key-crud-list-patch", "config-redaction",
          "ungranted-mount-denied", "granted-encrypt-decrypt", "grant-removal-denied",
          "remote-key-preserved", "cleanup"]


def input_hashes():
    return {path: snapshots.sha256(snapshots.read_regular_file(ROOT / path, 2 * 1024 * 1024)) for path in INPUTS}


def request(address, ca, token, method, path, payload=None):
    # PATCH must use the documented media type; no redirects or ambient proxy.
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    if body is not None and len(body) > fixture.MAX_BODY:
        raise harness.HarnessError("external-key request too large")
    headers = {"Content-Type": "application/merge-patch+json" if method == "PATCH" else "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    outgoing = urllib.request.Request(address + path, data=body, method=method, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), harness.RejectRedirect(),
                                        urllib.request.HTTPSHandler(context=fixture.context(ca)))
    try:
        response = opener.open(outgoing, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    except (OSError, urllib.error.URLError) as error:
        raise harness.HarnessError("external-key TLS request failed") from error
    with response:
        status = response.status
        data = response.read(fixture.MAX_BODY + 1)
        if len(data) > fixture.MAX_BODY:
            raise harness.HarnessError("external-key response too large")
        if data and response.headers.get_content_type() != "application/json":
            raise harness.HarnessError("external-key response is not JSON")
    return status, snapshots.parse_json(data, fixture.MAX_BODY) if data else {}


def require(condition):
    if not condition:
        raise harness.HarnessError("external-key contract assertion failed")


def require_grant_denial(status, response):
    errors = response.get("errors") if isinstance(response, dict) else None
    require(status in (400, 403, 500) and isinstance(errors, list) and errors
            and all(isinstance(error, str) for error in errors)
            and any("missing grant for key" in error for error in errors))


def require_missing(status, response, kind, name):
    # The 2.7 handler builds a coded 404, but RespondErrorCommon replaces an
    # error response with a plain error before HTTP adjustment: observed 400.
    # Require the exact missing-resource error, not just any bad request.
    require(status == 400 and isinstance(response, dict)
            and response.get("errors") == [f'{kind} "{name}" not found'])


def probe(address, ca, token):
    def call(method, path, payload=None, status=204, credential=None):
        actual, response = request(address, ca, token if credential is None else credential,
                                   method, "/v1/" + path, payload)
        fixture.require_status(actual, status)
        return response

    for mount in ("fixture-source", "fixture-allowed", "fixture-denied"):
        call("POST", "sys/mounts/" + mount, {"type": "transit"})
    call("POST", "fixture-source/keys/key", {"type": "aes256-gcm96"}, 200)
    policy = ('path "fixture-source/keys/key" { capabilities = ["read"] }\n'
              'path "fixture-source/encrypt/key" { capabilities = ["update"] }\n'
              'path "fixture-source/decrypt/key" { capabilities = ["update"] }\n'
              'path "auth/token/lookup-self" { capabilities = ["read"] }')
    call("POST", "sys/policies/acl/fixture-kms-source", {"policy": policy})
    issued = call("POST", "auth/token/create", {"policies": ["fixture-kms-source"],
                  "no_default_policy": True, "ttl": "5m", "explicit_max_ttl": "5m",
                  "renewable": False}, 200)
    auth = issued.get("auth")
    require(isinstance(auth, dict) and isinstance(auth.get("client_token"), str) and auth["client_token"])
    provider_token = auth["client_token"]
    require(set(auth.get("policies", [])) == {"fixture-kms-source"})
    call("GET", "sys/mounts", status=403, credential=provider_token)
    config = "sys/external-keys/configs/fixture-provider"
    key = config + "/keys/key"
    # The provider calls the server's container-local listener. Source is a
    # normal AES key in a different mount: no recursive external-key loop.
    call("POST", config, {"plugin": "transit", "address": "https://127.0.0.1:8200",
         "mount_path": "fixture-source", "token": provider_token,
         "tls_ca_cert_bytes": ca.read_text(encoding="ascii"), "verify": True})
    read = call("GET", config, status=200).get("data")
    require(isinstance(read, dict) and read.get("token") == "(redacted)")
    require("verify" not in read)
    require("fixture-provider" in call("LIST", "sys/external-keys/configs", status=200).get("data", {}).get("keys", []))
    call("PATCH", config, {"tls_server_name": "127.0.0.1", "verify": True})
    require(call("GET", config, status=200).get("data", {}).get("tls_server_name") == "127.0.0.1")
    call("PATCH", config, {"tls_server_name": None, "verify": True})
    require("tls_server_name" not in call("GET", config, status=200).get("data", {}))
    call("POST", key, {"name": "key", "version": 1, "verify": True})
    require("key" in call("LIST", config + "/keys", status=200).get("data", {}).get("keys", []))
    call("PATCH", key, {"disable_prehashing": True, "verify": True})
    require(call("GET", key, status=200).get("data", {}).get("disable_prehashing") is True)
    call("PATCH", key, {"disable_prehashing": None, "verify": True})
    require("disable_prehashing" not in call("GET", key, status=200).get("data", {}))
    mapping = {"type": "external-key", "external_key_ref": "fixture-provider:key"}
    print("External-key fixture: checking denied mount", flush=True)
    require_grant_denial(*request(address, ca, token, "POST", "/v1/fixture-denied/keys/delegated", mapping))
    call("POST", key + "/grants/fixture-allowed")
    require(call("LIST", key + "/grants", status=200).get("data", {}).get("keys") == ["fixture-allowed/"])
    call("POST", "fixture-allowed/keys/delegated", mapping, 200)
    plaintext = base64.b64encode(b"checkpoint-four-fixture").decode("ascii")
    encrypted = call("POST", "fixture-allowed/encrypt/delegated", {"plaintext": plaintext}, 200).get("data", {})
    ciphertext = encrypted.get("ciphertext")
    require(isinstance(ciphertext, str) and ciphertext.startswith("vault:v1:"))
    decrypted = call("POST", "fixture-allowed/decrypt/delegated", {"ciphertext": ciphertext}, 200).get("data", {})
    require(decrypted.get("plaintext") == plaintext)
    print("External-key fixture: checking revoked grant", flush=True)
    call("DELETE", key + "/grants/fixture-allowed")
    require_grant_denial(*request(address, ca, token, "POST", "/v1/fixture-allowed/encrypt/delegated", {"plaintext": plaintext}))
    call("DELETE", key)
    require_missing(*request(address, ca, token, "GET", "/v1/" + key), "key", "key")
    call("DELETE", config)
    require_missing(*request(address, ca, token, "GET", "/v1/" + config), "config", "fixture-provider")
    require(call("GET", "fixture-source/keys/key", status=200).get("data", {}).get("name") == "key")


def run():
    inputs = input_hashes()
    print("External-key fixture: verifying signed image", flush=True)
    staged.verify()
    staged.verify_image_signature()
    podman = str(evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-270-external-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root), "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    run_id = secrets.token_hex(16)
    container, network = "openbao-270-external-" + run_id, "openbao-270-extnet-" + run_id
    network_attempted = container_attempted = False
    token = ""
    try:
        tls, ca = harness.generate_tls(root, openssl, environment)
        config = harness.write_server_config(root, fixture.VERSION)
        image = harness.inspect_image(podman, staged.RELEASE, environment)
        network_attempted = True
        harness.run_bounded(fixture.network_command(podman, network, run_id), timeout=60, environment=environment)
        container_attempted = True
        harness.run_bounded(fixture.container_command(podman, image, container, network, run_id, config, tls), timeout=120, environment=environment)
        limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", container], maximum=64 * 1024, timeout=30, environment=environment)
        snapshots.validate_container_resource_config(snapshots.parse_json(limits, 64 * 1024))
        fixture.verify_network(podman, network, container, environment)
        port = harness.parse_port(harness.run_bounded([podman, "port", container, "8200/tcp"], maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        fixture.wait_for_health(podman, container, environment, address, ca)
        fixture.probe_tls(port, ca)
        token = harness.initialize_and_unseal(address, ca)
        print("External-key fixture: checking administration and delegation", flush=True)
        probe(address, ca, token)
    finally:
        token = ""
        failed = False
        for attempted, kind, name in ((container_attempted, "container", container), (network_attempted, "network", network)):
            if attempted:
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
        if failed:
            raise harness.HarnessError("external-key fixture cleanup incomplete")
    if inputs != input_hashes():
        raise harness.HarnessError("external-key fixture inputs changed")
    return {"schema": "openbao-external-key-tls/v1", "version": fixture.VERSION,
            "image_linux_amd64_digest": staged.AMD64, "inputs": inputs, "outcome": "passed",
            "scope": "server-fixture-only-not-sdk-integration", "tls": "TLSv1.3",
            "checks": CHECKS, "pkcs11_verified": False, "routable": False}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        result = run()
        with tempfile.NamedTemporaryFile(prefix="openbao-270-external-result-", suffix=".json", delete=False) as output:
            output.write(snapshots.canonical_json(result))
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            print(f"External-key fixture passed; result: {output.name}")
        return 0
    except (harness.HarnessError, snapshots.SnapshotError, OSError, ValueError, TypeError):
        print("External-key fixture failed; no compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
