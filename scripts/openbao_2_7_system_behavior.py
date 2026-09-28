#!/usr/bin/python3 -EsSB
"""Probe 2.7 sanitized config and wrapping-token revocation without promotion."""

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile
import urllib.error
import urllib.request

import openbao_2_7_external_keys as transport

fixture, harness, snapshots, staged = transport.fixture, transport.harness, transport.snapshots, transport.staged
ROOT = Path(__file__).resolve().parents[1]
INPUTS = (*transport.INPUTS, "scripts/openbao_2_7_system_behavior.py", "src/sys.rs", "src/auth/token.rs")
CONFIG_FIELDS = ("disable_standby_reads", "allow_unauthenticated_workflows", "unsafe_relative_paths")
CHECKS = ["exact-version-tls13", "tls-rejections", "resource-limits", "network-isolation",
          "sanitized-config-explicit-defaults", "wrapping-positive-unwrap-control",
          "wrapping-accessor-present", "revoke-self", "accessor-removed",
          "revoked-token-unwrap-denied", "revoked-token-reuse-denied", "cleanup"]


def input_hashes():
    return {path: snapshots.sha256(snapshots.read_regular_file(ROOT / path, 2 * 1024 * 1024)) for path in INPUTS}


def require(condition):
    if not condition:
        raise harness.HarnessError("system behavior fixture assertion failed")


def credential(value):
    require(isinstance(value, str) and 0 < len(value) <= 8192
            and all(0x21 <= ord(char) <= 0x7e for char in value))
    return value


def request(address, ca, token, method, path, payload=None, wrap=False):
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    require(body is None or len(body) <= fixture.MAX_BODY)
    headers = {"Content-Type": "application/json", "X-Vault-Token": credential(token)}
    if wrap:
        headers["X-Vault-Wrap-TTL"] = "5m"
    outgoing = urllib.request.Request(address + "/v1/" + path, data=body, method=method, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), harness.RejectRedirect(),
                                        urllib.request.HTTPSHandler(context=fixture.context(ca)))
    try:
        response = opener.open(outgoing, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    except (OSError, urllib.error.URLError) as error:
        raise harness.HarnessError("system behavior TLS request failed") from error
    with response:
        status = response.status
        data = response.read(fixture.MAX_BODY + 1)
        require(len(data) <= fixture.MAX_BODY)
        require(not data or response.headers.get_content_type() == "application/json")
    return status, snapshots.parse_json(data, fixture.MAX_BODY) if data else {}


def denied(status, response, message):
    expected = {"invalid accessor": 400, "permission denied": 403,
                "wrapping token is not valid or does not exist": 400}
    require(message in expected and type(status) is int and status == expected[message]
            and isinstance(response, dict)
            and response.get("errors") in ([message], [f"1 error occurred:\n\t* {message}\n\n"]))


def config_state(response):
    require(isinstance(response, dict) and isinstance(response.get("data"), dict))
    require(all(response["data"].get(field) is False for field in CONFIG_FIELDS))


def probe(address, ca, token):
    def call(method, path, payload=None, status=200, auth=token, wrap=False):
        actual, response = request(address, ca, auth, method, path, payload, wrap)
        fixture.require_status(actual, status)
        return response

    print("System behavior fixture: sanitized config explicit defaults", flush=True)
    config_state(call("GET", "sys/config/state/sanitized"))
    # A disposable payload, not a real credential. Keep it out of diagnostics.
    value = secrets.token_hex(16)

    def wrapped():
        response = call("POST", "sys/wrapping/wrap", {"value": value}, wrap=True)
        require(response.get("data") is None and isinstance(response.get("wrap_info"), dict))
        info = response["wrap_info"]
        return credential(info.get("token")), credential(info.get("accessor"))

    print("System behavior fixture: positive wrapping and unwrap control", flush=True)
    control, _ = wrapped()
    response = call("POST", "sys/wrapping/unwrap", auth=control)
    require(response.get("data") == {"value": value})

    print("System behavior fixture: immediate revoke-self and accessor removal", flush=True)
    wrapped_token, accessor = wrapped()
    response = call("POST", "auth/token/lookup-accessor", {"accessor": accessor})
    require(isinstance(response.get("data"), dict) and response["data"].get("accessor") == accessor)
    call("POST", "auth/token/revoke-self", status=204, auth=wrapped_token)
    denied(*request(address, ca, token, "POST", "auth/token/lookup-accessor", {"accessor": accessor}),
           "invalid accessor")
    # Wrapping validation precedes ordinary ACL checks in request_handling.go.
    # A removed wrapping token is a specific 400, not the revoke-self 403.
    print("System behavior fixture: revoked token cannot unwrap", flush=True)
    denied(*request(address, ca, wrapped_token, "POST", "sys/wrapping/unwrap"),
           "wrapping token is not valid or does not exist")
    print("System behavior fixture: revoked token cannot be reused", flush=True)
    denied(*request(address, ca, wrapped_token, "POST", "auth/token/revoke-self"), "permission denied")


def report_for(inputs):
    return {"schema": "openbao-system-behavior-tls/v1", "version": fixture.VERSION,
            "inputs": inputs, "image_linux_amd64_digest": staged.AMD64, "outcome": "passed",
            "scope": "server-fixture-only-not-sdk-integration", "tls": "TLSv1.3",
            "checks": CHECKS, "routable": False}


def validate_report(report):
    require(snapshots.canonical_json(report) == snapshots.canonical_json(report_for(input_hashes())))


def run():
    require(os.geteuid() == 0)
    inputs = input_hashes()
    print("System behavior fixture: verifying signed image", flush=True)
    staged.verify()
    staged.verify_image_signature()
    podman = str(transport.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(transport.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-270-system-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    run_id = secrets.token_hex(16)
    container, network = "openbao-270-system-" + run_id, "openbao-270-systemnet-" + run_id
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
        with tempfile.NamedTemporaryFile(prefix="openbao-270-system-result-", suffix=".json", delete=False) as output:
            output.write(snapshots.canonical_json(result))
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            print(f"System behavior fixture passed; result: {output.name}")
        return 0
    except (harness.HarnessError, snapshots.SnapshotError, OSError, ValueError, TypeError,
            KeyError, TimeoutError):
        print("System behavior fixture failed; no security-block or compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
