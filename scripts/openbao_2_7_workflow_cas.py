#!/usr/bin/python3 -EsSB
"""Probe exact 2.7 workflow CAS over TLS; never lift SDK security blocks."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile
import threading

import openbao_2_7_external_keys as transport

fixture, harness, snapshots, staged = transport.fixture, transport.harness, transport.snapshots, transport.staged
ROOT = Path(__file__).resolve().parents[1]
INPUTS = (*transport.INPUTS, "scripts/openbao_2_7_workflow_cas.py", "src/sys.rs")
WORKFLOW = 'flow "check" { request "status" { operation = "read" path = "sys/seal-status" } }'
BASE = "/v1/sys/workflows/manage/fixture-cas"
CHECKS = ["exact-version-tls13", "tls-rejections", "resource-limits", "network-isolation",
          "create-only", "absent-zero-positive-rejected", "required-cas-enforced",
          "zero-stale-future-rejected", "rejected-write-preserves-state", "matching-update",
          "required-cas-cannot-be-bypassed", "optional-cas-enforced", "concurrent-single-winner",
          "delete-recreate", "cleanup"]


def input_hashes():
    return {path: snapshots.sha256(snapshots.read_regular_file(ROOT / path, 2 * 1024 * 1024)) for path in INPUTS}


def require(condition):
    if not condition:
        raise harness.HarnessError("workflow CAS fixture assertion failed")


def payload(description, cas=None, required=True):
    result = {"workflow": WORKFLOW, "description": description, "cas_required": required,
              "allow_unauthenticated": False}
    if cas is not None:
        result["cas"] = cas
    return result


def require_error(status, response, message):
    require(status == 400 and isinstance(response, dict) and response.get("errors") == [message])


def state(response, version, description, required):
    require(isinstance(response, dict))
    data = response.get("data")
    require(isinstance(data, dict) and type(data.get("version")) is int
            and data["version"] == version and data.get("description") == description
            and data.get("workflow") == WORKFLOW and data.get("cas_required") is required
            and data.get("allow_unauthenticated") is False)


def probe(address, ca, token):
    def request(method, path=BASE, body=None):
        return transport.request(address, ca, token, method, path, body)

    def success(method, body=None, version=1, description="initial", required=True):
        status, response = request(method, body=body)
        fixture.require_status(status, 200)
        state(response, version, description, required)

    def rejected(body, error, version=1, description="initial", required=True):
        require_error(*request("POST", body=body), error)
        success("GET", version=version, description=description, required=required)

    print("Workflow CAS fixture: absent entries and create-only writes", flush=True)
    for cas in (0, 1):
        path = BASE + "-absent-" + str(cas)
        require_error(*request("POST", path, payload("absent", cas)),
                      "check-and-set parameter set greater than 1 on non-existent entry")
        fixture.require_status(request("GET", path)[0], 404)
    success("POST", payload("initial", -1))
    rejected(payload("duplicate", -1), "check-and-set parameter set to -1 on existing entry")
    print("Workflow CAS fixture: required, zero, stale and future versions", flush=True)
    rejected(payload("omitted"), "check-and-set parameter required for this call")
    for cas in (0, 2):
        rejected(payload("mismatch", cas), "check-and-set parameter did not match the current version")
    rejected(payload("disable-required", required=False), "check-and-set parameter required for this call")
    success("POST", payload("updated", 1), 2, "updated")
    rejected(payload("stale", 1), "check-and-set parameter did not match the current version", 2, "updated")
    print("Workflow CAS fixture: concurrent matching updates", flush=True)
    barrier = threading.Barrier(2, timeout=10)

    def writer(label):
        barrier.wait()
        status, response = request("POST", body=payload(label, 2))
        return label, status, response

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(writer, label) for label in ("writer-a", "writer-b")]
        results = [future.result(timeout=15) for future in futures]
    require(sorted(status for _, status, _ in results) == [200, 400])
    winner = None
    for label, status, response in results:
        if status == 200:
            state(response, 3, label, True)
            winner = label
        else:
            require_error(status, response, "check-and-set parameter did not match the current version")
    success("GET", version=3, description=winner)
    print("Workflow CAS fixture: explicit optional CAS and delete/recreate", flush=True)
    success("POST", payload("optional", 3, False), 4, "optional", False)
    for cas in (0, 3, 5):
        rejected(payload("mismatch", cas, False), "check-and-set parameter did not match the current version",
                 4, "optional", False)
    success("POST", payload("unconditional", required=False), 5, "unconditional", False)
    fixture.require_status(request("DELETE")[0], 204)
    fixture.require_status(request("GET")[0], 404)
    success("POST", payload("recreated", -1), 1, "recreated")
    fixture.require_status(request("DELETE")[0], 204)


def run():
    require(os.geteuid() == 0)
    inputs = input_hashes()
    print("Workflow CAS fixture: verifying signed image", flush=True)
    staged.verify()
    staged.verify_image_signature()
    podman = str(transport.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(transport.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-270-cas-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    run_id = secrets.token_hex(16)
    container, network = "openbao-270-cas-" + run_id, "openbao-270-casnet-" + run_id
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
    return {"schema": "openbao-workflow-cas-tls/v1", "version": fixture.VERSION,
            "inputs": inputs, "image_linux_amd64_digest": staged.AMD64, "outcome": "passed",
            "scope": "server-fixture-only-not-sdk-integration", "tls": "TLSv1.3",
            "checks": CHECKS, "prefix_listing_verified": False, "sdk_cas_enabled": False, "routable": False}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        result = run()
        with tempfile.NamedTemporaryFile(prefix="openbao-270-cas-result-", suffix=".json", delete=False) as output:
            output.write(snapshots.canonical_json(result))
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            print(f"Workflow CAS fixture passed; result: {output.name}")
        return 0
    except (harness.HarnessError, snapshots.SnapshotError, OSError, ValueError, TypeError,
            KeyError, TimeoutError, threading.BrokenBarrierError):
        print("Workflow CAS fixture failed; no security-block or compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
