#!/usr/bin/python3 -EsSB
"""Run established single-node server probes on pinned 2.7.3, not SDK promotion."""

import argparse
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile

import openbao_2_7_2_regressions as previous
import openbao_maintenance_capture as maintenance

patch = maintenance.previous
base, harness, tls = patch.base, patch.harness, patch.tls
VERSION = "2.7.3"
INDEX, AMD64 = maintenance.PINS[VERSION]
RELEASE = {"version": VERSION, "image": {"index_digest": INDEX, "linux_amd64_digest": AMD64}}
MODULES = {"external-keys": previous.external, "transit": previous.transit, "pki": previous.pki,
           "workflow-cas": previous.workflow, "system": previous.system, "mfa-totp": previous.mfa}
SUITES = tuple(MODULES)


class TransitProbe(previous.transit.Probe):
    def error(self, method, path, payload, fragment, statuses=(400, 500)):
        if (method, path, fragment) != ("GET", "fixture-delegated/export/encryption-key/forbidden-export",
                                        "unknown key type"):
            return super().error(method, path, payload, fragment, statuses)
        status, response = self.request(method, path, payload)
        patch.require(isinstance(response, dict) and set(response) == {"errors"})
        previous.transit.require_error(status, response,
            'unsupported key type "external-key" for export type "encryption-key"', statuses)


def probe_transit(address, ca, token):
    transit = previous.transit
    client = TransitProbe(address, ca, token)
    client.call("POST", "sys/mounts/fixture-transit", {"type": "transit"}, 204)
    wrapping = client.data("GET", "fixture-transit/wrapping_key").get("public_key")
    patch.require(isinstance(wrapping, str) and "PUBLIC KEY" in wrapping)
    client.call("POST", "fixture-transit/keys/wrapper/import", {"type": "rsa-4096", "public_key": wrapping}, 204)
    publics = {parameter: transit.probe_mldsa(client, parameter) for parameter in transit.PARAMETERS}
    transit.probe_external(client, publics)


def input_hashes():
    paths = {*maintenance.input_hashes(), "scripts/openbao_2_7_3_regressions.py",
             "scripts/openbao_2_7_2_regressions.py", "compat/onboarding/2.7.3/openapi.json"}
    for module in MODULES.values():
        paths.update(module.INPUTS)
    return {path: base.sha256(base.read_regular_file(patch.ROOT / path, 2 * 1024 * 1024)) for path in sorted(paths)}


def run(suite):
    patch.require(os.geteuid() == 0 and suite in SUITES)
    inputs = input_hashes()
    print(f"2.7.3 {suite}: verifying signed image", flush=True)
    maintenance.verify_signature(VERSION)
    podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-273-regression-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    owner = secrets.token_hex(16)
    container, network = "openbao-273-" + owner, "openbao-273-net-" + owner
    resources = []
    crypto = previous.pki.crypto.Crypto(root, openssl, environment)
    token = ""
    try:
        certs, ca = harness.generate_tls(root, openssl, environment)
        config = harness.write_server_config(root, VERSION)
        image = harness.inspect_image(podman, RELEASE, environment)
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, owner), timeout=60, environment=environment)
        resources.append(("container", container))
        print(f"2.7.3 {suite}: starting constrained TLS server", flush=True)
        harness.run_bounded(tls.container_command(podman, image, container, network, owner, config, certs),
                            timeout=120, environment=environment)
        limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", container],
                                     maximum=65536, timeout=30, environment=environment)
        base.validate_container_resource_config(base.parse_json(limits, 65536))
        tls.verify_network(podman, network, container, environment)
        port = harness.parse_port(harness.run_bounded([podman, "port", container, "8200/tcp"],
                                  maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        harness.wait_for_exact_version(address, ca, VERSION)
        tls.probe_tls(port, ca)
        token = harness.initialize_and_unseal(address, ca)
        if suite == "pki":
            previous.probe_pki(address, ca, token, crypto)
        elif suite == "transit":
            probe_transit(address, ca, token)
        else:
            MODULES[suite].probe(address, ca, token)
    finally:
        token = ""
        failed = False
        for kind, name in reversed(resources):
            try:
                harness.remove_owned_resource(podman, kind, name, owner, environment)
            except (harness.HarnessError, OSError):
                failed = True
        try:
            crypto.cleanup()
        except (harness.HarnessError, OSError):
            failed = True
        if not harness.cleanup_private_files(root):
            failed = True
        try:
            shutil.rmtree(root)
        except OSError:
            failed = True
        patch.require(not failed)
    patch.require(inputs == input_hashes())
    report = {"schema": "openbao-patch-regression/v1", "version": VERSION, "suite": suite,
              "inputs": inputs, "image_linux_amd64_digest": AMD64, "image_index_digest": INDEX,
              "tls": "TLSv1.3", "scope": "server-fixture-only-not-sdk-integration", "routable": False,
              "outcome": "passed", "checks": MODULES[suite].CHECKS,
              "harness_checks": ["exact-version", "tls-rejections", "resource-limits", "network-isolation", "cleanup"]}
    with tempfile.NamedTemporaryFile(prefix="openbao-273-" + suite + "-", suffix=".json", delete=False) as output:
        output.write(base.canonical_json(report))
        output.flush()
        os.fsync(output.fileno())
        os.fchmod(output.fileno(), 0o644)
        print(f"2.7.3 {suite} completed; result: {output.name}", flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("all", *SUITES), default="all")
    args = parser.parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        for suite in SUITES if args.suite == "all" else (args.suite,):
            run(suite)
    except (harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"2.7.3 regressions failed ({patch.failure_category(error)}); no compatibility promotion")
        return 1
    print("Selected 2.7.3 server regressions completed; SDK and multi-node gates remain separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
