#!/usr/bin/python3 -EsSB
"""Run established single-node server probes on pinned 2.7.1, not SDK promotion."""

import argparse
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile

import openbao_2_7_1 as patch
import openbao_2_7_external_keys as external
import openbao_2_7_transit as transit
import openbao_2_7_pki as pki
import openbao_2_7_workflow_cas as workflow
import openbao_2_7_control_groups as control
import openbao_2_7_system_behavior as system
import openbao_2_7_mfa_totp as mfa
import verify_openbao_2_7_1 as evidence

base, harness, tls = patch.base, patch.harness, patch.tls
SUITES = ("api", "external-keys", "transit", "pki", "workflow-cas", "control-groups", "system", "mfa-totp")
MODULES = (external, transit, pki, workflow, control, system, mfa)


def input_hashes():
    paths = {*patch.INPUTS, "scripts/openbao_2_7_1_regressions.py", "scripts/verify_openbao_2_7_1.py",
             "compat/onboarding/2.7.1/initial-patch-tls.json", "compat/onboarding/2.7.1/initial-openapi.json"}
    for module in MODULES:
        paths.update(module.INPUTS)
    return {path: base.sha256(base.read_regular_file(patch.ROOT / path, 2 * 1024 * 1024)) for path in sorted(paths)}


def excluded_plugins(address, ca, token):
    for kind, name in (("auth", "ldap"), ("auth", "kerberos"), ("auth", "radius"), ("secret", "ldap")):
        patch.call(address, ca, token, "GET", f"/v1/sys/plugins/catalog/{kind}/{name}", status=404)
        prefix = "auth" if kind == "auth" else "mounts"
        mount = "excluded-" + name
        response = patch.call(address, ca, token, "POST", f"/v1/sys/{prefix}/{mount}", {"type": name}, status=400)
        errors = response.get("errors")
        patch.require(isinstance(errors, list) and bool(errors) and all(isinstance(e, str) for e in errors)
                      and any("plugin not found in the catalog" in e for e in errors))
        mounts = patch.call(address, ca, token, "GET", f"/v1/sys/{prefix}").get("data")
        patch.require(isinstance(mounts, dict) and mount + "/" not in mounts)


def probe(suite, address, ca, token, crypto):
    if suite == "api":
        excluded_plugins(address, ca, token)
        api = patch.capture_api(address, ca, token)
        paths = api["document"]["paths"]
        patch.require("/sys/raw" in paths and "/sys/raw/{path}" in paths)
        return {"openapi": api, "checks": ["full-builtin-openapi", "raw-storage-enabled", "external-plugins-absent"]}
    if suite == "control-groups":
        replay_rejected = control.probe(address, ca, token)
        patch.require(type(replay_rejected) is bool)
        return {"checks": control.CHECKS, "server_replay_rejected": replay_rejected,
                "outcome": "passed" if replay_rejected else "completed-with-known-upstream-replay-failure"}
    if suite == "pki":
        pki.probe(address, ca, token, crypto)
        return {"checks": pki.CHECKS}
    module = {"external-keys": external, "transit": transit, "workflow-cas": workflow,
              "system": system, "mfa-totp": mfa}[suite]
    module.probe(address, ca, token)
    return {"checks": module.CHECKS}


def run(suite):
    patch.require(os.geteuid() == 0 and suite in SUITES)
    inputs = input_hashes()
    evidence.verify()
    print(f"2.7.1 {suite}: verifying signed image", flush=True)
    patch.verify_signature()
    podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-271-regression-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    owner = secrets.token_hex(16)
    container, network = "openbao-271-" + owner, "openbao-271-net-" + owner
    resources = []
    crypto = pki.crypto.Crypto(root, openssl, environment)
    token = ""
    try:
        certs, ca = harness.generate_tls(root, openssl, environment)
        config = harness.write_server_config(root, patch.VERSION)
        if suite == "api":
            # Dev-mode historical captures exposed raw routes. Match that
            # documented scope explicitly, only in this disposable instance.
            config.write_bytes(base.read_regular_file(config, 65536) + b'raw_storage_endpoint = true\n')
        image = harness.inspect_image(podman, patch.RELEASE, environment)
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, owner), timeout=60, environment=environment)
        resources.append(("container", container))
        print(f"2.7.1 {suite}: starting constrained TLS server", flush=True)
        harness.run_bounded(tls.container_command(podman, image, container, network, owner, config, certs),
                            timeout=120, environment=environment)
        limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", container],
                                     maximum=65536, timeout=30, environment=environment)
        base.validate_container_resource_config(base.parse_json(limits, 65536))
        tls.verify_network(podman, network, container, environment)
        port = harness.parse_port(harness.run_bounded([podman, "port", container, "8200/tcp"],
                                  maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        harness.wait_for_exact_version(address, ca, patch.VERSION)
        tls.probe_tls(port, ca)
        token = harness.initialize_and_unseal(address, ca)
        result = probe(suite, address, ca, token, crypto)
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
    api = result.pop("openapi", None)
    report = {"schema": "openbao-patch-regression/v1", "version": patch.VERSION, "suite": suite,
              "inputs": inputs, "image_linux_amd64_digest": patch.AMD64, "image_index_digest": patch.INDEX,
              "tls": "TLSv1.3", "scope": "server-fixture-only-not-sdk-integration", "routable": False,
              "outcome": "passed", **result,
              "harness_checks": ["exact-version", "tls-rejections", "resource-limits", "network-isolation", "cleanup"]}
    if api is not None:
        api_data = base.canonical_json(api)
        report["openapi_sha256"] = base.sha256(api_data)
        output = patch.write_capture_output(api_data, report)
        print(f"2.7.1 {suite} completed; result directory: {output}", flush=True)
    else:
        with tempfile.NamedTemporaryFile(prefix="openbao-271-" + suite + "-", suffix=".json", delete=False) as output:
            output.write(base.canonical_json(report))
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o644)
            print(f"2.7.1 {suite} completed; result: {output.name}", flush=True)
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
        print(f"2.7.1 regressions failed ({patch.failure_category(error)}); no compatibility promotion")
        return 1
    print("Selected 2.7.1 server regressions completed; SDK and multi-node gates remain separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
