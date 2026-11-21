#!/usr/bin/python3 -EsSB
"""Check the four pinned external plugins using a disposable strict SDK build."""

import argparse
import os
from pathlib import Path
import signal
import subprocess
import tempfile

import openbao_maintenance_sdk as sdk
import openbao_kerberos_sdk as kerberos
import openbao_ldap_sdk as ldap
import openbao_radius_sdk as radius
import verify_openbao_kerberos_plugins as kerberos_server
import verify_openbao_ldap_plugins as ldap_server
import verify_openbao_radius_plugins as radius_server

VERSION = "2.7.3"
FEATURES = "sys,kerberos-auth,ldap-auth,ldap,radius-auth,radius-auth-acknowledged,rustls-tls"
MODULES = (kerberos, radius, ldap)
VERIFIERS = (kerberos_server, radius_server, ldap_server)
SOURCE = "src/plugin/compatibility.rs"
require = ldap.fixture.require


def candidate_inputs(inputs):
    source = inputs[SOURCE]
    for indent in (b"            ", b"        "):
        old = b"\n" + indent + b"OpenBaoVersion::new(2, 7, 2),\n" + indent[:-4] + b"]\n" + indent[:-4] + b".contains(&server)"
        new = old.replace(b"2),\n", b"2),\n" + indent + b"OpenBaoVersion::new(2, 7, 3),\n")
        require(source.count(old) == 1 and new not in source)
        source = source.replace(old, new)
    return {**inputs, SOURCE: source}


def input_hashes():
    hashes = sdk.input_hashes()
    for module in MODULES:
        hashes.update(module.input_hashes())
    paths = [Path(__file__), *(Path(v.__file__) for v in VERIFIERS)]
    for verifier in VERIFIERS:
        verifier.verify(VERSION)
        paths.extend(verifier.ROOT / VERSION / name for name in ("report.json", "runtime-openapi.json"))
    for path in paths:
        hashes[str(path.relative_to(ldap.fixture.ROOT))] = sdk.base.sha256(sdk.base.read_regular_file(path, 2 * 1024 * 1024))
    return hashes


@sdk.execution.frozen_runner
def run(binary, *, strict_candidate, directory_ack, radius_ack):
    require(strict_candidate is True and directory_ack is True and radius_ack is True)
    uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    digest = sdk.execution.binary_hash(binary, uid, candidate=True)
    before = input_hashes()
    def exercise(address, ca, token, root, port, passwords, podman, server, owner, environment):
        args = (address, ca, token, root, port, passwords, podman, server, owner, environment)
        kerberos.fixture.exercise(*args, sdk_exercise=lambda *values: kerberos.run_test(binary, uid, gid, VERSION, *values))
        radius.fixture.exercise(*args, acknowledgement=radius_ack,
                                sdk_exercise=lambda *values: radius.run_test(binary, uid, gid, VERSION, *values))
        # Run LDAP last: its root-rotation test changes the directory manager credential.
        ldap.run_test(binary, uid, gid, VERSION, address, ca, token, root, port, passwords)

    report, schema = ldap.fixture.run(VERSION, directory_ack, extra_plugins=("auth-kerberos", "auth-radius"),
                                      extra_exercise=exercise)
    require(before == input_hashes() and digest == sdk.execution.binary_hash(binary, uid, candidate=True))
    source = candidate_inputs({SOURCE: sdk.base.read_regular_file(ldap.fixture.ROOT / SOURCE, 65536)})[SOURCE]
    report.update(schema="openbao-maintenance-plugin-sdk/v1", inputs=before, features=FEATURES,
                  candidate_plugin_source_sha256=sdk.base.sha256(source),
                  candidate_generated_rust_sha256=sdk.base.sha256(sdk.registry.rust_output(sdk.candidate(), verification_candidate=True)),
                  checks={m.TEST: list(m.STAGES) for m in MODULES}, binary_sha256=digest,
                  execution=sdk.execution.EXECUTION_ASSURANCE, scope="public-sdk-candidate-only",
                  kdc=kerberos_server.verify(VERSION)["kdc"], radius=radius_server.verify(VERSION)["radius"])
    output = Path(tempfile.mkdtemp(prefix="openbao-273-plugin-sdk-"))
    ldap.fixture.harness.write_private(output / "report.json", sdk.base.canonical_json(report), 0o644)
    ldap.fixture.harness.write_private(output / "runtime-openapi.json", schema, 0o644)
    output.chmod(0o755)
    print("2.7.3 candidate plugin SDK passed; result directory: " + str(output))


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--build", action="store_true")
    action.add_argument("--test-binary", type=Path)
    parser.add_argument("--acknowledge-unsigned-directory-image", action="store_true")
    parser.add_argument("--acknowledge-unsigned-radius-image", action="store_true")
    args = parser.parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, sdk.harness.interrupted)
    try:
        if args.build:
            sdk.build(prepare_inputs=candidate_inputs, features=FEATURES,
                      tests=[m.TEST for m in MODULES], hashes=input_hashes)
        else:
            run(args.test_binary, strict_candidate=True, directory_ack=args.acknowledge_unsigned_directory_image,
                radius_ack=args.acknowledge_unsigned_radius_image)
    except (sdk.harness.HarnessError, sdk.base.SnapshotError, sdk.registry.RegistryError,
            subprocess.SubprocessError, OSError, KeyError, ValueError):
        print("2.7.3 candidate plugin SDK failed; no compatibility promotion")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
