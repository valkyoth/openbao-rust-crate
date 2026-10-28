#!/usr/bin/python3 -EsSB
"""Build/run candidate public Kerberos SDK checks with real MIT KDC tickets."""

import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time

import check_openbao_2_7_candidate_sdk as builder
import openbao_2_7_consistency_sdk as execution
import openbao_kerberos_plugins as fixture

require = fixture.ldap.require
TEST = "kerberos_plugin_live::public_kerberos_tls"
FEATURES = "sys,kerberos-auth,rustls-tls"
STAGES = ("profile", "config", "ldap-config", "mappings", "mapped-login", "unmapped-login",
          "rejections", "mapping-removal", "complete")
OPERATIONS = (
    "openbao.delete.auth.kerberos.groups.name.531b18e6c0502640",
    "openbao.get.auth.kerberos.config.a8df007535cf11c8",
    "openbao.get.auth.kerberos.config.ldap.70521a241b0f202f",
    "openbao.get.auth.kerberos.groups.name.954ae92b9ea6a64f",
    "openbao.list.auth.kerberos.groups.fad52108a9209f19",
    "openbao.post.auth.kerberos.config.e23ef3bccd4f8768",
    "openbao.post.auth.kerberos.config.ldap.09ea51fb665e0383",
    "openbao.post.auth.kerberos.groups.name.9a59741aa62e99af",
    "openbao.post.auth.kerberos.login.a1f715e91255582a",
)


def candidate_source(source):
    old = "        ExternalPluginKind::KerberosAuth | ExternalPluginKind::RadiusAuth => &[],"
    new = "        ExternalPluginKind::KerberosAuth => &[\n" + "".join(
        "            " + json.dumps(operation) + ",\n" for operation in OPERATIONS)
    new += "        ],"
    if source.count(old) == 0:
        require(source.count(new) == 1)
        return source
    require(source.count(old) == 1 and source.count(new) == 0)
    return source.replace(old, new + "\n        ExternalPluginKind::RadiusAuth => &[],")


def input_hashes():
    inputs = builder.backup_inputs(builder.source_inputs())
    for path in ("scripts/openbao_kerberos_sdk.py", "scripts/check_openbao_2_7_candidate_sdk.py",
                 "scripts/openbao_2_7_consistency_sdk.py"):
        inputs[path] = fixture.base.read_regular_file(fixture.ldap.ROOT / path, 2 * 1024 * 1024)
    return {**fixture.input_hashes(), **{path: fixture.base.sha256(value) for path, value in inputs.items()}}


def build(*, normal=False):
    require(type(normal) is bool)
    require(os.geteuid() != 0)
    before = input_hashes()
    values = builder.backup_inputs(builder.source_inputs())
    path = "src/plugin/compatibility.rs"
    if not normal:
        values[path] = candidate_source(values[path].decode()).encode()
    with tempfile.TemporaryDirectory(prefix="openbao-kerberos-sdk-build-") as temporary:
        root = Path(temporary)
        for path, data in values.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        env = builder.build_environment(root)
        if normal:
            env["CARGO_TARGET_DIR"] = str(fixture.ldap.ROOT / "target")
        messages = builder.run(["cargo", "test", "--locked", "--offline", "--no-default-features",
            "--features", FEATURES, "--lib", "--no-run", "--message-format=json-render-diagnostics"],
            root, env, capture=True)
        rows = [json.loads(line) for line in messages.splitlines() if line.strip()]
        binaries = [row["executable"] for row in rows if row.get("reason") == "compiler-artifact"
            and row.get("executable") and row.get("target", {}).get("name") == "openbao"
            and row.get("profile", {}).get("test") is True]
        require(len(binaries) == 1)
    require(before == input_hashes())
    print("Kerberos " + ("normal" if normal else "candidate") + " SDK binary: " + binaries[0])


class Progress:
    def __init__(self):
        self.total = self.count = 0
        self.buffer = bytearray()

    def feed(self, chunk):
        self.total += len(chunk)
        require(self.total <= 65536)
        self.buffer.extend(chunk)
        while b"\n" in self.buffer:
            line, _, rest = self.buffer.partition(b"\n")
            self.buffer = bytearray(rest)
            if line.startswith(b"kerberos-sdk-stage:"):
                require(self.count < len(STAGES) and
                        line == ("kerberos-sdk-stage:" + STAGES[self.count]).encode())
                fixture.progress("SDK " + STAGES[self.count])
                self.count += 1
        require(len(self.buffer) <= 1024)


def exchange(process, payload, progress):
    deadline, offset = time.monotonic() + 120, 0
    try:
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdin, selectors.EVENT_WRITE)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0)
                events = selector.select(remaining)
                require(bool(events))
                for key, _ in events:
                    if key.fileobj is process.stdin:
                        offset += os.write(process.stdin.fileno(), payload[offset:offset + 4096])
                        if offset == len(payload):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        data = os.read(process.stdout.fileno(), 4096)
                        if data:
                            progress.feed(data)
                        else:
                            selector.unregister(process.stdout)
        require(process.wait(timeout=max(0.001, deadline - time.monotonic())) == 0
                and progress.count == len(STAGES))
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdin.close()
        process.stdout.close()


def run_test(binary, uid, gid, version, address, ca, token, passwords, ticket, keytab):
    tool = str(fixture.ldap.tls.evidence_tools.protected_path(Path("/usr/bin/setpriv")))
    command = [tool, f"--reuid={uid}", f"--regid={gid}", "--clear-groups", "--no-new-privs",
        "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
        str(binary), "--ignored", "--exact", TEST, "--test-threads=1"]
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    require(execution.test_listing(command, environment, binary) == f"{TEST}: test\n\n1 test, 0 benchmarks\n".encode())
    for policy in ("fixture-kerberos-base", "fixture-kerberos-group"):
        fixture.ldap.api(address, ca, token, "PUT", "sys/policies/acl/" + policy,
            {"policy": 'path "auth/token/lookup-self" { capabilities = ["read"] }'}, 204)
    payload = fixture.base.canonical_json({"version": version, "address": address,
        "ca_pem": ca.read_text(encoding="ascii"), "token": token, "manager": passwords["manager"],
        "keytab": keytab, "mapped_ticket": ticket("alice", "localhost"),
        "unmapped_ticket": ticket("static", "localhost"), "wrong_service_ticket": ticket("alice", "wronghost"),
        "realm_ticket": ticket("alice", "localhost"), "removed_ticket": ticket("alice", "localhost")})
    require(len(payload) < 131072)
    process = subprocess.Popen(command + ["--nocapture", "--format=terse"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=environment, cwd=fixture.ldap.ROOT, close_fds=True,
        pass_fds=(binary.fd,), start_new_session=True)
    exchange(process, payload, Progress())


@execution.frozen_runner
def run(binary, version, acknowledge_unsigned, *, strict_candidate=True):
    require(type(strict_candidate) is bool)
    uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    digest = execution.binary_hash(binary, uid, candidate=strict_candidate)
    before = input_hashes()
    callback = lambda address, ca, token, passwords, ticket, keytab: run_test(
        binary, uid, gid, version, address, ca, token, passwords, ticket, keytab)
    report, schema = fixture.run(version, acknowledge_unsigned, sdk_exercise=callback)
    require(before == input_hashes())
    report.update(schema="openbao-kerberos-plugin-sdk/v1", checks=list(STAGES), inputs=before,
                  binary_sha256=digest, execution=execution.EXECUTION_ASSURANCE,
                  scope="public-sdk-candidate-only" if strict_candidate else "public-sdk-normal-build")
    output = Path(tempfile.mkdtemp(prefix="openbao-kerberos-sdk-result-"))
    fixture.harness.write_private(output / "report.json", fixture.base.canonical_json(report), 0o644)
    fixture.harness.write_private(output / "runtime-openapi.json", schema, 0o644)
    output.chmod(0o755)
    mode = "candidate" if strict_candidate else "normal-build"
    print("Kerberos " + mode + " SDK fixture passed; result directory: " + str(output))


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--normal", action="store_true")
    parser.add_argument("--version", choices=tuple(fixture.ldap.VERSIONS))
    parser.add_argument("--test-binary", type=Path)
    parser.add_argument("--acknowledge-unsigned-directory-image", action="store_true")
    args = parser.parse_args()
    try:
        if args.build:
            require(args.version is None and args.test_binary is None)
            build(normal=args.normal)
        else:
            require(args.version is not None and args.test_binary is not None)
            run(args.test_binary, args.version, args.acknowledge_unsigned_directory_image,
                strict_candidate=not args.normal)
    except (fixture.harness.HarnessError, fixture.base.SnapshotError, builder.registry.RegistryError,
            OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("Kerberos SDK fixture failed; no compatibility promotion", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
