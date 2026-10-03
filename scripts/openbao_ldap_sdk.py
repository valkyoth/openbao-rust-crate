#!/usr/bin/python3 -EsSB
"""Build and run candidate-only public LDAP SDK checks against real LDAPS."""

import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import time

import check_openbao_2_7_candidate_sdk as builder
import openbao_2_7_consistency_sdk as execution
import openbao_ldap_plugins as fixture

TEST = "ldap_plugin_live::public_ldap_tls"
STAGES = ("profile", "auth-config", "mappings", "login", "secret-config",
          "static-create", "static-read", "static-list", "static-credentials", "static-bind",
          "static-rotate", "static-rotated-bind", "dynamic-revocation", "root-rotation", "cleanup",
          "library-create", "library-status", "library-checkout", "library-checkin",
          "library-force-checkin", "library-delete", "complete")
FEATURES = "sys,ldap-auth,ldap,rustls-tls"
# Only the operations exercised by the candidate fixture are opened in its
# disposable source tree. Production's contract table remains empty.
OPERATIONS = (
    "openbao.delete.ldap.library.set.name.b93f2cc7bd993d6c",
    "openbao.get.ldap.library.set.name.ac0b1f32711a1b17",
    "openbao.get.ldap.library.set.name.status.7ad9c35d9646b86c",
    "openbao.list.ldap.library.98e0afea05f266ad",
    "openbao.post.ldap.library.manage.set.name.check.in.31d9758041b60487",
    "openbao.post.ldap.library.set.name.b42bbb4ad1f4da44",
    "openbao.post.ldap.library.set.name.check.in.060342e4eeb9c95d",
    "openbao.post.ldap.library.set.name.check.out.8336f9c1d2da5f75",
    "openbao.delete.auth.ldap.groups.name.b950122721b5ebc7",
    "openbao.delete.auth.ldap.users.username.9c70ff08aa396e53",
    "openbao.delete.ldap.config.ecee1bad1781c163",
    "openbao.delete.ldap.role.role.name.62b78b0e2b96da27",
    "openbao.delete.ldap.static.role.role.name.cb104610a05417a6",
    "openbao.get.auth.ldap.config.811840bd137c6235",
    "openbao.get.auth.ldap.groups.name.7f1eeb5b0127592d",
    "openbao.get.auth.ldap.users.username.d1685a846a236f11",
    "openbao.get.ldap.config.2bbeeb0df9593a92",
    "openbao.get.ldap.creds.role.name.5da4ac8dcf228fae",
    "openbao.get.ldap.role.role.name.55c21b25fd8400cc",
    "openbao.get.ldap.static.cred.role.name.a69cdc5eca90bb18",
    "openbao.get.ldap.static.role.7b331d6e6718beed",
    "openbao.get.ldap.static.role.role.name.973bea91096ad800",
    "openbao.list.auth.ldap.groups.9a02185a1de217e9",
    "openbao.list.auth.ldap.users.c9811a9743a6d433",
    "openbao.post.auth.ldap.config.47513ec572cc61ae",
    "openbao.post.auth.ldap.groups.name.6dfccb47849561ea",
    "openbao.post.auth.ldap.login.username.f98effef801d364e",
    "openbao.post.auth.ldap.users.username.32b8480ab9dc3473",
    "openbao.post.ldap.config.5878fff52f427697",
    "openbao.post.ldap.role.role.name.c0c49e3483cfce41",
    "openbao.post.ldap.rotate.role.role.name.f6a539a049514645",
    "openbao.post.ldap.rotate.root.9c563cec09292028",
    "openbao.post.ldap.static.role.role.name.00febb1527662b40",
)


def verify_contract_source(source):
    auth = [value for value in OPERATIONS if ".auth.ldap." in value]
    secrets = [value for value in OPERATIONS if ".auth.ldap." not in value]
    expected = "// Exact LDAP v0.1.0 operations verified against OpenBao 2.7.0 and 2.7.1.\n\n"
    expected += "\n".join("pub(super) const " + name + ": &[&str] = &[\n" +
        "".join("    " + json.dumps(value) + ",\n" for value in values) + "];\n"
        for name, values in (("AUTH", auth), ("SECRETS", secrets)))
    fixture.require(source == expected)


def input_hashes():
    values = builder.backup_inputs(builder.source_inputs())
    hashes = {path: fixture.base.sha256(value) for path, value in values.items()}
    for path in ("scripts/openbao_ldap_sdk.py", "scripts/check_openbao_2_7_candidate_sdk.py",
                 "scripts/openbao_2_7_consistency_sdk.py"):
        hashes[path] = fixture.base.sha256(fixture.base.read_regular_file(fixture.ROOT / path, 2 * 1024 * 1024))
    return {**fixture.input_hashes(), **hashes}


def build(*, normal=False):
    fixture.require(os.geteuid() != 0)
    before = input_hashes()
    values = builder.backup_inputs(builder.source_inputs())
    verify_contract_source(values["src/plugin/ldap_contracts.rs"].decode())
    with tempfile.TemporaryDirectory(prefix="openbao-ldap-sdk-build-") as temporary:
        root = Path(temporary)
        for path, data in values.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        env = builder.build_environment(root)
        if normal:
            env["CARGO_TARGET_DIR"] = str(fixture.ROOT / "target")
        messages = builder.run(["cargo", "test", "--locked", "--offline", "--no-default-features",
                               "--features", FEATURES, "--lib", "--no-run",
                               "--message-format=json-render-diagnostics"], root, env, capture=True)
        rows = [json.loads(line) for line in messages.splitlines() if line.strip()]
        binaries = [row["executable"] for row in rows if row.get("reason") == "compiler-artifact"
                    and row.get("executable") and row.get("target", {}).get("name") == "openbao"
                    and row.get("profile", {}).get("test") is True]
        fixture.require(len(binaries) == 1)
    fixture.require(before == input_hashes())
    print("LDAP " + ("normal" if normal else "candidate") + " SDK binary: " + binaries[0])


class Progress:
    def __init__(self):
        self.total = 0
        self.buffer = bytearray()
        self.count = 0

    def feed(self, chunk):
        self.total += len(chunk)
        fixture.require(self.total <= 65536)
        self.buffer.extend(chunk)
        while b"\n" in self.buffer:
            line, _, rest = self.buffer.partition(b"\n")
            self.buffer = bytearray(rest)
            if line.startswith(b"ldap-sdk-stage:"):
                fixture.require(self.count < len(STAGES)
                                and line == ("ldap-sdk-stage:" + STAGES[self.count]).encode())
                fixture.progress("SDK " + STAGES[self.count])
                self.count += 1
        fixture.require(len(self.buffer) <= 1024)


def exchange(process, payload, progress):
    deadline = time.monotonic() + 120
    offset = 0
    try:
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdin, selectors.EVENT_WRITE)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                fixture.require(remaining > 0)
                events = selector.select(remaining)
                fixture.require(bool(events))
                for key, _ in events:
                    if key.fileobj is process.stdin:
                        offset += os.write(process.stdin.fileno(), payload[offset:offset + 4096])
                        if offset == len(payload):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                    else:
                        chunk = os.read(process.stdout.fileno(), 4096)
                        if chunk:
                            progress.feed(chunk)
                        else:
                            selector.unregister(process.stdout)
        fixture.require(process.wait(timeout=max(0.001, deadline - time.monotonic())) == 0
                        and progress.count == len(STAGES))
    finally:
        # Reap the entire owned test group, including any LDAP client children.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdin.close()
        process.stdout.close()


def run_test(binary, uid, gid, version, address, ca, token, root, port, passwords):
    tool = str(fixture.tls.evidence_tools.protected_path(Path("/usr/bin/setpriv")))
    ldap = str(fixture.tls.evidence_tools.protected_path(Path("/usr/bin/ldapwhoami")))
    command = [tool, f"--reuid={uid}", f"--regid={gid}", "--clear-groups", "--no-new-privs",
               "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
               str(binary), "--ignored", "--exact", TEST, "--test-threads=1"]
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    fixture.require(execution.test_listing(command, environment, binary) == f"{TEST}: test\n\n1 test, 0 benchmarks\n".encode())
    # Only a public CA certificate is made accessible to the non-root LDAP client.
    with tempfile.TemporaryDirectory(prefix="openbao-ldap-public-ca-") as temporary:
        public = Path(temporary)
        public.chmod(0o755)
        cert = public / "ca.crt"
        fixture.harness.write_private(cert, ca.read_bytes(), 0o644)
        payload = fixture.base.canonical_json({"address": address, "version": version,
            "ca_pem": ca.read_text(encoding="ascii"), "ca_path": str(cert), "ldap_tool": ldap,
            "ldap_port": port, "token": token, "manager": passwords["manager"],
            "alice": passwords["alice"], "static_password": passwords["static"]})
        fixture.require(len(payload) < 65536)
        process = subprocess.Popen(command + ["--nocapture", "--format=terse"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd=fixture.ROOT, env=environment,
            close_fds=True, pass_fds=(binary.fd,), start_new_session=True)
        exchange(process, payload, Progress())


@execution.frozen_runner
def run(binary, version, acknowledge_unsigned, *, strict_candidate=True):
    fixture.require(type(strict_candidate) is bool)
    uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    digest = execution.binary_hash(binary, uid, candidate=strict_candidate)
    before = input_hashes()
    callback = lambda address, ca, token, root, port, passwords: run_test(
        binary, uid, gid, version, address, ca, token, root, port, passwords)
    report, schema = fixture.run(version, acknowledge_unsigned, sdk_exercise=callback)
    fixture.require(before == input_hashes())
    report.update(schema="openbao-ldap-plugin-sdk/v1", inputs=before,
                  checks=list(STAGES), binary_sha256=digest, execution=execution.EXECUTION_ASSURANCE)
    if not strict_candidate:
        report["scope"] = "public-sdk-normal-build"
    output = Path(tempfile.mkdtemp(prefix="openbao-ldap-sdk-result-"))
    fixture.harness.write_private(output / "report.json", fixture.base.canonical_json(report), 0o644)
    fixture.harness.write_private(output / "runtime-openapi.json", schema, 0o644)
    output.chmod(0o755)
    print("LDAP " + ("candidate" if strict_candidate else "normal-build") +
          " public SDK fixture passed; result directory: " + str(output))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--normal", action="store_true")
    parser.add_argument("--version", choices=tuple(fixture.VERSIONS))
    parser.add_argument("--test-binary", type=Path)
    parser.add_argument("--acknowledge-unsigned-directory-image", action="store_true")
    args = parser.parse_args()
    try:
        if args.build:
            fixture.require(args.version is None and args.test_binary is None)
            build(normal=args.normal)
        else:
            fixture.require(args.version is not None and args.test_binary is not None)
            run(args.test_binary, args.version, args.acknowledge_unsigned_directory_image,
                strict_candidate=not args.normal)
    except (fixture.harness.HarnessError, fixture.base.SnapshotError, builder.registry.RegistryError,
            OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("LDAP candidate SDK fixture failed; no compatibility promotion")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
