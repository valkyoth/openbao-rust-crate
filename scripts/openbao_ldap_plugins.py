#!/usr/bin/python3 -EsSB
"""Disposable real-directory LDAP server checks; never promote SDK contracts."""

import argparse
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

import openbao_2_7_api as initial
import openbao_2_7_1 as modern
import openbao_2_7_tls as tls
import openbao_ldap_directory_image as directory
import openbao_plugin_artifacts as artifacts

base, harness = tls.base, tls.harness
ROOT = artifacts.ROOT
VERSIONS = {"2.7.0": initial, "2.7.1": modern}
BASE_DN = "dc=fixture,dc=invalid"
PEOPLE = "ou=people," + BASE_DN
ROOT_DN = "cn=bootstrap," + BASE_DN
MANAGER = "cn=manager," + PEOPLE
AUTH_MOUNT = "fixture-ldap-auth"
SECRET_MOUNT = "fixture-ldap-secrets"
PLUGINS = ("auth-ldap", "secrets-ldap")
CHECKS = ("installed-artifact-identities", "directory-tls-and-bind-rejection",
          "auth-user-group-mappings", "auth-invalid-credentials", "auth-policy-denial",
          "static-password-rotation", "dynamic-password-and-lease-revocation",
          "root-bind-password-rotation", "secret-policy-denial")


def require(condition):
    if not condition:
        raise harness.HarnessError("LDAP plugin fixture validation failed")


def progress(message):
    print("LDAP plugin fixture: " + message, file=sys.stderr, flush=True)


def install_plugins(root):
    for tool in ("gpg", "gpgv"):
        tls.evidence_tools.protected_path(Path("/usr/bin") / tool)
    destination = root / "plugins"
    destination.mkdir(mode=0o750)
    result = {}
    for plugin in artifacts.lock()["plugins"]:
        if plugin["id"] not in PLUGINS:
            continue
        downloads = {asset["name"]: artifacts.download(
            artifacts.ASSET_BASE + plugin["tag"] + "/" + asset["name"],
            min(artifacts.MAX_ARCHIVE, asset["size"])) for asset in plugin["assets"]}
        verified = artifacts.verify_plugin(plugin, downloads)
        command = "openbao-plugin-" + plugin["id"]
        binary = verified[command + "_linux_amd64_v1"]
        harness.write_private(destination / command, binary, 0o555)
        require(base.sha256(base.read_regular_file(destination / command, artifacts.MAX_BINARY))
                == plugin["binary_sha256"])
        result[plugin["id"]] = plugin["binary_sha256"]
    require(set(result) == set(PLUGINS))
    return destination, result


def directory_config(root, password):
    require(len(password) == 48 and all(c in "0123456789abcdef" for c in password))
    config = root / "slapd.conf"
    text = (
        "include /etc/openldap/openldap/schema/core.schema\n"
        "include /etc/openldap/openldap/schema/cosine.schema\n"
        "include /etc/openldap/openldap/schema/inetorgperson.schema\n"
        "modulepath /usr/lib/openldap/openldap\nmoduleload back_mdb.so\n"
        "pidfile /data/db/slapd.pid\nargsfile /data/db/slapd.args\n"
        "threads 4\nloglevel 0\n"
        "TLSCertificateFile /fixture-tls/server.crt\n"
        "TLSCertificateKeyFile /fixture-tls/server.key\n"
        "TLSCACertificateFile /fixture-tls/ca.crt\n"
        "TLSProtocolMin 3.3\n"
        "database mdb\nmaxsize 67108864\ndirectory /data/db\n"
        f'suffix "{BASE_DN}"\nrootdn "{ROOT_DN}"\nrootpw {password}\n'
        f'access to attrs=userPassword by dn.exact="{MANAGER}" write by self write by anonymous auth by * none\n'
        f'access to * by dn.exact="{MANAGER}" write by users read by * none\n'
    )
    harness.write_private(config, text.encode("ascii"), 0o640)
    return config


def directory_command(podman, image, container, server, owner, config, certs):
    # Share only this fixture's owned server namespace; never use host networking.
    return [podman, "run", "-d", "--name", container, "--label", harness.OWNER_LABEL + "=" + owner,
            "--pull", "never", "--network", "container:" + server,
            *base.CONTAINER_RESOURCE_OPTIONS, "--read-only", "--user", "65532:0",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--no-healthcheck",
            "--log-driver", "none", "--tmpfs", "/data:rw,noexec,nosuid,nodev,size=96m,mode=0770",
            "--volume", str(config) + ":/fixture/slapd.conf:ro,Z",
            "--volume", str(certs) + ":/fixture-tls:ro,z",
            "--entrypoint", "/bin/sh", image, "-c",
            'umask 077; mkdir /data/db && exec /usr/lib/openldap/slapd "$@"', "ldap-start",
            "-f", "/fixture/slapd.conf", "-h", "ldaps://0.0.0.0:1636", "-d", "0"]


def startup_classification(output):
    lowered = output.lower()
    markers = {
        "permission": (b"permission denied", b"operation not permitted"),
        "network": (b"netavark", b"network namespace", b"network mode", b"network=container"),
        "resource-limit": (b"cgroup", b"ulimit", b"rlimit", b"memory-swap"),
        "mount": (b"mount", b"relabel", b"selinux"),
        "executable": (b"executable file", b"execve", b"no such file"),
        "runtime": (b"crun", b"runc", b"conmon"),
        "option": (b"unknown flag", b"invalid argument", b"conflicting options"),
    }
    return ",".join(name for name, values in markers.items()
                    if any(value in lowered for value in values)) or "unclassified"


def start_container(command, environment, *, timeout=120, maximum=16384):
    # Capture runtime stderr only to classify it. Never print reflected paths,
    # configuration or credentials; cap the stream while the process is running.
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, env=environment, close_fds=True,
                               start_new_session=True)
    selector = None
    output = bytearray()
    try:
        require(process.stdout is not None)
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        selector = selectors.DefaultSelector()
        selector.register(descriptor, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            for key, _ in selector.select(min(remaining, 0.25)):
                chunk = os.read(key.fd, min(65536, maximum + 1 - len(output)))
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                output.extend(chunk)
                require(len(output) <= maximum)
        code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        # Podman may emit a bounded warning on stderr before the successful ID.
        # The exit status and subsequent owned-container inspection remain mandatory.
        if code != 0 or re.search(rb"(?:^|\n)[0-9a-f]{64}\n?\Z", output) is None:
            progress("startup diagnostic=" + startup_classification(output))
            require(False)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    finally:
        if selector is not None:
            selector.close()
        if process.stdout is not None:
            process.stdout.close()


def verify_container(info, owner, image, user):
    require(isinstance(info, dict) and info.get("State", {}).get("Running") is True
            and info.get("Config", {}).get("Labels", {}).get(harness.OWNER_LABEL) == owner
            and info.get("Config", {}).get("User") == user
            and info.get("ImageName") == image)
    config = info.get("HostConfig", {})
    base.validate_container_resource_config(config)
    require(config.get("ReadonlyRootfs") is True
            and "no-new-privileges" in config.get("SecurityOpt", []))
    # Podman does not populate EffectiveCaps. An empty BoundingCaps slice may
    # render as null; verify the actual process capability sets separately.
    require("BoundingCaps" in info and info["BoundingCaps"] in (None, []))


def verify_process_status(data, user):
    require(isinstance(data, bytes) and 0 < len(data) <= 16384)
    fields = {}
    names = {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Uid"}
    for line in data.decode("ascii").splitlines():
        key, separator, value = line.partition(":")
        if separator and key in names:
            require(key not in fields)
            fields[key] = value.split()
    require(set(fields) == names)
    for key in names - {"NoNewPrivs", "Uid"}:
        require(fields[key] == ["0000000000000000"])
    require(fields["NoNewPrivs"] == ["1"] and fields["Uid"] == [user.split(":")[0]] * 4)


def verify_process(podman, name, user, environment):
    status = harness.run_bounded([podman, "exec", name, "/bin/cat", "/proc/1/status"],
                                 maximum=16384, timeout=30, environment=environment)
    verify_process_status(status, user)


def inspect(podman, name, environment):
    raw = harness.run_bounded([podman, "inspect", "--format", "{{json .}}", name],
                              maximum=128 * 1024, timeout=30, environment=environment)
    return base.parse_json(raw, 128 * 1024)


class LdapCommandFailure(harness.HarnessError):
    def __init__(self, code):
        super().__init__("LDAP client returned an unexpected status")
        known = {1: "client-error", 49: "invalid-credentials", 255: "transport-error"}
        self.diagnostic = known.get(code, "unexpected-status")


def ldap_call(root, port, ca, dn, password, ldif=None, expected=0):
    require(isinstance(password, str) and 0 < len(password.encode()) <= 512
            and not any(c in password for c in "\x00\r\n"))
    require(isinstance(dn, str) and 0 < len(dn) <= 1024 and not any(c in dn for c in "\x00\r\n"))
    # ldapadd is commonly an argv[0]-selected alias of ldapmodify. Resolving a
    # protected executable path must not silently switch an add into a modify.
    tool = "ldapmodify" if ldif is not None else "ldapwhoami"
    executable = str(tls.evidence_tools.protected_path(Path("/usr/bin") / tool))
    descriptor = harness.create_secret_fd(password)
    try:
        command = [executable, "-x", "-H", f"ldaps://127.0.0.1:{port}",
                   "-D", dn, "-y", f"/proc/self/fd/{descriptor}"]
        if ldif is not None:
            command.append("-a")
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(root),
                       "LDAPCONF": str(root / "ldap-client.conf"), "LDAPRC": "/dev/null",
                       "LDAPTLS_CACERT": str(ca), "LDAPTLS_REQCERT": "demand"}
        result = subprocess.run(command, input=ldif, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=environment, timeout=30,
                                close_fds=True, pass_fds=(descriptor,))
        if result.returncode != expected:
            raise LdapCommandFailure(result.returncode)
    finally:
        require(harness.sanitize_secret_fd(descriptor))


def seed(passwords):
    output = f"dn: {BASE_DN}\nobjectClass: domain\ndc: fixture\n\n"
    for name in ("people", "groups"):
        output += f"dn: ou={name},{BASE_DN}\nobjectClass: organizationalUnit\nou: {name}\n\n"
    for user in ("manager", "alice", "static"):
        output += (f"dn: cn={user},{PEOPLE}\nobjectClass: inetOrgPerson\ncn: {user}\n"
                   f"sn: {user}\nuserPassword: {passwords[user]}\n\n")
    output += (f"dn: cn=engineers,ou=groups,{BASE_DN}\nobjectClass: groupOfNames\n"
               f"cn: engineers\nmember: cn=alice,{PEOPLE}\n\n")
    return output.encode("ascii")


def probe_directory_tls(port, ca):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as transport:
        with tls.context(ca).wrap_socket(transport, server_hostname="127.0.0.1") as channel:
            require(channel.version() == "TLSv1.3")
    for hostname, trusted in (("invalid.example", True), ("127.0.0.1", False)):
        context = tls.context(ca) if trusted else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as transport:
                with context.wrap_socket(transport, server_hostname=hostname):
                    pass
        except ssl.SSLCertVerificationError:
            continue
        require(False)


def prepare_directory(root, port, ca, passwords):
    progress("waiting for verified bootstrap directory bind")
    deadline = time.monotonic() + 30
    while True:
        try:
            ldap_call(root, port, ca, ROOT_DN, passwords["bootstrap"])
            break
        except LdapCommandFailure:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)
    progress("checking directory invalid-password rejection")
    ldap_call(root, port, ca, ROOT_DN, secrets.token_hex(24), expected=49)
    progress("checking directory certificate rejection cases")
    probe_directory_tls(port, ca)
    progress("seeding disposable directory entries")
    ldap_call(root, port, ca, ROOT_DN, passwords["bootstrap"], ldif=seed(passwords))
    progress("checking seeded manager and user credentials")
    for user in ("manager", "alice", "static"):
        ldap_call(root, port, ca, "cn=" + user + "," + PEOPLE, passwords[user])


def api(address, ca, token, method, path, payload=None, expected=200):
    status, response = tls.request(address, ca, token, method, "/v1/" + path, payload)
    tls.require_status(status, expected)
    require(isinstance(response, dict))
    return response


def register(address, ca, token, digests):
    for identifier, kind, mount in (("auth-ldap", "auth", AUTH_MOUNT),
                                    ("secrets-ldap", "secret", SECRET_MOUNT)):
        api(address, ca, token, "POST", "sys/plugins/catalog/" + kind + "/ldap",
            {"sha256": digests[identifier], "command": "openbao-plugin-" + identifier,
             "version": "v0.1.0"}, expected=204)
        endpoint = "sys/auth/" if kind == "auth" else "sys/mounts/"
        api(address, ca, token, "POST", endpoint + mount,
            {"type": "ldap", "config": {"plugin_version": "v0.1.0"}}, expected=204)
        catalog = api(address, ca, token, "GET", endpoint.rstrip("/"))["data"][mount + "/"]
        require(catalog.get("running_sha256") == digests[identifier]
                and catalog.get("running_plugin_version") == "v0.1.0")


def server_checks(address, ca, token, root, port, passwords):
    cert = ca.read_text(encoding="ascii")
    auth = "auth/" + AUTH_MOUNT
    progress("successful authentication and exact policy mappings")
    api(address, ca, token, "POST", auth + "/config", {
        "url": "ldaps://127.0.0.1:1636", "certificate": cert,
        "binddn": MANAGER, "bindpass": passwords["manager"], "userdn": PEOPLE,
        "userattr": "cn", "groupdn": "ou=groups," + BASE_DN, "groupattr": "cn",
        "groupfilter": "(&(objectClass=groupOfNames)(member={{.UserDN}}))",
        "deny_null_bind": True, "tls_min_version": "tls13", "tls_max_version": "tls13",
        "connection_timeout": 5, "request_timeout": 5, "token_no_default_policy": True}, expected=204)
    api(address, ca, token, "POST", auth + "/groups/engineers", {"policies": "fixture-group"}, expected=204)
    api(address, ca, token, "POST", auth + "/users/alice", {"policies": "fixture-user"}, expected=204)
    logged = api(address, ca, "", "POST", auth + "/login/alice", {"password": passwords["alice"]})["auth"]
    require(set(logged["policies"]) == {"fixture-group", "fixture-user"})
    progress("invalid passwords, filter-like username and least privilege")
    for username, password in (("alice", secrets.token_hex(24)), ("alice", ""), ("*)(cn=*)", passwords["alice"])):
        api(address, ca, "", "POST", auth + "/login/" + username, {"password": password}, expected=400)
    api(address, ca, logged["client_token"], "GET", auth + "/config", expected=403)
    api(address, ca, logged["client_token"], "GET", SECRET_MOUNT + "/config", expected=403)
    progress("real static credential rotation")
    api(address, ca, token, "POST", SECRET_MOUNT + "/config", {
        "binddn": MANAGER, "bindpass": passwords["manager"], "url": "ldaps://127.0.0.1:1636",
        "certificate": cert, "schema": "openldap", "userdn": PEOPLE, "userattr": "cn",
        "connection_timeout": 5, "request_timeout": 5}, expected=204)
    api(address, ca, token, "POST", SECRET_MOUNT + "/static-role/service",
        {"username": "static", "dn": "cn=static," + PEOPLE, "rotation_period": "1h"}, expected=204)
    first = api(address, ca, token, "GET", SECRET_MOUNT + "/static-cred/service")["data"]["password"]
    ldap_call(root, port, ca, "cn=static," + PEOPLE, first)
    ldap_call(root, port, ca, "cn=static," + PEOPLE, passwords["static"], expected=49)
    api(address, ca, token, "POST", SECRET_MOUNT + "/rotate-role/service", {}, expected=204)
    second = api(address, ca, token, "GET", SECRET_MOUNT + "/static-cred/service")["data"]["password"]
    require(first != second)
    ldap_call(root, port, ca, "cn=static," + PEOPLE, second)
    ldap_call(root, port, ca, "cn=static," + PEOPLE, first, expected=49)
    progress("real generated credential and revocation")
    creation = (f"dn: cn={{{{.Username}}}},{PEOPLE}\nobjectClass: inetOrgPerson\n"
                "cn: {{.Username}}\nsn: fixture\nuserPassword: {{.Password}}\n")
    deletion = f"dn: cn={{{{.Username}}}},{PEOPLE}\nchangetype: delete\n"
    api(address, ca, token, "POST", SECRET_MOUNT + "/role/dynamic",
        {"creation_ldif": creation, "deletion_ldif": deletion, "rollback_ldif": deletion,
         "default_ttl": "5m", "max_ttl": "10m"}, expected=204)
    issued = api(address, ca, token, "GET", SECRET_MOUNT + "/creds/dynamic")
    generated = issued["data"]
    require(isinstance(generated.get("distinguished_names"), list)
            and len(generated["distinguished_names"]) == 1)
    dn = generated["distinguished_names"][0]
    ldap_call(root, port, ca, dn, generated["password"])
    api(address, ca, token, "POST", "sys/leases/revoke", {"lease_id": issued["lease_id"]}, expected=204)
    ldap_call(root, port, ca, dn, generated["password"], expected=49)
    progress("manager password rotation preserves generation")
    api(address, ca, token, "POST", SECRET_MOUNT + "/rotate-root", {}, expected=204)
    ldap_call(root, port, ca, MANAGER, passwords["manager"], expected=49)
    another = api(address, ca, token, "GET", SECRET_MOUNT + "/creds/dynamic")
    ldap_call(root, port, ca, another["data"]["distinguished_names"][0], another["data"]["password"])
    api(address, ca, token, "POST", "sys/leases/revoke", {"lease_id": another["lease_id"]}, expected=204)
    api(address, ca, token, "DELETE", SECRET_MOUNT + "/role/dynamic", expected=204)
    api(address, ca, token, "DELETE", SECRET_MOUNT + "/static-role/service", expected=204)


def input_hashes():
    names = ("scripts/openbao_ldap_plugins.py", "scripts/openbao_ldap_directory_image.py",
             "scripts/openbao_plugin_artifacts.py", "scripts/openbao_api_snapshots.py",
             "scripts/openbao_test_harness.py", "scripts/openbao_2_7_tls.py", "scripts/evidence_tools.py",
             "scripts/openbao_2_7_api.py", "scripts/openbao_2_7_1.py",
             "scripts/test_openbao_ldap_plugins.py", "compat/plugins/artifacts.lock.json",
             "compat/plugins/openbao-release-key.asc")
    return {name: base.sha256(base.read_regular_file(ROOT / name, 2 * 1024 * 1024)) for name in names}


def run(version, acknowledge_unsigned, *, sdk_exercise=None):
    require(os.geteuid() == 0 and version in VERSIONS and acknowledge_unsigned is True)
    inputs = input_hashes()
    root = Path(tempfile.mkdtemp(prefix="openbao-ldap-plugins-", dir="/tmp"))
    owner = secrets.token_hex(16)
    resources = []
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(root),
                   "XDG_CONFIG_HOME": str(root), "XDG_CACHE_HOME": str(root)}
    podman = None
    try:
        podman = str(tls.evidence_tools.protected_path(Path("/usr/bin/podman")))
        progress("verifying signed OpenBao and pinned directory image")
        release = VERSIONS[version]
        if version == "2.7.0":
            release.verify_image_signature()
        else:
            release.verify_signature()
        observation = directory.verify(environment, acknowledge_unsigned)
        progress("verifying signed plugin archives")
        plugins, digests = install_plugins(root)
        certs, ca = harness.generate_tls(root, str(tls.evidence_tools.protected_path(Path("/usr/bin/openssl"))), environment)
        # Separate the shared public server key/cert from the CA private key.
        public_tls = root / "server-tls"
        public_tls.mkdir(mode=0o750)
        for name in ("server.key", "server.crt", "ca.crt"):
            harness.write_private(public_tls / name, (certs / name).read_bytes(), 0o640)
        config = harness.write_server_config(root, version)
        with config.open("ab") as file:
            file.write(b'plugin_directory = "/openbao/plugins"\n')
        passwords = {name: secrets.token_hex(24) for name in ("bootstrap", "manager", "alice", "static")}
        ldap_config = directory_config(root, passwords["bootstrap"])
        harness.write_private(root / "ldap-client.conf", ("TLS_CACERT " + str(ca) + "\nTLS_REQCERT demand\n").encode())
        image = harness.inspect_image(podman, release.RELEASE, environment)
        ldap_image = directory.prepare(podman, environment)
        network, server, ldap = (prefix + owner for prefix in ("openbao-ldap-net-", "openbao-ldap-server-", "openbao-ldap-directory-"))
        resources.append(("network", network))
        harness.run_bounded(tls.network_command(podman, network, owner), timeout=60, environment=environment)
        command = tls.container_command(podman, image, server, network, owner, config, public_tls)
        at = command.index("--entrypoint")
        command[at:at] = ["--publish", "127.0.0.1::1636", "--volume", str(plugins) + ":/openbao/plugins:ro,Z",
                         "--log-driver", "none"]
        # Shared SELinux label is required by the two containers reading TLS files.
        command = [part.replace(":/openbao/tls:ro,Z", ":/openbao/tls:ro,z") for part in command]
        resources.append(("container", server))
        progress("starting constrained OpenBao server")
        start_container(command, environment)
        progress("checking OpenBao container identity and resource limits")
        verify_container(inspect(podman, server, environment), owner, image, "100:0")
        progress("checking OpenBao process privileges")
        verify_process(podman, server, "100:0", environment)
        progress("checking isolated network and loopback publications")
        tls.verify_network(podman, network, server, environment)
        port = harness.parse_port(harness.run_bounded([podman, "port", server, "8200/tcp"], maximum=1024, timeout=30, environment=environment))
        ldap_port = harness.parse_port(harness.run_bounded([podman, "port", server, "1636/tcp"], maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        progress("waiting for exact-version OpenBao TLS health")
        harness.wait_for_exact_version(address, ca, version)
        tls.probe_tls(port, ca)
        resources.append(("container", ldap))
        progress("starting unprivileged constrained LDAPS directory")
        start_container(directory_command(podman, ldap_image, ldap, server, owner, ldap_config, public_tls), environment)
        progress("checking directory identity, resource limits and process privileges")
        info = inspect(podman, ldap, environment)
        verify_container(info, owner, ldap_image, "65532:0")
        verify_process(podman, ldap, "65532:0", environment)
        require(info["HostConfig"]["NetworkMode"] in {"container:" + server, "container:" + inspect(podman, server, environment)["Id"]})
        prepare_directory(root, ldap_port, ca, passwords)
        progress("initializing disposable OpenBao server")
        token = harness.initialize_and_unseal(address, ca)
        progress("registering and checking actual mounted plugin identities")
        register(address, ca, token, digests)
        if sdk_exercise is None:
            server_checks(address, ca, token, root, ldap_port, passwords)
        else:
            sdk_exercise(address, ca, token, root, ldap_port, passwords)
        progress("capturing mounted plugin API schemas")
        status, schema = modern.request(address, ca, token, "POST", "/v1/sys/internal/specs/openapi",
                                        {"generic_mount_paths": True}, openapi=True)
        tls.require_status(status, 200)
        require(str(schema.get("openapi", "")).startswith("3.") and isinstance(schema.get("paths"), dict))
        schema_bytes = base.canonical_json(schema)
    finally:
        failed = False
        for kind, name in reversed(resources):
            try:
                harness.remove_owned_resource(podman, kind, name, owner, environment)
            except (harness.HarnessError, OSError):
                failed = True
        if not harness.cleanup_private_files(root):
            failed = True
        for path in (root / "server-tls/server.key", root / "slapd.conf"):
            if path.exists() and not harness.sanitize_file(path):
                failed = True
        shutil.rmtree(root)
        require(not failed)
    require(inputs == input_hashes())
    return {"schema": "openbao-ldap-plugin-server/v1", "server_version": version,
            "outcome": "passed", "scope": ("server-fixture-only-not-public-sdk-integration"
                if sdk_exercise is None else "public-sdk-candidate-only"),
            "routable": False, "plugins": digests, "directory": observation,
            "checks": list(CHECKS) if sdk_exercise is None else [], "inputs": inputs, "cleanup": "passed",
            "runtime_openapi_sha256": base.sha256(schema_bytes)}, schema_bytes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", choices=tuple(VERSIONS), required=True)
    parser.add_argument("--acknowledge-unsigned-directory-image", action="store_true")
    args = parser.parse_args()
    try:
        result, schema = run(args.version, args.acknowledge_unsigned_directory_image)
        output = Path(tempfile.mkdtemp(prefix="openbao-ldap-plugin-result-"))
        harness.write_private(output / "report.json", base.canonical_json(result), 0o644)
        harness.write_private(output / "runtime-openapi.json", schema, 0o644)
        output.chmod(0o755)
        print("LDAP plugin server fixture passed; result directory: " + str(output))
        return 0
    except (harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError) as error:
        if isinstance(error, LdapCommandFailure):
            progress("LDAP-client diagnostic=" + error.diagnostic)
        print("LDAP plugin fixture failed; no SDK compatibility promotion", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
