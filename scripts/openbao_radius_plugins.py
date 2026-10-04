#!/usr/bin/python3 -EsSB
"""Isolated FreeRADIUS acceptance for the signed external OpenBao RADIUS plugin."""

import argparse
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

import openbao_ldap_plugins as ldap
import openbao_radius_image as image

base, harness = ldap.base, ldap.harness
MOUNT = "fixture-radius"
CHECKS = ("installed-artifact-identity", "backend-positive-negative-controls",
          "secret-omission", "user-mapping-crud", "mapped-login-policies", "fallback-login-policies",
          "wrong-password-rejection", "unknown-user-rejection", "least-privilege-denial",
          "mapping-removal", "wrong-shared-secret-rejection", "restored-secret-login")


def progress(stage):
    print("RADIUS plugin fixture: " + stage, file=sys.stderr, flush=True)


def configuration(root, values):
    ldap.require(set(values) == {"shared", "alice", "bob", "wrong"}
                 and all(re.fullmatch(r"[0-9a-f]{64}", value) for value in values.values())
                 and len(set(values.values())) == 4)
    directory = root / "radius-config"
    directory.mkdir(mode=0o750)
    config = '''prefix = /usr
localstatedir = /data
logdir = /data
run_dir = /data
libdir = /usr/lib/freeradius
radacctdir = /data
pidfile = /data/radius.pid
max_request_time = 5
cleanup_delay = 1
max_requests = 128
hostname_lookups = no
proxy_requests = no
log {
 destination = files
 file = /dev/null
 auth = no
 auth_badpass = no
 auth_goodpass = no
}
security {
 allow_core_dumps = no
 max_attributes = 64
 reject_delay = 0
}
client fixture {
 ipaddr = 127.0.0.1
 secret = SHARED
 require_message_authenticator = no
 limit_proxy_state = yes
}
modules {
 files {
  filename = /fixture/users
 }
 pap {
  normalise = yes
 }
}
server fixture {
 listen {
  type = auth
  ipaddr = 127.0.0.1
  port = 11812
 }
 authorize {
  files
  pap
 }
 authenticate {
  Auth-Type PAP {
   pap
  }
 }
}
'''.replace("SHARED", values["shared"])
    files = {"radiusd.conf": config, "dictionary": "$INCLUDE /usr/share/freeradius/dictionary\n",
             "users": "".join(name + ' Cleartext-Password := "' + values[name] + '"\n'
                              for name in ("alice", "bob")), "shared-secret": values["shared"] + "\n"}
    for label, user, password in (("positive", "alice", values["alice"]),
                                   ("negative", "alice", values["wrong"]),
                                   ("unknown", "missing", values["wrong"])):
        files[label] = 'User-Name = "' + user + '"\nUser-Password = "' + password + '"\n'
    for name, content in files.items():
        harness.write_private(directory / name, content.encode("ascii"), 0o640)
    return directory


def container_command(podman, name, server, owner, config):
    return [podman, "run", "-d", "--name", name, "--label", harness.OWNER_LABEL + "=" + owner,
            "--pull", "never", "--network", "container:" + server, *base.CONTAINER_RESOURCE_OPTIONS,
            "--read-only", "--user", "65532:0", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--no-healthcheck", "--log-driver", "none", "--tmpfs", "/data:rw,noexec,nosuid,nodev,size=16m,mode=0770",
            "--volume", str(config) + ":/fixture:ro,Z", "--entrypoint", "/usr/sbin/freeradius",
            image.REFERENCE, "-f", "-s", "-d", "/fixture", "-l", "/dev/null"]


def probe(podman, name, environment, label):
    ldap.require(label in {"positive", "negative", "unknown"})
    raw = harness.run_bounded([podman, "exec", "--user", "65532:0", name, "/usr/bin/radclient",
        "-t", "1", "-r", "1", "-S", "/fixture/shared-secret", "-f", "/fixture/" + label,
        "127.0.0.1:11812", "auth"], maximum=8192, timeout=5, environment=environment,
        accepted_codes=(0,) if label == "positive" else (0, 1))
    expected = b"Received Access-Accept" if label == "positive" else b"Received Access-Reject"
    opposite = b"Access-Reject" if label == "positive" else b"Access-Accept"
    ldap.require(expected in raw and opposite not in raw)


def register(address, ca, token):
    plugin = next(row for row in ldap.artifacts.lock()["plugins"] if row["id"] == "auth-radius")
    ldap.api(address, ca, token, "POST", "sys/plugins/catalog/auth/radius",
             {"sha256": plugin["binary_sha256"], "command": "openbao-plugin-auth-radius", "version": "v0.1.0"}, 204)
    ldap.api(address, ca, token, "POST", "sys/auth/" + MOUNT,
             {"type": "radius", "config": {"plugin_version": "v0.1.0"}}, 204)
    mounted = ldap.api(address, ca, token, "GET", "sys/auth")["data"][MOUNT + "/"]
    ldap.require(mounted.get("running_sha256") == plugin["binary_sha256"]
                 and mounted.get("running_plugin_version") == "v0.1.0")


def check_auth(response, user, policies):
    auth = response.get("auth", {})
    ldap.require(isinstance(auth.get("client_token"), str) and auth["client_token"]
                 and sorted(auth.get("policies", [])) == sorted(policies)
                 and auth.get("metadata", {}).get("username") == user)
    return auth["client_token"]


def server_checks(address, ca, token, values):
    api = lambda method, tail, payload=None, expected=200: ldap.api(
        address, ca, token, method, "auth/" + MOUNT + "/" + tail, payload, expected)
    settings = {"host": "127.0.0.1", "port": 11812, "secret": values["shared"],
                "dial_timeout": 1, "read_timeout": 1, "token_no_default_policy": True,
                "token_policies": ["fixture-radius-base"], "unregistered_user_policies": "fixture-radius-fallback",
                "token_ttl": "5m", "token_max_ttl": "10m"}
    progress("configuring backend and user policy mapping")
    for policy in ("base", "mapped", "fallback"):
        ldap.api(address, ca, token, "PUT", "sys/policies/acl/fixture-radius-" + policy,
                 {"policy": 'path "auth/token/lookup-self" { capabilities = ["read"] }'}, 204)
    api("POST", "config", settings, 204)
    ldap.require("secret" not in api("GET", "config")["data"])
    api("POST", "users/alice", {"policies": "fixture-radius-mapped"}, 204)
    policies = api("GET", "users/alice")["data"]["policies"]
    ldap.require(policies in ("fixture-radius-mapped", ["fixture-radius-mapped"]))
    ldap.require(api("LIST", "users")["data"]["keys"] == ["alice"])
    login = lambda user, password, expected=200: api("POST", "login", {"username": user, "password": password}, expected)
    progress("real mapped and fallback authentication")
    user_token = check_auth(login("alice", values["alice"]), "alice", ["fixture-radius-base", "fixture-radius-mapped"])
    check_auth(login("bob", values["bob"]), "bob", ["fixture-radius-base", "fixture-radius-fallback"])
    progress("invalid credentials and least privilege")
    login("alice", values["wrong"], 400)
    login("missing", values["wrong"], 400)
    ldap.api(address, ca, user_token, "POST", "auth/" + MOUNT + "/config", settings, 403)
    progress("mapping removal and shared-secret mismatch")
    api("DELETE", "users/alice", expected=204)
    api("GET", "users/alice", expected=404)
    check_auth(login("alice", values["alice"]), "alice", ["fixture-radius-base", "fixture-radius-fallback"])
    api("POST", "config", {**settings, "secret": values["wrong"]}, 204)
    login("alice", values["alice"], 400)
    api("POST", "config", settings, 204)
    check_auth(login("alice", values["alice"]), "alice", ["fixture-radius-base", "fixture-radius-fallback"])


def input_hashes():
    return {**ldap.input_hashes(), **{path: base.sha256(base.read_regular_file(ldap.ROOT / path, 2 * 1024 * 1024))
        for path in ("scripts/openbao_radius_plugins.py", "scripts/openbao_radius_image.py")}}


def exercise(address, ca, token, root, ldap_port, passwords, podman, server, owner, environment,
             *, acknowledgement, sdk_exercise=None):
    progress("verifying explicitly acknowledged pinned FreeRADIUS image")
    image.verify(environment, acknowledgement)
    image.prepare(podman, environment)
    values = {name: secrets.token_hex(32) for name in ("shared", "alice", "bob", "wrong")}
    config = configuration(root, values)
    name = "openbao-radius-" + owner
    try:
        progress("starting unprivileged loopback-only FreeRADIUS")
        ldap.start_container(container_command(podman, name, server, owner, config), environment)
        info = ldap.inspect(podman, name, environment)
        ldap.verify_container(info, owner, image.REFERENCE, "65532:0")
        ldap.verify_process(podman, name, "65532:0", environment)
        ldap.require(info["HostConfig"]["NetworkMode"] in {"container:" + server,
            "container:" + ldap.inspect(podman, server, environment)["Id"]})
        deadline = time.monotonic() + 30
        while True:
            try:
                probe(podman, name, environment, "positive")
                break
            except harness.HarnessError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)
        probe(podman, name, environment, "negative")
        probe(podman, name, environment, "unknown")
        register(address, ca, token)
        (server_checks if sdk_exercise is None else sdk_exercise)(address, ca, token, values)
    finally:
        harness.remove_owned_resource(podman, "container", name, owner, environment)


def run(version, directory_acknowledgement, radius_acknowledgement, *, sdk_exercise=None):
    ldap.require(radius_acknowledgement is True)
    before = input_hashes()
    callback = lambda *args: exercise(*args, acknowledgement=radius_acknowledgement, sdk_exercise=sdk_exercise)
    report, schema = ldap.run(version, directory_acknowledgement, extra_plugins=("auth-radius",), extra_exercise=callback)
    ldap.require(before == input_hashes())
    report.update(schema="openbao-radius-plugin-server/v1", inputs=before,
        checks=list(CHECKS) if sdk_exercise is None else [],
        scope="server-fixture-only-not-public-sdk-integration" if sdk_exercise is None else "public-sdk-candidate-only",
        radius={"image": image.REFERENCE, "config": image.CONFIG, "version": image.VERSION,
                "publisher_signature": "not-established", "trust": "explicit-local-fixture-only-unsigned-image-acknowledgement",
                "transport": "udp-owned-network-namespace-loopback-only", "message_authenticator_required": False})
    return report, schema


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--version", choices=tuple(ldap.VERSIONS), required=True)
    parser.add_argument("--acknowledge-unsigned-directory-image", action="store_true")
    parser.add_argument("--acknowledge-unsigned-radius-image", action="store_true")
    args = parser.parse_args()
    try:
        report, schema = run(args.version, args.acknowledge_unsigned_directory_image, args.acknowledge_unsigned_radius_image)
        output = Path(tempfile.mkdtemp(prefix="openbao-radius-plugin-result-"))
        harness.write_private(output / "report.json", base.canonical_json(report), 0o644)
        harness.write_private(output / "runtime-openapi.json", schema, 0o644)
        output.chmod(0o755)
        print("RADIUS server fixture passed; result directory: " + str(output))
        return 0
    except (harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("RADIUS plugin fixture failed; no SDK compatibility promotion", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
