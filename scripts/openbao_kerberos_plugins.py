#!/usr/bin/python3 -EsSB
"""Real MIT KDC and LDAPS fixture for the exact external Kerberos plugin."""

import argparse
import base64
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import openbao_ldap_plugins as ldap
import openbao_kerberos_image as image

base, harness = ldap.base, ldap.harness
MOUNT = "fixture-kerberos"
REALM = "FIXTURE.INVALID"
CHECKS = ("installed-artifact-identity", "real-kdc-ticket", "kdc-invalid-keytab-rejection",
          "passwordless-config-read", "group-mapping-crud", "mapped-login-policies",
          "unmapped-login-policies", "least-privilege-denial", "malformed-ticket-rejection",
          "wrong-service-ticket-rejection", "realm-mismatch-rejection", "mapping-removal")


def progress(message):
    print("Kerberos plugin fixture: " + message, file=sys.stderr, flush=True)


def configuration(root):
    directory = root / "kdc-config"
    directory.mkdir(mode=0o750)
    harness.write_private(directory / "kdc.py", base.read_regular_file(
        ldap.ROOT / "scripts/kerberos_kdc_helper.py", 64 * 1024), 0o640)
    client = ("[libdefaults]\n default_realm = FIXTURE.INVALID\n dns_lookup_kdc = false\n"
              " dns_lookup_realm = false\n dns_canonicalize_hostname = false\n rdns = false\n"
              " udp_preference_limit = 1\n ticket_lifetime = 5m\n forwardable = false\n"
              " default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n"
              " default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n"
              "[realms]\n FIXTURE.INVALID = {\n  kdc = 127.0.0.1:1188\n }\n")
    server = ("[kdcdefaults]\n kdc_listen = 127.0.0.1:1188\n kdc_tcp_listen = 127.0.0.1:1188\n"
              "[realms]\n FIXTURE.INVALID = {\n  database_name = /data/db/principal\n"
              "  key_stash_file = /data/db/stash\n  acl_file = /data/db/kadm5.acl\n"
              "  max_life = 10m\n  max_renewable_life = 10m\n"
              "  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal\n }\n"
              "[logging]\n kdc = FILE:/dev/null\n admin_server = FILE:/dev/null\n default = FILE:/dev/null\n")
    harness.write_private(directory / "krb5.conf", client.encode(), 0o640)
    harness.write_private(directory / "kdc.conf", server.encode(), 0o640)
    return directory


def kdc_command(podman, reference, name, server, owner, config):
    return [podman, "run", "-d", "--name", name, "--label", harness.OWNER_LABEL + "=" + owner,
            "--pull", "never", "--network", "container:" + server,
            *base.CONTAINER_RESOURCE_OPTIONS, "--read-only", "--user", "65532:0",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--no-healthcheck",
            "--log-driver", "none", "--tmpfs", "/data:rw,noexec,nosuid,nodev,size=64m,mode=0770",
            "--volume", str(config) + ":/fixture:ro,Z", reference, "start"]


def helper(podman, name, environment, *args):
    return harness.run_bounded([podman, "exec", "--user", "65532:0", name,
        "/usr/bin/python3.12", "-E", "-s", "-S", "-B", "/fixture/kdc.py", *args],
        maximum=48 * 1024, timeout=25, environment=environment)


def encoded_secret(value, maximum):
    ldap.require(isinstance(value, bytes) and 0 < len(value) <= maximum
                 and re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", value))
    decoded = base64.b64decode(value, validate=True)
    ldap.require(base64.b64encode(decoded) == value and bool(decoded))
    return value.decode("ascii")


def login(address, ca, ticket, *, expected=200):
    ldap.require(isinstance(ticket, str) and 0 < len(ticket) <= 48 * 1024
                 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", ticket))
    request = urllib.request.Request(address + "/v1/auth/" + MOUNT + "/login", method="POST",
        data=b"{}", headers={"Content-Type": "application/json", "Authorization": "Negotiate " + ticket})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), harness.RejectRedirect(),
        urllib.request.HTTPSHandler(context=ldap.tls.context(ca)))
    try:
        response = opener.open(request, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        ldap.tls.require_status(response.status, expected)
        if expected != 200:
            return None
        raw = response.read(ldap.tls.MAX_BODY + 1)
        ldap.require(len(raw) <= ldap.tls.MAX_BODY and response.headers.get_content_type() == "application/json")
    value = base.parse_json(raw, ldap.tls.MAX_BODY)
    ldap.require(isinstance(value.get("auth"), dict))
    return value["auth"]


def check_auth(auth, user, policies):
    ldap.require(isinstance(auth.get("client_token"), str) and auth["client_token"]
                 and sorted(auth.get("policies", [])) == sorted(policies)
                 and auth.get("metadata", {}).get("user") == user
                 and auth["metadata"].get("domain") == REALM)


def register(address, ca, token):
    plugin = next(row for row in ldap.artifacts.lock()["plugins"] if row["id"] == "auth-kerberos")
    ldap.api(address, ca, token, "POST", "sys/plugins/catalog/auth/kerberos",
        {"sha256": plugin["binary_sha256"], "command": "openbao-plugin-auth-kerberos",
         "version": plugin["version"]}, expected=204)
    ldap.api(address, ca, token, "POST", "sys/auth/" + MOUNT,
        {"type": "kerberos", "config": {"plugin_version": plugin["version"],
          "passthrough_request_headers": ["Authorization"]}}, expected=204)
    mounted = ldap.api(address, ca, token, "GET", "sys/auth")["data"][MOUNT + "/"]
    ldap.require(mounted.get("running_sha256") == plugin["binary_sha256"]
                 and mounted.get("running_plugin_version") == plugin["version"])


def server_checks(address, ca, token, passwords, ticket, keytab):
    api = lambda method, tail, payload=None, expected=200: ldap.api(
        address, ca, token, method, "auth/" + MOUNT + "/" + tail, payload, expected)
    progress("configuring keytab and verified LDAPS group lookup")
    api("POST", "config", {"keytab": keytab, "service_account": "HTTP/localhost",
        "remove_instance_name": False, "add_group_aliases": True, "decode_pac": False}, 204)
    config = api("GET", "config")["data"]
    ldap.require("keytab" not in config and config.get("service_account") == "HTTP/localhost"
                 and config.get("decode_pac") is False)
    settings = {"url": "ldaps://127.0.0.1:1636", "certificate": ca.read_text(),
        "binddn": ldap.MANAGER, "bindpass": passwords["manager"], "userdn": ldap.PEOPLE,
        "userattr": "cn", "groupdn": ldap.BASE_DN, "groupattr": "cn",
        "groupfilter": "(member={{.UserDN}})", "tls_min_version": "tls13", "tls_max_version": "tls13",
        "token_policies": ["fixture-kerberos-base"], "token_no_default_policy": True,
        "token_ttl": "5m", "token_max_ttl": "10m"}
    api("POST", "config/ldap", settings, 204)
    ldap_config = api("GET", "config/ldap")["data"]
    ldap.require("bindpass" not in ldap_config)
    for policy in ("fixture-kerberos-base", "fixture-kerberos-group"):
        ldap.api(address, ca, token, "PUT", "sys/policies/acl/" + policy,
                 {"policy": 'path "auth/token/lookup-self" { capabilities = ["read"] }'}, 204)
    progress("checking group mappings and real-ticket login")
    api("POST", "groups/engineers", {"policies": "fixture-kerberos-group"}, 204)
    ldap.require(api("GET", "groups/engineers")["data"]["policies"] == ["fixture-kerberos-group"])
    ldap.require(api("LIST", "groups")["data"]["keys"] == ["engineers"])
    auth = login(address, ca, ticket("alice", "localhost"))
    check_auth(auth, "alice", ["fixture-kerberos-base", "fixture-kerberos-group"])
    check_auth(login(address, ca, ticket("static", "localhost")), "static", ["fixture-kerberos-base"])
    progress("checking least privilege and invalid tickets")
    ldap.api(address, ca, auth["client_token"], "GET", "auth/" + MOUNT + "/config", expected=403)
    login(address, ca, "ZmFrZQ==", expected=401)
    login(address, ca, ticket("alice", "wronghost"), expected=401)
    progress("checking realm mismatch and mapping removal")
    api("POST", "config/ldap", {**settings, "upndomain": "OTHER.INVALID"}, 204)
    login(address, ca, ticket("alice", "localhost"), expected=400)
    api("POST", "config/ldap", {**settings, "upndomain": ""}, 204)
    api("DELETE", "groups/engineers", expected=204)
    api("GET", "groups/engineers", expected=404)
    check_auth(login(address, ca, ticket("alice", "localhost")), "alice", ["fixture-kerberos-base"])


def input_hashes():
    names = ("scripts/openbao_kerberos_plugins.py", "scripts/openbao_kerberos_image.py",
             "scripts/kerberos_kdc_helper.py", image.LOCK)
    index = base.sha256(base.read_regular_file(ldap.ROOT / image.APK_INDEX, 16 * 1024 * 1024))
    ldap.require(index == image.APK_INDEX_SHA256)
    return {**ldap.input_hashes(), **{name: base.sha256(base.read_regular_file(
        ldap.ROOT / name, 2 * 1024 * 1024)) for name in names}, image.APK_INDEX: index}


def exercise(address, ca, token, root, ldap_port, passwords, podman, server, owner, environment, *, sdk_exercise=None):
    reference = "localhost/openbao-kdc-fixture:" + owner
    name = "openbao-kdc-" + owner
    built = started = False
    try:
        progress("verifying signed KDC base and building pinned offline packages")
        reference = image.prepare(root, podman, owner, environment)
        built = True
        progress("starting constrained MIT KDC")
        config = configuration(root)
        started = True
        ldap.start_container(kdc_command(podman, reference, name, server, owner, config), environment)
        deadline = time.monotonic() + 30
        while True:
            try:
                helper(podman, name, environment, "ready")
                break
            except harness.HarnessError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)
        info = ldap.inspect(podman, name, environment)
        ldap.verify_container(info, owner, reference, "65532:0")
        ldap.verify_process(podman, name, "65532:0", environment)
        ldap.require(info["HostConfig"]["NetworkMode"] in {"container:" + server,
            "container:" + ldap.inspect(podman, server, environment)["Id"]})
        helper(podman, name, environment, "invalid-keytab")
        keytab = encoded_secret(helper(podman, name, environment, "keytab"), 32768)
        ticket = lambda user, service: encoded_secret(helper(podman, name, environment,
            "ticket", user, service), 48 * 1024)
        register(address, ca, token)
        if sdk_exercise is None:
            server_checks(address, ca, token, passwords, ticket, keytab)
        else:
            sdk_exercise(address, ca, token, passwords, ticket, keytab)
    finally:
        try:
            if started:
                harness.remove_owned_resource(podman, "container", name, owner, environment)
        finally:
            if built:
                image.remove(podman, reference, owner, environment)


def run(version, acknowledgement, *, sdk_exercise=None):
    before = input_hashes()
    callback = lambda *args: exercise(*args, sdk_exercise=sdk_exercise)
    report, schema = ldap.run(version, acknowledgement, extra_plugins=("auth-kerberos",), extra_exercise=callback)
    ldap.require(before == input_hashes())
    report.update(schema="openbao-kerberos-plugin-server/v1", checks=list(CHECKS) if sdk_exercise is None else [], inputs=before,
                  scope="server-fixture-only-not-public-sdk-integration" if sdk_exercise is None else "public-sdk-candidate-only",
                  kdc={"base": image.REFERENCE, "signed_index": image.INDEX,
                       "packages_sha256": image.LOCK_SHA256, "apk_index_sha256": image.APK_INDEX_SHA256,
                       "implementation": "MIT Kerberos 1.22.2-r4", "build": "local-offline-not-attested"})
    return report, schema


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--version", choices=tuple(ldap.VERSIONS), required=True)
    parser.add_argument("--acknowledge-unsigned-directory-image", action="store_true")
    args = parser.parse_args()
    try:
        report, schema = run(args.version, args.acknowledge_unsigned_directory_image)
        output = Path(tempfile.mkdtemp(prefix="openbao-kerberos-plugin-result-"))
        harness.write_private(output / "report.json", base.canonical_json(report), 0o644)
        harness.write_private(output / "runtime-openapi.json", schema, 0o644)
        output.chmod(0o755)
        print("Kerberos server fixture passed; result directory: " + str(output))
        return 0
    except (harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError):
        print("Kerberos plugin fixture failed; no SDK compatibility promotion", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
