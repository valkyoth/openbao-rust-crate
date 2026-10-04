#!/usr/bin/python3 -EsSB
"""Build a disposable KDC from a signed base and a signed, pinned APK index."""

from pathlib import Path
import json
import re
import sys
import urllib.request

import openbao_ldap_plugins as ldap

base, harness = ldap.base, ldap.harness
REPOSITORY = "cgr.dev/chainguard/wolfi-base"
INDEX = "sha256:9c2092b053779e14c82fb50f77b37bcc38b7d2c83972352d5813280f9d035b03"
AMD64 = "sha256:fbcaceb3a1eedec23eb80df9328f9be4a438546836ec15a67df39a104096d44a"
REFERENCE = REPOSITORY + "@" + AMD64
IDENTITY = "https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
LOCK = "compat/plugins/kerberos/packages.lock.json"
LOCK_SHA256 = "900c81c5ef0415701c2560d54fbd01f1d697d5fdf7179bff790de274de23fb0f"
PACKAGE_REPOSITORY = "https://packages.wolfi.dev/os/x86_64/"
MAX_PACKAGE = 32 * 1024 * 1024
APK_INDEX = "compat/plugins/kerberos/APKINDEX.tar.gz"
APK_INDEX_SHA256 = "f713a6bc6b5c2166ed39a21728c3c1f9fde660d9bf0ef2f435842afd58bd2a32"


def package_lock():
    raw = base.read_regular_file(ldap.ROOT / LOCK, 64 * 1024)
    ldap.require(base.sha256(raw) == LOCK_SHA256)
    value = base.parse_json(raw, 64 * 1024)
    ldap.require(set(value) == {"schema", "repository", "packages"}
                 and value["schema"] == "openbao-kerberos-fixture-packages/v1"
                 and value["repository"] == PACKAGE_REPOSITORY)
    rows = value["packages"]
    ldap.require(isinstance(rows, list) and len(rows) == 31)
    names = set()
    for row in rows:
        ldap.require(set(row) == {"file", "size", "sha256"}
                     and re.fullmatch(r"[a-zA-Z0-9+_.-]+\.apk", row["file"])
                     and "/" not in row["file"] and row["file"] not in names
                     and type(row["size"]) is int and 0 < row["size"] <= MAX_PACKAGE
                     and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]))
        names.add(row["file"])
    ldap.require(sum(row["size"] for row in rows) <= 128 * 1024 * 1024)
    return rows


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise harness.HarnessError("KDC package redirect rejected")


def fetch_package(row):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(PACKAGE_REPOSITORY + row["file"], timeout=60) as response:
        ldap.require(response.status == 200)
        data = response.read(row["size"] + 1)
    ldap.require(len(data) == row["size"] and base.sha256(data) == row["sha256"])
    return data


def verify_signature_claims(raw):
    base.scan_json_bounds(raw, 256 * 1024)
    value = json.loads(raw, object_pairs_hook=base.reject_duplicate_keys,
                       parse_constant=base.reject_non_finite_constant)
    base.validate_json_tree(value)
    ldap.require(isinstance(value, list) and 1 <= len(value) <= 16 and all(
        isinstance(row, dict) and row.get("critical", {}).get("image", {}).get("docker-manifest-digest") == INDEX
        for row in value))


def progress(stage):
    print("Kerberos KDC image: " + stage, file=sys.stderr, flush=True)


def verify_base(environment):
    tools = ldap.tls.evidence_tools
    cosign = str(tools.protected_path(Path("/usr/bin/cosign")))
    skopeo = str(tools.protected_path(Path("/usr/bin/skopeo")))
    progress("verifying base signature")
    verified = harness.run_bounded(
        [cosign, "verify", "--certificate-identity", IDENTITY,
         "--certificate-oidc-issuer", ISSUER, REPOSITORY + "@" + INDEX],
        maximum=256 * 1024, timeout=180, environment=environment)
    verify_signature_claims(verified)
    progress("checking signed index platform binding")
    raw = harness.run_bounded([skopeo, "inspect", "--no-creds", "--raw",
                              "docker://" + REPOSITORY + "@" + INDEX],
                             maximum=128 * 1024, timeout=120, environment=environment)
    ldap.require("sha256:" + base.sha256(raw) == INDEX)
    index = base.parse_json(raw, 128 * 1024)
    selected = [row for row in index["manifests"]
                if row.get("platform") == {"architecture": "amd64", "os": "linux"}]
    ldap.require(len(selected) == 1 and selected[0]["digest"] == AMD64)


def containerfile():
    return (f"FROM {REFERENCE}\n"
            "RUN --mount=type=bind,source=repository,target=/fixture-packages,ro "
            "apk add --no-network --repositories-file /dev/null --repository /fixture-packages "
            "krb5=1.22.2-r4 krb5-server=1.22.2-r4 python-3.12=3.12.15-r1\nUSER 65532:0\n"
            'ENTRYPOINT ["/usr/bin/python3.12", "-E", "-s", "-S", "-B", "/fixture/kdc.py"]\n').encode()


def prepare(root, podman, owner, environment):
    verify_base(environment)
    context = root / "kdc-build"
    packages = context / "repository/x86_64"
    packages.mkdir(parents=True, mode=0o700)
    index = base.read_regular_file(ldap.ROOT / APK_INDEX, 16 * 1024 * 1024)
    ldap.require(base.sha256(index) == APK_INDEX_SHA256)
    harness.write_private(packages / "APKINDEX.tar.gz", index)
    progress("downloading hash-pinned packages")
    for row in package_lock():
        harness.write_private(packages / row["file"], fetch_package(row))
    harness.write_private(context / "Containerfile", containerfile())
    auth = root / "kdc-registry-auth.json"
    harness.write_private(auth, b"{}")
    progress("preparing pinned base image")
    harness.run_bounded([podman, "pull", "--quiet", "--authfile", str(auth),
                         "--platform", "linux/amd64", REFERENCE], timeout=900, environment=environment)
    inspected = harness.run_bounded([podman, "image", "inspect", "--format",
                                     "{{.Digest}} {{.Architecture}} {{.Os}}", REFERENCE],
                                    maximum=1024, timeout=30, environment=environment)
    ldap.require(inspected.decode().split() == [AMD64, "amd64", "linux"])
    name = "localhost/openbao-kdc-fixture:" + owner
    progress("building offline with signed repository index")
    harness.run_bounded([podman, "build", "--pull=never", "--network=none", "--no-cache",
                         "--layers=false", "--force-rm", "--cap-drop=ALL",
                         "--security-opt=no-new-privileges", "--memory=1g", "--memory-swap=2g",
                         "--cpu-period=100000", "--cpu-quota=100000",
                         "--label", harness.OWNER_LABEL + "=" + owner, "--tag", name,
                         "--file", str(context / "Containerfile"), str(context)],
                        maximum=256 * 1024, timeout=300, environment=environment)
    return name


def remove(podman, name, owner, environment):
    raw = harness.run_bounded([podman, "image", "inspect", "--format", "{{json .}}", name], maximum=128 * 1024,
                             timeout=30, environment=environment)
    info = base.parse_json(raw, 128 * 1024)
    ldap.require(info["Labels"].get(harness.OWNER_LABEL) == owner)
    harness.run_bounded([podman, "image", "rm", info["Id"]], timeout=60, environment=environment)
