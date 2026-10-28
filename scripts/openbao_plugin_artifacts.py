#!/usr/bin/python3 -EsSB
"""Verify pinned plugin archives without executing them or promoting support."""

import argparse
import gzip
import io
import os
from pathlib import Path
import re
import ssl
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request

import openbao_api_snapshots as base

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "compat/plugins/artifacts.lock.json"
LOCK_SHA256 = "ef0f88d0f3af1cc58d54f534e32caa2ea929799ef780e6ff09c9c625043c51df"
KEY = ROOT / "compat/plugins/openbao-release-key.asc"
KEY_SHA256 = "1862a196422947124282e026ea4e09d6f7c5d383b628d90c17906936e6e5a8e0"
PRIMARY = "66D15FDD87287219C8E15478D200CD702853E6D0"
SIGNER = "E617DCD4065C2AFC0B2CF7A7BA8BC08C0F691F94"
PLUGINS = ("auth-ldap", "auth-kerberos", "auth-radius", "secrets-ldap")
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_BINARY = 48 * 1024 * 1024
MAX_LICENSE = 64 * 1024
ASSET_BASE = "https://github.com/openbao/openbao-plugins/releases/download/"


def require(condition):
    if not condition:
        raise base.SnapshotError("plugin artifact validation failed")


def lock():
    data = base.read_regular_file(LOCK, 32 * 1024)
    require(base.sha256(data) == LOCK_SHA256)
    document = base.parse_json(data, 32 * 1024)
    require(document["schema"] == "openbao-plugin-artifacts/v2"
            and document["platform"] == "linux_amd64_v1"
            and document["signing_primary_fingerprint"] == PRIMARY
            and tuple(p["id"] for p in document["plugins"]) == PLUGINS)
    require(all(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", p["version"])
                and p["tag"] == p["id"] + "-" + p["version"]
                and re.fullmatch(r"[0-9a-f]{40}", p["source_commit"])
                and re.fullmatch(r"[0-9a-f]{64}", p["binary_sha256"])
                for p in document["plugins"]))
    return document


def allowed_url(url):
    value = urllib.parse.urlsplit(url)
    return (value.scheme == "https" and value.hostname in
            {"github.com", "release-assets.githubusercontent.com"}
            and value.port in {None, 443} and value.username is None
            and value.password is None and not value.fragment)


class AssetRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        require(allowed_url(url))
        return super().redirect_request(request, response, code, message, headers, url)


def download(url, maximum):
    require(allowed_url(url) and maximum <= MAX_ARCHIVE)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), AssetRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={"User-Agent": "openbao-sdk-plugin-review"})
    with opener.open(request, timeout=30) as response:
        require(response.status == 200 and allowed_url(response.geturl()))
        data = response.read(maximum + 1)
    require(len(data) <= maximum)
    return data


def check_assets(plugin, assets):
    require(set(assets) == {a["name"] for a in plugin["assets"]})
    for asset in plugin["assets"]:
        data = assets[asset["name"]]
        require(len(data) == asset["size"] and base.sha256(data) == asset["sha256"])


def checksums(data):
    require(len(data) <= 32 * 1024)
    result = {}
    for line in data.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]{1,180})", line)
        require(match is not None)
        digest, name = match.groups()
        require(name not in result)
        result[name] = digest
    require(1 <= len(result) <= 128)
    return result


def signature_status(data):
    lines = data.decode("ascii").splitlines()
    valid = [line.split() for line in lines if line.startswith("[GNUPG:] VALIDSIG ")]
    require(len(valid) == 1)
    fields = valid[0]
    # Pin both signing subkey and primary key; disallow SHA-1/MD5 signatures.
    require(len(fields) == 12 and fields[2] == SIGNER and fields[11] == PRIMARY
            and fields[9] in {"8", "9", "10"})
    forbidden = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY"}
    require(not any(len(line.split()) > 1 and line.split()[1] in forbidden for line in lines))


def verify_signature(archive, signature):
    require(0 < len(signature) <= 16 * 1024 and len(archive) <= MAX_ARCHIVE)
    key = base.read_regular_file(KEY, 16 * 1024)
    require(base.sha256(key) == KEY_SHA256)
    with tempfile.TemporaryDirectory(prefix="openbao-plugin-signature-") as directory:
        home = Path(directory)
        (home / "public.asc").write_bytes(key)
        (home / "archive").write_bytes(archive)
        (home / "signature").write_bytes(signature)
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": directory}
        subprocess.run(["/usr/bin/gpg", "--no-options", "--batch", "--homedir", directory,
                        "--output", str(home / "keyring.gpg"), "--dearmor", str(home / "public.asc")],
                       check=True, timeout=30, env=env, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        result = subprocess.run(["/usr/bin/gpgv", "--homedir", directory,
                                 "--keyring", str(home / "keyring.gpg"), "--status-fd", "1",
                                 str(home / "signature"), str(home / "archive")],
                                check=True, timeout=30, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
        require(len(result.stdout) <= 16 * 1024)
        signature_status(result.stdout)


def unpack(archive, binary_name):
    require(len(archive) <= MAX_ARCHIVE)
    # Bound the entire expanded stream before tar parsing (including headers).
    with gzip.GzipFile(fileobj=io.BytesIO(archive)) as compressed:
        expanded = compressed.read(MAX_EXPANDED + 1)
    require(len(expanded) <= MAX_EXPANDED)
    result = {}
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as bundle:
        for member in bundle:
            require(member.name in {"LICENSE", binary_name} and member.name not in result
                    and member.type == tarfile.REGTYPE and not member.linkname
                    and not member.pax_headers and not member.issparse()
                    and member.mode & 0o7022 == 0)
            maximum = MAX_BINARY if member.name == binary_name else MAX_LICENSE
            require(0 < member.size <= maximum)
            with bundle.extractfile(member) as entry:
                data = entry.read(maximum + 1)
            require(len(data) == member.size)
            result[member.name] = data
    require(set(result) == {"LICENSE", binary_name})
    binary = result[binary_name]
    require(len(binary) >= 64 and binary[:7] == b"\x7fELF\x02\x01\x01"
            and binary[16:18] in {b"\x02\x00", b"\x03\x00"}
            and binary[18:20] == b"\x3e\x00")
    return result


def verify_plugin(plugin, assets):
    check_assets(plugin, assets)
    name = f'openbao-plugin-{plugin["id"]}_linux_amd64_v1'
    archive = assets[name + ".tar.gz"]
    verify_signature(archive, assets[name + ".tar.gz.sig"])
    inventory = checksums(assets[f'checksums-{plugin["id"]}.txt'])
    require(inventory.get(name + ".tar.gz") == base.sha256(archive)
            and inventory.get(name) == plugin["binary_sha256"])
    files = unpack(archive, name)
    require(base.sha256(files[name]) == plugin["binary_sha256"])
    # Upstream emits CycloneDX despite the asset's .spdx.sbom.json suffix.
    sbom = base.parse_json(assets[name + ".tar.gz.spdx.sbom.json"], 1024 * 1024)
    require(sbom.get("bomFormat") == "CycloneDX" and sbom.get("specVersion") == "1.7")
    return files


def capture():
    require(os.geteuid() != 0)
    document = lock()
    reports = []
    inputs = {str(path.relative_to(ROOT)): base.sha256(base.read_regular_file(path, 1024 * 1024))
              for path in (LOCK, KEY, Path(__file__), ROOT / "scripts/openbao_api_snapshots.py")}
    with tempfile.TemporaryDirectory(prefix="openbao-plugin-review-") as directory:
        output = Path(directory)
        for plugin in document["plugins"]:
            assets = {a["name"]: download(ASSET_BASE + plugin["tag"] + "/" + a["name"], a["size"])
                      for a in plugin["assets"]}
            files = verify_plugin(plugin, assets)
            reports.append({"id": plugin["id"], "version": plugin["version"],
                            "source_commit": plugin["source_commit"],
                            "binary_sha256": plugin["binary_sha256"],
                            "license_sha256": base.sha256(files["LICENSE"]),
                            "signature_verified": True})
            # Files are private, non-executable, and never installed in a server.
            for name, data in assets.items():
                (output / name).write_bytes(data)
            print(f'Plugin artifact verified: {plugin["id"]} {plugin["version"]}', flush=True)
        result = {"schema": "openbao-plugin-artifact-review/v2", "inputs": inputs,
                  "platform": document["platform"],
                  "signing_primary_fingerprint": PRIMARY, "plugins": reports,
                  "scope": "artifact-signature-and-identity-only", "routable": False,
                  "contracts_verified": False, "source_to_binary_provenance_verified": False}
        with tempfile.NamedTemporaryFile(prefix="openbao-plugin-artifact-result-", suffix=".json",
                                         delete=False) as report:
            report.write(base.canonical_json(result))
            print(f"Artifact review result: {report.name}")
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="store_true", help="download and verify; never execute plugins")
    args = parser.parse_args()
    try:
        if args.capture:
            capture()
        else:
            lock()
            require(base.sha256(base.read_regular_file(KEY, 16 * 1024)) == KEY_SHA256)
            print("Plugin artifact lock verified; plugin compatibility remains excluded")
        return 0
    except (base.SnapshotError, OSError, ValueError, KeyError, TypeError, tarfile.TarError,
            EOFError, subprocess.SubprocessError):
        print("Plugin artifact review failed; no compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
