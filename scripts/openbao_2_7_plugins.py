#!/usr/bin/python3 -EsSB
"""Record external-plugin availability without treating absence as compatibility."""

import argparse
import datetime
from pathlib import Path
import ssl
import tempfile
import urllib.request

import openbao_api_snapshots as base

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "compat/onboarding/2.7.0/plugin-availability.json"
EXPECTED_SHA256 = "21a12f04d7ba2b51f3d7b62baac3ed115a2f3595564fb9e8ac03bdd1fd3bb6fb"
SOURCE_COMMIT = "93abe36c053ce018af1d276d5b4b66575c7de10f"
REPOSITORY = "https://api.github.com/repos/openbao/openbao-plugins"
PLUGINS = {
    "auth/ldap": "auth/ldap",
    "auth/kerberos": "auth/kerberos",
    "auth/radius": "auth/radius",
    "secret/ldap": "secrets/ldap",
}
MAX_BYTES = 8 * 1024 * 1024


def classify(tags: list[str], paths: list[str]) -> list[dict]:
    result = []
    for plugin, source in sorted(PLUGINS.items()):
        name = plugin.split("/")[1]
        candidates = sorted(tag for tag in tags if name in tag.lower())
        present = source in paths
        result.append({
            "id": plugin, "source_directory": source, "source_present": present,
            "candidate_tags": candidates,
            "status": "requires-artifact-review" if candidates else "no-published-artifact-observed",
            "artifact_verified": False, "contract_verified": False,
            "server_version_alone_proves_support": False,
        })
    return result


def validate(document: dict) -> None:
    base.require_keys(document, {"schema", "observed_on", "repository", "source_commit", "release_tags", "git_tags", "source_directories", "plugins", "promotion_allowed"}, "plugin observation")
    if (document["schema"] != "openbao-plugin-availability/v1"
        or document["repository"] != REPOSITORY
        or document["source_commit"] != SOURCE_COMMIT
        or document["promotion_allowed"] is not False):
        raise base.SnapshotError("plugin observation metadata or promotion boundary changed")
    try:
        if datetime.date.fromisoformat(document["observed_on"]).isoformat() != document["observed_on"]:
            raise ValueError("noncanonical date")
    except (ValueError, TypeError) as error:
        raise base.SnapshotError("plugin observation date is invalid") from error
    for field in ("release_tags", "git_tags", "source_directories"):
        values = document[field]
        if not isinstance(values, list) or not values or len(values) > 4096:
            raise base.SnapshotError("plugin inventory exceeds its bound")
        for value in values:
            if not isinstance(value, str):
                raise base.SnapshotError("plugin inventory entry is not text")
            base.validate_text(value, "plugin inventory entry", 512)
        if values != sorted(set(values)):
            raise base.SnapshotError("plugin inventory is duplicated or unordered")
    if base.canonical_json(document["plugins"]) != base.canonical_json(classify(sorted(set(document["release_tags"] + document["git_tags"])), document["source_directories"])):
        raise base.SnapshotError("plugin availability contradicts its observation")


def require_verified_plugins(document: dict) -> None:
    validate(document)
    if any(p["artifact_verified"] is not True or p["contract_verified"] is not True for p in document["plugins"]):
        raise base.SnapshotError("external plugin artifacts and contracts are not verified; checkpoint 03 is incomplete")


def verify() -> dict:
    data = base.read_regular_file(EVIDENCE, MAX_BYTES)
    if base.sha256(data) != EXPECTED_SHA256:
        raise base.SnapshotError("plugin observation checksum changed")
    document = base.parse_json(data, MAX_BYTES)
    validate(document)
    if data != base.canonical_json(document):
        raise base.SnapshotError("plugin observation is not canonical")
    return document


def fetch(suffix: str):
    request = urllib.request.Request(REPOSITORY + suffix, headers={"Accept": "application/vnd.github+json", "User-Agent": "openbao-sdk-evidence"})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise base.SnapshotError("plugin inventory request redirected")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(request, timeout=30) as response:
        if response.status != 200:
            raise base.SnapshotError("plugin inventory request failed")
        data = response.read(MAX_BYTES + 1)
    # The shared parser also bounds nested arrays and rejects duplicate keys.
    return base.parse_json(b'{"result":' + data + b'}', MAX_BYTES)["result"]


def records(value, maximum: int, field: str) -> list[dict]:
    if not isinstance(value, list) or len(value) > maximum:
        raise base.SnapshotError("plugin API list is malformed or exceeds its bound")
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get(field), str):
            raise base.SnapshotError("plugin API record is malformed")
        base.validate_text(item[field], "plugin API record", 512)
    return value


def observe() -> dict:
    releases = []
    for page in range(1, 5):
        batch = records(fetch(f"/releases?per_page=100&page={page}"), 100, "tag_name")
        releases.extend(item["tag_name"] for item in batch)
        if len(batch) < 100:
            break
    else:
        raise base.SnapshotError("plugin release pagination exceeds its bound")
    refs = records(fetch("/git/matching-refs/tags"), 4096, "ref")
    tree = fetch(f"/git/trees/{SOURCE_COMMIT}?recursive=1")
    if not isinstance(tree, dict) or tree.get("truncated") is not False:
        raise base.SnapshotError("plugin source tree is incomplete")
    entries = records(tree.get("tree"), 16384, "path")
    if any(not item["ref"].startswith("refs/tags/") for item in refs):
        raise base.SnapshotError("plugin tag inventory contains a non-tag ref")
    if any(item.get("type") not in {"tree", "blob", "commit"} for item in entries):
        raise base.SnapshotError("plugin source tree has an unsupported entry")
    tags = sorted(item["ref"].removeprefix("refs/tags/") for item in refs)
    paths = sorted(item["path"] for item in entries if item["type"] == "tree")
    document = {
        "schema": "openbao-plugin-availability/v1", "observed_on": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
        "repository": REPOSITORY, "source_commit": SOURCE_COMMIT,
        "release_tags": sorted(set(releases)), "git_tags": tags,
        "source_directories": paths,
        "plugins": classify(sorted(set(releases + tags)), paths),
        "promotion_allowed": False,
    }
    validate(document)
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observe", action="store_true", help="write a fresh observation to a new temporary file, never promote it")
    parser.add_argument("--require-verified", action="store_true", help="fail unless external-plugin verification is complete")
    args = parser.parse_args()
    if args.observe and args.require_verified:
        parser.error("observation and promotion checks cannot be combined")
    try:
        if args.observe:
            document = observe()
            with tempfile.NamedTemporaryFile(prefix="openbao-plugin-observation-", suffix=".json", delete=False) as handle:
                handle.write(base.canonical_json(document))
                print(handle.name)
        else:
            document = verify()
            if args.require_verified:
                require_verified_plugins(document)
            print("OpenBao 2.7 plugin observation: verified; artifact/contract verification remains blocked")
        return 0
    except (base.SnapshotError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"Plugin observation failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
