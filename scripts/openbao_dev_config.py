#!/usr/bin/python3 -EsSB
"""Resolve the local development image only from the verified active inventory."""

import argparse
from pathlib import Path
import sys

import openbao_api_snapshots as base
from validate_openbao_release_lock import LockValidationError, validate_lock_files

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "deploy/podman/profile.json"


def resolve(document: dict, inventory: dict) -> dict[str, str]:
    base.require_keys(document, {"schema", "server_version"}, "local development profile")
    if document["schema"] != "openbao-local-dev/v1":
        raise base.SnapshotError("unsupported local development profile schema")
    version = document["server_version"]
    records = [r for r in inventory["records"] if r["version"] == version]
    if len(records) != 1:
        raise base.SnapshotError("development server must be an exact verified active version")
    release = records[0]
    return {
        "version": version,
        "project": "openbao-rust-crate-" + version.replace(".", "-"),
        "image": f"docker.io/openbao/openbao:{version}@{release['image']['index_digest']}",
    }


def load() -> dict[str, str]:
    document = base.parse_json(base.read_regular_file(PROFILE, 1024), 1024)
    return resolve(document, validate_lock_files())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("field", choices=("image", "project", "version", "profile"))
    args = parser.parse_args()
    try:
        profile = load()
        print(" ".join(profile[field] for field in ("version", "project", "image")) if args.field == "profile" else profile[args.field])
        return 0
    except (base.SnapshotError, LockValidationError, OSError, TypeError, KeyError) as error:
        print(f"Invalid local development profile: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
