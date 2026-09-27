#!/usr/bin/python3 -EsSB
"""Lock source-only OpenBao 2.7.0 onboarding evidence; never promote routes."""

from __future__ import annotations

import argparse
import copy
import sys
from pathlib import Path

import openbao_api_snapshots as snapshots
from generate_openbao_version_contracts import ContractError, atomic_write

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "compat/onboarding/2.7.0/source-inventory.json"
VERSION = "2.7.0"
SOURCE_COMMIT = "ca305a02daa68b203325daa1b25c18d7a252d4b3"
PREDECESSOR = ROOT / "compat/api-snapshots/2.6.3/documentation.json"
PREDECESSOR_SHA256 = "535c8a2fefa024f2b2d08d105988603c30015226809e37437808261e01bd8c08"
EXPECTED_SHA256 = "5e562faaed04a9a48de847dacfe10752c4b5bf8d576ed919e6052f6c92ff3f73"


def checked_bytes(data: bytes) -> dict:
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("2.7.0 source inventory digest changed")
    return snapshots.parse_json(data, snapshots.MAX_SNAPSHOT_BYTES)


def build(repository_text: str) -> bytes:
    repository = snapshots.validate_source_repository(repository_text)
    tag_commit = snapshots.git_output(
        repository, ["rev-parse", "--verify", "refs/tags/v2.7.0^{commit}"], 128
    ).strip().decode("ascii")
    if tag_commit != SOURCE_COMMIT:
        raise snapshots.SnapshotError("2.7.0 tag does not resolve to the reviewed commit")
    before_data = snapshots.read_regular_file(PREDECESSOR, snapshots.MAX_SNAPSHOT_BYTES)
    if snapshots.sha256(before_data) != PREDECESSOR_SHA256:
        raise snapshots.SnapshotError("2.6.3 predecessor documentation changed")
    before = snapshots.parse_json(before_data, snapshots.MAX_SNAPSHOT_BYTES)
    after = snapshots.extract_documentation(repository, {
        "version": VERSION,
        "source": {"peeled_commit_sha1": SOURCE_COMMIT},
        "documentation": {"source_path": "website/content/docs/api"},
    })
    old_files = {entry["path"]: entry for entry in before["files"]}
    new_files = {entry["path"]: entry for entry in after["files"]}
    changes = []
    for path in sorted(old_files.keys() | new_files.keys()):
        old, new = old_files.get(path), new_files.get(path)
        if old == new:
            continue
        changes.append({
            "path": path,
            "change": "added" if old is None else "removed" if new is None else "modified",
            "before_sha256": old["sha256"] if old else None,
            "after_sha256": new["sha256"] if new else None,
        })
    # Retain file identities only. The historical operation parser does not
    # cover 2.7's comma-separated method cells; no endpoint count is asserted.
    return snapshots.canonical_json({
        "schema": "openbao-onboarding-source-inventory/v1",
        "version": VERSION,
        "source_commit_sha1": SOURCE_COMMIT,
        "published_at": "2026-09-23T17:39:54Z",
        "release_url": "https://github.com/openbao/openbao/releases/tag/v2.7.0",
        "source_path": after["source_path"],
        "predecessor_version": "2.6.3",
        "predecessor_documentation_sha256": PREDECESSOR_SHA256,
        "status": "source-only-not-routable",
        "image_signature_verified": False,
        "runtime_openapi_captured": False,
        "files": after["files"],
        "changes": changes,
    })


def verify() -> dict:
    return checked_bytes(snapshots.read_regular_file(OUTPUT, snapshots.MAX_SNAPSHOT_BYTES))


def self_test() -> None:
    document = verify()
    mutations = (
        ("status", "routable"),
        ("source_commit_sha1", "0" * 40),
        ("version", "2.7.1"),
        ("image_signature_verified", True),
        ("runtime_openapi_captured", True),
        ("files", []),
        ("changes", []),
    )
    for key, value in mutations:
        changed = copy.deepcopy(document)
        changed[key] = value
        snapshots.expect_rejected(key, lambda: checked_bytes(snapshots.canonical_json(changed)))
    data = snapshots.canonical_json(document)
    for invalid in (b"", data[:-1], data + b" ", b'{"schema":1,"schema":2}'):
        snapshots.expect_rejected("altered inventory bytes", lambda: checked_bytes(invalid))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--verify", action="store_true")
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--write", action="store_true")
    parser.add_argument("--source-repository")
    args = parser.parse_args()
    try:
        if args.write:
            if not args.source_repository:
                parser.error("--write requires --source-repository")
            data = build(args.source_repository)
            checked_bytes(data)
            atomic_write(OUTPUT, data)
        elif args.self_test:
            self_test()
        else:
            verify()
        print("OpenBao 2.7.0 source inventory: ok (not runtime support)")
        return 0
    except (snapshots.SnapshotError, ContractError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"OpenBao 2.7.0 source inventory failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
