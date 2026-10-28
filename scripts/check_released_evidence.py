#!/usr/bin/python3 -EsSB
"""Check released 2.7.0 evidence bytes without requiring Git history in CI."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "compat/released-2.7.0-evidence-v2.2.4.json"
# Independent of current-report pins. Refresh tools must not update this anchor.
MANIFEST_SHA256 = "f32ef983d5fcb6eb56516a522fbc569d29c09b7f19c076cc9843b4efd9a61cbc"
RELEASE_COMMIT = "606c60ee282f5fb6c82e8106c02dde731069bbfd"


def released_files(raw):
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError("released-evidence manifest changed")
    manifest = json.loads(raw)
    if (manifest["schema"] != "openbao-released-evidence/v1"
            or manifest["release"] != "v2.2.4"
            or manifest["commit"] != RELEASE_COMMIT):
        raise ValueError("released-evidence baseline changed")
    return manifest["files"]


def validate(root, entries):
    for relative, expected in entries.items():
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"released evidence missing or replaced: {relative}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"released evidence changed: {relative}")


def main():
    try:
        entries = released_files(MANIFEST.read_bytes())
        validate(ROOT, entries)
    except (OSError, ValueError, KeyError) as error:
        print(f"Released evidence check failed: {error}")
        return 1
    print(f"Released evidence: {len(entries)} original v2.2.4 files unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
