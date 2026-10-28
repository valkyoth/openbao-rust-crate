#!/usr/bin/python3 -EsSB
"""Released evidence cannot be rewritten, removed, or repinned by a refresh."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import check_released_evidence as check


class ReleasedEvidenceTests(unittest.TestCase):
    def test_released_repository_bytes(self):
        entries = check.released_files(check.MANIFEST.read_bytes())
        self.assertEqual(len(entries), 88)
        check.validate(check.ROOT, entries)

    def test_manifest_change_and_entry_removal_are_rejected(self):
        raw = check.MANIFEST.read_bytes()
        with self.assertRaises(ValueError):
            check.released_files(raw + b"\n")
        manifest = json.loads(raw)
        manifest["files"].pop(next(iter(manifest["files"])))
        with self.assertRaises(ValueError):
            check.released_files(json.dumps(manifest).encode())

    def test_changed_missing_and_symlinked_capture_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "capture.json"
            original = b'{"outcome":"passed"}\n'
            entries = {path.name: hashlib.sha256(original).hexdigest()}
            path.write_bytes(original)
            check.validate(root, entries)
            for content in (b'{}\n', original + b"\n"):
                path.write_bytes(content)
                with self.assertRaises(ValueError):
                    check.validate(root, entries)
            path.unlink()
            with self.assertRaises(ValueError):
                check.validate(root, entries)
            target = root / "replacement.json"
            target.write_bytes(original)
            path.symlink_to(target)
            with self.assertRaises(ValueError):
                check.validate(root, entries)

    def test_new_capture_does_not_replace_released_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "v1.json").write_bytes(b"old")
            (root / "v2.json").write_bytes(b"new")
            check.validate(root, {"v1.json": hashlib.sha256(b"old").hexdigest()})


if __name__ == "__main__":
    unittest.main()
