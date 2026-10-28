#!/usr/bin/python3 -EsSB
"""Released evidence cannot be rewritten, removed, or repinned by a refresh."""

import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import check_released_evidence as check


class ReleasedEvidenceTests(unittest.TestCase):
    def test_released_repository_bytes(self):
        entries = check.released_files(check.read_regular_file(check.MANIFEST, check.MAX_MANIFEST_SIZE))
        self.assertEqual(len(entries), 88)
        check.validate(check.ROOT, entries)

    def test_manifest_change_and_entry_removal_are_rejected(self):
        raw = check.read_regular_file(check.MANIFEST, check.MAX_MANIFEST_SIZE)
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

    def test_evidence_limit_accepts_boundary_and_rejects_overflow_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "capture.json"
            content = b"x" * check.MAX_EVIDENCE_SIZE
            path.write_bytes(content)
            entries = {path.name: hashlib.sha256(content).hexdigest()}
            check.validate(root, entries)
            for size in (check.MAX_EVIDENCE_SIZE + 1, 4 * 1024**3):
                with self.subTest(size=size):
                    with path.open("wb") as output:
                        output.truncate(size)
                    with patch("openbao_api_snapshots.os.read") as read:
                        with self.assertRaises(check.SnapshotError):
                            check.validate(root, entries)
                        read.assert_not_called()

    def test_manifest_limit_rejects_overflow_before_read_and_parse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            for size in (check.MAX_MANIFEST_SIZE + 1, 4 * 1024**3):
                with self.subTest(size=size):
                    with path.open("wb") as output:
                        output.truncate(size)
                    with patch.object(check, "MANIFEST", path), \
                         patch("openbao_api_snapshots.os.read") as read, \
                         patch.object(check, "released_files") as parse, \
                         redirect_stdout(io.StringIO()):
                        self.assertEqual(check.main(), 1)
                        read.assert_not_called()
                        parse.assert_not_called()

    def test_manifest_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.symlink_to(check.MANIFEST)
            with patch.object(check, "MANIFEST", path), redirect_stdout(io.StringIO()):
                self.assertEqual(check.main(), 1)

    def test_symlinked_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "real"
            target.mkdir()
            (target / "capture.json").write_bytes(b"old")
            (root / "alias").symlink_to(target, target_is_directory=True)
            with self.assertRaises(check.SnapshotError):
                check.validate(root, {"alias/capture.json": hashlib.sha256(b"old").hexdigest()})


if __name__ == "__main__":
    unittest.main()
