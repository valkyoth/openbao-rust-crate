#!/usr/bin/python3 -EsSB
"""Cross-language artifact identity drift regressions."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import openbao_api_snapshots as base
import check_openbao_plugin_registry as subject


class RegistryTests(unittest.TestCase):
    def test_current_registry(self):
        subject.verify()

    def test_missing_mutated_duplicate_and_reordered_entries(self):
        good = subject.render()
        lines = good.splitlines(keepends=True)
        for changed in (good.replace(b"18fa83", b"08fa83"), b"".join(lines[:-2]),
                        good + b"".join(lines[-2:]),
                        b"".join(lines[:2] + lines[4:6] + lines[2:4] + lines[6:])):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "artifacts.rs"
                path.write_bytes(changed)
                with patch.object(subject, "DESTINATION", path), self.assertRaises(base.SnapshotError):
                    subject.verify()


if __name__ == "__main__":
    unittest.main()
