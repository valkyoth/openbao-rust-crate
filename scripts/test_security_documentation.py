#!/usr/bin/python3 -EsSB
"""Regression checks for the packaged security policy's release links."""

import copy
import tempfile
import tomllib
import unittest
from pathlib import Path

import check_security_documentation as check


class SecurityDocumentationTests(unittest.TestCase):
    def setUp(self):
        with (check.ROOT / "Cargo.toml").open("rb") as source:
            self.package = tomllib.load(source)["package"]
        self.policy = (check.ROOT / "SECURITY.md").read_text()

    def test_current_release(self):
        check.validate(self.package, self.policy)

    def test_each_link_rejects_wrong_release_branch_repository_or_omission(self):
        prefix = f'{self.package["repository"]}/blob/v{self.package["version"]}/docs/'
        for name in check.DOCUMENTS:
            target = prefix + name
            for replacement in (
                target.replace(f'v{self.package["version"]}', "v2.1.9"),
                target.replace(f'v{self.package["version"]}', "main"),
                "https://example.invalid/docs/" + name,
                "",
            ):
                with self.subTest(name=name, replacement=replacement):
                    with self.assertRaises(ValueError):
                        check.validate(self.package, self.policy.replace(target, replacement))

    def test_bump_requires_link_update(self):
        package = copy.deepcopy(self.package)
        package["version"] = "99.0.0"
        with self.assertRaises(ValueError):
            check.validate(package, self.policy)

    def test_missing_packaging_or_source_is_rejected(self):
        package = copy.deepcopy(self.package)
        package["include"].remove("/SECURITY.md")
        with self.assertRaises(ValueError):
            check.validate(package, self.policy)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                check.validate(self.package, self.policy, Path(directory))


if __name__ == "__main__":
    unittest.main()
