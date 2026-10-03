#!/usr/bin/python3 -EsSB
"""Mutation regressions for the crates.io README release contract."""

import copy
import tomllib
import unittest

import check_release_documentation as check


class ReleaseDocumentationTests(unittest.TestCase):
    def setUp(self):
        self.package = tomllib.loads((check.ROOT / "Cargo.toml").read_text())["package"]
        self.documents = {name: (check.ROOT / name).read_text() for name in check.CURRENT_DOCUMENTS}
        self.notes = (check.ROOT / "release-notes" / f'RELEASE_NOTES_{self.package["version"]}.md').read_text()

    def test_current_documentation(self):
        check.validate(self.package, self.documents, self.notes)

    def test_stale_installation_and_release_link(self):
        for fragment in (f'openbao = "{self.package["version"]}"',
                         f'blob/v{self.package["version"]}/release-notes/'):
            documents = copy.deepcopy(self.documents)
            documents["README.md"] = documents["README.md"].replace(fragment, "obsolete")
            with self.assertRaises(ValueError):
                check.validate(self.package, documents, self.notes)

    def test_stale_preparation_text_in_each_current_document(self):
        for name in check.CURRENT_DOCUMENTS:
            for phrase in ("unreleased 2.2.1", "development build", "GitHub approval pending",
                           "Security retesting remains required before release"):
                documents = copy.deepcopy(self.documents)
                documents[name] = phrase + "\n" + documents[name]
                with self.subTest(name=name, phrase=phrase), self.assertRaises(ValueError):
                    check.validate(self.package, documents, self.notes)

    def test_version_bump_and_wrong_notes_fail(self):
        package = copy.deepcopy(self.package)
        package["version"] = "99.0.0"
        with self.assertRaises(ValueError):
            check.validate(package, self.documents, self.notes)
        with self.assertRaises(ValueError):
            check.validate(self.package, self.documents, "Version: 99.0.0\n")


if __name__ == "__main__":
    unittest.main()
