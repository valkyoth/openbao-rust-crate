#!/usr/bin/python3 -EsSB
"""Reject stale package installation, release links and current-release wording."""

from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]
CURRENT_DOCUMENTS = ("README.md", "docs/CURRENT_STATUS.md", "docs/OPENBAO_VERSION_SELECTION.md")


def validate(package, documents, notes):
    version = package["version"]
    if f'openbao = "{version}"' not in documents["README.md"]:
        raise ValueError("README install version must match package")
    link = f'{package["repository"]}/blob/v{version}/release-notes/RELEASE_NOTES_{version}.md'
    if documents["README.md"].count("](" + link + ")") != 1:
        raise ValueError("README release link must match package")
    if f"Version: {version}\n" not in notes:
        raise ValueError("current release notes must match package")
    stale = re.compile(r"unreleased|development build|approval.{0,30}(pending|outstanding)|"
                       r"(retesting|retest).{0,30}(required|outstanding)|before (release|tagging)", re.I)
    for name in CURRENT_DOCUMENTS:
        # Historical baseline notes belong below this explicit heading.
        current = documents[name].split("### Published 2.2.0 Baseline", 1)[0]
        if stale.search(current):
            raise ValueError("current release documentation contains stale preparation wording")


def main():
    package = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    documents = {name: (ROOT / name).read_text() for name in CURRENT_DOCUMENTS}
    notes = (ROOT / "release-notes" / f'RELEASE_NOTES_{package["version"]}.md').read_text()
    validate(package, documents, notes)
    print("current-release documentation verified")


if __name__ == "__main__":
    main()
