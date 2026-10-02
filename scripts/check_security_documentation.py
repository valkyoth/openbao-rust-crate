#!/usr/bin/python3 -EsSB
"""Keep the packaged security policy bound to this SDK release's source."""

from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = (
    "SECURITY_MODEL.md",
    "OPENBAO_COMPATIBILITY_THREAT_MODEL.md",
    "PANIC_POLICY.md",
)


def validate(package, policy, root=ROOT):
    if "/SECURITY.md" not in package["include"]:
        raise ValueError("security policy must be packaged")
    prefix = f'{package["repository"]}/blob/v{package["version"]}/docs/'
    links = re.findall(r"\]\(([^\s)]+)\)", policy)
    for name in DOCUMENTS:
        references = [link for link in links if link.endswith("/" + name)]
        if references != [prefix + name]:
            raise ValueError("security model link must match the SDK release")
        if not (root / "docs" / name).is_file():
            raise ValueError("referenced security document is missing")


def main():
    with (ROOT / "Cargo.toml").open("rb") as source:
        package = tomllib.load(source)["package"]
    validate(package, (ROOT / "SECURITY.md").read_text())
    print("release-bound security documentation verified")


if __name__ == "__main__":
    main()
