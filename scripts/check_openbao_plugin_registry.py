#!/usr/bin/python3 -EsSB
"""Ensure Rust plugin identities exactly match the verified artifact lock."""

import openbao_api_snapshots as base
import openbao_plugin_artifacts as artifacts

DESTINATION = artifacts.ROOT / "src/plugin/artifacts.rs"


def render():
    lines = ["// Generated from compat/plugins/artifacts.lock.json; do not edit by hand.", ""]
    for plugin in artifacts.lock()["plugins"]:
        name = plugin["id"].replace("-", "_").upper()
        digest = plugin["binary_sha256"]
        base.require_hash(digest, "plugin binary identity")
        lines.extend([f"pub(super) const {name}: &str =", f'    "{digest}";'])
    return ("\n".join(lines) + "\n").encode()


def verify():
    artifacts.require(base.read_regular_file(DESTINATION, 16 * 1024) == render())


if __name__ == "__main__":
    verify()
    print("Rust plugin artifact registry verified; contracts remain separate")
