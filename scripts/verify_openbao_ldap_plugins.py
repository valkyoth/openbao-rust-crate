#!/usr/bin/python3 -EsSB
"""Validate retained LDAP server evidence without promoting SDK contracts."""

import argparse

import openbao_ldap_plugins as fixture

base = fixture.base
ROOT = fixture.ROOT / "compat/plugins/ldap"
ANCHORS = {
    "2.7.3": "a927ea67e17e815b03b0d7c29101d3063253ffcc57c9ea7086ae17af45504126",
    "2.7.0": "1414da8b7316bf9a5eb25f2d170a791cf5d18e8d3cf146da393474403c780896",
    "2.7.1": "219afa273006ed5a61d612c88ee0909f0d8d129f39b14cf60f2a29ea579b0fdc",
    "2.7.2": "bac87d417a344d2da55a86b1ae1171d4a8a6c2af1d40a25807aa332787bf5fb6",
}


def require(condition):
    if not condition:
        raise base.SnapshotError("LDAP server evidence validation failed")


def server_directory(root, version):
    require(version in ANCHORS)
    return root / version / "server-v2" if version in ("2.7.0", "2.7.1", "2.7.2") else root / version


def validate_report(report, version, inputs, schema_bytes):
    require(version in ANCHORS)
    plugins = {row["id"]: row["binary_sha256"] for row in fixture.artifacts.lock()["plugins"]
               if row["id"] in fixture.PLUGINS}
    image = fixture.directory
    expected = {
        "schema": "openbao-ldap-plugin-server/v1", "server_version": version,
        "outcome": "passed", "scope": "server-fixture-only-not-public-sdk-integration",
        "routable": False, "plugins": plugins,
        "directory": {"image": image.REFERENCE, "index": image.INDEX,
                      "source_revision_observation": image.SOURCE,
                      "publisher_signature": "not-available",
                      "trust": "explicit-local-fixture-only-unsigned-image-acknowledgement"},
        "checks": list(fixture.CHECKS), "inputs": inputs, "cleanup": "passed",
        "runtime_openapi_sha256": base.sha256(schema_bytes),
    }
    require(isinstance(report, dict) and report == expected and report.get("routable") is False)
    schema = base.parse_json(schema_bytes, 2 * 1024 * 1024)
    require(base.canonical_json(schema) == schema_bytes
            and str(schema.get("openapi", "")).startswith("3.")
            and isinstance(schema.get("paths"), dict))
    paths = schema["paths"]
    for path in ("/auth/{fixture_ldap_auth_mount_path}/login/{username}",
                 "/auth/{fixture_ldap_auth_mount_path}/config",
                 "/{fixture_ldap_secrets_mount_path}/config",
                 "/{fixture_ldap_secrets_mount_path}/creds/{name}",
                 "/{fixture_ldap_secrets_mount_path}/static-cred/{name}"):
        require(path in paths)


def verify(version):
    require(version in ANCHORS)
    directory = server_directory(ROOT, version)
    data = base.read_regular_file(directory / "report.json", 64 * 1024)
    require(base.sha256(data) == ANCHORS[version])
    report = base.parse_json(data, 64 * 1024)
    require(base.canonical_json(report) == data)
    schema = base.read_regular_file(directory / "runtime-openapi.json", 2 * 1024 * 1024)
    validate_report(report, version, fixture.input_hashes(), schema)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        for version in ANCHORS:
            verify(version)
    except (base.SnapshotError, fixture.harness.HarnessError, OSError, ValueError,
            KeyError, TypeError):
        print("LDAP server evidence verification failed")
        return 1
    print("LDAP server evidence verified; public SDK evidence remains a separate gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
