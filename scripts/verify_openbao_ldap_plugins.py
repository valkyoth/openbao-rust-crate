#!/usr/bin/python3 -EsSB
"""Validate retained LDAP server evidence without promoting SDK contracts."""

import argparse

import openbao_ldap_plugins as fixture

base = fixture.base
ROOT = fixture.ROOT / "compat/plugins/ldap"
ANCHORS = {
    "2.7.0": "1d2ca7f8942ac02b4c7fa41d406139446bf3b6a034d90a3ef66d33022152f28f",
    "2.7.1": "7316f7f37644db3ccb5853544017071ce3e37ca6f877d17c2745b9e8eb2489cc",
}


def require(condition):
    if not condition:
        raise base.SnapshotError("LDAP server evidence validation failed")


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
    directory = ROOT / version
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
    print("LDAP server evidence verified for 2.7.0 and 2.7.1; public SDK evidence remains a separate gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
