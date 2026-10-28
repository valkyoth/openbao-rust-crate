#!/usr/bin/python3 -EsSB
"""Validate retained LDAP server evidence without promoting SDK contracts."""

import argparse

import openbao_ldap_plugins as fixture

base = fixture.base
ROOT = fixture.ROOT / "compat/plugins/ldap"
ANCHORS = {
    "2.7.0": "9b39c3782b3dbc5181e8fff043b1a095a562d5a2b2a66b34b1a58723b293ee25",
    "2.7.1": "6828e2f39cb039255359368426e957d416dd204effecf1181aae619cabfe057f",
    "2.7.2": "c1a115ab94395391a7acb4760c8178c956896118aa5d6c187a51423efb9eab1f",
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
    print("LDAP server evidence verified for 2.7.0, 2.7.1 and 2.7.2; public SDK evidence remains a separate gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
