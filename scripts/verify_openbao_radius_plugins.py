#!/usr/bin/python3 -EsSB
"""Verify retained RADIUS server evidence without granting SDK compatibility."""

import argparse

import openbao_radius_plugins as fixture
import verify_openbao_ldap_plugins as ldap

base = fixture.base
require = ldap.require
ROOT = fixture.ldap.ROOT / "compat/plugins/radius"
ANCHORS = {
    "2.7.0": "c66a7e7e44e7b2d9eaffa6665fd48cc09e36838e930a8654342b9506c6ee4a44",
    "2.7.1": "b6993fb0b84d0dd60de8b5a69c1c16dd86a9cd584cb5001905040c21d9a5e809",
}


def validate_report(report, version, inputs, schema):
    require(version in ANCHORS and isinstance(report, dict))
    image = fixture.image
    require(report.get("radius") == {
        "image": image.REFERENCE, "config": image.CONFIG, "version": image.VERSION,
        "publisher_signature": "not-established",
        "trust": "explicit-local-fixture-only-unsigned-image-acknowledgement",
        "transport": "udp-owned-network-namespace-loopback-only", "message_authenticator_required": False})
    require(report["radius"]["message_authenticator_required"] is False)
    require(report.get("schema") == "openbao-radius-plugin-server/v1"
            and report.get("checks") == list(fixture.CHECKS))
    plugins = {row["id"]: row["binary_sha256"] for row in fixture.ldap.artifacts.lock()["plugins"]
               if row["id"] in (*fixture.ldap.PLUGINS, "auth-radius")}
    require(report.get("plugins") == plugins)
    converted = dict(report)
    del converted["radius"]
    converted.update(schema="openbao-ldap-plugin-server/v1", checks=list(fixture.ldap.CHECKS),
                     plugins={key: value for key, value in plugins.items() if key != "auth-radius"})
    ldap.validate_report(converted, version, inputs, schema)
    paths = base.parse_json(schema, 2 * 1024 * 1024)["paths"]
    for suffix, methods in (("config", ("get", "post")), ("users", ("get",)),
                            ("users/{name}", ("get", "post", "delete")),
                            ("login", ("post",)), ("login/{urlusername}", ("post",))):
        contract = paths.get("/auth/{fixture_radius_mount_path}/" + suffix, {})
        require(all(method in contract for method in methods))
    parameters = paths["/auth/{fixture_radius_mount_path}/users"]["get"].get("parameters", [])
    require(any(p.get("name") == "list" and p.get("in") == "query" and p.get("required") is True
                and p.get("schema", {}).get("enum") == ["true"] for p in parameters))


def verify(version):
    require(version in ANCHORS)
    root = ROOT / version
    raw = base.read_regular_file(root / "report.json", 64 * 1024)
    require(base.sha256(raw) == ANCHORS[version])
    report = base.parse_json(raw, 64 * 1024)
    require(base.canonical_json(report) == raw)
    schema = base.read_regular_file(root / "runtime-openapi.json", 2 * 1024 * 1024)
    validate_report(report, version, fixture.input_hashes(), schema)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        for version in ANCHORS:
            verify(version)
    except (base.SnapshotError, fixture.harness.HarnessError, OSError, ValueError, KeyError, TypeError):
        print("RADIUS server evidence verification failed")
        return 1
    print("RADIUS server evidence verified; public SDK acceptance remains separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
