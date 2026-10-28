#!/usr/bin/python3 -EsSB
"""Verify retained exact Kerberos server evidence, separately from SDK acceptance."""

import argparse

import openbao_kerberos_plugins as fixture
import verify_openbao_ldap_plugins as ldap

base = fixture.base
require = ldap.require
ROOT = fixture.ldap.ROOT / "compat/plugins/kerberos"
ANCHORS = {
    "2.7.0": "7009194db7c36e03866d343c6755dde576cd9492b26897d0db017bef5ad5247b",
    "2.7.1": "f36b4a7a5965f007a8060218e6d00672aaf7fea6ece4e13804cf3dadac45d181",
    "2.7.2": "2b4540f6b1937251c81b4b0ec1e84c39356408b51949fcae5fa88f76a0c83902",
}


def validate_report(report, version, inputs, schema):
    require(version in ANCHORS and isinstance(report, dict))
    image = fixture.image
    require(report.get("kdc") == {
        "base": image.REFERENCE, "signed_index": image.INDEX,
        "packages_sha256": image.LOCK_SHA256, "apk_index_sha256": image.APK_INDEX_SHA256,
        "implementation": "MIT Kerberos 1.22.2-r4", "build": "local-offline-not-attested"})
    require(report.get("schema") == "openbao-kerberos-plugin-server/v1"
            and report.get("checks") == list(fixture.CHECKS))
    plugins = {row["id"]: row["binary_sha256"] for row in fixture.ldap.artifacts.lock()["plugins"]
               if row["id"] in (*fixture.ldap.PLUGINS, "auth-kerberos")}
    require(report.get("plugins") == plugins)
    converted = dict(report)
    del converted["kdc"]
    converted.update(schema="openbao-ldap-plugin-server/v1", checks=list(fixture.ldap.CHECKS),
                     plugins={key: value for key, value in plugins.items() if key != "auth-kerberos"})
    ldap.validate_report(converted, version, inputs, schema)
    paths = base.parse_json(schema, 2 * 1024 * 1024)["paths"]
    for suffix, methods in (("config", ("get", "post")), ("config/ldap", ("get", "post")),
                            ("groups", ("get",)), ("groups/{name}", ("get", "post", "delete")),
                            ("login", ("post",))):
        contract = paths.get("/auth/{fixture_kerberos_mount_path}/" + suffix, {})
        require(all(method in contract for method in methods))


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
        print("Kerberos server evidence verification failed")
        return 1
    print("Kerberos server evidence verified; normal-build SDK acceptance remains separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
