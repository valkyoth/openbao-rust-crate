#!/usr/bin/python3 -EsSB
"""Require current server and normal-SDK evidence for all eight plugin pairs."""

import verify_openbao_ldap_sdk as ldap
import verify_openbao_kerberos_sdk as kerberos
import verify_openbao_radius_sdk as radius

VERSIONS = ("2.7.0", "2.7.1")
FAMILIES = ((ldap, 33), (kerberos, 9), (radius, 6))


def verify():
    operations = set()
    for module, count in FAMILIES:
        current = tuple(module.sdk.OPERATIONS)
        if len(current) != count or len(set(current)) != count or operations.intersection(current):
            raise ValueError("plugin operation inventory mismatch")
        operations.update(current)
        for version in VERSIONS:
            module.server.verify(version)
            report = module.verify(version)
            if report.get("scope") != "public-sdk-normal-build":
                raise ValueError("normal-build evidence required")
    if len(operations) != 48:
        raise ValueError("incomplete plugin release coverage")


if __name__ == "__main__":
    verify()
    print("All eight exact plugin/server pairs have current server and normal-SDK evidence")
