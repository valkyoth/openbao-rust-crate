#!/usr/bin/python3 -EsSB
"""Digest-pinned official FreeRADIUS fixture image; no signature claim."""

from pathlib import Path

import openbao_ldap_plugins as ldap

base, harness = ldap.base, ldap.harness
REPOSITORY = "docker.io/freeradius/freeradius-server"
DIGEST = "sha256:cc7fd136e7b03e7b332d94297530318e824a4ecfedbce54562cced723e71e812"
CONFIG = "sha256:801bb663071f6230612cd2ca43cbc3ebd9ba7887b32a6716d632ce2d847c6c9d"
REFERENCE = REPOSITORY + "@" + DIGEST
VERSION = "3.2.10"


def validate(manifest, config):
    ldap.require("sha256:" + base.sha256(manifest) == DIGEST
                 and "sha256:" + base.sha256(config) == CONFIG)
    manifest = base.parse_json(manifest, 128 * 1024)
    config = base.parse_json(config, 128 * 1024)
    ldap.require(manifest.get("schemaVersion") == 2
                 and manifest.get("config", {}).get("digest") == CONFIG
                 and config.get("architecture") == "amd64" and config.get("os") == "linux")
    return {"image": REFERENCE, "config": CONFIG, "version": VERSION,
            "publisher_signature": "not-established",
            "trust": "explicit-local-fixture-only-unsigned-image-acknowledgement"}


def verify(environment, acknowledgement):
    ldap.require(acknowledgement is True)
    skopeo = str(ldap.tls.evidence_tools.protected_path(Path("/usr/bin/skopeo")))
    documents = [harness.run_bounded([skopeo, "inspect", "--no-creds", *flags, "docker://" + REFERENCE],
                 maximum=128 * 1024, timeout=120, environment=environment)
                 for flags in (("--raw",), ("--raw", "--config"))]
    return validate(*documents)


def prepare(podman, environment):
    auth = Path(environment["HOME"]) / "radius-registry-auth.json"
    harness.write_private(auth, b"{}")
    harness.run_bounded([podman, "pull", "--quiet", "--authfile", str(auth),
                         "--platform", "linux/amd64", REFERENCE], timeout=900, environment=environment)
    raw = harness.run_bounded([podman, "image", "inspect", "--format",
                               "{{.Digest}} {{.Architecture}} {{.Os}}", REFERENCE],
                              maximum=1024, timeout=30, environment=environment)
    ldap.require(raw.decode().split() == [DIGEST, "amd64", "linux"])
    return REFERENCE
