#!/usr/bin/python3 -EsSB
"""Check a pinned disposable directory image; do not claim publisher signatures."""

from pathlib import Path

import openbao_2_7_tls as tls

base, harness = tls.base, tls.harness
REPOSITORY = "docker.io/chrroessner/openldap"
INDEX = "sha256:f6015ce5a66fd1be22d54cebc2c2db9d976a7690d199e5058954128f38454536"
AMD64 = "sha256:b34d863b73dc1105044c8b589450d15a8d235215723fdcadaf4028d9fbf57a56"
CONFIG = "sha256:ea92cc3350eb0cff35694d9163c8d2f1cef61af2b684739ee77e816422681838"
SOURCE = "8f782df51305a3ee38d29b7bd5039ec3ff9e1057"
VERSION = "2.6.15-r3"
REFERENCE = REPOSITORY + "@" + AMD64


def require(condition):
    if not condition:
        raise harness.HarnessError("directory image validation failed")


def pinned(data, digest):
    require(base.sha256(data) == digest.removeprefix("sha256:"))
    return base.parse_json(data, 128 * 1024)


def validate(index, manifest, config):
    index = pinned(index, INDEX)
    manifest = pinned(manifest, AMD64)
    config = pinned(config, CONFIG)
    require(index.get("schemaVersion") == 2 and manifest.get("schemaVersion") == 2)
    selected = [row for row in index.get("manifests", [])
                if row.get("platform") == {"architecture": "amd64", "os": "linux"}]
    require(len(selected) == 1 and selected[0].get("digest") == AMD64
            and manifest.get("config", {}).get("digest") == CONFIG)
    require(config.get("architecture") == "amd64" and config.get("os") == "linux")
    labels = config.get("config", {}).get("Labels", {})
    require(labels.get("org.opencontainers.image.source") == "https://github.com/croessner/docker-openldap"
            and labels.get("org.opencontainers.image.revision") == SOURCE
            and labels.get("org.opencontainers.image.version") == VERSION
            and config.get("config", {}).get("User") == "ldap:ldap")
    # These labels and attached BuildKit attestations are not publisher signatures.
    return {"image": REFERENCE, "index": INDEX, "source_revision_observation": SOURCE,
            "publisher_signature": "not-available",
            "trust": "explicit-local-fixture-only-unsigned-image-acknowledgement"}


def verify(environment, acknowledge_unsigned=False):
    require(acknowledge_unsigned is True)
    skopeo = str(tls.evidence_tools.protected_path(Path("/usr/bin/skopeo")))
    documents = []
    for flags, digest in ((("--raw",), INDEX), (("--raw",), AMD64), (("--raw", "--config"), AMD64)):
        documents.append(harness.run_bounded(
            [skopeo, "inspect", "--no-creds", *flags, "docker://" + REPOSITORY + "@" + digest],
            maximum=128 * 1024, timeout=120, environment=environment))
    return validate(*documents)


def prepare(podman, environment):
    auth = Path(environment["HOME"]) / "ldap-registry-auth.json"
    harness.write_private(auth, b"{}")
    harness.run_bounded([podman, "pull", "--quiet", "--authfile", str(auth), "--platform", "linux/amd64", REFERENCE],
                        timeout=900, environment=environment)
    output = harness.run_bounded([podman, "image", "inspect", "--format",
                                 "{{.Digest}} {{.Architecture}} {{.Os}}", REFERENCE],
                                maximum=1024, timeout=30, environment=environment)
    require(output.decode("ascii").split() == [AMD64, "amd64", "linux"])
    return REFERENCE
