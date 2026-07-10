#!/usr/bin/env python3
"""Offline fail-closed validation for compat/releases.lock.json."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "compat" / "releases.lock.json"
CHECKSUM_PATH = ROOT / "compat" / "releases.lock.sha256"
SIGNATURE_LOCK_PATH = ROOT / "compat" / "image-signatures.lock.json"
SIGNATURE_CHECKSUM_PATH = ROOT / "compat" / "image-signatures.lock.sha256"
EXPECTED_LOCK_SHA256 = "028dfa5cf562816b3a51d894aaf723ba06354dd422b606e60546ac2eb236f136"
EXPECTED_SIGNATURE_LOCK_SHA256 = "5b7f471f6bcbbf040251fab695c18a2d9de707ee96f25182660626a449c1c3d5"
MAX_LOCK_BYTES = 512 * 1024
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 16_384
MAX_STRING_BYTES = 4_096
MAX_RECORDS = 128

EXPECTED_RELEASES = (
    ("2.0.0", "700fe3f27ab1f0ec39ce20c36f6d9d97c9fe6ac3", "5eedbca9922d85eca5e4bc68c11f968d245b4046641dd4173c1dcff7ae7091aa", "bdd0f74946f0fe2b5d69761886fb7a6bae6b5e90d1562937aa046cb3ece90e4d"),
    ("2.0.1", "88383dece6b4ff1b3b242280a54aeabef8101495", "4fe96e91e531ef2694916fb2a92d7f7efd4a172059378bf83e0eafd8160b4396", "47a0d9217f3b52252a6825eb80a9ddd465b65adf1270257349e55ed5f2e52148"),
    ("2.0.2", "96853bb4de27ab8ffd1b0c2898c691460d43edeb", "522892470c0c01836c097d64b7053a515a60fe5ce1b0549605fb3bd7bfeb4f1a", "1f5bd1ed455b954658155d5686de000aa76a7d3d401c009cac583a7ea3d462cb"),
    ("2.0.3", "a2522eb71d1854f83c7e2e02fdbfc01ae74c3a78", "05d777d6b47d0d0985b87317914632de31d98994b58e490ebabde3c389b09f8f", "3a074934b3b750247b8cf5be970c8071c64059fdf274b5b6af0aeb4e47a61c09"),
    ("2.1.0", "93609bf0c73a18dd81ac8c7d21b95cbde1e4887c", "7de07aa6df3937d44c96c2d65c188b2d4a70546f2a764ad4510301305af6a223", "c214512044d9da35a42ad330baead674905df60a5569c85e1eb474f22a089efb"),
    ("2.1.1", "17509a8c5e0af4ff921d4e70b06224397c44dd74", "af40ca17625ec44aa1ffe3698f85162d71d9cc97adc9e97821ef393ac94b6e42", "6bc66d973401a7ee4d9dfe0b51d1db4ee3dfb453ebb6a85e87f6436f7ce7514f"),
    ("2.2.0", "a2bf51c891680240888f7363322ac5b2d080bb23", "19612d67a4a95d05a7b77c6ebc6c2ac5dac67a8712d8df2e4c31ad28bee7edaa", "936afc14a970bac6b0a3357131ec7176eb31265edd3d48bd0ae62fee59a703d5"),
    ("2.2.1", "91733be3109e5a5000b750939e5748433c78cfcf", "62f582f85e405ef00d48f678c19863d096a2bc0c05e0e5a9bbccd676a1c7316c", "372647ba9f34d29d2464425dacaa005d6709b6e79af7eb18a2ff18bbb9d02e10"),
    ("2.2.2", "8c0322c0423231836a1432fdad29dc2e99640da9", "d5d098f98f5ca7cae2e33d1e6dd9e2bea332275ad6bb7ff09032b48af3e1141e", "3ee05b27b88115f2a24f4d99bea4fab9f55a2cb2041315ddbf11fa7bf694a443"),
    ("2.3.1", "e3cdbbde8eb48fb7ae92b1d34afb63012e805233", "41dc3e47da01575e1ffea70aa635180b57ff999264398313334c259a697bf7a2", "2f0c914d160a138b26bfbfff0bde495f9b6cb87bfe1991c911a6bf497bf70d42"),
    ("2.3.2", "b1a68f558c89d18d38fbb8675bb6fc1d90b71e98", "afec9f65a7067a22acf24b29f07d2f028353c02cc0fa9c80dfa4e7fab158b373", "c664f682703b751165e3ead271a6e15e642f862bddf7f77a96b5fc8d5190260b"),
    ("2.4.0", "f9407a27fbee45f62ba521bba2bf1e2360c61031", "e32efa32d85567a7ff02ff91cd6e10da1bff809287db5cedfd9373c83437a80c", "ef48a10304e0d3fc45652b4712e137f7cc9e9e282ec8a43a10909e8d3466b3be"),
    ("2.4.1", "efb9efa12f550e8322f3cec040862355e966f565", "597f62847dd382382056a1d6704d50465908c2040038c4611832a23269a67112", "06a26f632cd0bdd0fd6e25034f55d68bc28b62590adc8efea3b8dacade11579a"),
    ("2.4.3", "ef854342df72dba6ecfbdd3f130e251941ba7dca", "48174d0c98dbb955731c5d54a7e7083987fd25a7fb5d793181db8576ada8ed64", "ba4519574cc4b8763143dddd76faa95fddf044812e466645ae00622d8d8a9e8e"),
    ("2.4.4", "4bfd70723d4f9b82be00e87b8c018ac661dd9b99", "595c83b42614a4d2b044608e4593c05b019c5db25bc9c185d8fff3ac96c03ddd", "01bdba095690b1fe7cc1ec956ca422cfe01fd9a994ea28d9a6a2f84886dc9569"),
    ("2.5.0", "bcbb6036ec2b747bceb98c7706ce9b974faa1b23", "d24890f589bc57658a43c18faab2afc4fbedaadad3806d5a638e1adaed2dff8d", "74a9997f0fc630f429fd71bdf2e7fffba39fe3024ca1ded9f094b15f7ea3f79e"),
    ("2.5.1", "e546fae8cbfe95d8f36a351deb2cd23bfb94119e", "87d715029a47328172774638cabfeb04d5b356678d660621b796b6a671f93581", "8843249c9bc051b0c547e53888565ee5a23a40a49079a8cd63578ef1517ba56b"),
    ("2.5.2", "932fcf892eba8d646a9bfc58a59ea3b2475b17fa", "6c75c97223873807260352f269640935a07db0c26b3dbf12a98a36ec43ad9878", "a6452398f866efd173b3173cdffe7d0fc231649ca8a7283789094fd2496e725d"),
    ("2.5.3", "988c88d7ef54b4d4581629b229488dfba5e085ba", "fdc6da21ca6963560c32336fd7feb9cf2d5e52668f1a1647205a4b41171f0806", "adc30a9eb5c80093730ded08d5487b5ce03b55ab84ede907bb64cb408f841096"),
    ("2.5.4", "4f6d47246a053375271a5fd8af85c3b75695aa46", "436eaf9778cad75507ff70ea26ace30dcbe15606e619ac3823495663d7f7c115", "d0424c95859f7b4c1e308abf57c4cd72b9cba835bb946eb397172b799fba9477"),
    ("2.5.5", "028992583c693c4de6350b8aa52ff85e30375a99", "6150c4a6b62067db6141c8da7a6a6b5763f4f47c315343d0c848b40fecdfd452", "e59b4c73cfce6875363d25548222819433c6ce0af9c6d3ec9ede220e905723f9"),
)

TOP_LEVEL_KEYS = {
    "schema",
    "inventory_revision",
    "observed_on",
    "source_repository",
    "image_repository",
    "snapshot_lock",
    "verification",
    "records",
}
VERIFICATION_KEYS = {
    "git_version",
    "go_version",
    "skopeo_version",
    "github_cli_version",
    "github_releases_api_checked",
    "cosign_version",
    "cosign_module",
    "cosign_source_commit_sha1",
    "certificate_oidc_issuer",
    "certificate_identity_template",
    "signature_bundle_lock",
    "signature_bundle_lock_sha256",
    "oci_attestation_tags_checked",
    "github_attestations_api_checked",
    "cosign_claims_validated",
    "transparency_log_verified",
    "certificate_chain_verified",
    "attestation_observation",
}
RECORD_KEYS = {
    "version",
    "source",
    "image",
    "documentation",
    "compatibility_status",
    "security_notes",
}
SOURCE_KEYS = {
    "tag",
    "tag_kind",
    "tag_object_sha1",
    "peeled_commit_sha1",
    "commit_timestamp",
    "github_release_published_at",
    "tag_signature_status",
}
IMAGE_KEYS = {
    "tag",
    "index_digest",
    "linux_amd64_digest",
    "index_signature_status",
    "linux_amd64_signature_status",
    "certificate_identity",
    "certificate_oidc_issuer",
    "transparency_log_verified",
    "attestation_status",
}
DOCUMENTATION_KEYS = {
    "source_commit_sha1",
    "source_path",
    "normalized_openapi_status",
    "normalized_openapi_sha256",
}
SIGNATURE_TOP_LEVEL_KEYS = {
    "schema",
    "observed_on",
    "repository",
    "bundle_format",
    "records",
}
SIGNATURE_RECORD_KEYS = {
    "version",
    "index_bundle_sha256",
    "linux_amd64_bundle_sha256",
}


class LockValidationError(ValueError):
    """The release lock does not satisfy its fail-closed schema."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LockValidationError("release lock contains a duplicate JSON key")
        result[key] = value
    return result


def parse_json(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_LOCK_BYTES:
        raise LockValidationError("release lock exceeds the byte limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise LockValidationError("release lock is not valid UTF-8") from error
    try:
        document = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, LockValidationError) as error:
        raise LockValidationError("release lock is not valid duplicate-free JSON") from error
    if not isinstance(document, dict):
        raise LockValidationError("release lock root must be an object")
    validate_json_bounds(document)
    return document


def validate_json_bounds(value: Any) -> None:
    nodes = 0

    def visit(current: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise LockValidationError("release lock exceeds the node limit")
        if depth > MAX_JSON_DEPTH:
            raise LockValidationError("release lock exceeds the depth limit")
        if isinstance(current, str):
            if len(current.encode("utf-8")) > MAX_STRING_BYTES:
                raise LockValidationError("release lock string exceeds the byte limit")
        elif isinstance(current, list):
            if len(current) > MAX_RECORDS:
                raise LockValidationError("release lock array exceeds the item limit")
            for item in current:
                visit(item, depth + 1)
        elif isinstance(current, dict):
            if len(current) > 64:
                raise LockValidationError("release lock object exceeds the field limit")
            for key, item in current.items():
                visit(key, depth + 1)
                visit(item, depth + 1)
        elif current is not None and not isinstance(current, (bool, int)):
            raise LockValidationError("release lock contains an unsupported JSON value")

    visit(value, 0)


def require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise LockValidationError(f"{label} fields do not match the locked schema")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise LockValidationError(f"{label} must be a non-empty string")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise LockValidationError(f"{label} contains a control character")
    return value


def require_safe_relative_path(value: Any, label: str) -> str:
    path_text = require_string(value, label)
    if "\\" in path_text:
        raise LockValidationError(f"{label} must use POSIX separators")
    path = PurePosixPath(path_text)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise LockValidationError(f"{label} must be a normalized relative path")
    return path_text


def require_sha1(value: Any, label: str) -> str:
    text = require_string(value, label)
    if re.fullmatch(r"[0-9a-f]{40}", text) is None:
        raise LockValidationError(f"{label} must be a lowercase Git SHA-1 object ID")
    return text


def require_sha256_digest(value: Any, label: str) -> str:
    text = require_string(value, label)
    if re.fullmatch(r"sha256:[0-9a-f]{64}", text) is None:
        raise LockValidationError(f"{label} must be a lowercase SHA-256 digest")
    return text


def parse_version(value: Any) -> tuple[int, int, int]:
    text = require_string(value, "release version")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", text) is None:
        raise LockValidationError("release version is not canonical")
    components = tuple(int(component) for component in text.split("."))
    if any(str(component) != raw for component, raw in zip(components, text.split("."))):
        raise LockValidationError("release version contains a non-canonical component")
    return components  # type: ignore[return-value]


def validate_document(document: dict[str, Any]) -> None:
    require_exact_keys(document, TOP_LEVEL_KEYS, "release lock")
    if document["schema"] != "openbao-release-inventory/v1":
        raise LockValidationError("release lock schema is unsupported")
    if document["inventory_revision"] != 1:
        raise LockValidationError("release lock revision is unsupported")
    if document["observed_on"] != "2026-07-10":
        raise LockValidationError("release lock observation date changed")
    if document["source_repository"] != "https://github.com/openbao/openbao.git":
        raise LockValidationError("source repository is not the official immutable origin")
    if document["image_repository"] != "docker.io/openbao/openbao":
        raise LockValidationError("image repository is not the locked official origin")
    if require_safe_relative_path(document["snapshot_lock"], "snapshot lock") != "compat/api-snapshots.lock.json":
        raise LockValidationError("snapshot lock path changed")

    verification = require_exact_keys(document["verification"], VERIFICATION_KEYS, "verification")
    expected_verification = {
        "git_version": "2.54.0",
        "go_version": "1.26.4",
        "skopeo_version": "1.22.2",
        "github_cli_version": "2.95.0",
        "github_releases_api_checked": True,
        "cosign_version": "3.1.1",
        "cosign_module": "github.com/sigstore/cosign/v3@v3.1.1",
        "cosign_source_commit_sha1": "7914231b348c4057891edeb321772aad3ed04fce",
        "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
        "certificate_identity_template": "https://github.com/openbao/openbao/.github/workflows/release.yml@refs/tags/v{version}",
        "signature_bundle_lock": "compat/image-signatures.lock.json",
        "signature_bundle_lock_sha256": f"sha256:{EXPECTED_SIGNATURE_LOCK_SHA256}",
        "oci_attestation_tags_checked": True,
        "github_attestations_api_checked": True,
        "cosign_claims_validated": True,
        "transparency_log_verified": True,
        "certificate_chain_verified": True,
    }
    for key, expected in expected_verification.items():
        if verification[key] != expected:
            raise LockValidationError("release verification policy was downgraded")
    require_string(verification["attestation_observation"], "attestation observation")
    require_safe_relative_path(verification["signature_bundle_lock"], "signature bundle lock")

    records = document["records"]
    if not isinstance(records, list) or len(records) != len(EXPECTED_RELEASES):
        raise LockValidationError("release inventory must contain every locked release exactly once")

    seen_versions: set[str] = set()
    seen_source_tags: set[str] = set()
    seen_source_objects: set[str] = set()
    seen_image_tags: set[str] = set()
    seen_image_digests: set[str] = set()
    previous_version: tuple[int, int, int] | None = None

    for index, (record_value, expected) in enumerate(zip(records, EXPECTED_RELEASES)):
        record = require_exact_keys(record_value, RECORD_KEYS, f"record {index}")
        version, expected_source, expected_index, expected_amd64 = expected
        parsed_version = parse_version(record["version"])
        if record["version"] != version or (previous_version is not None and parsed_version <= previous_version):
            raise LockValidationError("release records were reordered, removed, or replaced")
        previous_version = parsed_version
        if version in seen_versions:
            raise LockValidationError("release inventory contains a duplicate version")
        seen_versions.add(version)

        source = require_exact_keys(record["source"], SOURCE_KEYS, f"source {version}")
        source_tag = require_string(source["tag"], f"source tag {version}")
        source_object = require_sha1(source["tag_object_sha1"], f"tag object {version}")
        peeled_commit = require_sha1(source["peeled_commit_sha1"], f"peeled commit {version}")
        if source_tag != f"v{version}" or source["tag_kind"] != "lightweight":
            raise LockValidationError("source tag identity or kind changed")
        if source_object != expected_source or peeled_commit != expected_source or source_object != peeled_commit:
            raise LockValidationError("lightweight tag object or peeled commit changed")
        if source["tag_signature_status"] != "not_available_lightweight_tag":
            raise LockValidationError("source tag signature status was misrepresented")
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|[+-][0-9]{2}:[0-9]{2})", require_string(source["commit_timestamp"], "commit timestamp")) is None:
            raise LockValidationError("source commit timestamp is malformed")
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", require_string(source["github_release_published_at"], "release publication timestamp")) is None:
            raise LockValidationError("GitHub release publication timestamp is malformed")
        if source_tag in seen_source_tags or source_object in seen_source_objects:
            raise LockValidationError("release inventory reuses a source identifier")
        seen_source_tags.add(source_tag)
        seen_source_objects.add(source_object)

        image = require_exact_keys(record["image"], IMAGE_KEYS, f"image {version}")
        image_tag = require_string(image["tag"], f"image tag {version}")
        index_digest = require_sha256_digest(image["index_digest"], f"image index {version}")
        amd64_digest = require_sha256_digest(image["linux_amd64_digest"], f"amd64 image {version}")
        if image_tag != version or image_tag == "latest":
            raise LockValidationError("image tag is mutable or does not match the release")
        if index_digest != f"sha256:{expected_index}" or amd64_digest != f"sha256:{expected_amd64}":
            raise LockValidationError("locked image digest changed")
        if image["index_signature_status"] != "verified_cosign_keyless" or image["linux_amd64_signature_status"] != "verified_cosign_keyless":
            raise LockValidationError("image signature verification status was downgraded")
        expected_identity = f"https://github.com/openbao/openbao/.github/workflows/release.yml@refs/tags/v{version}"
        if image["certificate_identity"] != expected_identity or image["certificate_oidc_issuer"] != "https://token.actions.githubusercontent.com":
            raise LockValidationError("image signer identity changed")
        if image["transparency_log_verified"] is not True:
            raise LockValidationError("image transparency-log verification was downgraded")
        if image["attestation_status"] != "not_published":
            raise LockValidationError("image attestation status changed without a reviewed schema update")
        if image_tag in seen_image_tags or index_digest in seen_image_digests or amd64_digest in seen_image_digests:
            raise LockValidationError("release inventory reuses an image identifier")
        seen_image_tags.add(image_tag)
        seen_image_digests.update((index_digest, amd64_digest))

        documentation = require_exact_keys(record["documentation"], DOCUMENTATION_KEYS, f"documentation {version}")
        if require_sha1(documentation["source_commit_sha1"], f"documentation commit {version}") != peeled_commit:
            raise LockValidationError("documentation source does not match the locked release commit")
        if require_safe_relative_path(documentation["source_path"], f"documentation path {version}") != "website/content/api-docs":
            raise LockValidationError("documentation source path changed")
        if documentation["normalized_openapi_status"] != "pending_commit_03" or documentation["normalized_openapi_sha256"] is not None:
            raise LockValidationError("API snapshot state must remain pending until the separate snapshot lock lands")
        if record["compatibility_status"] != "artifact_locked_api_pending":
            raise LockValidationError("compatibility status exceeds current evidence")
        notes = record["security_notes"]
        if not isinstance(notes, list) or len(notes) > 32:
            raise LockValidationError("security notes must be a bounded list")
        for note in notes:
            require_string(note, "security note")


def validate_signature_document(document: dict[str, Any]) -> None:
    require_exact_keys(document, SIGNATURE_TOP_LEVEL_KEYS, "signature evidence lock")
    if document["schema"] != "openbao-image-signature-evidence/v1":
        raise LockValidationError("signature evidence schema is unsupported")
    if document["observed_on"] != "2026-07-10":
        raise LockValidationError("signature evidence observation date changed")
    if document["repository"] != "docker.io/openbao/openbao":
        raise LockValidationError("signature evidence repository changed")
    if document["bundle_format"] != "application/vnd.dev.sigstore.bundle.v0.3+json newline stream":
        raise LockValidationError("signature evidence bundle format changed")
    records = document["records"]
    if not isinstance(records, list) or len(records) != len(EXPECTED_RELEASES):
        raise LockValidationError("signature evidence must cover every locked release")
    seen_bundle_hashes: set[str] = set()
    for index, (record_value, expected) in enumerate(zip(records, EXPECTED_RELEASES)):
        record = require_exact_keys(
            record_value, SIGNATURE_RECORD_KEYS, f"signature evidence {index}"
        )
        if record["version"] != expected[0]:
            raise LockValidationError("signature evidence records were reordered or replaced")
        index_hash = require_sha256_digest(
            record["index_bundle_sha256"], f"index signature bundle {expected[0]}"
        )
        amd64_hash = require_sha256_digest(
            record["linux_amd64_bundle_sha256"],
            f"amd64 signature bundle {expected[0]}",
        )
        if index_hash in seen_bundle_hashes or amd64_hash in seen_bundle_hashes:
            raise LockValidationError("signature evidence reuses a bundle fingerprint")
        seen_bundle_hashes.update((index_hash, amd64_hash))


def read_regular_file(path: Path, maximum: int) -> bytes:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    if no_follow is None or non_block is None:
        raise LockValidationError("secure non-blocking no-follow file reads are unavailable")

    flags = os.O_RDONLY | no_follow | non_block | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LockValidationError("release lock input could not be opened securely") from error

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise LockValidationError("release lock inputs must be regular files")
        if metadata.st_size > maximum:
            raise LockValidationError("release lock input exceeds its byte limit")

        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise LockValidationError("release lock input exceeds its byte limit")
        return data
    except OSError as error:
        raise LockValidationError("release lock input could not be read securely") from error
    finally:
        os.close(descriptor)


def require_content_digest(data: bytes, expected: str, label: str) -> None:
    if hashlib.sha256(data).hexdigest() != expected:
        raise LockValidationError(f"{label} does not match its immutable checksum")


def validate_lock_files() -> dict[str, Any]:
    lock_data = read_regular_file(LOCK_PATH, MAX_LOCK_BYTES)
    checksum_data = read_regular_file(CHECKSUM_PATH, 256)
    signature_data = read_regular_file(SIGNATURE_LOCK_PATH, MAX_LOCK_BYTES)
    signature_checksum_data = read_regular_file(SIGNATURE_CHECKSUM_PATH, 256)
    try:
        checksum_text = checksum_data.decode("ascii")
    except UnicodeDecodeError as error:
        raise LockValidationError("release lock checksum is not ASCII") from error
    match = re.fullmatch(r"([0-9a-f]{64})  releases\.lock\.json\n", checksum_text)
    if match is None or match.group(1) != EXPECTED_LOCK_SHA256:
        raise LockValidationError("release lock checksum anchor changed")
    require_content_digest(lock_data, EXPECTED_LOCK_SHA256, "release lock content")
    try:
        signature_checksum_text = signature_checksum_data.decode("ascii")
    except UnicodeDecodeError as error:
        raise LockValidationError("signature lock checksum is not ASCII") from error
    signature_match = re.fullmatch(
        r"([0-9a-f]{64})  image-signatures\.lock\.json\n", signature_checksum_text
    )
    if signature_match is None or signature_match.group(1) != EXPECTED_SIGNATURE_LOCK_SHA256:
        raise LockValidationError("signature lock checksum anchor changed")
    require_content_digest(
        signature_data,
        EXPECTED_SIGNATURE_LOCK_SHA256,
        "signature lock content",
    )
    document = parse_json(lock_data)
    validate_document(document)
    validate_signature_document(parse_json(signature_data))
    return document


def expect_rejected(label: str, operation: Any) -> None:
    try:
        operation()
    except LockValidationError:
        return
    raise LockValidationError(f"self-test did not reject {label}")


def run_self_tests() -> None:
    lock_data = read_regular_file(LOCK_PATH, MAX_LOCK_BYTES)
    signature_data = read_regular_file(SIGNATURE_LOCK_PATH, MAX_LOCK_BYTES)
    document = parse_json(lock_data)
    signature_document = parse_json(signature_data)
    validate_document(document)
    validate_signature_document(signature_document)

    expect_rejected("duplicate JSON keys", lambda: parse_json(b'{"schema":1,"schema":2}'))

    with tempfile.TemporaryDirectory(prefix="openbao-release-lock-") as directory:
        temporary_root = Path(directory)
        bounded_file = temporary_root / "bounded.json"
        bounded_file.write_bytes(b"x" * 17)
        expect_rejected(
            "oversized input before allocation",
            lambda: read_regular_file(bounded_file, 16),
        )

        target_file = temporary_root / "target.json"
        target_file.write_bytes(b"{}")
        symlink_file = temporary_root / "symlink.json"
        symlink_file.symlink_to(target_file)
        expect_rejected(
            "symbolic-link input",
            lambda: read_regular_file(symlink_file, MAX_LOCK_BYTES),
        )

        fifo_file = temporary_root / "input.fifo"
        os.mkfifo(fifo_file)
        expect_rejected(
            "FIFO input",
            lambda: read_regular_file(fifo_file, MAX_LOCK_BYTES),
        )

    reordered = copy.deepcopy(document)
    reordered["records"][0], reordered["records"][1] = reordered["records"][1], reordered["records"][0]
    expect_rejected("reordered records", lambda: validate_document(reordered))

    duplicate_version = copy.deepcopy(document)
    duplicate_version["records"][1]["version"] = duplicate_version["records"][0]["version"]
    expect_rejected("duplicate versions", lambda: validate_document(duplicate_version))

    duplicate_digest = copy.deepcopy(document)
    duplicate_digest["records"][1]["image"]["index_digest"] = duplicate_digest["records"][0]["image"]["index_digest"]
    expect_rejected("duplicate image digests", lambda: validate_document(duplicate_digest))

    traversal = copy.deepcopy(document)
    traversal["records"][0]["documentation"]["source_path"] = "../api-docs"
    expect_rejected("path traversal", lambda: validate_document(traversal))

    missing_hash = copy.deepcopy(document)
    missing_hash["records"][0]["image"]["index_digest"] = ""
    expect_rejected("missing artifact hashes", lambda: validate_document(missing_hash))

    mutable_tag = copy.deepcopy(document)
    mutable_tag["records"][0]["image"]["tag"] = "latest"
    expect_rejected("mutable image tags", lambda: validate_document(mutable_tag))

    verification_downgrade = copy.deepcopy(document)
    verification_downgrade["records"][0]["image"]["index_signature_status"] = "unverified"
    expect_rejected("verification downgrade", lambda: validate_document(verification_downgrade))

    tag_confusion = copy.deepcopy(document)
    tag_confusion["records"][0]["source"]["tag_kind"] = "annotated"
    expect_rejected("tag-object confusion", lambda: validate_document(tag_confusion))

    signature_reorder = copy.deepcopy(signature_document)
    signature_reorder["records"][0], signature_reorder["records"][1] = (
        signature_reorder["records"][1],
        signature_reorder["records"][0],
    )
    expect_rejected(
        "reordered signature evidence",
        lambda: validate_signature_document(signature_reorder),
    )

    duplicate_bundle = copy.deepcopy(signature_document)
    duplicate_bundle["records"][1]["index_bundle_sha256"] = duplicate_bundle["records"][0][
        "index_bundle_sha256"
    ]
    expect_rejected(
        "duplicate signature evidence",
        lambda: validate_signature_document(duplicate_bundle),
    )

    modified = lock_data.replace(b'"version": "2.0.0"', b'"version": "2.0.9"', 1)
    expect_rejected(
        "release lock checksum substitution",
        lambda: require_content_digest(modified, EXPECTED_LOCK_SHA256, "mutated release lock"),
    )

    modified_signatures = signature_data.replace(
        b'"version":"2.0.0"', b'"version":"2.0.9"', 1
    )
    expect_rejected(
        "signature lock checksum substitution",
        lambda: require_content_digest(
            modified_signatures,
            EXPECTED_SIGNATURE_LOCK_SHA256,
            "mutated signature lock",
        ),
    )


def main() -> int:
    try:
        validate_lock_files()
        if sys.argv[1:] == ["--self-test"]:
            run_self_tests()
            print("OpenBao release lock self-tests: ok")
        elif sys.argv[1:]:
            raise LockValidationError("unsupported validator argument")
        else:
            print("OpenBao release lock: 21 immutable release artifacts verified")
        return 0
    except (LockValidationError, OSError) as error:
        print(f"OpenBao release lock validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
