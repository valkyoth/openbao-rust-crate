#!/usr/bin/env python3
"""Generate and verify immutable OpenBao API evidence snapshots."""

from __future__ import annotations

import argparse
import copy
import hashlib
import html
import json
import os
import re
import secrets
import selectors
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

from validate_openbao_release_lock import (
    EXPECTED_LOCK_SHA256,
    LockValidationError,
    validate_lock_files,
)

ROOT = Path(__file__).resolve().parents[1]
COMPAT_ROOT = ROOT / "compat"
SNAPSHOT_ROOT = COMPAT_ROOT / "api-snapshots"
DIFF_ROOT = COMPAT_ROOT / "api-diffs"
RENDERED_ROOT = COMPAT_ROOT / "rendered-api-cross-checks"
SNAPSHOT_LOCK_PATH = COMPAT_ROOT / "api-snapshots.lock.json"
SNAPSHOT_CHECKSUM_PATH = COMPAT_ROOT / "api-snapshots.lock.sha256"

GENERATOR_VERSION = 1
OBSERVED_ON = "2026-07-17"
EXPECTED_SNAPSHOT_LOCK_SHA256 = "92b317b33daa1be8428f48d76caf8d65c6d331874a3a615c79ab2719929d63ba"
EXPECTED_SNAPSHOT_RECORDS = (
    ("2.0.0", "edc1e8daae71bba48e1656555a82a3ad5f80b497ce87918a0a1a7cc564627081", "6251b7f9e971bd5d791ccab4e43775228c27461883a1ed6587af22aa9a56dd95", None),
    ("2.0.1", "1ae9535ec91318fe990ae71aa93dfa9ea1ea81506c85a092965eca92bb9b07e6", "4b32092b3a8a9bcdcc25ff1e9182d9cd7fdaba91a7b781e575420e32b1a91e95", "5b9424973f9fcaa0e5a64f481a956425b23f32dfeb59504ca4e6522f10a64272"),
    ("2.0.2", "a18175a6e92896f60aad85bb5b15c8bc6445a1c3c237d11469c7edae95d1940f", "25daf16211faf30fa767c367d8b971033d3892c665fd4b5accfcd5b02ac5c8dc", "e3b175def2a248af509f0aa3ff1991f120bbbd0b7688226aca818cad1a8fc716"),
    ("2.0.3", "693388f5699f3ffb9038658d876e6ee75c92d5f2ce7388ed93150c391b4ef4ed", "4cedeed73f67712a82c7cd9e2d9eae4a1ec5e90a77dda6b297a69c2caa6b8aa6", "e7fe396f287fb2d5cf5a950b3e97dd16af9d0adf5917a9570a400e08e409dccb"),
    ("2.1.0", "1c9c11eff938aef529b81a4dd3312f2b7d245446ec95e7329f037404db7b294f", "b118f93b1ef34778c0f2b3a2ad0d8ac404d01ab66493ab6f719f7593be71c92c", "fe75272ef268a693a50dc6bc75ad6dd29ec1e5840ccd742f2075033c6b474c37"),
    ("2.1.1", "2ee18a7c83bfebf2debfbc618cd39cd55df5a95c35c04e09aa73378eeacfd903", "19cfcf3e4a25c123a96287a6fce8046ecc40e2c548cb60f1f66ed3bc2b9a5538", "70ad82267e5183869b9a3d88055c1f756bc59e326919b0b1b4eb672d16a6ae61"),
    ("2.2.0", "d0ee584b433427a80c36f8b8275796d8e705e3792ecd224e50bf2393dcc4c735", "08b6a56346777e7b3162545acbc8b8c9b706711af3aec35e1bde70806d5f3952", "9e831326ef904b478ce9c2fda1ae06d5c803125d1f23eef74c094e1d5fd133fe"),
    ("2.2.1", "5e232b09a989cdfae7cb54f1e7170cf1053bcf13a98c290fa611f74ee8c6df35", "a5ab87bfd593ab817cb5d39de11790b35072cd10d01c910b80f20c61497167e6", "2af541d023a69666de10bc18cd63c193554cafd12b5fabdeb00cc2585b5b236f"),
    ("2.2.2", "4d2f2c20dc20fa9e40c04ca78f867606738c817ab596fa1c37dbc0d3c267ab94", "245e06bf67e0b23fdb1d28dc38604f7e7ab5e8cf534fb777c2453189f84910d0", "5bd120784f3c9fecb83e8d340adfb41a00c641c2c0f9cafe7242f7052c6aeda5"),
    ("2.3.1", "95faa8704a0fd4855049cc82d5c84c493013d2d957db1922c88aa763cad09330", "0a35090685e93da18f4f70ce6ebf993260a2821c66c0d4a013220a13140b4f9d", "b44806f957be03a40fa9e470b284ee34c370a2f06db79baf270c2d93ba9b5b33"),
    ("2.3.2", "44d9d99ea938270972d2d9db11bbcba03e9be2762cf67bfd4a421363e50304d5", "39f03229ada6bb90a4d99714e6d8d671167b19b6ca32551e73ce1ccc36e4dd46", "51312b49aa605948b63c5f417d9e4dd7db4f0c6b249d39c04ef64179a97e18cf"),
    ("2.4.0", "e254e3f9a8002a887afd4611918b2707b7da3707bd800a03027f032369d1fdfd", "d06098ab4f303591b3c92178092b6ea5fb3859c96c47b863f8ed7625039d77b2", "3963f009cc6f4be6a8cfba4fd02e375e5b2595d3575b08cc9afd1d12189ce36c"),
    ("2.4.1", "95f44c5a63bb8ecb4b6e1646db8c926dc1ffc2549daaba383dd4028f20c80092", "2f55860da4e4a6e19b70b6aa8e567a6baa53230251b168a1d642b80099e12939", "d9c0d97d2e696aead21f8dbb79d3854b70281e65dd6205434547ed313c74b1ea"),
    ("2.4.3", "3e8cd4a8cc3a76fd11624d478189e281a3708f5837a5e4eec8e10aba1e66424f", "29ae28ded7eebc923206c5870d3a9ac0a827b1c08b3b88a049bf96a44ed92888", "3f97767539ce8d8a6b6b4cf5a23a0d168eb44faf65483123d7fb90a465dfd560"),
    ("2.4.4", "e0306721ca84f2106e272574d75271c7f8b939c3168b055ee217b7fa6f74c580", "42533c03c0f6e3226259210a7c21ef7e5ef87056f1058b58a62c152557d11786", "61c18b50439d09b1d7762b6da8e4b9adecc1a3adf59a743b9e814d369eefd595"),
    ("2.5.0", "9191dd1712f6c53bdf93e92a5b7c6328cc0a9bde751742007cb882cf8f14b243", "6bbbbe3a3f4b6e0bcb47ea4d8e485eabaae559ef5f4e8e62a49196819708208f", "a5c6c86ba035fbf09cc23b3bb1ed5a92ab77218aafc6537a3726c81897a528d5"),
    ("2.5.1", "8e4c434532477570a2990599150d37746003433edeb9292d5b83305c4cc4951d", "b71f9fec0e35509b6980624f3d4e28b2636451a85c12a1ff1440a9f533cfa956", "6d121a6589f15a0787078e8283db618600d3ed190410e4cec4cf3ecdc6333b79"),
    ("2.5.2", "59e81215c7d1c8d94b2596c6c3c3df6e991ff56181382c41dd64a2b613f69692", "7f8d875b8f8d44483024e758c75ceea32ab59182f3d7bb6176b67239220832b1", "047f17f9b083ada57870401981873f6d44db7459cd7045432d2a9a9f5e999e21"),
    ("2.5.3", "bf82462ec7d30e2cbfc7c03905da930f609e37e3f4960c5e083e34be7c58376b", "9ea04ce4b2f2c2ae3cdd15bcd705e664e0957f5789d1a0b7e80a4edf0547b886", "ba06610c4480fe5ae565718629396ada6884d32b29c40b27223255c222d199fb"),
    ("2.5.4", "412840864974eff0b65f8506681a275483da285cd82822719bab92cee7e36822", "d8e2dcc85f8bf50076abe9fa7635aa5bfa7750f3dc27dc9baa4c0b4bc43c9430", "d95b39e69411e409cd93d707b7c510e1b063106ce4efeeab9e10db875dd76841"),
    ("2.5.5", "511d18f9bf894cba50c857c247cf3a22b8fd3529144039f27c3552209557be63", "e959918796dd3b67b1ecd3562841e949d1db35af278d3519622cc690b0c696d4", "88b414dfdb76a17a0cb92a6d52da07ce24cd83903d7ffb6ca00d4de692234e5e"),
    ("2.6.0", "d6ab7dfebcad55bed1c2fb383af00d1141018a4373571c850705f8e684eb934d", "3479568c017fa999258a9e1022299d8be6283b1b02c8994bdcd88c27afd10442", "be2a87012e39b8c66ef07ec51b0014b1ffafc5849a9a7b1215ab3b24f2fa7865"),
)
MAX_LOCK_BYTES = 256 * 1024
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_OPENAPI_BYTES = 32 * 1024 * 1024
MAX_DOC_FILE_BYTES = 2 * 1024 * 1024
MAX_DOC_TOTAL_BYTES = 32 * 1024 * 1024
MAX_RENDERED_PAGE_BYTES = 4 * 1024 * 1024
MAX_RENDERED_TOTAL_BYTES = 96 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 1_000_000
MAX_JSON_STRING_BYTES = 2 * 1024 * 1024
MAX_DOC_FILES = 512
MAX_OPERATIONS = 4_096
MAX_FIELDS_PER_SECTION = 1_024
MAX_RENDERED_PAGES = 512
MAX_DIFF_CHANGES = 250_000
CONTAINER_MEMORY_BYTES = 1024 * 1024 * 1024
CONTAINER_MEMORY_SWAP_BYTES = 2 * CONTAINER_MEMORY_BYTES
CONTAINER_NANO_CPUS = 1_000_000_000
CONTAINER_PIDS_LIMIT = 256
CONTAINER_RESOURCE_OPTIONS = (
    "--memory",
    "1g",
    "--memory-swap",
    "2g",
    "--cpus",
    "1",
    "--pids-limit",
    "256",
    "--stop-timeout",
    "5",
    "--ulimit",
    "data=1073741824:1073741824",
    "--ulimit",
    "cpu=300:300",
    "--ulimit",
    "nofile=1024:1024",
    "--ulimit",
    "nproc=256:256",
)

DOC_PREFIX = "website/content/api-docs"
HTTP_METHODS = frozenset(("delete", "get", "head", "options", "patch", "post", "put", "trace"))
DOCUMENTED_METHODS = frozenset(
    ("ACME", "DELETE", "GET", "HEAD", "LIST", "PATCH", "POST", "PUT", "SCAN")
)
ANNOTATION_KEYS = frozenset(("description", "example", "examples", "externalDocs", "summary", "tags"))
NAMED_OPENAPI_MAPS = frozenset(
    (
        "$defs",
        "content",
        "definitions",
        "dependentRequired",
        "dependentSchemas",
        "encoding",
        "headers",
        "links",
        "mapping",
        "parameters",
        "pathItems",
        "paths",
        "patternProperties",
        "properties",
        "requestBodies",
        "responses",
        "schemas",
        "scopes",
        "securitySchemes",
        "variables",
        "webhooks",
    )
)
NESTED_NAMED_OPENAPI_MAPS = frozenset(("callbacks",))
NAMED_OPENAPI_MAP_ARRAYS = frozenset(("security",))
METHOD_ROW = re.compile(
    r"^\|\s*`?([A-Z]+(?:/[A-Z]+)*)`?\s*\|\s*`([^`]+)`",
    re.ASCII,
)
FIELD_ROW = re.compile(r"^\s*[-*]\s+`([^`]{1,256})`\s+`\(([^`]{1,512})\)`", re.ASCII)
HEADING = re.compile(r"^(#{2,6})\s+(.{1,512})$")
GIT_TREE_ROW = re.compile(rb"100644 blob ([0-9a-f]{40}) +([0-9]+)\t([^\x00]+)\x00")
HTML_ENDPOINT_ROW = re.compile(
    rb"<tr><td[^>]*><code>([^<]{1,128})</code><td[^>]*><code>([^<]{1,4096})</code>"
)

SECRET_MOUNTS = (
    ("kv-v1", "kv", ("-version=1",)),
    ("kv-v2", "kv", ("-version=2",)),
    ("database", "database", ()),
    ("kubernetes", "kubernetes", ()),
    ("ldap", "ldap", ()),
    ("pki", "pki", ()),
    ("rabbitmq", "rabbitmq", ()),
    ("ssh", "ssh", ()),
    ("totp", "totp", ()),
    ("transit", "transit", ()),
)
AUTH_MOUNTS = (
    ("approle", "approle"),
    ("cert", "cert"),
    ("jwt", "jwt"),
    ("kerberos", "kerberos"),
    ("kubernetes", "kubernetes"),
    ("ldap", "ldap"),
    ("radius", "radius"),
    ("userpass", "userpass"),
)


class SnapshotError(ValueError):
    """API evidence could not be generated or verified safely."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError("snapshot JSON contains a duplicate key")
        result[key] = value
    return result


def reject_non_finite_constant(_value: str) -> None:
    raise SnapshotError("snapshot JSON contains a non-finite number")


def scan_json_bounds(data: bytes, maximum: int) -> None:
    if len(data) > maximum:
        raise SnapshotError("snapshot JSON exceeds its byte limit")
    depth = 0
    structural_nodes = 0
    string_bytes = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
                string_bytes = 0
            else:
                string_bytes += 1
                if string_bytes > MAX_JSON_STRING_BYTES:
                    raise SnapshotError("snapshot JSON string exceeds its byte limit")
            continue
        if byte == 0x22:
            in_string = True
            string_bytes = 0
        elif byte in (0x7B, 0x5B):
            depth += 1
            structural_nodes += 1
            if depth > MAX_JSON_DEPTH:
                raise SnapshotError("snapshot JSON exceeds its depth limit")
        elif byte in (0x7D, 0x5D):
            depth -= 1
            if depth < 0:
                raise SnapshotError("snapshot JSON has unbalanced delimiters")
        elif byte in (0x2C, 0x3A):
            structural_nodes += 1
        if structural_nodes > MAX_JSON_NODES:
            raise SnapshotError("snapshot JSON exceeds its structural-node limit")
    if in_string or depth != 0:
        raise SnapshotError("snapshot JSON is structurally incomplete")


def validate_json_tree(value: Any) -> None:
    nodes = 0

    def visit(current: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise SnapshotError("snapshot JSON exceeds its node limit")
        if depth > MAX_JSON_DEPTH:
            raise SnapshotError("snapshot JSON exceeds its depth limit")
        if isinstance(current, str):
            if len(current.encode()) > MAX_JSON_STRING_BYTES:
                raise SnapshotError("snapshot JSON string exceeds its byte limit")
        elif isinstance(current, list):
            if len(current) > MAX_JSON_NODES:
                raise SnapshotError("snapshot JSON array exceeds its item limit")
            for item in current:
                visit(item, depth + 1)
        elif isinstance(current, dict):
            if len(current) > MAX_JSON_NODES:
                raise SnapshotError("snapshot JSON object exceeds its field limit")
            for key, item in current.items():
                if not isinstance(key, str):
                    raise SnapshotError("snapshot JSON object key is not text")
                visit(key, depth + 1)
                visit(item, depth + 1)
        elif current is not None and not isinstance(current, (bool, int, float)):
            raise SnapshotError("snapshot JSON contains an unsupported value")

    visit(value, 0)


def parse_json(data: bytes, maximum: int) -> dict[str, Any]:
    scan_json_bounds(data, maximum)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SnapshotError("snapshot JSON is not valid UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_non_finite_constant,
        )
    except (json.JSONDecodeError, SnapshotError) as error:
        raise SnapshotError("snapshot JSON is not valid duplicate-free JSON") from error
    if not isinstance(value, dict):
        raise SnapshotError("snapshot JSON root must be an object")
    validate_json_tree(value)
    return value


def safe_relative_path(value: str, label: str) -> PurePosixPath:
    if not value or len(value.encode()) > 1_024 or "\\" in value:
        raise SnapshotError(f"{label} is not a bounded POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise SnapshotError(f"{label} is not a normalized relative path")
    return path


def require_repo_path(relative: str) -> Path:
    pure = safe_relative_path(relative, "snapshot artifact path")
    candidate = ROOT.joinpath(*pure.parts)
    current = ROOT
    for part in pure.parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise SnapshotError("snapshot artifact parent must not be a symbolic link")
    return candidate


def read_regular_file(path: Path, maximum: int) -> bytes:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or non_block is None or directory_flag is None:
        raise SnapshotError("secure directory-relative file reads are unavailable")
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    absolute = path.absolute()
    if not absolute.parts or absolute.name in ("", ".", ".."):
        raise SnapshotError("snapshot input path is incomplete")
    directory_flags = os.O_RDONLY | no_follow | non_block | directory_flag | close_on_exec
    try:
        directory = os.open(absolute.anchor, directory_flags)
        for part in absolute.parts[1:-1]:
            next_directory = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = next_directory
    except OSError as error:
        if "directory" in locals():
            os.close(directory)
        raise SnapshotError("snapshot input parent could not be opened securely") from error
    flags = os.O_RDONLY | no_follow | non_block | close_on_exec
    try:
        descriptor = os.open(absolute.name, flags, dir_fd=directory)
    except OSError as error:
        raise SnapshotError("snapshot input could not be opened securely") from error
    finally:
        os.close(directory)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SnapshotError("snapshot inputs must be regular files")
        if metadata.st_size > maximum:
            raise SnapshotError("snapshot input exceeds its byte limit")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise SnapshotError("snapshot input exceeds its byte limit")
        return data
    except OSError as error:
        raise SnapshotError("snapshot input could not be read securely") from error
    finally:
        os.close(descriptor)


def ensure_output_parent(path: Path) -> None:
    relative = path.relative_to(ROOT).as_posix()
    require_repo_path(relative)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    current = ROOT
    for part in path.relative_to(ROOT).parts[:-1]:
        current = current / part
        if current.is_symlink() or not current.is_dir():
            raise SnapshotError("snapshot output parent is not a regular directory")


def write_immutable(path: Path, data: bytes) -> None:
    ensure_output_parent(path)
    if path.exists() or path.is_symlink():
        existing = read_regular_file(path, max(len(data), MAX_SNAPSHOT_BYTES))
        if existing != data:
            raise SnapshotError(f"existing snapshot would change: {path.relative_to(ROOT)}")
        return
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def run_bounded(
    command: list[str],
    maximum: int,
    *,
    timeout: float,
    environment: dict[str, str] | None = None,
    accepted_codes: tuple[int, ...] = (0,),
) -> tuple[int, bytes]:
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=environment,
        close_fds=True,
    )
    if process.stdout is None:
        process.kill()
        raise SnapshotError("bounded command did not expose stdout")
    descriptor = process.stdout.fileno()
    os.set_blocking(descriptor, False)
    selector = selectors.DefaultSelector()
    selector.register(descriptor, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    output = bytearray()
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                raise SnapshotError("bounded command timed out")
            events = selector.select(min(remaining, 0.25))
            if not events and process.poll() is not None:
                events = [(selector.get_key(descriptor), selectors.EVENT_READ)]
            for key, _ in events:
                chunk = os.read(key.fd, min(64 * 1024, maximum + 1 - len(output)))
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                output.extend(chunk)
                if len(output) > maximum:
                    process.kill()
                    raise SnapshotError("bounded command output exceeds its byte limit")
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
    if return_code not in accepted_codes:
        raise SnapshotError("evidence command failed without exposing its output")
    return return_code, bytes(output)


def run_quiet(command: list[str], *, timeout: float, environment: dict[str, str] | None = None) -> None:
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=timeout,
            check=False,
            close_fds=True,
        )
    except subprocess.TimeoutExpired as error:
        raise SnapshotError("evidence command timed out") from error
    if result.returncode != 0:
        raise SnapshotError("evidence command failed without exposing its output")


def validate_source_repository(path_text: str) -> Path:
    candidate = Path(path_text)
    if candidate.is_symlink():
        raise SnapshotError("source repository must not be a symbolic link")
    try:
        path = candidate.resolve(strict=True)
    except OSError as error:
        raise SnapshotError("source repository is unavailable") from error
    if not path.is_dir():
        raise SnapshotError("source repository is not a directory")
    _, remote = run_bounded(
        ["git", "-C", str(path), "remote", "get-url", "origin"],
        1_024,
        timeout=10,
    )
    if remote.strip() not in (
        b"https://github.com/openbao/openbao.git",
        b"git@github.com:openbao/openbao.git",
    ):
        raise SnapshotError("source repository origin is not the official OpenBao repository")
    return path


def git_output(repository: Path, arguments: list[str], maximum: int) -> bytes:
    _, output = run_bounded(
        ["git", "-C", str(repository), *arguments],
        maximum,
        timeout=60,
    )
    return output


def validate_text(value: str, label: str, maximum: int = 4_096) -> str:
    if not value or len(value.encode()) > maximum:
        raise SnapshotError(f"{label} is empty or exceeds its byte limit")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise SnapshotError(f"{label} contains a control character")
    return value


def parse_doc_block(source: str, block: list[str]) -> list[dict[str, Any]]:
    if not block:
        return []
    heading_match = HEADING.match(block[0])
    if heading_match is None or len(heading_match.group(1)) != 2:
        return []
    heading = validate_text(heading_match.group(2).strip(), "documentation heading", 512)
    section = "body"
    fields: list[dict[str, str]] = []
    endpoints: list[tuple[list[str], str, str]] = []
    for line in block[1:]:
        heading_row = HEADING.match(line)
        if heading_row is not None:
            section = heading_row.group(2).strip().lower().replace(" ", "-")[:128]
            continue
        field = FIELD_ROW.match(line)
        if field is not None:
            if len(fields) >= MAX_FIELDS_PER_SECTION:
                raise SnapshotError("documentation field count exceeds its limit")
            fields.append(
                {
                    "name": validate_text(field.group(1).strip(), "documentation field", 256),
                    "section": section,
                    "signature": validate_text(field.group(2).strip(), "documentation field signature", 512),
                }
            )
        endpoint = METHOD_ROW.match(line)
        if endpoint is None:
            continue
        methods = endpoint.group(1).split("/")
        if any(method not in DOCUMENTED_METHODS for method in methods):
            raise SnapshotError("documentation contains an unsupported method token")
        path = html.unescape(endpoint.group(2).strip()).replace("\\|", "|")
        validate_text(path, "documented endpoint path")
        path_style = "absolute"
        if not path.startswith("/"):
            path = "/" + path
            path_style = "relative-normalized"
        endpoints.append((methods, path, path_style))
    operations: list[dict[str, Any]] = []
    for methods, path, path_style in endpoints:
        for method in methods:
            operations.append(
                {
                    "fields": copy.deepcopy(fields),
                    "heading": heading,
                    "method": method,
                    "path": path,
                    "path_style": path_style,
                    "source": source,
                }
            )
    return operations


def extract_documentation(repository: Path, release: dict[str, Any]) -> dict[str, Any]:
    version = release["version"]
    commit = release["source"]["peeled_commit_sha1"]
    resolved = git_output(repository, ["rev-parse", "--verify", f"{commit}^{{commit}}"], 128).strip().decode()
    if resolved != commit:
        raise SnapshotError("tagged documentation commit does not match the release lock")
    tree = git_output(
        repository,
        ["ls-tree", "-r", "-z", "--long", commit, "--", DOC_PREFIX],
        2 * 1024 * 1024,
    )
    rows = GIT_TREE_ROW.findall(tree)
    if not rows or len(rows) > MAX_DOC_FILES:
        raise SnapshotError("tagged documentation file count is outside its bound")
    if b"".join(match.group(0) for match in GIT_TREE_ROW.finditer(tree)) != tree:
        raise SnapshotError("tagged documentation tree contains an unsupported entry")
    files: list[dict[str, Any]] = []
    operations: list[dict[str, Any]] = []
    total = 0
    for object_id_raw, size_raw, path_raw in rows:
        try:
            path_text = path_raw.decode("utf-8")
            size = int(size_raw)
        except (UnicodeDecodeError, ValueError) as error:
            raise SnapshotError("tagged documentation tree metadata is invalid") from error
        pure = safe_relative_path(path_text, "tagged documentation path")
        if pure.parts[:3] != ("website", "content", "api-docs") or pure.suffix != ".mdx":
            raise SnapshotError("tagged documentation tree contains an unexpected file")
        if size > MAX_DOC_FILE_BYTES:
            raise SnapshotError("tagged documentation file exceeds its byte limit")
        total += size
        if total > MAX_DOC_TOTAL_BYTES:
            raise SnapshotError("tagged documentation tree exceeds its byte limit")
        object_id = object_id_raw.decode("ascii")
        blob = git_output(repository, ["cat-file", "blob", object_id], size + 1)
        if len(blob) != size:
            raise SnapshotError("tagged documentation blob size changed")
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SnapshotError("tagged documentation is not valid UTF-8") from error
        lines = text.splitlines()
        block: list[str] = []
        for line in lines:
            if line.startswith("## "):
                operations.extend(parse_doc_block(path_text, block))
                block = [line]
            elif block:
                block.append(line)
        operations.extend(parse_doc_block(path_text, block))
        files.append(
            {
                "blob_sha1": object_id,
                "bytes": size,
                "path": path_text,
                "sha256": sha256(blob),
            }
        )
    if len(operations) > MAX_OPERATIONS:
        raise SnapshotError("tagged documentation operation count exceeds its limit")
    files.sort(key=lambda item: item["path"])
    operations.sort(key=lambda item: (item["method"], item["path"], item["source"], item["heading"]))
    return {
        "schema": "openbao-tagged-api-documentation/v1",
        "generator_version": GENERATOR_VERSION,
        "version": version,
        "source_commit_sha1": commit,
        "source_path": DOC_PREFIX,
        "files": files,
        "operations": operations,
    }


def contract_only_legacy(value: Any) -> Any:
    """Reproduce the immutable v1 snapshots, including annotation-name collisions."""
    if isinstance(value, dict):
        return {
            key: contract_only_legacy(item)
            for key, item in sorted(value.items())
            if key not in ANNOTATION_KEYS
        }
    if isinstance(value, list):
        return [contract_only_legacy(item) for item in value]
    return value


def contract_only(
    value: Any,
    *,
    names_are_data: bool = False,
    map_values_are_named_maps: bool = False,
    array_items_are_named_maps: bool = False,
) -> Any:
    """Remove annotations while preserving identifiers in named OpenAPI maps."""
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in sorted(value.items()):
            if not names_are_data and key in ANNOTATION_KEYS:
                continue
            item_is_map = isinstance(item, dict)
            item_is_reference = item_is_map and "$ref" in item
            if names_are_data:
                child_names_are_data = (
                    map_values_are_named_maps and item_is_map and not item_is_reference
                )
                child_map_values_are_named_maps = False
                child_array_items_are_named_maps = False
            else:
                child_names_are_data = item_is_map and (
                    key in NAMED_OPENAPI_MAPS or key in NESTED_NAMED_OPENAPI_MAPS
                )
                child_map_values_are_named_maps = (
                    item_is_map and key in NESTED_NAMED_OPENAPI_MAPS
                )
                child_array_items_are_named_maps = (
                    isinstance(item, list) and key in NAMED_OPENAPI_MAP_ARRAYS
                )
            result[key] = contract_only(
                item,
                names_are_data=child_names_are_data,
                map_values_are_named_maps=child_map_values_are_named_maps,
                array_items_are_named_maps=child_array_items_are_named_maps,
            )
        return result
    if isinstance(value, list):
        return [
            contract_only(item, names_are_data=array_items_are_named_maps)
            for item in value
        ]
    return value


def deterministic_byte_mutations(seed: bytes, limit: int = 512) -> list[bytes]:
    """Return a bounded, deterministic parser corpus derived from one artifact."""
    if not seed or limit <= 0:
        return []
    mutations = [b"", seed[:1], seed[:-1], seed + b"\x00", seed + b"{}"]
    stride = max(1, len(seed) // max(1, limit // 4))
    for offset in range(0, len(seed), stride):
        for replacement in (0, ord('"'), ord('{'), 0xFF):
            changed = bytearray(seed)
            changed[offset] = replacement
            mutations.append(bytes(changed))
            if len(mutations) >= limit:
                return mutations
    return mutations[:limit]


def podman_environment(token: str) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "BAO_ADDR": "http://127.0.0.1:8200",
            "BAO_DEV_LISTEN_ADDRESS": "127.0.0.1:8200",
            "BAO_DEV_ROOT_TOKEN_ID": token,
            "BAO_DISABLE_MLOCK": "true",
            "BAO_TOKEN": token,
            "HOME": "/tmp",
        }
    )
    return environment


def bao_command(container: str, token: str, arguments: list[str], maximum: int = 64 * 1024) -> bytes:
    environment = podman_environment(token)
    _, output = run_bounded(
        [
            "podman",
            "exec",
            "--env",
            "BAO_ADDR",
            "--env",
            "BAO_TOKEN",
            "--env",
            "HOME",
            container,
            "bao",
            *arguments,
        ],
        maximum,
        timeout=120,
        environment=environment,
    )
    return output


def ensure_container_removed(container: str) -> None:
    run_bounded(
        ["podman", "rm", "--force", container],
        4 * 1024,
        timeout=60,
        accepted_codes=(0, 1),
    )
    exists_code, _ = run_bounded(
        ["podman", "container", "exists", container],
        256,
        timeout=15,
        accepted_codes=(0, 1),
    )
    if exists_code == 0:
        raise SnapshotError("API evidence container survived cleanup")


def validate_container_resource_config(config: Any) -> None:
    if not isinstance(config, dict):
        raise SnapshotError("API evidence container resource configuration is malformed")
    expected = {
        "Memory": CONTAINER_MEMORY_BYTES,
        "MemorySwap": CONTAINER_MEMORY_SWAP_BYTES,
        "NanoCpus": CONTAINER_NANO_CPUS,
        "PidsLimit": CONTAINER_PIDS_LIMIT,
    }
    if any(config.get(key) != value for key, value in expected.items()):
        raise SnapshotError("API evidence container aggregate resource limits were not applied")


def verify_container_resource_limits(container: str) -> None:
    _, output = run_bounded(
        ["podman", "inspect", "--format", "{{json .HostConfig}}", container],
        64 * 1024,
        timeout=30,
    )
    validate_container_resource_config(parse_json(output, 64 * 1024))


def capture_openapi(
    release: dict[str, Any],
    *,
    legacy_annotation_collisions: bool = False,
) -> dict[str, Any]:
    version = release["version"]
    index_digest = release["image"]["index_digest"]
    amd64_digest = release["image"]["linux_amd64_digest"]
    image = f"docker.io/openbao/openbao@{index_digest}"
    _, index_data = run_bounded(
        ["skopeo", "inspect", "--raw", f"docker://{image}"],
        2 * 1024 * 1024,
        timeout=120,
    )
    index = parse_json(index_data, 2 * 1024 * 1024)
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise SnapshotError("locked OCI index does not contain a manifest list")
    matching_digests = [
        manifest.get("digest")
        for manifest in manifests
        if isinstance(manifest, dict)
        and isinstance(manifest.get("platform"), dict)
        and manifest["platform"].get("architecture") == "amd64"
        and manifest["platform"].get("os") == "linux"
    ]
    if matching_digests != [amd64_digest]:
        raise SnapshotError("locked OCI index does not resolve to the locked Linux amd64 manifest")
    run_quiet(["podman", "pull", "--platform", "linux/amd64", image], timeout=900)
    _, inspect_output = run_bounded(
        [
            "podman",
            "image",
            "inspect",
            "--format",
            "{{.Digest}} {{.Architecture}} {{.Os}}",
            image,
        ],
        1_024,
        timeout=60,
    )
    try:
        inspected_digest, architecture, operating_system = inspect_output.decode("ascii").split()
    except (UnicodeDecodeError, ValueError) as error:
        raise SnapshotError("locked server image inspection is malformed") from error
    if inspected_digest != index_digest or architecture != "amd64" or operating_system != "linux":
        raise SnapshotError("pulled server image does not match the locked Linux amd64 artifact")

    token = secrets.token_urlsafe(32)
    container = f"openbao-api-evidence-{version.replace('.', '-')}-{secrets.token_hex(6)}"
    environment = podman_environment(token)
    run_command = [
        "podman",
        "run",
        "-d",
        "--name",
        container,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--user",
        "100:1000",
        "--cap-drop",
        "all",
        "--security-opt",
        "no-new-privileges",
        *CONTAINER_RESOURCE_OPTIONS,
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=32m,mode=700",
        "--env",
        "BAO_DEV_ROOT_TOKEN_ID",
        "--env",
        "BAO_DEV_LISTEN_ADDRESS",
        "--env",
        "BAO_DISABLE_MLOCK",
        "--env",
        "HOME",
        image,
        "server",
        "-dev",
        "-dev-no-store-token",
    ]
    try:
        run_bounded(run_command, 1_024, timeout=120, environment=environment)
        verify_container_resource_limits(container)
        status: dict[str, Any] | None = None
        for _ in range(120):
            try:
                status = parse_json(
                    bao_command(container, token, ["status", "-format=json"], 1024 * 1024),
                    1024 * 1024,
                )
                break
            except SnapshotError:
                time.sleep(0.25)
        if status is None or status.get("version") != version:
            raise SnapshotError("locked server artifact reported an unexpected version")

        bao_command(container, token, ["secrets", "disable", "secret"])
        mounts: list[dict[str, str]] = []
        for path, plugin_type, options in SECRET_MOUNTS:
            bao_command(
                container,
                token,
                ["secrets", "enable", f"-path={path}", *options, plugin_type],
            )
            mounts.append({"kind": "secret", "path": path, "type": plugin_type})
        for path, plugin_type in AUTH_MOUNTS:
            bao_command(container, token, ["auth", "enable", f"-path={path}", plugin_type])
            mounts.append({"kind": "auth", "path": path, "type": plugin_type})

        envelope = parse_json(
            bao_command(
                container,
                token,
                ["write", "-format=json", "sys/internal/specs/openapi", "generic_mount_paths=true"],
                MAX_OPENAPI_BYTES,
            ),
            MAX_OPENAPI_BYTES,
        )
        document = envelope.get("data")
        if not isinstance(document, dict):
            raise SnapshotError("OpenAPI response did not contain an object document")
        validate_json_tree(document)
        if not str(document.get("openapi", "")).startswith("3."):
            raise SnapshotError("server artifact returned an unsupported OpenAPI version")
        info = document.get("info")
        if not isinstance(info, dict) or info.get("version") != version:
            raise SnapshotError("OpenAPI document version does not match the locked release")
        paths = document.get("paths")
        components = document.get("components")
        if not isinstance(paths, dict) or not isinstance(components, dict):
            raise SnapshotError("OpenAPI document is missing paths or components")
        if legacy_annotation_collisions:
            normalized = contract_only_legacy(document)
            normalized_schema = "openbao-normalized-openapi/v1"
        else:
            normalized = contract_only(document)
            normalized_schema = "openbao-normalized-openapi/v2"
        operation_count = sum(
            1
            for path_item in paths.values()
            if isinstance(path_item, dict)
            for method in path_item
            if method in HTTP_METHODS
        )
        schemas = components.get("schemas", {})
        if not isinstance(schemas, dict):
            raise SnapshotError("OpenAPI components.schemas is not an object")
        return {
            "schema": normalized_schema,
            "generator_version": GENERATOR_VERSION,
            "version": version,
            "image_index_digest": index_digest,
            "image_linux_amd64_digest": amd64_digest,
            "mounts": mounts,
            "path_count": len(paths),
            "operation_count": operation_count,
            "schema_count": len(schemas),
            "document": normalized,
        }
    finally:
        try:
            ensure_container_removed(container)
        finally:
            token = ""
            environment["BAO_DEV_ROOT_TOKEN_ID"] = ""
            environment["BAO_TOKEN"] = ""


def rendered_line(version: str) -> tuple[str, tuple[str, ...]] | None:
    minor = ".".join(version.split(".")[:2])
    if minor == "2.3":
        return ("2.3.x", ("/api-docs/2.3.x/auth/", "/api-docs/2.3.x/secret/", "/api-docs/2.3.x/system/"))
    if minor == "2.4":
        return ("2.4.x", ("/api-docs/2.4.x/auth/", "/api-docs/2.4.x/secret/", "/api-docs/2.4.x/system/"))
    if minor == "2.5":
        return ("2.5.x-current", ("/api-docs/auth/", "/api-docs/secret/", "/api-docs/system/"))
    if minor == "2.6":
        return ("2.6.x-current", ("/api-docs/auth/", "/api-docs/secret/", "/api-docs/system/"))
    return None


def fetch_rendered_page(path: str) -> bytes:
    url = urllib.parse.urljoin("https://openbao.org", path)
    request = urllib.request.Request(url, headers={"User-Agent": "openbao-rust-crate-api-evidence/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if (
            final.scheme != "https"
            or final.hostname != "openbao.org"
            or urllib.parse.unquote(final.path) != path
            or final.query
            or final.fragment
        ):
            raise SnapshotError("rendered documentation redirected outside openbao.org")
        content_type = response.headers.get_content_type()
        if content_type != "text/html":
            raise SnapshotError("rendered documentation did not return HTML")
        length = response.headers.get("Content-Length")
        if length is not None:
            try:
                content_length = int(length)
            except ValueError as error:
                raise SnapshotError("rendered documentation content length is malformed") from error
            if content_length < 0 or content_length > MAX_RENDERED_PAGE_BYTES:
                raise SnapshotError("rendered documentation page exceeds its byte limit")
        data = response.read(MAX_RENDERED_PAGE_BYTES + 1)
    if len(data) > MAX_RENDERED_PAGE_BYTES:
        raise SnapshotError("rendered documentation page exceeds its byte limit")
    return data


def capture_rendered_cross_check(
    label: str,
    roots: tuple[str, ...],
    *,
    observed_on: str = OBSERVED_ON,
) -> dict[str, Any]:
    base_prefix = roots[0].removesuffix("auth/")
    link_pattern = re.compile(
        rb'href=(?:"|\')?(' + re.escape(base_prefix.encode()) + rb'(?:auth|secret|system)/[^"\' >#?]+/)(?:"|\')?'
    )
    pending = list(roots)
    seen: set[str] = set()
    pages: list[dict[str, Any]] = []
    operations: set[tuple[str, str, str]] = set()
    total = 0
    while pending:
        path = pending.pop(0)
        if path in seen:
            continue
        if not any(path.startswith(root) for root in roots):
            raise SnapshotError("rendered documentation crawl escaped its version roots")
        seen.add(path)
        if len(seen) > MAX_RENDERED_PAGES:
            raise SnapshotError("rendered documentation crawl exceeds its page limit")
        page = fetch_rendered_page(path)
        total += len(page)
        if total > MAX_RENDERED_TOTAL_BYTES:
            raise SnapshotError("rendered documentation crawl exceeds its total byte limit")
        pages.append({"bytes": len(page), "path": path, "sha256": sha256(page)})
        for method_raw, endpoint_raw in HTML_ENDPOINT_ROW.findall(page):
            try:
                method = html.unescape(method_raw.decode("utf-8")).strip()
                endpoint = html.unescape(endpoint_raw.decode("utf-8")).strip()
            except UnicodeDecodeError as error:
                raise SnapshotError("rendered endpoint row is not valid UTF-8") from error
            methods = method.split("/")
            if any(item not in DOCUMENTED_METHODS for item in methods):
                continue
            if not endpoint.startswith("/"):
                endpoint = "/" + endpoint
            validate_text(endpoint, "rendered endpoint path")
            for item in methods:
                operations.add((item, endpoint, path))
        for match in link_pattern.finditer(page):
            try:
                link = html.unescape(match.group(1).decode("utf-8"))
            except UnicodeDecodeError as error:
                raise SnapshotError("rendered documentation link is not valid UTF-8") from error
            if link not in seen and link not in pending:
                pending.append(link)
    pages.sort(key=lambda item: item["path"])
    return {
        "schema": "openbao-rendered-api-cross-check/v1",
        "generator_version": GENERATOR_VERSION,
        "observed_on": observed_on,
        "line": label,
        "authority": "secondary-only; tagged source remains primary",
        "roots": list(roots),
        "pages": pages,
        "operations": [
            {"method": method, "path": path, "source": source}
            for method, path, source in sorted(operations)
        ],
    }


def operation_index(document: dict[str, Any]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for operation in document["operations"]:
        key = f"{operation['method']} {operation['path']}"
        fields = result.setdefault(key, set())
        fields.add(f"path-style:{operation['path_style']}")
        for field in operation["fields"]:
            fields.add(f"{field['section']}:{field['name']}:{field['signature']}")
    return result


def flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    if isinstance(value, dict):
        if not value:
            result[prefix or "/"] = {}
        for key, item in sorted(value.items()):
            escaped = key.replace("~", "~0").replace("/", "~1")
            result.update(flatten(item, f"{prefix}/{escaped}"))
    elif isinstance(value, list):
        if not value:
            result[prefix or "/"] = []
        for index, item in enumerate(value):
            result.update(flatten(item, f"{prefix}/{index}"))
    else:
        result[prefix or "/"] = value
    return result


def openapi_indexes(snapshot: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    document = snapshot["document"]
    operations: dict[str, dict[str, Any]] = {}
    for path, path_item in document["paths"].items():
        if not isinstance(path_item, dict):
            continue
        path_parameters = path_item.get("parameters")
        for method, operation in path_item.items():
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            combined = copy.deepcopy(operation)
            if path_parameters is not None:
                combined["x-evidence-path-parameters"] = path_parameters
            operations[f"{method.upper()} {path}"] = flatten(combined)
    schemas = {
        name: flatten(schema)
        for name, schema in document.get("components", {}).get("schemas", {}).items()
    }
    return operations, schemas


def append_map_changes(
    changes: list[dict[str, Any]],
    evidence: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    for identity in sorted(set(before) | set(after)):
        if identity not in before:
            changes.append({"change": "added", "evidence": evidence, "identity": identity, "field": "/"})
            continue
        if identity not in after:
            changes.append({"change": "removed", "evidence": evidence, "identity": identity, "field": "/"})
            continue
        before_fields = before[identity]
        after_fields = after[identity]
        if isinstance(before_fields, set) and isinstance(after_fields, set):
            for field in sorted(before_fields - after_fields):
                changes.append({"change": "removed", "evidence": evidence, "identity": identity, "field": field})
            for field in sorted(after_fields - before_fields):
                changes.append({"change": "added", "evidence": evidence, "identity": identity, "field": field})
            continue
        for field in sorted(set(before_fields) | set(after_fields)):
            if field not in before_fields:
                change = "added"
            elif field not in after_fields:
                change = "removed"
            elif before_fields[field] != after_fields[field]:
                change = "changed"
            else:
                continue
            changes.append({"change": change, "evidence": evidence, "identity": identity, "field": field})
        if len(changes) > MAX_DIFF_CHANGES:
            raise SnapshotError("generated API diff exceeds its change limit")


def build_diff(
    before_version: str,
    before_docs: dict[str, Any],
    before_openapi: dict[str, Any],
    after_version: str,
    after_docs: dict[str, Any],
    after_openapi: dict[str, Any],
    before_hashes: dict[str, str],
    after_hashes: dict[str, str],
) -> dict[str, Any]:
    changes: list[dict[str, Any]] = []
    append_map_changes(changes, "tagged-documentation", operation_index(before_docs), operation_index(after_docs))
    before_operations, before_schemas = openapi_indexes(before_openapi)
    after_operations, after_schemas = openapi_indexes(after_openapi)
    append_map_changes(changes, "openapi-operation", before_operations, after_operations)
    append_map_changes(changes, "openapi-schema", before_schemas, after_schemas)
    changes.sort(key=lambda item: (item["evidence"], item["identity"], item["field"], item["change"]))
    return {
        "schema": "openbao-api-evidence-diff/v1",
        "generator_version": GENERATOR_VERSION,
        "from_version": before_version,
        "to_version": after_version,
        "from_snapshot_sha256": before_hashes,
        "to_snapshot_sha256": after_hashes,
        "change_count": len(changes),
        "changes": changes,
    }


def release_records() -> list[dict[str, Any]]:
    try:
        document = validate_lock_files()
    except LockValidationError as error:
        raise SnapshotError("release lock validation failed") from error
    records = document.get("records")
    if not isinstance(records, list):
        raise SnapshotError("release lock records are unavailable")
    return records


def generate(source_repository: str) -> None:
    repository = validate_source_repository(source_repository)
    releases = release_records()
    rendered_artifacts: dict[str, tuple[str, bytes, dict[str, Any]]] = {}
    for release in releases:
        line = rendered_line(release["version"])
        if line is None or line[0] in rendered_artifacts:
            continue
        relative = f"compat/rendered-api-cross-checks/{line[0]}.json"
        artifact_path = ROOT / relative
        if artifact_path.exists():
            data = read_regular_file(artifact_path, MAX_SNAPSHOT_BYTES)
            document = parse_json(data, MAX_SNAPSHOT_BYTES)
            if (
                document.get("schema") != "openbao-rendered-api-cross-check/v1"
                or document.get("line") != line[0]
                or document.get("observed_on") != OBSERVED_ON
            ):
                raise SnapshotError("existing rendered cross-check metadata changed")
        else:
            document = capture_rendered_cross_check(*line)
            data = canonical_json(document)
            write_immutable(artifact_path, data)
        rendered_artifacts[line[0]] = (relative, data, document)

    generated: list[tuple[dict[str, Any], dict[str, Any], bytes, dict[str, Any], bytes]] = []
    for release in releases:
        version = release["version"]
        documentation = extract_documentation(repository, release)
        documentation_data = canonical_json(documentation)
        # The active lock contains immutable v1-normalized evidence. Keep its
        # historical regeneration byte-identical while onboarding uses v2.
        openapi = capture_openapi(release, legacy_annotation_collisions=True)
        openapi_data = canonical_json(openapi)
        write_immutable(SNAPSHOT_ROOT / version / "documentation.json", documentation_data)
        write_immutable(SNAPSHOT_ROOT / version / "openapi.json", openapi_data)
        generated.append((release, documentation, documentation_data, openapi, openapi_data))

    lock_records: list[dict[str, Any]] = []
    previous: tuple[dict[str, Any], dict[str, Any], bytes, dict[str, Any], bytes] | None = None
    for item in generated:
        release, documentation, documentation_data, openapi, openapi_data = item
        version = release["version"]
        documentation_hash = sha256(documentation_data)
        openapi_hash = sha256(openapi_data)
        diff_record: dict[str, Any] | None = None
        if previous is not None:
            previous_release, previous_docs, previous_docs_data, previous_openapi, previous_openapi_data = previous
            previous_version = previous_release["version"]
            diff = build_diff(
                previous_version,
                previous_docs,
                previous_openapi,
                version,
                documentation,
                openapi,
                {"documentation": sha256(previous_docs_data), "openapi": sha256(previous_openapi_data)},
                {"documentation": documentation_hash, "openapi": openapi_hash},
            )
            diff_data = canonical_json(diff)
            diff_path = f"compat/api-diffs/{previous_version}--{version}.json"
            write_immutable(ROOT / diff_path, diff_data)
            diff_record = {
                "path": diff_path,
                "sha256": sha256(diff_data),
                "bytes": len(diff_data),
                "change_count": diff["change_count"],
            }

        line = rendered_line(version)
        if line is None:
            rendered_record: dict[str, Any] = {
                "status": "not-published-for-minor-line",
                "line": None,
                "path": None,
                "sha256": None,
                "bytes": None,
                "tagged_only_operation_count": None,
                "rendered_only_operation_count": None,
            }
        else:
            if line[0] not in rendered_artifacts:
                raise SnapshotError("rendered cross-check artifact was not captured")
            rendered_path, rendered_data, rendered_document = rendered_artifacts[line[0]]
            tagged = set(operation_index(documentation))
            rendered = {
                f"{operation['method']} {operation['path']}"
                for operation in rendered_document["operations"]
            }
            rendered_record = {
                "status": "secondary-observation-only",
                "line": line[0],
                "path": rendered_path,
                "sha256": sha256(rendered_data),
                "bytes": len(rendered_data),
                "tagged_only_operation_count": len(tagged - rendered),
                "rendered_only_operation_count": len(rendered - tagged),
            }
        lock_records.append(
            {
                "version": version,
                "source_commit_sha1": release["source"]["peeled_commit_sha1"],
                "image_index_digest": release["image"]["index_digest"],
                "image_linux_amd64_digest": release["image"]["linux_amd64_digest"],
                "documentation": {
                    "path": f"compat/api-snapshots/{version}/documentation.json",
                    "sha256": documentation_hash,
                    "bytes": len(documentation_data),
                    "file_count": len(documentation["files"]),
                    "operation_count": len(documentation["operations"]),
                },
                "openapi": {
                    "path": f"compat/api-snapshots/{version}/openapi.json",
                    "sha256": openapi_hash,
                    "bytes": len(openapi_data),
                    "path_count": openapi["path_count"],
                    "operation_count": openapi["operation_count"],
                    "schema_count": openapi["schema_count"],
                },
                "rendered_cross_check": rendered_record,
                "diff_from_previous": diff_record,
            }
        )
        previous = item
    lock = {
        "schema": "openbao-api-snapshot-lock/v1",
        "generator_version": GENERATOR_VERSION,
        "observed_on": OBSERVED_ON,
        "release_lock_sha256": EXPECTED_LOCK_SHA256,
        "records": lock_records,
    }
    lock_data = canonical_json(lock)
    write_immutable(SNAPSHOT_LOCK_PATH, lock_data)
    checksum = f"{sha256(lock_data)}  api-snapshots.lock.json\n".encode()
    write_immutable(SNAPSHOT_CHECKSUM_PATH, checksum)
    print(f"generated {len(lock_records)} immutable OpenBao API evidence profiles")


def require_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise SnapshotError(f"{label} fields do not match the locked schema")
    return value


def require_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SnapshotError(f"{label} is not a lowercase SHA-256")
    return value


def require_nonnegative_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SnapshotError(f"{label} is not a non-negative integer")
    return value


def validate_documentation_snapshot(
    document: dict[str, Any], data: bytes, version: str, source_commit: str
) -> None:
    require_keys(
        document,
        {
            "schema",
            "generator_version",
            "version",
            "source_commit_sha1",
            "source_path",
            "files",
            "operations",
        },
        "documentation snapshot",
    )
    if (
        document["schema"] != "openbao-tagged-api-documentation/v1"
        or document["generator_version"] != GENERATOR_VERSION
        or document["version"] != version
        or document["source_commit_sha1"] != source_commit
        or document["source_path"] != DOC_PREFIX
        or canonical_json(document) != data
    ):
        raise SnapshotError("documentation snapshot metadata or canonical form changed")
    files = document["files"]
    operations = document["operations"]
    if not isinstance(files, list) or not files or len(files) > MAX_DOC_FILES:
        raise SnapshotError("documentation snapshot file count is outside its bound")
    if not isinstance(operations, list) or len(operations) > MAX_OPERATIONS:
        raise SnapshotError("documentation snapshot operation count exceeds its bound")
    source_paths: set[str] = set()
    previous_file = ""
    for index, file_value in enumerate(files):
        file_record = require_keys(
            file_value,
            {"blob_sha1", "bytes", "path", "sha256"},
            f"documentation file {index}",
        )
        path_text = file_record["path"]
        if not isinstance(path_text, str):
            raise SnapshotError("documentation source path is not text")
        pure = safe_relative_path(path_text, "documentation source path")
        if pure.parts[:3] != ("website", "content", "api-docs") or pure.suffix != ".mdx":
            raise SnapshotError("documentation source path escaped the tagged API tree")
        if path_text <= previous_file or path_text in source_paths:
            raise SnapshotError("documentation source files are duplicated or unordered")
        previous_file = path_text
        source_paths.add(path_text)
        if re.fullmatch(r"[0-9a-f]{40}", str(file_record["blob_sha1"])) is None:
            raise SnapshotError("documentation blob identity is malformed")
        require_hash(file_record["sha256"], "documentation blob digest")
        if require_nonnegative_int(file_record["bytes"], "documentation blob size") > MAX_DOC_FILE_BYTES:
            raise SnapshotError("documentation blob size exceeds its limit")
    operation_keys: list[tuple[str, str, str, str]] = []
    for index, operation_value in enumerate(operations):
        operation = require_keys(
            operation_value,
            {"fields", "heading", "method", "path", "path_style", "source"},
            f"documentation operation {index}",
        )
        if operation["method"] not in DOCUMENTED_METHODS:
            raise SnapshotError("documentation operation method is unsupported")
        path_text = validate_text(operation["path"], "documentation operation path")
        if not path_text.startswith("/"):
            raise SnapshotError("documentation operation path is not absolute")
        if operation["path_style"] not in ("absolute", "relative-normalized"):
            raise SnapshotError("documentation operation path style is unsupported")
        if operation["source"] not in source_paths:
            raise SnapshotError("documentation operation references an unknown source")
        validate_text(operation["heading"], "documentation operation heading", 512)
        fields = operation["fields"]
        if not isinstance(fields, list) or len(fields) > MAX_FIELDS_PER_SECTION:
            raise SnapshotError("documentation operation field count exceeds its limit")
        for field_index, field_value in enumerate(fields):
            field = require_keys(
                field_value,
                {"name", "section", "signature"},
                f"documentation operation field {field_index}",
            )
            validate_text(field["name"], "documentation field name", 256)
            validate_text(field["section"], "documentation field section", 128)
            validate_text(field["signature"], "documentation field signature", 512)
        key = (operation["method"], path_text, operation["source"], operation["heading"])
        operation_keys.append(key)
    if operation_keys != sorted(operation_keys):
        raise SnapshotError("documentation operations are not canonically ordered")


def validate_openapi_snapshot(
    document: dict[str, Any],
    data: bytes,
    record: dict[str, Any],
    *,
    expected_schema: str = "openbao-normalized-openapi/v1",
) -> None:
    require_keys(
        document,
        {
            "schema",
            "generator_version",
            "version",
            "image_index_digest",
            "image_linux_amd64_digest",
            "mounts",
            "path_count",
            "operation_count",
            "schema_count",
            "document",
        },
        "OpenAPI snapshot",
    )
    if canonical_json(document) != data:
        raise SnapshotError("OpenAPI snapshot is not canonical JSON")
    expected_mounts = [
        {"kind": "secret", "path": path, "type": plugin_type}
        for path, plugin_type, _ in SECRET_MOUNTS
    ] + [
        {"kind": "auth", "path": path, "type": plugin_type}
        for path, plugin_type in AUTH_MOUNTS
    ]
    if document["mounts"] != expected_mounts:
        raise SnapshotError("OpenAPI snapshot mount catalog changed")
    openapi = require_keys(document["document"], {"components", "info", "openapi", "paths"}, "OpenAPI document")
    info = openapi["info"]
    paths = openapi["paths"]
    components = openapi["components"]
    if (
        document["schema"] != expected_schema
        or document["generator_version"] != GENERATOR_VERSION
        or document["version"] != record["version"]
        or document["image_index_digest"] != record["image_index_digest"]
        or document["image_linux_amd64_digest"] != record["image_linux_amd64_digest"]
        or not isinstance(info, dict)
        or info.get("version") != record["version"]
        or not str(openapi["openapi"]).startswith("3.")
        or not isinstance(paths, dict)
        or not isinstance(components, dict)
        or not isinstance(components.get("schemas"), dict)
    ):
        raise SnapshotError("OpenAPI snapshot identity or document shape changed")
    operation_count = 0
    for path_text, path_value in paths.items():
        validate_text(path_text, "OpenAPI path")
        if not path_text.startswith("/") or not isinstance(path_value, dict):
            raise SnapshotError("OpenAPI path entry is malformed")
        operation_count += sum(method in HTTP_METHODS for method in path_value)
    if (
        require_nonnegative_int(document["path_count"], "OpenAPI path count") != len(paths)
        or require_nonnegative_int(document["operation_count"], "OpenAPI operation count")
        != operation_count
        or require_nonnegative_int(document["schema_count"], "OpenAPI schema count")
        != len(components["schemas"])
    ):
        raise SnapshotError("OpenAPI snapshot counts changed")


def validate_rendered_snapshot(
    document: dict[str, Any],
    data: bytes,
    line: str,
    *,
    observed_on: str = OBSERVED_ON,
) -> None:
    require_keys(
        document,
        {"schema", "generator_version", "observed_on", "line", "authority", "roots", "pages", "operations"},
        "rendered cross-check snapshot",
    )
    if (
        document["schema"] != "openbao-rendered-api-cross-check/v1"
        or document["generator_version"] != GENERATOR_VERSION
        or document["observed_on"] != observed_on
        or document["line"] != line
        or document["authority"] != "secondary-only; tagged source remains primary"
        or canonical_json(document) != data
    ):
        raise SnapshotError("rendered cross-check metadata or canonical form changed")
    pages = document["pages"]
    operations = document["operations"]
    if not isinstance(pages, list) or not pages or len(pages) > MAX_RENDERED_PAGES:
        raise SnapshotError("rendered cross-check page count is outside its bound")
    if not isinstance(operations, list) or len(operations) > MAX_OPERATIONS:
        raise SnapshotError("rendered cross-check operation count exceeds its bound")
    page_paths: list[str] = []
    for index, page_value in enumerate(pages):
        page = require_keys(page_value, {"bytes", "path", "sha256"}, f"rendered page {index}")
        path_text = validate_text(page["path"], "rendered page path")
        if not path_text.startswith("/api-docs/"):
            raise SnapshotError("rendered page path escaped the API documentation tree")
        require_hash(page["sha256"], "rendered page digest")
        if require_nonnegative_int(page["bytes"], "rendered page size") > MAX_RENDERED_PAGE_BYTES:
            raise SnapshotError("rendered page size exceeds its limit")
        page_paths.append(path_text)
    if page_paths != sorted(set(page_paths)):
        raise SnapshotError("rendered pages are duplicated or unordered")
    operation_keys: list[tuple[str, str, str]] = []
    for index, operation_value in enumerate(operations):
        operation = require_keys(operation_value, {"method", "path", "source"}, f"rendered operation {index}")
        if operation["method"] not in DOCUMENTED_METHODS or operation["source"] not in page_paths:
            raise SnapshotError("rendered operation identity is unsupported")
        path_text = validate_text(operation["path"], "rendered operation path")
        if not path_text.startswith("/"):
            raise SnapshotError("rendered operation path is not absolute")
        operation_keys.append((operation["method"], path_text, operation["source"]))
    if operation_keys != sorted(set(operation_keys)):
        raise SnapshotError("rendered operations are duplicated or unordered")


def validate_diff_snapshot(document: dict[str, Any], data: bytes, previous: str, version: str) -> None:
    require_keys(
        document,
        {
            "schema",
            "generator_version",
            "from_version",
            "to_version",
            "from_snapshot_sha256",
            "to_snapshot_sha256",
            "change_count",
            "changes",
        },
        "API diff snapshot",
    )
    changes = document["changes"]
    if (
        document["schema"] != "openbao-api-evidence-diff/v1"
        or document["generator_version"] != GENERATOR_VERSION
        or document["from_version"] != previous
        or document["to_version"] != version
        or canonical_json(document) != data
        or not isinstance(changes, list)
        or len(changes) > MAX_DIFF_CHANGES
        or require_nonnegative_int(document["change_count"], "API diff change count") != len(changes)
    ):
        raise SnapshotError("API diff metadata, count, or canonical form changed")
    for hashes in (document["from_snapshot_sha256"], document["to_snapshot_sha256"]):
        require_keys(hashes, {"documentation", "openapi"}, "API diff snapshot identities")
        require_hash(hashes["documentation"], "API diff documentation identity")
        require_hash(hashes["openapi"], "API diff OpenAPI identity")
    change_keys: list[tuple[str, str, str, str]] = []
    for index, change_value in enumerate(changes):
        change = require_keys(change_value, {"change", "evidence", "identity", "field"}, f"API diff change {index}")
        if change["change"] not in ("added", "changed", "removed"):
            raise SnapshotError("API diff change kind is unsupported")
        if change["evidence"] not in ("openapi-operation", "openapi-schema", "tagged-documentation"):
            raise SnapshotError("API diff evidence kind is unsupported")
        validate_text(change["identity"], "API diff identity")
        validate_text(change["field"], "API diff field")
        change_keys.append((change["evidence"], change["identity"], change["field"], change["change"]))
    if change_keys != sorted(set(change_keys)):
        raise SnapshotError("API diff changes are duplicated or unordered")


def verify_artifact(record: dict[str, Any], maximum: int, cache: dict[str, bytes]) -> bytes:
    path_text = record["path"]
    if not isinstance(path_text, str):
        raise SnapshotError("snapshot artifact path is not text")
    path = require_repo_path(path_text)
    if path_text in cache:
        data = cache[path_text]
    else:
        data = read_regular_file(path, maximum)
        cache[path_text] = data
    if record["bytes"] != len(data) or require_hash(record["sha256"], path_text) != sha256(data):
        raise SnapshotError("snapshot artifact size or digest changed")
    return data


def verify() -> dict[str, Any]:
    releases = release_records()
    lock_data = read_regular_file(SNAPSHOT_LOCK_PATH, MAX_LOCK_BYTES)
    checksum_data = read_regular_file(SNAPSHOT_CHECKSUM_PATH, 256)
    if sha256(lock_data) != EXPECTED_SNAPSHOT_LOCK_SHA256:
        raise SnapshotError("snapshot lock does not match its validator anchor")
    expected_checksum = f"{EXPECTED_SNAPSHOT_LOCK_SHA256}  api-snapshots.lock.json\n".encode()
    if checksum_data != expected_checksum:
        raise SnapshotError("snapshot lock checksum sidecar changed")
    lock = parse_json(lock_data, MAX_LOCK_BYTES)
    require_keys(
        lock,
        {"schema", "generator_version", "observed_on", "release_lock_sha256", "records"},
        "snapshot lock",
    )
    if (
        lock["schema"] != "openbao-api-snapshot-lock/v1"
        or lock["generator_version"] != GENERATOR_VERSION
        or lock["observed_on"] != OBSERVED_ON
        or lock["release_lock_sha256"] != EXPECTED_LOCK_SHA256
        or canonical_json(lock) != lock_data
    ):
        raise SnapshotError("snapshot lock metadata changed")
    records = lock["records"]
    if (
        not isinstance(records, list)
        or len(records) != len(releases)
        or len(records) != len(EXPECTED_SNAPSHOT_RECORDS)
    ):
        raise SnapshotError("snapshot lock must cover every release exactly once")
    cache: dict[str, bytes] = {}
    previous_version: str | None = None
    previous_hashes: dict[str, str] | None = None
    for index, (record_value, release, expected_snapshot) in enumerate(
        zip(records, releases, EXPECTED_SNAPSHOT_RECORDS)
    ):
        record = require_keys(
            record_value,
            {
                "version",
                "source_commit_sha1",
                "image_index_digest",
                "image_linux_amd64_digest",
                "documentation",
                "openapi",
                "rendered_cross_check",
                "diff_from_previous",
            },
            f"snapshot record {index}",
        )
        version = release["version"]
        if (
            record["version"] != version
            or expected_snapshot[0] != version
            or record["source_commit_sha1"] != release["source"]["peeled_commit_sha1"]
            or record["image_index_digest"] != release["image"]["index_digest"]
            or record["image_linux_amd64_digest"] != release["image"]["linux_amd64_digest"]
        ):
            raise SnapshotError("snapshot record identity differs from the release lock")
        documentation_record = require_keys(
            record["documentation"],
            {"path", "sha256", "bytes", "file_count", "operation_count"},
            "documentation snapshot",
        )
        openapi_record = require_keys(
            record["openapi"],
            {"path", "sha256", "bytes", "path_count", "operation_count", "schema_count"},
            "OpenAPI snapshot",
        )
        if documentation_record["path"] != f"compat/api-snapshots/{version}/documentation.json":
            raise SnapshotError("documentation snapshot path changed")
        if openapi_record["path"] != f"compat/api-snapshots/{version}/openapi.json":
            raise SnapshotError("OpenAPI snapshot path changed")
        if (
            documentation_record["sha256"] != expected_snapshot[1]
            or openapi_record["sha256"] != expected_snapshot[2]
        ):
            raise SnapshotError("historical API snapshot identity changed")
        documentation_data = verify_artifact(documentation_record, MAX_SNAPSHOT_BYTES, cache)
        openapi_data = verify_artifact(openapi_record, MAX_SNAPSHOT_BYTES, cache)
        documentation = parse_json(documentation_data, MAX_SNAPSHOT_BYTES)
        openapi = parse_json(openapi_data, MAX_SNAPSHOT_BYTES)
        validate_documentation_snapshot(
            documentation,
            documentation_data,
            version,
            record["source_commit_sha1"],
        )
        validate_openapi_snapshot(
            openapi,
            openapi_data,
            record,
            expected_schema=(
                "openbao-normalized-openapi/v2"
                if version == "2.6.0"
                else "openbao-normalized-openapi/v1"
            ),
        )
        if (
            len(documentation["files"]) != documentation_record["file_count"]
            or len(documentation.get("operations", [])) != documentation_record["operation_count"]
        ):
            raise SnapshotError("documentation snapshot metadata changed")
        if (
            openapi["path_count"] != openapi_record["path_count"]
            or openapi.get("operation_count") != openapi_record["operation_count"]
            or openapi.get("schema_count") != openapi_record["schema_count"]
        ):
            raise SnapshotError("OpenAPI snapshot metadata changed")
        rendered_record = require_keys(
            record["rendered_cross_check"],
            {
                "status",
                "line",
                "path",
                "sha256",
                "bytes",
                "tagged_only_operation_count",
                "rendered_only_operation_count",
            },
            "rendered cross-check",
        )
        if rendered_record["status"] == "secondary-observation-only":
            expected_line = rendered_line(version)
            if (
                expected_line is None
                or rendered_record["line"] != expected_line[0]
                or rendered_record["path"]
                != f"compat/rendered-api-cross-checks/{expected_line[0]}.json"
            ):
                raise SnapshotError("rendered cross-check identity changed")
            rendered_data = verify_artifact(rendered_record, MAX_SNAPSHOT_BYTES, cache)
            rendered_document = parse_json(rendered_data, MAX_SNAPSHOT_BYTES)
            validate_rendered_snapshot(
                rendered_document,
                rendered_data,
                rendered_record["line"],
                observed_on=(
                    OBSERVED_ON
                    if version == "2.6.0"
                    else "2026-07-10"
                ),
            )
            tagged_operations = set(operation_index(documentation))
            rendered_operations = {
                f"{operation['method']} {operation['path']}"
                for operation in rendered_document["operations"]
            }
            if (
                rendered_record["tagged_only_operation_count"]
                != len(tagged_operations - rendered_operations)
                or rendered_record["rendered_only_operation_count"]
                != len(rendered_operations - tagged_operations)
            ):
                raise SnapshotError("rendered cross-check comparison counts changed")
        elif rendered_record["status"] != "not-published-for-minor-line" or any(
            rendered_record[field] is not None
            for field in (
                "line",
                "path",
                "sha256",
                "bytes",
                "tagged_only_operation_count",
                "rendered_only_operation_count",
            )
        ):
            raise SnapshotError("rendered cross-check status is unsupported")
        diff_record = record["diff_from_previous"]
        if previous_version is None:
            if diff_record is not None or expected_snapshot[3] is not None:
                raise SnapshotError("first snapshot record must not have a predecessor diff")
        else:
            diff_fields = {"path", "sha256", "bytes", "change_count"}
            if version == "2.6.0":
                diff_fields.add("normalized_predecessor_openapi")
            diff = require_keys(diff_record, diff_fields, "API diff")
            if diff["path"] != f"compat/api-diffs/{previous_version}--{version}.json":
                raise SnapshotError("API diff path changed")
            if diff["sha256"] != expected_snapshot[3]:
                raise SnapshotError("historical API diff identity changed")
            diff_data = verify_artifact(diff, MAX_SNAPSHOT_BYTES, cache)
            diff_document = parse_json(diff_data, MAX_SNAPSHOT_BYTES)
            validate_diff_snapshot(diff_document, diff_data, previous_version, version)
            expected_from_hashes = previous_hashes
            if version == "2.6.0":
                normalized_record = require_keys(
                    diff["normalized_predecessor_openapi"],
                    {"path", "sha256", "bytes"},
                    "normalized predecessor OpenAPI snapshot",
                )
                if normalized_record["path"] != "compat/api-snapshots/2.5.5/openapi-v2.json":
                    raise SnapshotError("normalized predecessor OpenAPI path changed")
                normalized_data = verify_artifact(normalized_record, MAX_SNAPSHOT_BYTES, cache)
                normalized_document = parse_json(normalized_data, MAX_SNAPSHOT_BYTES)
                predecessor_record = records[index - 1]
                validate_openapi_snapshot(
                    normalized_document,
                    normalized_data,
                    predecessor_record,
                    expected_schema="openbao-normalized-openapi/v2",
                )
                expected_from_hashes = {
                    "documentation": previous_hashes["documentation"],
                    "openapi": normalized_record["sha256"],
                }
            if (
                diff_document["change_count"] != diff["change_count"]
                or diff_document["from_snapshot_sha256"] != expected_from_hashes
                or diff_document["to_snapshot_sha256"]
                != {
                    "documentation": documentation_record["sha256"],
                    "openapi": openapi_record["sha256"],
                }
            ):
                raise SnapshotError("API diff metadata changed")
        previous_version = version
        previous_hashes = {
            "documentation": documentation_record["sha256"],
            "openapi": openapi_record["sha256"],
        }
    return lock


def expect_rejected(label: str, operation: Any) -> None:
    try:
        operation()
    except SnapshotError:
        return
    raise SnapshotError(f"snapshot self-test did not reject {label}")


def self_test() -> None:
    verify()
    expect_rejected("duplicate keys", lambda: parse_json(b'{"a":1,"a":2}', 128))
    expect_rejected("non-finite number", lambda: parse_json(b'{"a":NaN}', 128))
    expect_rejected("deep JSON", lambda: parse_json((b"[" * 65) + (b"]" * 65), 1024))
    expect_rejected("oversized JSON", lambda: parse_json(b"{} ", 2))
    expect_rejected(
        "long JSON string",
        lambda: parse_json(b'{"a":"' + (b"x" * (MAX_JSON_STRING_BYTES + 1)) + b'"}', MAX_OPENAPI_BYTES),
    )
    collision = {
        "components": {
            "schemas": {
                "Collision": {
                    "description": "annotation to remove",
                    "properties": {
                        "description": {"type": "string"},
                        "tags": {
                            "description": "nested annotation to remove",
                            "type": "string",
                        },
                    },
                    "type": "object",
                }
            }
        }
    }
    normalized_collision = contract_only(collision)
    collision_schema = normalized_collision["components"]["schemas"]["Collision"]
    collision_properties = collision_schema["properties"]
    if set(collision_properties) != {"description", "tags"}:
        raise SnapshotError("annotation-named OpenAPI properties were removed")
    if "description" in collision_schema or "description" in collision_properties["tags"]:
        raise SnapshotError("OpenAPI annotation was retained outside a named map")
    legacy_properties = contract_only_legacy(collision)["components"]["schemas"]["Collision"][
        "properties"
    ]
    if legacy_properties:
        raise SnapshotError("legacy OpenAPI normalization changed historical behavior")
    for map_name in NAMED_OPENAPI_MAPS:
        normalized_map = contract_only(
            {
                map_name: {
                    "description": {
                        "description": "annotation to remove",
                        "type": "string",
                    },
                    "tags": {"type": "string"},
                }
            }
        )[map_name]
        if set(normalized_map) != {"description", "tags"}:
            raise SnapshotError(f"OpenAPI named-map identifiers were removed from {map_name}")
        if "description" in normalized_map["description"]:
            raise SnapshotError(f"OpenAPI annotation was retained within {map_name}")
    normalized_callbacks = contract_only(
        {
            "callbacks": {
                "description": {
                    "tags": {
                        "description": "annotation to remove",
                        "get": {"responses": {"200": {"description": "annotation to remove"}}},
                    }
                },
                "tags": {"$ref": "#/components/callbacks/example", "description": "remove"},
            }
        }
    )["callbacks"]
    if set(normalized_callbacks) != {"description", "tags"}:
        raise SnapshotError("OpenAPI callback identifiers were removed")
    if set(normalized_callbacks["description"]) != {"tags"}:
        raise SnapshotError("OpenAPI callback expression identifiers were removed")
    if "description" in normalized_callbacks["description"]["tags"]:
        raise SnapshotError("OpenAPI callback annotation was retained")
    if "description" in normalized_callbacks["tags"]:
        raise SnapshotError("OpenAPI callback reference annotation was retained")
    normalized_security = contract_only(
        {"security": [{"description": [], "tags": []}]}
    )["security"]
    if set(normalized_security[0]) != {"description", "tags"}:
        raise SnapshotError("OpenAPI security requirement identifiers were removed")
    normalized_parameters = contract_only(
        {"parameters": [{"description": "remove", "name": "description"}]}
    )["parameters"]
    if normalized_parameters != [{"name": "description"}]:
        raise SnapshotError("OpenAPI parameter annotations were treated as identifiers")
    validate_container_resource_config(
        {
            "Memory": CONTAINER_MEMORY_BYTES,
            "MemorySwap": CONTAINER_MEMORY_SWAP_BYTES,
            "NanoCpus": CONTAINER_NANO_CPUS,
            "PidsLimit": CONTAINER_PIDS_LIMIT,
        }
    )
    expect_rejected(
        "missing aggregate container limit",
        lambda: validate_container_resource_config(
            {
                "Memory": CONTAINER_MEMORY_BYTES,
                "MemorySwap": CONTAINER_MEMORY_SWAP_BYTES,
                "NanoCpus": 0,
                "PidsLimit": CONTAINER_PIDS_LIMIT,
            }
        ),
    )
    if CONTAINER_RESOURCE_OPTIONS != (
        "--memory",
        "1g",
        "--memory-swap",
        "2g",
        "--cpus",
        "1",
        "--pids-limit",
        "256",
        "--stop-timeout",
        "5",
        "--ulimit",
        "data=1073741824:1073741824",
        "--ulimit",
        "cpu=300:300",
        "--ulimit",
        "nofile=1024:1024",
        "--ulimit",
        "nproc=256:256",
    ):
        raise SnapshotError("API evidence container resource limits changed")
    normalization_seed = canonical_json(
        {
            "components": {"schemas": {"Example": {"type": "object"}}},
            "info": {"description": "removed annotation", "version": "2.5.5"},
            "openapi": "3.0.2",
            "paths": {"/sys/health": {"get": {"responses": {"200": {"description": "ok"}}}}},
        }
    )
    accepted_mutations = 0
    rejected_mutations = 0
    for mutation in deterministic_byte_mutations(normalization_seed):
        try:
            parsed = parse_json(mutation, len(normalization_seed) + 16)
        except SnapshotError:
            rejected_mutations += 1
            continue
        normalized = contract_only(parsed)
        validate_json_tree(normalized)
        canonical = canonical_json(normalized)
        reparsed = parse_json(canonical, len(canonical))
        if canonical_json(reparsed) != canonical:
            raise SnapshotError("snapshot normalization mutation was not deterministic")
        accepted_mutations += 1
    if accepted_mutations == 0 or rejected_mutations == 0:
        raise SnapshotError("snapshot normalization mutation corpus was ineffective")
    with tempfile.TemporaryDirectory(prefix="openbao-api-snapshot-") as directory:
        root = Path(directory)
        target = root / "target"
        target.write_bytes(b"{}")
        symlink = root / "symlink"
        symlink.symlink_to(target)
        expect_rejected("symbolic-link input", lambda: read_regular_file(symlink, 128))
        real_parent = root / "real-parent"
        real_parent.mkdir()
        nested_target = real_parent / "target"
        nested_target.write_bytes(b"{}")
        symlink_parent = root / "symlink-parent"
        symlink_parent.symlink_to(real_parent, target_is_directory=True)
        expect_rejected(
            "symbolic-link parent",
            lambda: read_regular_file(symlink_parent / "target", 128),
        )
        fifo = root / "fifo"
        os.mkfifo(fifo)
        expect_rejected("FIFO input", lambda: read_regular_file(fifo, 128))
        oversized = root / "oversized"
        oversized.write_bytes(b"x" * 129)
        expect_rejected("oversized file input", lambda: read_regular_file(oversized, 128))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--generate", action="store_true")
    action.add_argument("--verify", action="store_true")
    action.add_argument("--self-test", action="store_true")
    parser.add_argument("--source-repository")
    arguments = parser.parse_args()
    try:
        if arguments.generate:
            if not arguments.source_repository:
                raise SnapshotError("--generate requires --source-repository")
            generate(arguments.source_repository)
        elif arguments.verify:
            lock = verify()
            print(f"OpenBao API snapshots: {len(lock['records'])} immutable profiles verified")
        else:
            self_test()
            print("OpenBao API snapshot self-tests: ok")
        return 0
    except (OSError, SnapshotError, subprocess.SubprocessError) as error:
        print(f"OpenBao API snapshot operation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
