#!/usr/bin/env python3
"""Run the real integration test against one exact locked OpenBao release."""

from __future__ import annotations

import argparse
import fcntl
import json
import math
import os
import pwd
import re
import secrets
import selectors
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from validate_openbao_release_lock import LockValidationError, validate_lock_files

ROOT = Path(__file__).resolve().parents[1]
IMAGE_REPOSITORY = "docker.io/openbao/openbao"
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+", re.ASCII)
RESOURCE = re.compile(r"openbao-it-[a-z0-9-]{1,64}", re.ASCII)
LOOPBACK_PORT = re.compile(r"127\.0\.0\.1:([0-9]{1,5})\n?", re.ASCII)
MAX_COMMAND_OUTPUT = 1024 * 1024
MAX_CARGO_OUTPUT = 32 * 1024 * 1024
MAX_HTTP_BODY = 1024 * 1024
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 16_384
MAX_JSON_STRING_BYTES = 64 * 1024
OWNER_LABEL = "io.openbao.rust-crate.integration-run"
CORE_OPERATION_IDS = (
    "health",
    "mount-management",
    "kv1",
    "kv2",
    "policy",
    "token",
    "capabilities",
    "response-wrapping",
)


class HarnessError(RuntimeError):
    """The version-locked integration harness failed closed."""


class HarnessInterrupted(HarnessError):
    """The harness received a termination signal."""


class VersionMismatch(HarnessError):
    """The running server is not the exact selected release."""


class IntegrationTestFailure(HarnessError):
    """The Rust core integration flow failed."""


def reject_non_finite(value: str) -> None:
    del value
    raise HarnessError("JSON response contains a non-finite number")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HarnessError("JSON response contains a duplicate key")
        result[key] = value
    return result


def parse_json(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_HTTP_BODY:
        raise HarnessError("JSON response exceeds the byte limit")
    try:
        value = json.loads(
            data,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_non_finite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, HarnessError) as error:
        raise HarnessError("response is not bounded duplicate-free JSON") from error
    if not isinstance(value, dict):
        raise HarnessError("JSON response root must be an object")
    validate_json_bounds(value)
    return value


def validate_json_bounds(value: Any) -> None:
    nodes = 0

    def visit(current: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise HarnessError("JSON response exceeds the node limit")
        if depth > MAX_JSON_DEPTH:
            raise HarnessError("JSON response exceeds the depth limit")
        if isinstance(current, str):
            if len(current.encode("utf-8")) > MAX_JSON_STRING_BYTES:
                raise HarnessError("JSON response string exceeds the byte limit")
        elif isinstance(current, list):
            for item in current:
                visit(item, depth + 1)
        elif isinstance(current, dict):
            for key, item in current.items():
                visit(key, depth + 1)
                visit(item, depth + 1)
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise HarnessError("JSON response contains a non-finite number")
        elif current is not None and not isinstance(current, (bool, int)):
            raise HarnessError("JSON response contains an unsupported value")

    visit(value, 0)


def select_release(document: dict[str, Any], version: str) -> dict[str, Any]:
    if VERSION.fullmatch(version) is None:
        raise HarnessError("OpenBao version must be an exact canonical inventory version")
    records = document.get("records")
    if not isinstance(records, list):
        raise HarnessError("validated release inventory has no records")
    selected = [record for record in records if record.get("version") == version]
    if len(selected) != 1:
        raise HarnessError("OpenBao version is not an exact release inventory entry")
    release = selected[0]
    image = release.get("image")
    if not isinstance(image, dict):
        raise HarnessError("selected release has no locked image")
    digest = image.get("linux_amd64_digest")
    if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise HarnessError("selected release has no valid locked Linux amd64 digest")
    return release


def image_reference(release: dict[str, Any]) -> str:
    return f"{IMAGE_REPOSITORY}@{release['image']['linux_amd64_digest']}"


def resource_name(version: str) -> str:
    value = f"openbao-it-{version.replace('.', '-')}-{secrets.token_hex(12)}"
    if RESOURCE.fullmatch(value) is None:
        raise HarnessError("generated container resource name is invalid")
    return value


def verify_reported_version(actual: Any, expected: str) -> None:
    if actual != expected:
        raise VersionMismatch("OpenBao health version does not match the selected release")


def command_environment(home: Path) -> dict[str, str]:
    del home
    account_home = pwd.getpwuid(os.getuid()).pw_dir
    if not account_home or "\x00" in account_home:
        raise HarnessError("local account home directory is invalid")
    environment = {
        "HOME": account_home,
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
    }
    for name in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def run_bounded(
    command: list[str],
    maximum: int = MAX_COMMAND_OUTPUT,
    *,
    timeout: float,
    environment: dict[str, str],
    accepted_codes: tuple[int, ...] = (0,),
) -> bytes:
    if not command or any(not isinstance(item, str) or "\x00" in item for item in command):
        raise HarnessError("subprocess command is malformed")
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
        raise HarnessError("bounded command has no output pipe")
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
                raise HarnessError("subprocess timed out")
            events = selector.select(min(remaining, 0.25))
            if not events and process.poll() is not None:
                events = [(selector.get_key(descriptor), selectors.EVENT_READ)]
            for key, _ in events:
                allowed = maximum + 1 - len(output)
                if allowed <= 0:
                    process.kill()
                    raise HarnessError("subprocess output exceeds the byte limit")
                chunk = os.read(key.fd, min(64 * 1024, allowed))
                if not chunk:
                    selector.unregister(key.fd)
                    continue
                output.extend(chunk)
                if len(output) > maximum:
                    process.kill()
                    raise HarnessError("subprocess output exceeds the byte limit")
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
    if return_code not in accepted_codes:
        raise HarnessError("subprocess failed")
    return bytes(output)


def run_quiet(
    command: list[str],
    *,
    timeout: float,
    environment: dict[str, str],
    accepted_codes: tuple[int, ...] = (0,),
) -> int:
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
        raise HarnessError("subprocess timed out") from error
    if result.returncode not in accepted_codes:
        raise HarnessError("subprocess failed")
    return result.returncode


def require_tools() -> tuple[str, str]:
    podman = shutil.which("podman")
    openssl = shutil.which("openssl")
    if podman is None or openssl is None:
        raise HarnessError("podman and openssl are required")
    return podman, openssl


def write_private(path: Path, data: bytes, mode: int = 0o600) -> None:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise HarnessError("no-follow private file creation is unavailable")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow
    descriptor = os.open(path, flags, mode)
    try:
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise HarnessError("private file write made no progress")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def generate_tls(root: Path, openssl: str, environment: dict[str, str]) -> tuple[Path, Path]:
    tls = root / "tls"
    tls.mkdir(mode=0o750)
    ca_key = tls / "ca.key"
    ca_cert = tls / "ca.crt"
    server_key = tls / "server.key"
    server_csr = tls / "server.csr"
    server_cert = tls / "server.crt"
    extensions = tls / "server.ext"
    write_private(
        extensions,
        b"subjectAltName=IP:127.0.0.1\n"
        b"extendedKeyUsage=serverAuth\n"
        b"keyUsage=critical,digitalSignature,keyEncipherment\n",
    )
    run_quiet(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:3072",
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_cert),
            "-subj",
            "/CN=OpenBao integration ephemeral CA",
            "-addext",
            "basicConstraints=critical,CA:true",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
        timeout=60,
        environment=environment,
    )
    run_quiet(
        [
            openssl,
            "req",
            "-newkey",
            "rsa:3072",
            "-sha256",
            "-nodes",
            "-keyout",
            str(server_key),
            "-out",
            str(server_csr),
            "-subj",
            "/CN=127.0.0.1",
        ],
        timeout=60,
        environment=environment,
    )
    run_quiet(
        [
            openssl,
            "x509",
            "-req",
            "-in",
            str(server_csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(server_cert),
            "-days",
            "1",
            "-sha256",
            "-extfile",
            str(extensions),
        ],
        timeout=60,
        environment=environment,
    )
    server_csr.unlink()
    extensions.unlink()
    os.chmod(ca_key, 0o600)
    os.chmod(server_key, 0o640)
    os.chmod(ca_cert, 0o640)
    os.chmod(server_cert, 0o640)
    return tls, ca_cert


def write_server_config(root: Path) -> Path:
    config = root / "openbao.hcl"
    write_private(
        config,
        b'ui = false\n'
        b'disable_mlock = true\n'
        b'storage "inmem" {}\n'
        b'listener "tcp" {\n'
        b'  address = "0.0.0.0:8200"\n'
        b'  cluster_address = "0.0.0.0:8201"\n'
        b'  tls_cert_file = "/openbao/tls/server.crt"\n'
        b'  tls_key_file = "/openbao/tls/server.key"\n'
        b'  tls_min_version = "tls13"\n'
        b'}\n'
        b'api_addr = "https://127.0.0.1:8200"\n'
        b'cluster_addr = "https://127.0.0.1:8201"\n',
        0o640,
    )
    return config


def inspect_image(
    podman: str,
    release: dict[str, Any],
    environment: dict[str, str],
) -> str:
    image = image_reference(release)
    try:
        run_bounded(
            [podman, "pull", "--quiet", "--platform", "linux/amd64", image],
            timeout=900,
            environment=environment,
        )
        output = run_bounded(
            [
                podman,
                "image",
                "inspect",
                "--format",
                "{{.Digest}} {{.Architecture}} {{.Os}}",
                image,
            ],
            maximum=1024,
            timeout=60,
            environment=environment,
        )
    except HarnessError as error:
        raise HarnessError("locked image preparation failed") from error
    try:
        digest, architecture, operating_system = output.decode("ascii").split()
    except (UnicodeDecodeError, ValueError) as error:
        raise HarnessError("locked image inspection is malformed") from error
    if (
        digest != release["image"]["linux_amd64_digest"]
        or architecture != "amd64"
        or operating_system != "linux"
    ):
        raise HarnessError("pulled image does not match the locked Linux amd64 digest")
    return image


def container_command(
    podman: str,
    image: str,
    container: str,
    network: str,
    run_id: str,
    config: Path,
    tls: Path,
) -> list[str]:
    return [
        podman,
        "run",
        "-d",
        "--name",
        container,
        "--label",
        f"{OWNER_LABEL}={run_id}",
        "--pull",
        "never",
        "--network",
        network,
        "--read-only",
        "--user",
        "100:0",
        "--cap-drop",
        "all",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--ulimit",
        "nofile=1024:1024",
        "--ulimit",
        "nproc=256:256",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
        "--publish",
        "127.0.0.1::8200",
        "--volume",
        f"{config}:/openbao/config/openbao.hcl:ro,Z",
        "--volume",
        f"{tls}:/openbao/tls:ro,Z",
        "--entrypoint",
        "bao",
        image,
        "server",
        "-config=/openbao/config/openbao.hcl",
    ]


def parse_port(value: bytes) -> int:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise HarnessError("published port is not ASCII") from error
    match = LOOPBACK_PORT.fullmatch(text)
    if match is None:
        raise HarnessError("container did not publish one dynamic loopback port")
    port = int(match.group(1))
    if not 1 <= port <= 65535:
        raise HarnessError("published port is outside the TCP range")
    return port


class RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: Any, file: Any, code: int, message: str, headers: Any, url: str) -> None:
        del request, file, code, message, headers, url
        raise HarnessError("OpenBao preflight attempted an HTTP redirect")


def https_json(
    address: str,
    ca_cert: Path,
    method: str,
    path: str,
    payload: dict[str, Any] | None,
    accepted_statuses: set[int],
) -> dict[str, Any]:
    if method not in {"GET", "POST", "PUT"} or not path.startswith("/v1/"):
        raise HarnessError("internal HTTP request is malformed")
    context = ssl.create_default_context(cafile=str(ca_cert))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        address + path,
        data=body,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        RejectRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )
    try:
        response = opener.open(request, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    except (OSError, urllib.error.URLError) as error:
        raise HarnessError("OpenBao preflight request failed") from error
    with response:
        if response.status not in accepted_statuses:
            raise HarnessError("OpenBao preflight returned an unexpected status")
        content_type = response.headers.get_content_type()
        if content_type != "application/json":
            raise HarnessError("OpenBao preflight returned a non-JSON response")
        length = response.headers.get("Content-Length")
        if length is not None:
            try:
                parsed_length = int(length)
            except ValueError as error:
                raise HarnessError("OpenBao preflight Content-Length is malformed") from error
            if parsed_length < 0 or parsed_length > MAX_HTTP_BODY:
                raise HarnessError("OpenBao preflight response exceeds its byte limit")
        data = response.read(MAX_HTTP_BODY + 1)
    return parse_json(data)


def wait_for_exact_version(address: str, ca_cert: Path, expected: str) -> None:
    for _ in range(120):
        try:
            health = https_json(
                address,
                ca_cert,
                "GET",
                "/v1/sys/health",
                None,
                {200, 429, 472, 473, 501, 503},
            )
            verify_reported_version(health.get("version"), expected)
            return
        except VersionMismatch:
            raise
        except HarnessError:
            time.sleep(0.25)
    raise HarnessError("OpenBao did not become reachable before the preflight deadline")


def initialize_and_unseal(address: str, ca_cert: Path) -> str:
    initialized = https_json(
        address,
        ca_cert,
        "PUT",
        "/v1/sys/init",
        {"secret_shares": 1, "secret_threshold": 1},
        {200},
    )
    keys = initialized.get("keys_base64")
    token = initialized.get("root_token")
    if (
        not isinstance(keys, list)
        or len(keys) != 1
        or not isinstance(keys[0], str)
        or not keys[0]
        or not isinstance(token, str)
        or not token
    ):
        raise HarnessError("OpenBao initialization response is missing secret material")
    unseal = https_json(
        address,
        ca_cert,
        "POST",
        "/v1/sys/unseal",
        {"key": keys[0]},
        {200},
    )
    keys[0] = ""
    if unseal.get("sealed") is not False:
        raise HarnessError("OpenBao remained sealed after initialization")
    return token


def create_secret_fd(value: str) -> int:
    memfd_create = getattr(os, "memfd_create", None)
    if memfd_create is None:
        raise HarnessError("anonymous memory-backed credential files are unavailable")
    descriptor = memfd_create(
        "openbao-integration-token",
        getattr(os, "MFD_CLOEXEC", 0),
    )
    try:
        data = value.encode()
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise HarnessError("anonymous credential write made no progress")
            written += count
        os.lseek(descriptor, 0, os.SEEK_SET)
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
        fcntl.fcntl(descriptor, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def sanitize_secret_fd(descriptor: int) -> bool:
    sanitized = False
    try:
        size = os.fstat(descriptor).st_size
        os.lseek(descriptor, 0, os.SEEK_SET)
        remaining = size
        block = b"\0" * min(64 * 1024, max(1, remaining))
        while remaining:
            written = os.write(descriptor, block[:remaining])
            if written <= 0:
                break
            remaining -= written
        os.ftruncate(descriptor, 0)
        sanitized = remaining == 0
    except OSError:
        sanitized = False
    finally:
        os.close(descriptor)
    return sanitized


def read_descriptor(descriptor: int, maximum: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
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
        raise HarnessError("integration attestation exceeds the byte limit")
    return data


def validate_attestation(value: dict[str, Any], version: str) -> None:
    if set(value) != {"schema", "version", "executed", "skipped"}:
        raise HarnessError("integration attestation fields are invalid")
    if (
        value.get("schema") != "openbao-core-flow-attestation/v1"
        or value.get("version") != version
        or value.get("executed") != list(CORE_OPERATION_IDS)
        or value.get("skipped") != []
    ):
        raise HarnessError("integration attestation is incomplete or contradictory")
    if not value["executed"]:
        raise HarnessError("integration attestation contains zero executed operations")


def cargo_build_environment(root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "OPENBAO_ADDR",
        "OPENBAO_EXPECTED_VERSION",
        "OPENBAO_INTEGRATION",
        "OPENBAO_RESULT_FILE",
        "OPENBAO_TOKEN",
        "BAO_ADDR",
        "BAO_CACERT",
        "BAO_TOKEN",
        "BAO_TOKEN_FILE",
        "VAULT_ADDR",
        "VAULT_CACERT",
        "VAULT_TOKEN",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "CARGO_TARGET_DIR": str(ROOT / "target"),
            "HOME": os.environ.get("HOME", str(root)),
        }
    )
    return environment


def cargo_runtime_environment(
    root: Path,
    address: str,
    ca_cert: Path,
    token_path: str,
    result_path: str,
    version: str,
) -> dict[str, str]:
    environment = cargo_build_environment(root)
    for name in (
        "ALL_PROXY",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "all_proxy",
        "https_proxy",
        "http_proxy",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "OPENBAO_INTEGRATION": "1",
            "OPENBAO_EXPECTED_VERSION": version,
            "OPENBAO_RESULT_FILE": result_path,
            "BAO_ADDR": address,
            "BAO_CACERT": str(ca_cert),
            "BAO_TOKEN_FILE": token_path,
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        }
    )
    return environment


def validate_test_binary(path: Path, target_root: Path | None = None) -> Path:
    expected_root = target_root if target_root is not None else ROOT / "target"
    if not path.is_absolute() or len(os.fsencode(path)) > 4096:
        raise HarnessError("Cargo integration test executable path is invalid")
    try:
        root_metadata = os.lstat(expected_root)
        candidate_metadata = os.lstat(path)
        resolved_root = expected_root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except OSError as error:
        raise HarnessError("Cargo integration test executable is missing or unsafe") from error
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise HarnessError("Cargo target directory is not a real directory")
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as error:
        raise HarnessError("Cargo integration test executable escaped the target directory") from error
    if (
        resolved_path != path
        or not stat.S_ISREG(candidate_metadata.st_mode)
        or candidate_metadata.st_nlink != 1
        or candidate_metadata.st_uid != os.getuid()
        or candidate_metadata.st_mode & 0o022 != 0
        or candidate_metadata.st_mode & 0o100 == 0
    ):
        raise HarnessError("Cargo integration test executable ownership or mode is unsafe")
    return resolved_path


def compile_integration_test(root: Path) -> Path:
    output = run_bounded(
        [
            "cargo",
            "test",
            "--no-run",
            "--test",
            "openbao_integration",
            "--all-features",
            "--message-format=json-render-diagnostics",
        ],
        maximum=MAX_CARGO_OUTPUT,
        timeout=1200,
        environment=cargo_build_environment(root),
    )
    candidates: list[Path] = []
    for line in output.splitlines():
        if not line or len(line) > MAX_HTTP_BODY:
            if len(line) > MAX_HTTP_BODY:
                raise HarnessError("Cargo JSON message exceeds the byte limit")
            continue
        message = parse_json(line)
        if message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target")
        executable = message.get("executable")
        if (
            isinstance(target, dict)
            and target.get("name") == "openbao_integration"
            and target.get("kind") == ["test"]
            and isinstance(executable, str)
        ):
            candidates.append(Path(executable))
    if len(candidates) != 1:
        raise HarnessError("Cargo did not produce exactly one integration test executable")
    return validate_test_binary(candidates[0])


def sanitize_file(path: Path) -> bool:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        return False
    try:
        flags = os.O_WRONLY | no_follow
        descriptor = os.open(path, flags)
    except OSError:
        return False
    sanitized = False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return False
        remaining = metadata.st_size
        block = b"\0" * min(64 * 1024, max(1, remaining))
        while remaining:
            written = os.write(descriptor, block[:remaining])
            if written <= 0:
                break
            remaining -= written
        os.fsync(descriptor)
        sanitized = remaining == 0
    except OSError:
        sanitized = False
    finally:
        os.close(descriptor)
    return sanitized


def cleanup_private_files(root: Path) -> bool:
    sanitized = True
    for relative in ("tls/ca.key", "tls/server.key"):
        if not sanitize_file(root / relative):
            sanitized = False
    return sanitized


def resource_label(
    podman: str,
    kind: str,
    name: str,
    environment: dict[str, str],
) -> str:
    if kind == "container":
        template = f'{{{{ index .Config.Labels "{OWNER_LABEL}" }}}}'
    elif kind == "network":
        template = f'{{{{ index .Labels "{OWNER_LABEL}" }}}}'
    else:
        raise HarnessError("internal cleanup resource kind is invalid")
    output = run_bounded(
        [podman, kind, "inspect", "--format", template, name],
        maximum=256,
        timeout=60,
        environment=environment,
    )
    try:
        return output.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise HarnessError("cleanup ownership label is not ASCII") from error


def remove_owned_resource(
    podman: str,
    kind: str,
    name: str,
    run_id: str,
    environment: dict[str, str],
) -> None:
    exists_code = run_quiet(
        [podman, kind, "exists", name],
        timeout=60,
        environment=environment,
        accepted_codes=(0, 1),
    )
    if exists_code == 1:
        return
    if resource_label(podman, kind, name, environment) != run_id:
        raise HarnessError("refusing to remove a resource owned by another run")
    if kind == "container":
        command = [podman, "rm", "-f", "--time", "5", name]
    else:
        command = [podman, "network", "rm", "-f", name]
    run_quiet(command, timeout=60, environment=environment)
    remaining = run_quiet(
        [podman, kind, "exists", name],
        timeout=60,
        environment=environment,
        accepted_codes=(0, 1),
    )
    if remaining != 1:
        raise HarnessError("isolated resource survived cleanup")


def run_integration(version: str) -> dict[str, Any]:
    try:
        release = select_release(validate_lock_files(), version)
    except LockValidationError as error:
        raise HarnessError("immutable release inventory validation failed") from error
    podman, openssl = require_tools()
    old_umask = os.umask(0o077)
    try:
        root = Path(tempfile.mkdtemp(prefix="openbao-integration-", dir="/tmp"))
        os.chmod(root, 0o700)
    finally:
        os.umask(old_umask)
    container = resource_name(version)
    network = resource_name(version)
    run_id = secrets.token_hex(16)
    podman_env = command_environment(root)
    container_attempted = False
    network_created = False
    cleanup_failed = False
    primary_error: BaseException | None = None
    token_descriptor: int | None = None
    result_descriptor: int | None = None
    try:
        test_binary = compile_integration_test(root)
        tls, ca_cert = generate_tls(root, openssl, command_environment(root))
        config = write_server_config(root)
        image = inspect_image(podman, release, podman_env)
        try:
            run_bounded(
                [
                    podman,
                    "network",
                    "create",
                    "--internal",
                    "--label",
                    f"{OWNER_LABEL}={run_id}",
                    network,
                ],
                maximum=1024,
                timeout=60,
                environment=podman_env,
            )
        except HarnessError as error:
            raise HarnessError("isolated network creation failed") from error
        network_created = True
        container_attempted = True
        try:
            run_bounded(
                container_command(podman, image, container, network, run_id, config, tls),
                maximum=1024,
                timeout=120,
                environment=podman_env,
            )
        except HarnessError as error:
            raise HarnessError("isolated OpenBao container start failed") from error
        try:
            port = parse_port(
                run_bounded(
                    [podman, "port", container, "8200/tcp"],
                    maximum=1024,
                    timeout=60,
                    environment=podman_env,
                )
            )
        except HarnessError as error:
            raise HarnessError("dynamic loopback port discovery failed") from error
        address = f"https://127.0.0.1:{port}"
        wait_for_exact_version(address, ca_cert, version)
        token = initialize_and_unseal(address, ca_cert)
        token_descriptor = create_secret_fd(token)
        token_path = f"/proc/self/fd/{token_descriptor}"
        result_descriptor = create_secret_fd("")
        result_path = f"/proc/self/fd/{result_descriptor}"
        token = ""
        print(f"OpenBao integration: locked {version} preflight passed")
        result = subprocess.run(
            [str(test_binary), "--test-threads=1"],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            env=cargo_runtime_environment(
                root,
                address,
                ca_cert,
                token_path,
                result_path,
                version,
            ),
            pass_fds=(token_descriptor, result_descriptor),
            timeout=1800,
            check=False,
            close_fds=True,
        )
        if result.returncode != 0:
            raise IntegrationTestFailure("OpenBao core integration test failed")
        attestation = parse_json(read_descriptor(result_descriptor, 64 * 1024))
        validate_attestation(attestation, version)
        return {
            "version": version,
            "image_linux_amd64_digest": release["image"]["linux_amd64_digest"],
            "reported_version": version,
            "compatibility_status": "tested-subset",
            "outcome": "passed",
            "test_count": 1,
            "operations": [
                {
                    "id": operation,
                    "status": "passed",
                    "reason_code": None,
                    "classification": None,
                }
                for operation in CORE_OPERATION_IDS
            ],
            "failure_class": None,
            "failure_reason_code": None,
        }
    except subprocess.TimeoutExpired as error:
        primary_error = error
        raise HarnessError("OpenBao integration test timed out") from error
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if container_attempted:
            try:
                remove_owned_resource(
                    podman, "container", container, run_id, podman_env
                )
            except HarnessError:
                cleanup_failed = True
        if network_created:
            try:
                remove_owned_resource(podman, "network", network, run_id, podman_env)
            except HarnessError:
                cleanup_failed = True
        if token_descriptor is not None:
            if not sanitize_secret_fd(token_descriptor):
                cleanup_failed = True
        if result_descriptor is not None:
            if not sanitize_secret_fd(result_descriptor):
                cleanup_failed = True
        if not cleanup_private_files(root):
            cleanup_failed = True
        try:
            shutil.rmtree(root)
        except OSError:
            cleanup_failed = True
        if root.exists():
            cleanup_failed = True
        if cleanup_failed:
            if primary_error is not None:
                raise HarnessError("integration failed and isolated resource cleanup was incomplete") from primary_error
            raise HarnessError("isolated integration resources could not be fully cleaned")


def expect_rejected(label: str, operation: Any) -> None:
    try:
        operation()
    except (HarnessError, OSError):
        return
    raise HarnessError(f"self-test accepted {label}")


def self_test() -> None:
    try:
        document = validate_lock_files()
    except LockValidationError as error:
        raise HarnessError("immutable release inventory validation failed") from error
    release = select_release(document, "2.5.5")
    if not image_reference(release).endswith(release["image"]["linux_amd64_digest"]):
        raise HarnessError("self-test did not select the locked architecture digest")
    image = image_reference(release)
    command = container_command(
        "podman",
        image,
        "openbao-it-test-container",
        "openbao-it-test-network",
        "0" * 32,
        Path("/tmp/openbao-test-config"),
        Path("/tmp/openbao-test-tls"),
    )
    if (
        command.count(image) != 1
        or release["image"]["tag"] in command
        or "--read-only" not in command
        or "--cap-drop" not in command
        or "no-new-privileges" not in command
        or "--publish" not in command
        or "127.0.0.1::8200" not in command
        or command.count("--entrypoint") != 1
        or command[command.index("--entrypoint") + 1] != "bao"
        or command[-2:] != ["server", "-config=/openbao/config/openbao.hcl"]
    ):
        raise HarnessError("self-test container command is not locked and sandboxed")
    for value in ("", "2.5", "v2.5.5", "2.5.5;id", "docker.io/openbao/openbao:2.5.5", "9.9.9"):
        expect_rejected(f"unsafe or unknown version {value!r}", lambda value=value: select_release(document, value))
    expect_rejected(
        "a mismatched health version",
        lambda: verify_reported_version("2.5.4", "2.5.5"),
    )
    if parse_port(b"127.0.0.1:49152\n") != 49152:
        raise HarnessError("self-test failed to parse a dynamic loopback port")
    for value in (b"0.0.0.0:49152\n", b"127.0.0.1:1\n127.0.0.1:2\n", b"127.0.0.1:70000\n"):
        expect_rejected("unsafe published port", lambda value=value: parse_port(value))
    expect_rejected("duplicate response keys", lambda: parse_json(b'{"a":1,"a":2}'))
    expect_rejected("non-finite response number", lambda: parse_json(b'{"a":NaN}'))
    expect_rejected(
        "deep response JSON",
        lambda: parse_json((b'{"a":' * 18) + b"null" + (b"}" * 18)),
    )
    valid_attestation = {
        "schema": "openbao-core-flow-attestation/v1",
        "version": "2.5.5",
        "executed": list(CORE_OPERATION_IDS),
        "skipped": [],
    }
    validate_attestation(valid_attestation, "2.5.5")
    for mutation in (
        {**valid_attestation, "executed": []},
        {**valid_attestation, "executed": list(CORE_OPERATION_IDS[:-1])},
        {**valid_attestation, "skipped": ["health"]},
        {**valid_attestation, "version": "2.5.4"},
    ):
        expect_rejected(
            "a false-green integration attestation",
            lambda mutation=mutation: validate_attestation(mutation, "2.5.5"),
        )
    with tempfile.TemporaryDirectory(prefix="openbao-harness-self-test-") as directory:
        root = Path(directory)
        secret = root / "secret"
        write_private(secret, b"credential")
        if not sanitize_file(secret):
            raise HarnessError("self-test could not sanitize a credential file")
        if secret.read_bytes() != b"\0" * len(b"credential"):
            raise HarnessError("self-test did not sanitize a credential file")
        target = root / "target"
        target.write_bytes(b"x")
        symlink = root / "symlink"
        symlink.symlink_to(target)
        expect_rejected("symbolic-link credential creation", lambda: write_private(symlink, b"secret"))
        fifo = root / "fifo"
        os.mkfifo(fifo)
        expect_rejected("FIFO credential creation", lambda: write_private(fifo, b"secret"))
        cargo_target = root / "cargo-target"
        cargo_target.mkdir(mode=0o700)
        test_binary = cargo_target / "openbao_integration-test"
        test_binary.write_bytes(b"test executable")
        test_binary.chmod(0o700)
        if validate_test_binary(test_binary, cargo_target) != test_binary:
            raise HarnessError("self-test rejected a private integration executable")
        binary_symlink = cargo_target / "test-symlink"
        binary_symlink.symlink_to(test_binary)
        expect_rejected(
            "symbolic-link integration executable",
            lambda: validate_test_binary(binary_symlink, cargo_target),
        )
        writable_binary = cargo_target / "writable-test"
        writable_binary.write_bytes(b"test executable")
        writable_binary.chmod(0o722)
        expect_rejected(
            "group-writable integration executable",
            lambda: validate_test_binary(writable_binary, cargo_target),
        )
        outside_binary = root / "outside-test"
        outside_binary.write_bytes(b"test executable")
        outside_binary.chmod(0o700)
        expect_rejected(
            "integration executable outside target",
            lambda: validate_test_binary(outside_binary, cargo_target),
        )
        descriptor = create_secret_fd("credential")
        if Path(f"/proc/self/fd/{descriptor}").read_text() != "credential":
            raise HarnessError("self-test anonymous credential is unreadable")
        if not sanitize_secret_fd(descriptor):
            raise HarnessError("self-test could not sanitize an anonymous credential")
    first = resource_name("2.5.5")
    second = resource_name("2.5.5")
    if first == second or RESOURCE.fullmatch(first) is None or RESOURCE.fullmatch(second) is None:
        raise HarnessError("self-test generated colliding or unsafe resource names")


def interrupted(signum: int, frame: Any) -> None:
    del signum, frame
    raise HarnessInterrupted("OpenBao integration interrupted")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--version")
    action.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if arguments.self_test:
            self_test()
            print("OpenBao integration harness self-tests: ok")
        else:
            run_integration(arguments.version)
            print(f"OpenBao integration: locked {arguments.version} passed")
        return 0
    except (HarnessError, OSError) as error:
        print(f"OpenBao integration harness failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
