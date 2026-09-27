"""System-tool trust boundary for API evidence acquisition (not SDK transport)."""

from contextlib import contextmanager
from pathlib import Path
import stat
import tempfile


TOOLS = {name: Path("/usr/bin") / name for name in ("cosign", "git", "podman", "skopeo")}
BAO_ENV = frozenset({"BAO_ADDR", "BAO_DEV_LISTEN_ADDRESS", "BAO_DEV_ROOT_TOKEN_ID", "BAO_DISABLE_MLOCK", "BAO_TOKEN"})


def protected_path(path: Path) -> Path:
    # Check both the installed path and resolved target (distro alternatives).
    resolved = path.resolve(strict=True)
    for candidate in {path, *path.parents, resolved, *resolved.parents}:
        metadata = candidate.lstat()
        if metadata.st_uid != 0 or (not stat.S_ISLNK(metadata.st_mode) and metadata.st_mode & 0o022):
            raise ValueError("evidence tool and its parents must be root-owned and not group/world writable")
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
        raise ValueError("evidence tool must be an executable regular file")
    return resolved


@contextmanager
def invocation(command: list[str], environment: dict[str, str] | None = None):
    if not command or command[0] not in TOOLS:
        raise ValueError("unsupported evidence tool")
    executable = protected_path(TOOLS[command[0]])
    additions = environment or {}
    if set(additions) - BAO_ENV:
        raise ValueError("unsupported evidence environment override")
    # A fresh home/config prevents user-level Git, Sigstore and registry settings
    # from overriding verification. System installation/configuration is trusted.
    with tempfile.TemporaryDirectory(prefix="openbao-tool-", dir="/tmp") as home:
        safe = {
            "PATH": "/usr/bin:/bin", "HOME": home, "LANG": "C.UTF-8",
            "XDG_CONFIG_HOME": home, "XDG_CACHE_HOME": home,
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
            **additions,
        }
        yield [str(executable), *command[1:]], safe
