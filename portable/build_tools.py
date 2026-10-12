#!/usr/bin/env python3
"""Bind portable CMake/Ninja execution to the producer's installed bytes.

The producer OS, dynamic libraries and CMake modules remain trusted. These
receipts protect the selected executables against an unprivileged consumer;
they do not attest the complete transitive execution environment.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import subprocess

PATHS = {"cmake": "/usr/bin/cmake", "ninja": "/usr/bin/ninja"}
FIELDS = {"path", "resolved_path", "sha256", "size", "executable", "version"}
MAX_BINARY_SIZE = 512 * 1024 * 1024


def validate(installed: dict) -> dict:
    if type(installed) is not dict:
        raise ValueError("invalid producer installed metadata object")
    receipt = installed.get("build_tools")
    if receipt is None:
        raise ValueError("missing producer build_tools receipt; rebuild the portable SDK with CMake/Ninja identities")
    if (type(receipt) is not dict or set(receipt) != {"schema_version", "tools"}
            or type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1
            or type(receipt["tools"]) is not dict or set(receipt["tools"]) != set(PATHS)):
        raise ValueError("invalid producer build_tools schema or roles")
    legacy = installed.get("tools")
    if type(legacy) is not dict:
        raise ValueError("missing installed tool version strings")
    for role, path in PATHS.items():
        item = receipt["tools"][role]
        if type(item) is not dict or set(item) != FIELDS or item["path"] != path:
            raise ValueError("invalid producer build tool fields or fixed path: " + role)
        resolved = item["resolved_path"]
        if (type(resolved) is not str or not resolved.startswith("/")
                or resolved.startswith("//") or "\x00" in resolved
                or posixpath.normpath(resolved) != resolved or resolved != path):
            raise ValueError("invalid canonical build tool path: " + role)
        if (type(item["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                or type(item["size"]) is not int or not 0 < item["size"] <= MAX_BINARY_SIZE
                or item["executable"] is not True):
            raise ValueError("invalid producer build tool identity: " + role)
        version = item["version"]
        if (type(version) is not str or not version or len(version) > 65536
                or any((ord(char) < 32 and char != "\n") or ord(char) == 127 for char in version)):
            raise ValueError("invalid complete build tool version: " + role)
        first = version.splitlines()[0]
        pattern = r"cmake version [0-9]+\.[0-9]+\.[0-9]+" if role == "cmake" else r"[0-9]+\.[0-9]+(?:\.[0-9]+)?"
        if not re.fullmatch(pattern, first) or type(legacy.get(role)) is not str or legacy[role] != first:
            raise ValueError("build tool version disagrees with installed.tools: " + role)
    return receipt


def _protected_path(path: Path) -> Path:
    """Check every component; fixed Debian tool/metadata paths cannot use links."""
    resolved = Path("/")
    parts = list(path.parts[1:]) if path.is_absolute() else [*Path.cwd().parts[1:], *path.parts]

    def check(candidate):
        info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("symlink in installed build tool path: " + str(candidate))
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("unprotected installed build tool path: " + str(candidate))
        return info

    check(resolved)
    while parts:
        component = parts.pop(0)
        if component in ("", "."):
            continue
        if component == "..":
            resolved = resolved.parent
            check(resolved)
            continue
        candidate = resolved / component
        info = check(candidate)
        if parts and not stat.S_ISDIR(info.st_mode):
            raise ValueError("invalid build tool directory: " + str(candidate))
        resolved = candidate
    return resolved


def _identity(fd: int) -> tuple[os.stat_result, str]:
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o6022
            or not info.st_mode & 0o111 or not 0 < info.st_size <= MAX_BINARY_SIZE):
        raise ValueError("build tool must be a protected executable regular file")
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
    return info, digest.hexdigest()


def _coordinates(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def protected_tools(expected: dict | None = None):
    """Keep verified descriptors alive and fence fixed paths around execution."""
    handles = {}
    identities = {}
    try:
        # All roles must pass byte admission BEFORE either --version executes.
        for role, value in PATHS.items():
            path = Path(value)
            resolved = _protected_path(path)
            fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            handles[role] = fd
            info, digest = _identity(fd)
            if _coordinates(info) != _coordinates(resolved.stat()) or _protected_path(path) != resolved:
                raise ValueError("build tool changed during admission: " + role)
            item = {"path": value, "resolved_path": str(resolved), "sha256": digest,
                    "size": info.st_size, "executable": True}
            if expected is not None and any(item[key] != expected[role][key] for key in item):
                raise ValueError("changed installed producer build tool identity: " + role)
            identities[role] = (item, info)

        def fence():
            for role, (item, before) in identities.items():
                resolved = _protected_path(Path(item["path"]))
                info, digest = _identity(handles[role])
                if (str(resolved) != item["resolved_path"] or _coordinates(info) != _coordinates(before)
                        or _coordinates(resolved.stat()) != _coordinates(before) or digest != item["sha256"]):
                    raise ValueError("installed build tool changed across execution: " + role)

        fence()
        try:
            yield {role: item for role, (item, _) in identities.items()}, fence
        finally:
            fence()
    finally:
        for fd in handles.values():
            os.close(fd)


def _versions(items: dict, fence, expected: dict | None = None) -> None:
    for role, item in items.items():
        fence()
        # Preserve complete stdout, including its final newline, in the receipt.
        try:
            version = subprocess.check_output([item["path"], "--version"]).decode("utf-8")
        finally:
            fence()
        if expected is not None and version != expected[role]["version"]:
            raise ValueError("changed installed producer build tool version: " + role)
        item["version"] = version


def record() -> dict:
    with protected_tools() as (items, fence):
        _versions(items, fence)
        receipt = {"schema_version": 1, "tools": items}
        validate({"build_tools": receipt, "tools": {role: item["version"].splitlines()[0]
                                                   for role, item in items.items()}})
        return receipt


def verify(installed: dict, *, role: str | None = None, arguments: list[str] | None = None) -> None:
    receipt = validate(installed)
    with protected_tools(receipt["tools"]) as (items, fence):
        _versions(items, fence, receipt["tools"])
        if role is not None:
            if role not in PATHS:
                raise ValueError("unsupported portable build tool role")
            fence()
            subprocess.run([PATHS[role], *(arguments or [])], check=True)
            fence()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", required=True, type=Path, help="producer installed.json")
    parser.add_argument("--run", choices=PATHS)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments
    if arguments[:1] == ["--"]:
        arguments = arguments[1:]
    if arguments and args.run is None:
        parser.error("arguments require --run")
    try:
        verify(load_installed(args.verify), role=args.run, arguments=arguments)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"portable build tool verification failed: {exc}\n")


def load_installed(path: Path) -> dict:
    """Metadata cannot be supplied by an unprivileged consumer either."""
    resolved = _protected_path(path)
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
                or not 0 < before.st_size <= 1024 * 1024):
            raise ValueError("installed metadata must be a protected regular file")
        with os.fdopen(os.dup(fd), "rb") as source:
            payload = source.read(1024 * 1024 + 1)
        if (_protected_path(path) != resolved or _coordinates(os.fstat(fd)) != _coordinates(before)
                or _coordinates(resolved.stat()) != _coordinates(before) or len(payload) != before.st_size):
            raise ValueError("installed metadata changed during admission")

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate installed metadata field: " + key)
                result[key] = value
            return result

        return json.loads(payload, object_pairs_hook=unique)
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
