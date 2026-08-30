#!/usr/bin/env python3
"""Install the checksum-locked Classic Linux GPU shader toolchain."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
from typing import BinaryIO, Iterable
import urllib.parse
import urllib.request
import json
import os
import re


MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_MEMBERS = 100_000
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")


class ToolchainError(RuntimeError):
    """The shader toolchain manifest, archive, or build failed validation."""


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ToolchainError(f"duplicate shader toolchain manifest key: {key}")
        value[key] = item
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_keys(value: dict[str, object], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        raise ToolchainError(f"{context}: {'; '.join(details)}")


def locked_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ToolchainError(f"{field} must be a non-empty trimmed string")
    return value


def locked_digest(value: object, field: str) -> str:
    value = locked_text(value, field)
    if not SHA256_RE.fullmatch(value):
        raise ToolchainError(f"{field} must be a lowercase SHA-256")
    return value


def safe_relative_path(value: object, field: str) -> str:
    value = locked_text(value, field)
    if "\\" in value or "\x00" in value:
        raise ToolchainError(f"{field} must be a safe relative path")
    path = PurePosixPath(value)
    if (
        value != path.as_posix()
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ToolchainError(f"{field} must be a safe relative path")
    return value


def safe_absolute_path(value: object, field: str) -> str:
    value = locked_text(value, field)
    if "\\" in value or "\x00" in value:
        raise ToolchainError(f"{field} must be a safe absolute path")
    path = PurePosixPath(value)
    if (
        value != path.as_posix()
        or not path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ToolchainError(f"{field} must be a safe absolute path")
    return value


def canonical_https(value: object, field: str) -> str:
    value = locked_text(value, field)
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as error:
        raise ToolchainError(f"{field} must be a canonical HTTPS URL") from error
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
    ):
        raise ToolchainError(f"{field} must be a canonical HTTPS URL")
    return value


def load_manifest(path: Path) -> dict[str, object]:
    try:
        data = path.read_bytes()
        if len(data) > MAX_MANIFEST_BYTES:
            raise ToolchainError("shader toolchain manifest exceeds the JSON size limit")
        value = json.loads(
            data, object_pairs_hook=reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ToolchainError(f"cannot read shader toolchain manifest {path}: {error}") from error
    if not isinstance(value, dict):
        raise ToolchainError("shader toolchain manifest root must be an object")
    require_keys(
        value,
        {
            "$schema",
            "schema_version",
            "platform",
            "target",
            "image",
            "dxc",
            "spirv_cross",
            "install",
            "runtime",
        },
        "manifest root",
    )
    if value["$schema"] != "https://json-schema.org/draft/2020-12/schema":
        raise ToolchainError("manifest $schema is not the governed schema")
    if value["schema_version"] != 1 or value["platform"] != "linux/amd64":
        raise ToolchainError("unsupported shader toolchain manifest")
    if value["target"] != "classic-final" or value["image"] != "ghcr.io/atrinik/classic-build":
        raise ToolchainError("manifest does not describe the public Classic image")

    dxc = value["dxc"]
    spirv_cross = value["spirv_cross"]
    if not isinstance(dxc, dict) or not isinstance(spirv_cross, dict):
        raise ToolchainError("shader tool entries must be objects")
    require_keys(
        dxc,
        {"repository", "tag", "commit", "url", "sha256", "archive_root", "files"},
        "dxc",
    )
    require_keys(
        spirv_cross,
        {
            "repository",
            "commit",
            "url",
            "sha256",
            "license",
            "license_path",
            "license_sha256",
        },
        "spirv_cross",
    )
    if dxc["repository"] != "microsoft/DirectXShaderCompiler":
        raise ToolchainError("dxc.repository is not the governed upstream")
    if spirv_cross["repository"] != "KhronosGroup/SPIRV-Cross":
        raise ToolchainError("spirv_cross.repository is not the governed upstream")
    if dxc["tag"] != "v1.9.2607":
        raise ToolchainError("dxc.tag is not the qualified release")
    if dxc["commit"] != "0d3ee6b551b8fa768fbf825300ebab81047ef6a8":
        raise ToolchainError("dxc.commit is not the qualified release commit")
    for context, entry in (("dxc", dxc), ("spirv_cross", spirv_cross)):
        commit = locked_text(entry["commit"], f"{context}.commit")
        if not COMMIT_RE.fullmatch(commit):
            raise ToolchainError(f"{context}.commit must be a full lowercase Git SHA")
        canonical_https(entry["url"], f"{context}.url")
        locked_digest(entry["sha256"], f"{context}.sha256")

    archive_root = safe_relative_path(dxc["archive_root"], "dxc.archive_root")
    if "/" in archive_root:
        raise ToolchainError("dxc.archive_root must be one safe path component")
    expected_dxc_url = (
        "https://github.com/microsoft/DirectXShaderCompiler/releases/download/"
        f"{dxc['tag']}/{archive_root}.tar.gz"
    )
    if dxc["url"] != expected_dxc_url:
        raise ToolchainError("dxc.url does not match its governed release coordinate")
    expected_spirv_url = (
        "https://codeload.github.com/KhronosGroup/SPIRV-Cross/tar.gz/"
        f"{spirv_cross['commit']}"
    )
    if spirv_cross["url"] != expected_spirv_url:
        raise ToolchainError("spirv_cross.url does not match its governed commit coordinate")
    if spirv_cross["license"] != "Apache-2.0":
        raise ToolchainError("spirv_cross.license is not the governed license")
    safe_relative_path(spirv_cross["license_path"], "spirv_cross.license_path")
    locked_digest(spirv_cross["license_sha256"], "spirv_cross.license_sha256")

    files = dxc["files"]
    if not isinstance(files, dict) or set(files) != {
        "bin/dxc",
        "lib/libdxcompiler.so",
        "lib/libdxil.so",
        "LICENCE-MIT.txt",
        "LICENSE-LLVM.txt",
        "LICENSE-MS.txt",
    }:
        raise ToolchainError("dxc.files does not describe the complete locked archive")
    for name, digest in files.items():
        safe_relative_path(name, f"dxc.files.{name}")
        locked_digest(digest, f"dxc.files.{name}")

    install = value["install"]
    runtime = value["runtime"]
    if not isinstance(install, dict) or not isinstance(runtime, dict):
        raise ToolchainError("manifest install and runtime entries must be objects")
    require_keys(install, {"dxc", "spirv_cross"}, "install")
    install_dxc = install["dxc"]
    install_spirv = install["spirv_cross"]
    if not isinstance(install_dxc, dict) or not isinstance(install_spirv, dict):
        raise ToolchainError("manifest install entries must be objects")
    require_keys(install_dxc, {"executable", "libraries", "licenses"}, "install.dxc")
    require_keys(install_spirv, {"executable", "license"}, "install.spirv_cross")
    if install_dxc["executable"] != "bin/dxc":
        raise ToolchainError("install.dxc.executable is unexpected")
    libraries = install_dxc["libraries"]
    if libraries != ["lib/libdxcompiler.so", "lib/libdxil.so"]:
        raise ToolchainError("install.dxc.libraries are unexpected")
    if not isinstance(libraries, list) or any(
        not isinstance(path, str) or path not in files for path in libraries
    ):
        raise ToolchainError("install.dxc.libraries are not locked DXC members")
    licenses = install_dxc["licenses"]
    if not isinstance(licenses, list) or len(licenses) != 3:
        raise ToolchainError("install.dxc.licenses must contain all DXC licenses")
    license_names: set[str] = set()
    for index, item in enumerate(licenses):
        if not isinstance(item, dict):
            raise ToolchainError(f"install.dxc.licenses[{index}] must be an object")
        require_keys(item, {"archive_path", "destination"}, f"install.dxc.licenses[{index}]")
        archive_path = safe_relative_path(
            item["archive_path"], f"install.dxc.licenses[{index}].archive_path"
        )
        if archive_path in license_names or archive_path not in files or archive_path.startswith("bin/") or archive_path.startswith("lib/"):
            raise ToolchainError("install.dxc.licenses contains an invalid or duplicate member")
        license_names.add(archive_path)
        safe_relative_path(item["destination"], f"install.dxc.licenses[{index}].destination")
    if license_names != {"LICENCE-MIT.txt", "LICENSE-LLVM.txt", "LICENSE-MS.txt"}:
        raise ToolchainError("install.dxc.licenses is incomplete")
    if install_spirv["executable"] != "bin/spirv-cross":
        raise ToolchainError("install.spirv_cross.executable is unexpected")
    spirv_license = install_spirv["license"]
    if not isinstance(spirv_license, dict):
        raise ToolchainError("install.spirv_cross.license must be an object")
    require_keys(spirv_license, {"archive_path", "destination"}, "install.spirv_cross.license")
    if spirv_license["archive_path"] != spirv_cross["license_path"]:
        raise ToolchainError("SPIRV-Cross license path is inconsistent")
    safe_relative_path(spirv_license["archive_path"], "install.spirv_cross.license.archive_path")
    safe_relative_path(spirv_license["destination"], "install.spirv_cross.license.destination")

    require_keys(runtime, {"vulkan_icd", "display_server", "commands"}, "runtime")
    if runtime["vulkan_icd"] != "/usr/share/vulkan/icd.d/lvp_icd.json":
        raise ToolchainError("runtime.vulkan_icd is not the governed Lavapipe path")
    if runtime["display_server"] != "Xvfb":
        raise ToolchainError("runtime.display_server is not Xvfb")
    if runtime["commands"] != ["vulkaninfo", "Xvfb", "xvfb-run"]:
        raise ToolchainError("runtime.commands are incomplete")
    return value


def download(url: str, expected: str, cache: Path) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / f"{expected}.tar.gz"
    if destination.is_symlink():
        raise ToolchainError(f"shader toolchain cache entry is a symlink: {destination}")
    if destination.is_file() and destination.stat().st_size <= MAX_ARCHIVE_BYTES:
        if sha256(destination) == expected:
            return destination
    elif destination.exists():
        raise ToolchainError(f"invalid shader toolchain cache entry: {destination}")

    request = urllib.request.Request(url, headers={"User-Agent": "Atrinik shader toolchain/1"})
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{expected}.", dir=cache)
    temporary = Path(temporary_name)
    try:
        total = 0
        with os.fdopen(descriptor, "wb") as output, urllib.request.urlopen(
            request, timeout=120
        ) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https":
                raise ToolchainError("shader toolchain download left HTTPS")
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > MAX_ARCHIVE_BYTES:
                    raise ToolchainError("shader toolchain archive exceeds size limit")
                output.write(block)
        if sha256(temporary) != expected:
            raise ToolchainError("shader toolchain archive digest mismatch")
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def safe_archive_path(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name:
        raise ToolchainError(f"unsafe shader archive member: {name}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ToolchainError(f"unsafe shader archive member: {name}")
    return path


def copy_member(source: BinaryIO, destination: Path, size: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        remaining = size
        while remaining:
            block = source.read(min(1024 * 1024, remaining))
            if not block:
                raise ToolchainError(f"truncated archive member: {destination}")
            output.write(block)
            remaining -= len(block)


def extract_dxc(archive_path: Path, destination: Path, entry: dict[str, object]) -> None:
    root = str(entry["archive_root"])
    files = entry["files"]
    assert isinstance(files, dict)
    expected = {f"{root}/{name}": name for name in files}
    seen: set[str] = set()
    count = 0
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive:
            count += 1
            if count > MAX_MEMBERS:
                raise ToolchainError("DXC archive has too many members")
            safe_archive_path(member.name)
            name = expected.get(member.name)
            if name is None:
                continue
            if name in seen or not member.isfile() or member.size > MAX_FILE_BYTES:
                raise ToolchainError(f"invalid DXC archive member: {member.name}")
            source = archive.extractfile(member)
            if source is None:
                raise ToolchainError(f"cannot read DXC archive member: {member.name}")
            with source:
                copy_member(source, destination / name, member.size)
            output = destination / name
            output.chmod(0o755 if name == "bin/dxc" else 0o644)
            if sha256(output) != files[name]:
                raise ToolchainError(f"DXC member digest mismatch: {name}")
            seen.add(name)
    if seen != set(files):
        missing = sorted(set(files) - seen)
        raise ToolchainError(f"DXC archive is missing locked members: {missing}")


def source_relative_path(name: str) -> PurePosixPath | None:
    path = safe_archive_path(name)
    if len(path.parts) <= 1:
        return None
    return PurePosixPath(*path.parts[1:])


def extract_spirv_cross(archive_path: Path, destination: Path) -> None:
    seen: set[str] = set()
    expanded = 0
    count = 0
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive:
            count += 1
            if count > MAX_MEMBERS:
                raise ToolchainError("SPIRV-Cross archive has too many members")
            relative = source_relative_path(member.name)
            if relative is None:
                continue
            key = relative.as_posix().casefold()
            if key in seen:
                raise ToolchainError(f"duplicate SPIRV-Cross archive path: {relative}")
            seen.add(key)
            output = destination.joinpath(*relative.parts)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.size > MAX_FILE_BYTES:
                raise ToolchainError(f"unsupported SPIRV-Cross archive member: {member.name}")
            expanded += member.size
            if expanded > MAX_EXPANDED_BYTES:
                raise ToolchainError("SPIRV-Cross archive exceeds expanded size limit")
            source = archive.extractfile(member)
            if source is None:
                raise ToolchainError(f"cannot read SPIRV-Cross archive member: {member.name}")
            with source:
                copy_member(source, output, member.size)
            output.chmod(stat.S_IMODE(member.mode) & 0o755 or 0o644)
    if not (destination / "CMakeLists.txt").is_file():
        raise ToolchainError("SPIRV-Cross archive has no source root")


def install_file(source: Path, destination: Path, expected: str, executable: bool) -> None:
    if source.is_symlink() or not source.is_file():
        raise ToolchainError(f"shader toolchain source is not a regular file: {source}")
    if sha256(source) != expected:
        raise ToolchainError(f"shader toolchain installed file digest mismatch: {source}")
    if destination.is_symlink():
        raise ToolchainError(f"shader toolchain destination is a symlink: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.unlink(missing_ok=True)
    shutil.copyfile(source, temporary)
    temporary.chmod(0o755 if executable else 0o644)
    temporary.replace(destination)


def run_build(source: Path, build: Path, jobs: int) -> Path:
    subprocess.run(
        [
            "cmake",
            "-S",
            str(source),
            "-B",
            str(build),
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DSPIRV_CROSS_CLI=ON",
            "-DSPIRV_CROSS_ENABLE_TESTS=OFF",
            "-DGIT_EXECUTABLE=GIT_EXECUTABLE-NOTFOUND",
        ],
        check=True,
    )
    subprocess.run(
        ["cmake", "--build", str(build), "--target", "spirv-cross", "--parallel", str(jobs)],
        check=True,
    )
    executable = build / "spirv-cross"
    if executable.is_symlink() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise ToolchainError("SPIRV-Cross build did not produce an executable")
    return executable


def install_manifest_files(manifest: dict[str, object], prefix: Path, staging: Path) -> None:
    dxc = manifest["dxc"]
    spirv_cross = manifest["spirv_cross"]
    install = manifest["install"]
    assert isinstance(dxc, dict) and isinstance(spirv_cross, dict) and isinstance(install, dict)
    install_dxc = install["dxc"]
    install_spirv = install["spirv_cross"]
    assert isinstance(install_dxc, dict) and isinstance(install_spirv, dict)
    files = dxc["files"]
    assert isinstance(files, dict)
    dxc_source = staging / "dxc"
    install_file(
        dxc_source / str(install_dxc["executable"]),
        prefix / str(install_dxc["executable"]),
        str(files[str(install_dxc["executable"])]),
        True,
    )
    for relative in install_dxc["libraries"]:  # type: ignore[union-attr]
        install_file(
            dxc_source / str(relative),
            prefix / str(relative),
            str(files[str(relative)]),
            False,
        )
    for license_entry in install_dxc["licenses"]:  # type: ignore[union-attr]
        assert isinstance(license_entry, dict)
        archive_path = str(license_entry["archive_path"])
        install_file(
            dxc_source / archive_path,
            prefix / str(license_entry["destination"]),
            str(files[archive_path]),
            False,
        )

    spirv_license = install_spirv["license"]
    assert isinstance(spirv_license, dict)
    source_license = staging / "spirv-cross-source" / str(spirv_license["archive_path"])
    install_file(
        source_license,
        prefix / str(spirv_license["destination"]),
        str(spirv_cross["license_sha256"]),
        False,
    )
    spirv_executable = staging / "spirv-cross-build" / "spirv-cross"
    install_file(
        spirv_executable,
        prefix / str(install_spirv["executable"]),
        sha256(spirv_executable),
        True,
    )


def install(manifest_path: Path, cache: Path, prefix: Path, jobs: int) -> None:
    manifest = load_manifest(manifest_path.resolve(strict=True))
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise ToolchainError("the governed shader toolchain targets x86-64 Linux")
    if jobs < 1 or jobs > 256:
        raise ToolchainError("jobs must be between 1 and 256")
    prefix = prefix.resolve()
    if prefix == Path("/") or not prefix.is_absolute():
        raise ToolchainError("install prefix must be a non-root absolute path")
    dxc = manifest["dxc"]
    spirv_cross = manifest["spirv_cross"]
    assert isinstance(dxc, dict) and isinstance(spirv_cross, dict)
    dxc_archive = download(str(dxc["url"]), str(dxc["sha256"]), cache)
    spirv_archive = download(str(spirv_cross["url"]), str(spirv_cross["sha256"]), cache)
    staging = Path(tempfile.mkdtemp(prefix=".classic-shader-toolchain-", dir=cache.parent))
    try:
        extract_dxc(dxc_archive, staging / "dxc", dxc)
        extract_spirv_cross(spirv_archive, staging / "spirv-cross-source")
        run_build(
            staging / "spirv-cross-source",
            staging / "spirv-cross-build",
            jobs,
        )
        install_manifest_files(manifest, prefix, staging)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--jobs", type=int, required=True)
    arguments = parser.parse_args(argv)
    try:
        install(arguments.manifest, arguments.cache.resolve(), arguments.prefix, arguments.jobs)
    except (OSError, subprocess.CalledProcessError, ToolchainError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
