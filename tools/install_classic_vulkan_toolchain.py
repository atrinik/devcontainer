#!/usr/bin/env python3
"""Build and install the checksum-locked Mesa Dozen Vulkan runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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
import re


MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_MEMBERS = 100_000
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")


class ToolchainError(RuntimeError):
    """The Vulkan toolchain manifest, archive, or build failed validation."""


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ToolchainError(f"duplicate Vulkan toolchain manifest key: {key}")
        value[key] = item
    return value


def load_json(path: Path, description: str) -> object:
    try:
        data = path.read_bytes()
        if len(data) > MAX_MANIFEST_BYTES:
            raise ToolchainError(f"{description} exceeds the JSON size limit")
        return json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ToolchainError(f"cannot read {description} {path}: {error}") from error


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


def locked_commit(value: object, field: str) -> str:
    value = locked_text(value, field)
    if not COMMIT_RE.fullmatch(value):
        raise ToolchainError(f"{field} must be a full lowercase Git SHA")
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


def expected_options() -> dict[str, object]:
    return {
        "build-tests": False,
        "display-info": "disabled",
        "egl": "disabled",
        "expat": "disabled",
        "gallium-d3d12-graphics": "enabled",
        "gallium-d3d12-video": "disabled",
        "gallium-drivers": ["d3d12"],
        "gallium-rusticl": False,
        "gallium-va": "disabled",
        "gbm": "disabled",
        "glx": "disabled",
        "gles1": "disabled",
        "gles2": "disabled",
        "html-docs": "disabled",
        "install-mesa-clc": False,
        "libunwind": "disabled",
        "llvm": "disabled",
        "lmsensors": "disabled",
        "mesa-clc": "auto",
        "opengl": False,
        "perfetto": False,
        "platforms": ["wayland"],
        "shared-glapi": "disabled",
        "spirv-tools": "disabled",
        "teflon": False,
        "valgrind": "disabled",
        "vulkan-drivers": ["microsoft-experimental"],
        "vulkan-manifest-per-architecture": True,
        "xmlconfig": "disabled",
        "zstd": "disabled",
    }


def load_manifest(path: Path) -> dict[str, object]:
    value = load_json(path, "Vulkan toolchain manifest")
    if not isinstance(value, dict):
        raise ToolchainError("Vulkan toolchain manifest root must be an object")
    require_keys(
        value,
        {"$schema", "schema_version", "platform", "target", "image", "base", "source", "build", "install", "runtime"},
        "manifest root",
    )
    if value["$schema"] != "https://json-schema.org/draft/2020-12/schema":
        raise ToolchainError("manifest $schema is not the governed schema")
    if value["schema_version"] != 1 or value["platform"] != "linux/amd64":
        raise ToolchainError("unsupported Vulkan toolchain manifest")
    if value["target"] != "classic-final" or value["image"] != "ghcr.io/atrinik/classic-build":
        raise ToolchainError("manifest does not describe the public Classic image")

    base = value["base"]
    if not isinstance(base, dict):
        raise ToolchainError("manifest base must be an object")
    require_keys(base, {"image", "digest", "apt_snapshot"}, "base")
    if base != {
        "image": "ubuntu:26.04",
        "digest": "sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03",
        "apt_snapshot": "20260810T000000Z",
    }:
        raise ToolchainError("manifest base does not match the governed Classic image")

    source = value["source"]
    if not isinstance(source, dict):
        raise ToolchainError("manifest source must be an object")
    require_keys(
        source,
        {"repository", "tag", "version", "commit", "url", "sha256", "archive_root"},
        "source",
    )
    if source["repository"] != "mesa/mesa":
        raise ToolchainError("source.repository is not the governed Mesa repository")
    if source["tag"] != "mesa-26.0.8" or source["version"] != "26.0.8":
        raise ToolchainError("source is not the qualified Mesa 26.0.8 release")
    locked_commit(source["commit"], "source.commit")
    if source["commit"] != "60e95b787857afbc9a00b693b91c0d9c8923a430":
        raise ToolchainError("source.commit is not the qualified Mesa release commit")
    canonical_https(source["url"], "source.url")
    if source["url"] != "https://archive.mesa3d.org/mesa-26.0.8.tar.xz":
        raise ToolchainError("source.url does not match the governed Mesa archive")
    locked_digest(source["sha256"], "source.sha256")
    if source["sha256"] != "caf1c0061a68e88dfa74967a7e780c0e85d65b6c4e334cd69095a5dc54ad78bc":
        raise ToolchainError("source.sha256 is not the qualified Mesa archive digest")
    archive_root = safe_relative_path(source["archive_root"], "source.archive_root")
    if archive_root != "mesa-26.0.8" or "/" in archive_root:
        raise ToolchainError("source.archive_root is not the qualified archive root")

    build = value["build"]
    if not isinstance(build, dict):
        raise ToolchainError("manifest build must be an object")
    require_keys(build, {"system", "version", "package_lock", "configure", "options"}, "build")
    if build["system"] != "meson" or build["version"] != "1.10.1":
        raise ToolchainError("manifest does not describe the pinned Meson build")
    safe_relative_path(build["package_lock"], "build.package_lock")
    if build["package_lock"] != "classic-vulkan-packages.lock":
        raise ToolchainError("build.package_lock is not the governed package lock")
    configure = build["configure"]
    if not isinstance(configure, dict):
        raise ToolchainError("build.configure must be an object")
    require_keys(configure, {"buildtype", "libdir", "prefix", "wrap_mode"}, "build.configure")
    if configure != {
        "buildtype": "release",
        "libdir": "lib/x86_64-linux-gnu",
        "prefix": "/usr",
        "wrap_mode": "nodownload",
    }:
        raise ToolchainError("build.configure is not the governed release configuration")
    options = build["options"]
    if not isinstance(options, dict) or options != expected_options():
        raise ToolchainError("build.options are not the governed narrow Dozen configuration")

    install = value["install"]
    if not isinstance(install, dict):
        raise ToolchainError("manifest install must be an object")
    require_keys(install, {"library", "icd", "icd_library", "icd_api_version"}, "install")
    if install != {
        "library": "/usr/lib/x86_64-linux-gnu/libvulkan_dzn.so",
        "icd": "/usr/share/vulkan/icd.d/dzn_icd.x86_64.json",
        "icd_library": "libvulkan_dzn.so",
        "icd_api_version": "1.1.335",
    }:
        raise ToolchainError("manifest install paths are not the governed Dozen artifacts")
    safe_absolute_path(install["library"], "install.library")
    safe_absolute_path(install["icd"], "install.icd")
    safe_relative_path(install["icd_library"], "install.icd_library")
    locked_text(install["icd_api_version"], "install.icd_api_version")

    runtime = value["runtime"]
    if not isinstance(runtime, dict):
        raise ToolchainError("manifest runtime must be an object")
    require_keys(runtime, {"packages", "shared_library_sonames", "headless", "wslg"}, "runtime")
    packages = runtime["packages"]
    expected_packages = [
        {"name": "libdrm2", "version": "2.4.131-1"},
        {"name": "libudev1", "version": "259.5-0ubuntu3.3"},
        {"name": "libvulkan1", "version": "1.4.341.0-1"},
        {"name": "libwayland-client0", "version": "1.24.0-2"},
        {"name": "mesa-vulkan-drivers", "version": "26.0.3-1ubuntu1"},
        {"name": "vulkan-tools", "version": "1.4.341.0+dfsg1-1"},
        {"name": "zlib1g", "version": "1:1.3.dfsg+really1.3.1-1ubuntu3"},
    ]
    if packages != expected_packages:
        raise ToolchainError("runtime.packages are not the locked Vulkan runtime closure")
    shared = runtime["shared_library_sonames"]
    if shared != [
        "libc.so.6",
        "libdrm.so.2",
        "libgcc_s.so.1",
        "libm.so.6",
        "libudev.so.1",
        "libwayland-client.so.0",
        "libz.so.1",
    ]:
        raise ToolchainError("runtime.shared_library_sonames are incomplete")

    headless = runtime["headless"]
    if not isinstance(headless, dict):
        raise ToolchainError("runtime.headless must be an object")
    require_keys(headless, {"vulkan_icd", "display_server", "commands"}, "runtime.headless")
    if headless != {
        "vulkan_icd": "/usr/share/vulkan/icd.d/lvp_icd.json",
        "display_server": "Xvfb",
        "commands": ["vulkaninfo", "Xvfb", "xvfb-run"],
    }:
        raise ToolchainError("runtime.headless is not the governed Lavapipe/Xvfb path")
    safe_absolute_path(headless["vulkan_icd"], "runtime.headless.vulkan_icd")

    wslg = runtime["wslg"]
    if not isinstance(wslg, dict):
        raise ToolchainError("runtime.wslg must be an object")
    require_keys(
        wslg,
        {
            "vulkan_icd",
            "required_mounts",
            "required_host_libraries",
            "fixed_environment",
            "consumer_environment",
            "probe",
        },
        "runtime.wslg",
    )
    if wslg["vulkan_icd"] != install["icd"]:
        raise ToolchainError("runtime.wslg.vulkan_icd does not match install.icd")
    if wslg["required_mounts"] != ["/dev/dxg", "/mnt/wslg/runtime-dir", "/usr/lib/wsl"]:
        raise ToolchainError("runtime.wslg.required_mounts are incomplete")
    if wslg["required_host_libraries"] != [
        "/usr/lib/wsl/lib/libd3d12.so",
        "/usr/lib/wsl/lib/libdxcore.so",
    ]:
        raise ToolchainError("runtime.wslg.required_host_libraries are incomplete")
    if wslg["fixed_environment"] != {
        "DISPLAY": "",
        "GALLIUM_DRIVER": "d3d12",
        "LD_LIBRARY_PATH": "/usr/lib/wsl/lib",
        "VK_DRIVER_FILES": "/usr/share/vulkan/icd.d/dzn_icd.x86_64.json",
        "WAYLAND_DISPLAY": "wayland-0",
        "XDG_RUNTIME_DIR": "/mnt/wslg/runtime-dir",
    }:
        raise ToolchainError("runtime.wslg.fixed_environment is incomplete")
    if wslg["consumer_environment"] != ["MESA_D3D12_DEFAULT_ADAPTER_NAME"]:
        raise ToolchainError("runtime.wslg.consumer_environment must remain consumer supplied")
    if wslg["probe"] != ["vulkaninfo", "--summary"]:
        raise ToolchainError("runtime.wslg.probe is unexpected")
    for index, mount in enumerate(wslg["required_mounts"]):
        safe_absolute_path(mount, f"runtime.wslg.required_mounts[{index}]")
    for index, library in enumerate(wslg["required_host_libraries"]):
        safe_absolute_path(library, f"runtime.wslg.required_host_libraries[{index}]")
    return value


def download(url: str, expected: str, cache: Path) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / f"{expected}.tar.xz"
    if destination.is_symlink():
        raise ToolchainError(f"Vulkan toolchain cache entry is a symlink: {destination}")
    if destination.is_file() and destination.stat().st_size <= MAX_ARCHIVE_BYTES:
        if sha256(destination) == expected:
            return destination
    elif destination.exists():
        raise ToolchainError(f"invalid Vulkan toolchain cache entry: {destination}")

    request = urllib.request.Request(url, headers={"User-Agent": "Atrinik Vulkan toolchain/1"})
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{expected}.", dir=cache)
    temporary = Path(temporary_name)
    try:
        total = 0
        with os.fdopen(descriptor, "wb") as output, urllib.request.urlopen(
            request, timeout=120
        ) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https":
                raise ToolchainError("Vulkan toolchain download left HTTPS")
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > MAX_ARCHIVE_BYTES:
                    raise ToolchainError("Vulkan toolchain archive exceeds size limit")
                output.write(block)
        if sha256(temporary) != expected:
            raise ToolchainError("Vulkan toolchain archive digest mismatch")
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def safe_archive_path(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name:
        raise ToolchainError(f"unsafe Mesa archive member: {name}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ToolchainError(f"unsafe Mesa archive member: {name}")
    return path


def normalize_link_target(member: PurePosixPath, linkname: str, root: str) -> str:
    if not linkname or "\x00" in linkname or "\\" in linkname:
        raise ToolchainError(f"unsafe Mesa archive link target: {linkname}")
    target = PurePosixPath(linkname)
    if target.is_absolute():
        raise ToolchainError(f"unsafe Mesa archive link target: {linkname}")
    stack = list(member.parent.parts)
    for part in target.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not stack:
                raise ToolchainError(f"Mesa archive link escapes source root: {linkname}")
            stack.pop()
        else:
            stack.append(part)
    if not stack or stack[0] != root:
        raise ToolchainError(f"Mesa archive link escapes source root: {linkname}")
    return "/".join(stack[1:])


def copy_member(source: BinaryIO, destination: Path, size: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        remaining = size
        while remaining:
            block = source.read(min(1024 * 1024, remaining))
            if not block:
                raise ToolchainError(f"truncated Mesa archive member: {destination}")
            output.write(block)
            remaining -= len(block)


def extract_source(archive_path: Path, destination: Path, entry: dict[str, object]) -> Path:
    root = str(entry["archive_root"])
    records: set[str] = set()
    expanded = 0
    count = 0
    with tarfile.open(archive_path, mode="r:xz") as archive:
        for member in archive:
            count += 1
            if count > MAX_MEMBERS:
                raise ToolchainError("Mesa archive has too many members")
            path = safe_archive_path(member.name)
            if path.parts[0] != root:
                raise ToolchainError(f"Mesa archive has an unexpected root: {member.name}")
            key = path.as_posix().casefold()
            if key in records:
                raise ToolchainError(f"duplicate Mesa archive path: {member.name}")
            if member.isdir():
                pass
            elif member.isfile():
                if member.size > MAX_FILE_BYTES:
                    raise ToolchainError(f"Mesa archive member is too large: {member.name}")
                expanded += member.size
                if expanded > MAX_EXPANDED_BYTES:
                    raise ToolchainError("Mesa archive exceeds expanded size limit")
            elif member.issym():
                normalize_link_target(path, member.linkname, root)
            else:
                raise ToolchainError(f"unsupported Mesa archive member: {member.name}")
            records.add(key)

    source_root = destination
    source_root.mkdir(parents=True, exist_ok=True)
    directories: list[PurePosixPath] = []
    symlinks: list[tuple[PurePosixPath, str]] = []
    with tarfile.open(archive_path, mode="r:xz") as archive:
        for member in archive:
            path = safe_archive_path(member.name)
            relative = PurePosixPath(*path.parts[1:])
            if member.isdir():
                if relative.parts:
                    directories.append(relative)
            elif member.issym():
                symlinks.append((relative, member.linkname))

        for relative in sorted(directories, key=lambda item: len(item.parts)):
            (source_root / relative).mkdir(parents=True, exist_ok=False)
        for member in archive.getmembers():
            if not member.isfile():
                continue
            relative = PurePosixPath(*safe_archive_path(member.name).parts[1:])
            output = source_root / relative
            source = archive.extractfile(member)
            if source is None:
                raise ToolchainError(f"cannot read Mesa archive member: {member.name}")
            with source:
                copy_member(source, output, member.size)
            output.chmod(stat.S_IMODE(member.mode) & 0o755 or 0o644)
        for relative, linkname in symlinks:
            output = source_root / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(linkname, output)

    version_path = source_root / "VERSION"
    if version_path.is_symlink() or not version_path.is_file():
        raise ToolchainError("Mesa archive has no regular VERSION file")
    version = version_path.read_text(encoding="utf-8").strip()
    if version != str(entry["version"]):
        raise ToolchainError(f"Mesa source VERSION is {version!r}, expected {entry['version']!r}")
    return source_root


def option_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return ",".join(value)
    if isinstance(value, str):
        return value
    raise ToolchainError(f"unsupported Meson option value: {value!r}")


def run_build(
    source: Path,
    build: Path,
    staging: Path,
    manifest: dict[str, object],
    jobs: int,
) -> None:
    build_contract = manifest["build"]
    assert isinstance(build_contract, dict)
    configure = build_contract["configure"]
    options = build_contract["options"]
    assert isinstance(configure, dict) and isinstance(options, dict)
    meson = shutil.which("meson")
    if meson is None:
        raise ToolchainError("meson is unavailable")
    version = subprocess.check_output([meson, "--version"], text=True).strip()
    if version != build_contract["version"]:
        raise ToolchainError(f"Meson is {version}, expected {build_contract['version']}")
    option_args = [
        f"-D{name}={option_value(options[name])}" for name in sorted(options)
    ]
    subprocess.run(
        [
            meson,
            "setup",
            str(build),
            str(source),
            f"--buildtype={configure['buildtype']}",
            f"--prefix={configure['prefix']}",
            f"--libdir={configure['libdir']}",
            f"--wrap-mode={configure['wrap_mode']}",
            *option_args,
        ],
        check=True,
    )
    subprocess.run([meson, "compile", "-C", str(build), "--jobs", str(jobs)], check=True)
    subprocess.run(
        [meson, "install", "-C", str(build), "--destdir", str(staging)],
        check=True,
    )


def install_file(source: Path, destination: Path, executable: bool) -> None:
    if source.is_symlink() or not source.is_file():
        raise ToolchainError(f"Mesa staged artifact is not a regular file: {source}")
    if destination.is_symlink():
        raise ToolchainError(f"Mesa destination is a symlink: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.unlink(missing_ok=True)
    shutil.copyfile(source, temporary)
    temporary.chmod(0o755 if executable else 0o644)
    temporary.replace(destination)


def staged_path(staging: Path, absolute: str) -> Path:
    return staging / PurePosixPath(absolute).relative_to("/")


def install_runtime_files(manifest: dict[str, object], staging: Path, root: Path = Path("/")) -> None:
    install = manifest["install"]
    assert isinstance(install, dict)
    library = str(install["library"])
    icd = str(install["icd"])
    destination_library = root / PurePosixPath(library).relative_to("/")
    destination_icd = root / PurePosixPath(icd).relative_to("/")
    install_file(staged_path(staging, library), destination_library, True)
    install_file(staged_path(staging, icd), destination_icd, False)


def validate_installed(manifest: dict[str, object], root: Path = Path("/")) -> None:
    install = manifest["install"]
    assert isinstance(install, dict)
    library_path = root / PurePosixPath(str(install["library"])).relative_to("/")
    icd_path = root / PurePosixPath(str(install["icd"])).relative_to("/")
    if library_path.is_symlink() or not library_path.is_file():
        raise ToolchainError(f"installed Dozen library is missing: {library_path}")
    value = load_json(icd_path, "installed Dozen ICD")
    if not isinstance(value, dict):
        raise ToolchainError("installed Dozen ICD root must be an object")
    require_keys(value, {"ICD", "file_format_version"}, "installed Dozen ICD")
    icd = value["ICD"]
    if not isinstance(icd, dict):
        raise ToolchainError("installed Dozen ICD entry must be an object")
    require_keys(icd, {"api_version", "library_arch", "library_path"}, "installed Dozen ICD entry")
    if value["file_format_version"] != "1.0.1":
        raise ToolchainError("installed Dozen ICD format is unexpected")
    if icd["api_version"] != install["icd_api_version"]:
        raise ToolchainError("installed Dozen ICD API version is unexpected")
    if icd["library_arch"] != "64" or icd["library_path"] != install["library"]:
        raise ToolchainError("installed Dozen ICD does not point to libvulkan_dzn.so")


def install(manifest_path: Path, cache: Path, prefix: Path, jobs: int) -> None:
    manifest = load_manifest(manifest_path.resolve(strict=True))
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise ToolchainError("the governed Vulkan toolchain targets x86-64 Linux")
    if jobs < 1 or jobs > 256:
        raise ToolchainError("jobs must be between 1 and 256")
    if prefix.resolve() != Path("/usr"):
        raise ToolchainError("the governed Dozen install prefix is /usr")
    cache = cache.resolve()
    if cache == Path("/"):
        raise ToolchainError("Vulkan toolchain cache must not be the filesystem root")
    source = manifest["source"]
    assert isinstance(source, dict)
    archive = download(str(source["url"]), str(source["sha256"]), cache)
    staging_work = Path(tempfile.mkdtemp(prefix=".classic-vulkan-toolchain-", dir=cache.parent))
    try:
        source_root = extract_source(archive, staging_work / "source", source)
        build = staging_work / "build"
        staging = staging_work / "stage"
        run_build(source_root, build, staging, manifest, jobs)
        install_runtime_files(manifest, staging)
        validate_installed(manifest)
    finally:
        shutil.rmtree(staging_work, ignore_errors=True)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--jobs", type=int, required=True)
    arguments = parser.parse_args(argv)
    try:
        install(arguments.manifest, arguments.cache, arguments.prefix, arguments.jobs)
    except (OSError, subprocess.CalledProcessError, ToolchainError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
