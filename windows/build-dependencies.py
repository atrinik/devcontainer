#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
"""Build the locked Classic Windows dependency closure with llvm-mingw.

Only verified archives enter the source directory. Recipes are argument arrays,
not shell fragments; host and target compiler environments are kept separate.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import tarfile
import urllib.request

TARGET = "x86_64-w64-mingw32"
SYSTEM_DLLS = {
    'advapi32.dll',
    'avrt.dll',
    'bcrypt.dll',
    'cabinet.dll',
    'cfgmgr32.dll',
    'comctl32.dll',
    'comdlg32.dll',
    'crypt32.dll',
    'd2d1.dll',
    'd3d11.dll',
    'd3d12.dll',
    'd3d9.dll',
    'd3dcompiler_47.dll',
    'dbghelp.dll',
    'dinput8.dll',
    'dnsapi.dll',
    'dwmapi.dll',
    'dwrite.dll',
    'dxgi.dll',
    'gdi32.dll',
    'gdiplus.dll',
    'hid.dll',
    'imagehlp.dll',
    'imm32.dll',
    'iphlpapi.dll',
    'kernel32.dll',
    'ksuser.dll',
    'mf.dll',
    'mfplat.dll',
    'mfreadwrite.dll',
    'mfuuid.dll',
    'msimg32.dll',
    'mswsock.dll',
    'ncrypt.dll',
    'netapi32.dll',
    'netio.dll',
    'normaliz.dll',
    'ntdll.dll',
    'ole32.dll',
    'oleaut32.dll',
    'opengl32.dll',
    'powrprof.dll',
    'propsys.dll',
    'psapi.dll',
    'rpcrt4.dll',
    'runtimeobject.dll',
    'secur32.dll',
    'setupapi.dll',
    'shell32.dll',
    'shlwapi.dll',
    'ucrtbase.dll',
    'uiautomationcore.dll',
    'user32.dll',
    'userenv.dll',
    'usp10.dll',
    'uxtheme.dll',
    'version.dll',
    'winhttp.dll',
    'wininet.dll',
    'winmm.dll',
    'winspool.drv',
    'wintrust.dll',
    'wldap32.dll',
    'ws2_32.dll',
    'wsock32.dll',
    'wtsapi32.dll',
}


def load_lock(path: Path) -> dict:
    lock = json.loads(path.read_text())
    if lock.get("schema_version") != 1:
        raise ValueError("unsupported dependency lock schema")
    names = set()
    for item in lock["dependencies"]:
        name = item["name"]
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name) or name in names:
            raise ValueError(f"invalid or duplicate dependency: {name}")
        if not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise ValueError(f"invalid SHA-256: {name}")
        if Path(item["archive"]).name != item["archive"] or not item["archive"]:
            raise ValueError(f"unsafe archive filename: {name}")
        if not item["url"].startswith("https://"):
            raise ValueError(f"source must use HTTPS: {name}")
        if not item.get("licenses") or not item.get("license"):
            raise ValueError(f"missing license: {name}")
        for notice in item["licenses"]:
            if Path(notice).is_absolute() or ".." in Path(notice).parts:
                raise ValueError(f"unsafe license path: {name}")
        if not set(item.get("depends", [])).issubset(names):
            raise ValueError(f"dependencies must precede {name}")
        if item["build_system"] not in {"cmake", "autotools", "openssl", "make", "custom", "meson"}:
            raise ValueError(f"unsupported build system: {name}")
        if item["build_system"] == "autotools" and not item.get("host"):
            if not item.get("shared_artifacts"):
                raise ValueError(f"missing expected shared artifacts: {name}")
            for artifact in item["shared_artifacts"]:
                if (set(artifact) != {"dll", "import_library"}
                        or not re.fullmatch(r"[A-Za-z0-9_.*-]+\.dll", artifact["dll"])
                        or not re.fullmatch(r"[A-Za-z0-9_.-]+\.dll\.a", artifact["import_library"])):
                    raise ValueError(f"unsafe shared artifact contract: {name}")
        names.add(name)
    return lock


def environment(prefix: Path, host_prefix: Path, llvm: Path, host: bool = False, host_llvm: Path | None = None,
                build_system: str | None = None) -> dict:
    env = os.environ.copy()
    native_path = f"{host_llvm}/bin:" if host_llvm else ""
    # Meson's release profile owns optimization; external -O2 would override -O3.
    default_flags = "" if build_system == "meson" else "-O2"
    env.update({"PATH": f"{native_path}{llvm}/bin:{host_prefix}/bin:{env.get('PATH', '')}",
                "CC": "clang" if host else f"{TARGET}-clang",
                "CXX": "clang++" if host else f"{TARGET}-clang++",
                "AR": "llvm-ar", "RANLIB": "llvm-ranlib", "STRIP": "llvm-strip",
                "LD": "ld.lld" if host else f"{llvm}/bin/{TARGET}-ld",
                "OBJDUMP": "llvm-objdump" if host else f"{llvm}/bin/{TARGET}-objdump",
                "RC": f"{TARGET}-windres",
                "CC_FOR_BUILD": "clang", "CXX_FOR_BUILD": "clang++",
                "BUILD_CC": "clang", "HOSTCC": "clang",
                "PKG_CONFIG": "pkg-config" if host else f"{TARGET}-pkg-config",
                "PKG_CONFIG_PATH": "", "PKG_CONFIG_LIBDIR": os.pathsep.join(str((host_prefix if host else prefix) / path) for path in ("lib/pkgconfig", "share/pkgconfig")),
                "CFLAGS": default_flags, "CXXFLAGS": default_flags,
                "CPPFLAGS": f"-I{host_prefix if host else prefix}/include",
                "LDFLAGS": f"-L{host_prefix if host else prefix}/lib",
                "CMAKE_PREFIX_PATH": str(host_prefix if host else prefix),
                "LD_LIBRARY_PATH": f"{host_prefix}/lib:{env.get('LD_LIBRARY_PATH', '')}"})
    return env


def meson_flags(env: dict) -> list[str]:
    """Bind each recipe's actual flags without a shared machine-file override."""
    cpp = shlex.split(env.get("CPPFLAGS", ""))
    values = {
        "c_args": cpp + shlex.split(env.get("CFLAGS", "")),
        "cpp_args": cpp + shlex.split(env.get("CXXFLAGS", "")),
        "c_link_args": shlex.split(env.get("LDFLAGS", "")),
        "cpp_link_args": shlex.split(env.get("LDFLAGS", "")),
    }
    return ["-D" + name + "=" + json.dumps(flags) for name, flags in values.items()]


def commands(item: dict, source: Path, build: Path, prefix: Path, jobs: int, host: bool = False, env: dict | None = None) -> list[list[str]]:
    source = source / item.get("source_subdir", "")
    substitutions = {"{prefix}": str(prefix), "{source}": str(source), "{build}": str(build),
                     "{jobs}": str(jobs), "{work}": str(build.parent.parent),
                     "{host_prefix}": str(build.parent.parent / "host")}
    def expand(argument):
        for key, value in substitutions.items():
            argument = argument.replace(key, value)
        return argument
    options = [expand(x) for x in item.get("options", [])]
    system = item["build_system"]
    if system == "custom":
        substitutions = {"{prefix}": str(prefix), "{source}": str(source),
                         "{build}": str(build), "{jobs}": str(jobs)}
        recipe = []
        for row in item["commands"]:
            expanded = []
            for argument in row:
                for key, value in substitutions.items():
                    argument = argument.replace(key, value)
                expanded.append(argument)
            recipe.append(expanded)
        return recipe
    if system == "meson":
        setup = ["meson", "setup", str(build), str(source), f"--prefix={prefix}",
                 "--libdir=lib", "--buildtype=release", "--default-library=shared",
                 "--wrap-mode=nodownload", "--native-file=" + str(build.parent.parent / "llvm-native.ini")]
        if not host:
            setup += ["--cross-file=" + str(build.parent.parent / "llvm-cross.ini")]
        return [setup + options + meson_flags(env or {}), ["meson", "compile", "-C", str(build), "-j", str(jobs)],
                ["meson", "install", "-C", str(build)]]
    if system == "cmake":
        configure = ["cmake", "-S", str(source), "-B", str(build), "-G", "Ninja",
                     f"-DCMAKE_INSTALL_PREFIX={prefix}", "-DCMAKE_BUILD_TYPE=Release",
                     "-DBUILD_SHARED_LIBS=ON"]
        if host:
            configure += ["-DCMAKE_C_COMPILER=clang", "-DCMAKE_CXX_COMPILER=clang++"]
        else:
            configure += [f"-DCMAKE_TOOLCHAIN_FILE={prefix}/share/cmake/llvm-mingw.cmake"]
        return [configure + options, ["cmake", "--build", str(build), "--parallel", str(jobs)],
                ["cmake", "--install", str(build)]]
    if system == "autotools":
        configure = [str(source / "configure"), f"--prefix={prefix}", "--enable-shared", "--disable-static"]
        if not host:
            configure += [f"--host={TARGET}", "--build=x86_64-pc-linux-gnu"]
        make = ["make"]
        if item.get("make_subdir"):
            make += ["-C", str(build / item["make_subdir"])]
        make_options = item.get("make_options", [])
        return [configure + options, make + [f"-j{jobs}"] + make_options, make + ["install"] + make_options]
    if system == "openssl":
        # CC is already the complete cross compiler; do not prepend the triple twice.
        return [["perl", str(source / "Configure"), "mingw64", "shared", "no-tests",
                 f"--prefix={prefix}", f"--openssldir={prefix}/ssl", f"--libdir={prefix}/lib", "no-capieng"] + options,
                ["make", f"-j{jobs}", "build_sw", f"ENGINESDIR={prefix}/bin/engines"],
                ["make", "install_sw", f"ENGINESDIR={prefix}/bin/engines"]]
    compiler_options = [f"CC={'clang' if host else TARGET + '-clang'}",
                        f"CXX={'clang++' if host else TARGET + '-clang++'}", "AR=llvm-ar", "RANLIB=llvm-ranlib"]
    return [["make", "-C", str(source), f"-j{jobs}", f"PREFIX={prefix}"] + compiler_options + options,
            ["make", "-C", str(source), f"PREFIX={prefix}", "install"] + compiler_options + item.get("install_options", [])]


def verified_archive(item: dict, cache: Path) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / item["archive"]
    if not archive.exists():
        temporary = archive.with_suffix(archive.suffix + ".partial")
        try:
            with urllib.request.urlopen(item["url"], timeout=120) as response, temporary.open("wb") as output:
                shutil.copyfileobj(response, output)
            temporary.replace(archive)
        finally:
            temporary.unlink(missing_ok=True)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != item["sha256"]:
        raise ValueError(f"source checksum mismatch: {item['name']}")
    return archive


def safe_archive_path(name: str, root: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (not name or "\\" in name or "\x00" in name or path.is_absolute()
            or not path.parts or ".." in path.parts or path.parts[0] != root):
        raise ValueError(f"unsafe dependency archive path: {name!r}")
    return path


def normalized_link_target(path: PurePosixPath, member: tarfile.TarInfo, root: str) -> PurePosixPath:
    target = member.linkname
    if not target or "\\" in target or "\x00" in target or PurePosixPath(target).is_absolute():
        raise ValueError(f"unsafe dependency archive link: {member.name!r}")
    # Tar hardlink names start at the archive root; symlinks are relative to
    # their containing directory. Never let '..' pop the archive root.
    parts = list(path.parent.parts) if member.issym() else []
    for part in PurePosixPath(target).parts:
        if part == "..":
            if len(parts) <= 1:
                raise ValueError(f"dependency archive link escapes source root: {member.name!r}")
            parts.pop()
        elif part != ".":
            parts.append(part)
    if not parts or parts[0] != root:
        raise ValueError(f"dependency archive link escapes source root: {member.name!r}")
    return PurePosixPath(*parts)


def resolved_symbolic_target(path: PurePosixPath, member: tarfile.TarInfo,
                             records: dict[PurePosixPath, tarfile.TarInfo], root: str,
                             directories: set[PurePosixPath]) -> PurePosixPath:
    """Resolve archive links in POSIX component order without filesystem reads."""
    active = {path}
    expansions = 1  # Include the initial link in POSIX's 40-traversal limit.

    def walk(target: str, parent: PurePosixPath) -> PurePosixPath:
        nonlocal expansions
        if not target or "\\" in target or "\x00" in target or PurePosixPath(target).is_absolute():
            raise ValueError(f"unsafe dependency archive link: {path}")
        parts = list(parent.parts)
        for component in target.split("/"):
            if not component:
                continue
            current = PurePosixPath(*parts)
            if current not in directories or (current in records and not records[current].isdir()):
                raise ValueError(f"dependency archive link traverses non-directory: {path}")
            if component == ".":
                continue
            if component == "..":
                if len(parts) <= 1:
                    raise ValueError(f"dependency archive link escapes source root: {path}")
                parts.pop()
                continue
            candidate = current / component
            target_member = records.get(candidate)
            if target_member is not None and target_member.issym():
                expansions += 1
                if expansions > 40 or candidate in active:
                    raise ValueError(f"dependency archive symbolic link cycle or expansion limit: {path}")
                active.add(candidate)
                try:
                    resolved = walk(target_member.linkname, candidate.parent)
                finally:
                    active.remove(candidate)
                parts = list(resolved.parts)
            else:
                parts.append(component)
        resolved = PurePosixPath(*parts)
        if not resolved.parts or resolved.parts[0] != root:
            raise ValueError(f"dependency archive link escapes source root: {path}")
        if target.endswith("/") and (resolved not in directories or
                                     (resolved in records and not records[resolved].isdir())):
            raise ValueError(f"dependency archive link traverses non-directory: {path}")
        return resolved

    return walk(member.linkname, path.parent)


def validate_archive_members(members: list[tarfile.TarInfo], root: str) -> dict[PurePosixPath, tarfile.TarInfo]:
    records: dict[PurePosixPath, tarfile.TarInfo] = {}
    expanded = 0
    if len(members) > 400000:
        raise ValueError("dependency archive exceeds extraction limits")
    for member in members:
        path = safe_archive_path(member.name, root)
        if path in records:
            raise ValueError(f"duplicate dependency archive path: {path}")
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise ValueError(f"unsupported dependency archive member: {path}")
        if member.size < 0 or member.size > 512 * 1024**2:
            raise ValueError(f"invalid dependency archive member size: {path}")
        if not isinstance(member.mtime, (int, float)) or not math.isfinite(member.mtime):
            raise ValueError(f"invalid dependency archive member timestamp: {path}")
        expanded += member.size
        if expanded > 8 * 1024**3:
            raise ValueError("dependency archive exceeds extraction limits")
        records[path] = member
    directories = {PurePosixPath(root)}
    for path, member in records.items():
        directories.update(path.parents)
        if member.isdir():
            directories.add(path)
    for path, member in records.items():
        for parent in path.parents:
            if parent in records and not records[parent].isdir():
                raise ValueError(f"dependency archive member traverses non-directory parent: {path}")
        if member.issym():
            resolved_symbolic_target(path, member, records, root, directories)
        elif member.islnk():
            target = normalized_link_target(path, member, root)
            raw_parts = list(path.parent.parts) if member.issym() else []
            for part in PurePosixPath(member.linkname).parts:
                if part == "..":
                    raw_parts.pop()
                elif part != ".":
                    raw_parts.append(part)
                intermediate = PurePosixPath(*raw_parts)
                if intermediate in records and (records[intermediate].issym() or records[intermediate].islnk()):
                    raise ValueError(f"dependency archive link traverses another link: {path}")
            # Hardlinks keep the shared installer's strict declared-file policy.
            for component in (target, *target.parents):
                if component in records and (records[component].issym() or records[component].islnk()):
                    raise ValueError(f"dependency archive link traverses another link: {path}")
            if member.islnk() and (target not in records or not records[target].isfile()):
                raise ValueError(f"dependency archive hardlink target is not a regular file: {path}")
    return records


def extract(archive: Path, directory: Path) -> Path:
    """Extract prevalidated sources without depending on Python's filter API."""
    if directory.is_symlink() or (directory.exists() and (not directory.is_dir() or any(directory.iterdir()))):
        raise ValueError("dependency extraction requires a new or empty destination")
    if archive.suffix == ".lz":
        content = subprocess.run(["lzip", "--decompress", "--stdout", str(archive)], capture_output=True, check=True).stdout
        opened = tarfile.open(fileobj=io.BytesIO(content))
    else:
        opened = tarfile.open(archive)
    with opened as tar:
        members = tar.getmembers()
        roots = {PurePosixPath(member.name).parts[0] for member in members if PurePosixPath(member.name).parts}
        if len(roots) != 1:
            raise ValueError("source archive must have one root directory")
        root_name = next(iter(roots))
        records = validate_archive_members(members, root_name)
        root_member = records.get(PurePosixPath(root_name))
        if root_member is not None and not root_member.isdir():
            raise ValueError("source archive root must be a directory")
        directory.mkdir(parents=True, exist_ok=True)
        # Match the shared LLVM installer's exclusive writes and delayed links.
        # Restoring ordinary-file timestamps preserves release build inputs.
        for path, member in records.items():
            output = directory.joinpath(*path.parts)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                output.chmod(0o755)
            elif member.isfile():
                output.parent.mkdir(parents=True, exist_ok=True)
                contents = tar.extractfile(member)
                if contents is None:
                    raise ValueError(f"cannot read dependency archive member: {path}")
                with contents, output.open("xb") as target:
                    shutil.copyfileobj(contents, target)
                output.chmod(0o755 if member.mode & 0o111 else 0o644)
                os.utime(output, (member.mtime, member.mtime), follow_symlinks=False)
        for path, member in records.items():
            if not (member.issym() or member.islnk()):
                continue
            output = directory.joinpath(*path.parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                os.symlink(member.linkname, output)
            else:
                target = normalized_link_target(path, member, root_name)
                os.link(directory.joinpath(*target.parts), output, follow_symlinks=False)
    return directory / root_name


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def provider_paths(prefix: Path) -> tuple[dict[str, Path], dict[str, Path]]:
    """Keep root runtime DLLs separate from scoped provider/engine modules."""
    dlls = {}
    modules = {}
    folded = set()
    # External Python is sealed separately; target DLL install roots are bin/lib.
    roots = (prefix / "bin", prefix / "lib")
    if any(root.is_symlink() or (root.exists() and not root.is_dir()) for root in roots):
        raise ValueError("PE provider root must be a normal directory")
    installed = [path for root in roots for path in root.rglob("*")]
    for path in sorted(installed):
        if path.is_symlink():
            target = path.resolve()
            # Pinned SDKs install aliases such as libpng.pc; these cannot hide
            # providers. Directory, DLL, broken and external aliases fail closed.
            if (not target.is_file() or not target.is_relative_to(prefix.resolve())
                    or path.suffix.lower() == ".dll" or target.suffix.lower() == ".dll"):
                raise ValueError("unsafe symlink in PE provider tree")
            continue
        if path.suffix.lower() != ".dll":
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError("PE provider must be a normal file")
        relative = path.relative_to(prefix).as_posix()
        if relative.lower() in folded:
            raise ValueError("case-colliding DLL paths")
        folded.add(relative.lower())
        if path.parent == prefix / "bin":
            dlls[path.name] = path
        else:
            modules[relative] = path
    return dlls, modules


def dll_snapshot(prefix: Path) -> dict:
    return {name: file_hash(path) for name, path in provider_paths(prefix)[0].items()}


def module_snapshot(prefix: Path) -> dict:
    return {name: file_hash(path) for name, path in provider_paths(prefix)[1].items()}


def ownership_path(prefix: Path) -> Path:
    return prefix / "share/atrinik/windows-dependencies/runtime-ownership.json"


def save_ownership(prefix: Path, receipt: dict) -> None:
    ownership_path(prefix).write_text(json.dumps(receipt, indent=2) + "\n")


def assert_receipt(prefix: Path, receipt: dict, allow_new: set | None = None) -> None:
    if receipt.get("schema_version") != 1:
        raise ValueError("unsupported runtime ownership receipt")
    actual = dll_snapshot(prefix)
    for name, record in receipt["dlls"].items():
        if actual.get(name) != record["sha256"]:
            raise ValueError(f"changed or missing owned DLL: {name}")
    if set(actual) - set(receipt["dlls"]) - (allow_new or set()):
        raise ValueError("unowned DLL in target prefix")
    actual_modules = module_snapshot(prefix)
    for name, record in receipt.get("modules", {}).items():
        if actual_modules.get(name) != record["sha256"]:
            raise ValueError(f"changed or missing owned PE module: {name}")
    if set(actual_modules) - set(receipt.get("modules", {})):
        raise ValueError("unowned PE module in target prefix")
    for notices in receipt["notices"].values():
        for name, digest in notices.items():
            path = prefix / "share/licenses" / name
            if not path.is_file() or file_hash(path) != digest:
                raise ValueError(f"changed or missing dependency notice: {name}")


def initial_ownership(lock: dict, prefix: Path) -> dict:
    provider = lock["runtime_providers"]["llvm-mingw"]
    actual = dll_snapshot(prefix)
    if actual != provider["dlls"] or module_snapshot(prefix):
        raise ValueError("initial runtime bytes do not match verified llvm-mingw archive")
    notices = {}
    for name, digest in provider["notices"].items():
        path = prefix / "share/licenses/llvm-mingw" / name
        if not path.is_file() or file_hash(path) != digest:
            raise ValueError(f"llvm-mingw notice does not match verified archive: {name}")
        notices["llvm-mingw/" + name] = digest
    return {"schema_version": 1,
            "dlls": {name: {"sha256": digest, "owner": "llvm-mingw", "source_sha256": provider["sha256"]}
                     for name, digest in actual.items()},
            "modules": {}, "notices": {"llvm-mingw": notices}}


def register_audio(lock: dict, audio_path: Path, prefix: Path, work: Path) -> None:
    """Called immediately after the separately owned, pinned audio installer."""
    audio = json.loads(audio_path.read_text())
    provider = lock["runtime_providers"]["sdl3-mixer"]
    if {"sdl_mixer": audio["sdl_mixer"], "dependencies": audio["dependencies"]} != provider["contract"]:
        raise ValueError("audio source/codec contract differs from dependency inventory")
    receipt = json.loads(ownership_path(prefix).read_text())
    assert_receipt(prefix, receipt, {"SDL3_mixer.dll"})
    dll = prefix / "bin/SDL3_mixer.dll"
    if not dll.is_file() or "SDL3_mixer.dll" in receipt["dlls"]:
        raise ValueError("audio registration requires one fresh SDL3_mixer DLL")
    notices = {}
    components = [audio["sdl_mixer"]] + audio["dependencies"]
    inventory = ownership_path(prefix).parent
    for component in components:
        name = component["name"]
        item = {"name": name, "url": component["source"]["url"], "sha256": component["source"]["sha256"],
                "archive": name + "-" + component["source"]["sha256"][:12] + ".tar.gz"}
        archive = verified_archive(item, work / "audio-archives")
        source = extract(archive, work / "audio-sources" / name)
        upstream_notice = source / ("LICENSE.txt" if name == "SDL3_mixer" else "COPYING")
        if not upstream_notice.is_file():
            raise ValueError(f"missing audio source notice: {name}")
        relative = "sdl3-mixer/" + name + "-" + upstream_notice.name
        notice = prefix / "share/licenses" / relative
        notice.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(upstream_notice, notice)
        notices[relative] = file_hash(notice)
        shutil.copy2(archive, inventory / item["archive"])
    receipt["dlls"][dll.name] = {"sha256": file_hash(dll), "owner": "sdl3-mixer", "source_sha256": provider["sha256"]}
    receipt["notices"]["sdl3-mixer"] = notices
    save_ownership(prefix, receipt)



def retain_configuration(item: dict, build: Path, destination: Path) -> None:
    """Retain resolved feature/compiler settings, then require used SDL backends."""
    for relative in ("CMakeCache.txt", "config.log", "config.status", "meson-logs/meson-log.txt"):
        source = build / relative
        if source.is_file():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    if (build / "meson-info").is_dir():
        shutil.copytree(build / "meson-info", destination / "meson-info")
    required = {"sdl3-image": {"jpg", "png", "webp"}, "sdl3-ttf": {"freetype", "harfbuzz"}}.get(item["name"])
    if required:
        output = (destination / "command-0.log").read_text()
        marker = "SDL3_image backends:" if item["name"] == "sdl3-image" else "SDL3_ttf backends:"
        summary = output.split(marker, 1)[-1] if marker in output else ""
        enabled = re.search(r"^-- - enabled:\s*(.*)$", summary, re.MULTILINE)
        if enabled is None or not required.issubset(enabled.group(1).split()):
            raise ValueError(f"required resolved backends absent: {item['name']}: {sorted(required)}")


def require_shared_configuration(item: dict, build: Path, destination: Path) -> None:
    """Reject a requested shared build that configuration silently disabled."""
    if item["name"] == "icu4c":
        candidates = [Path("icudefs.mk")]
        required = {"ENABLE_SHARED": "YES", "ENABLE_STATIC": ""}
    elif item["name"] == "sqlite":
        candidates = [Path("Makefile")]
        required = {"ENABLE_LIB_SHARED": "1", "ENABLE_LIB_STATIC": "0"}
    else:
        candidates = [Path("libtool"), Path("builds/unix/libtool")]
        required = {"build_libtool_libs": "yes", "build_old_libs": "no"}
    found = [relative for relative in candidates if (build / relative).exists()]
    if not found:
        raise ValueError(f"missing resolved shared configuration: {item['name']}")
    settings = {}
    for relative in found:
        path = build / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"unsafe resolved shared configuration: {item['name']}/{relative}")
        text = path.read_text()
        if relative.name == "libtool":
            # The script also contains optional disable-shared/static tags.
            # Only its generated default configuration describes this build.
            starts = list(re.finditer(r"^# ### BEGIN LIBTOOL CONFIG$", text, re.MULTILINE))
            ends = list(re.finditer(r"^# ### END LIBTOOL CONFIG$", text, re.MULTILINE))
            if len(starts) != 1 or len(ends) != 1 or starts[0].end() >= ends[0].start():
                raise ValueError(f"required shared/static configuration absent: {item['name']}: libtool default scope")
            text = text[starts[0].end():ends[0].start()]
        for key, expected in required.items():
            values = re.findall(r"^" + re.escape(key) + r"[ \t]*=[ \t]*([^\n]*)$", text, re.MULTILINE)
            if len(values) != 1 or values[0].strip() != expected:
                raise ValueError(f"required shared/static configuration absent: {item['name']}: {key}")
        target = destination / "shared" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        settings[relative.as_posix()] = {"sha256": file_hash(path), "settings": required}
    (destination / "shared-settings.json").write_text(json.dumps(settings, indent=2) + "\n")


def require_shared_artifacts(item: dict, prefix: Path, llvm: Path, destination: Path, receipt: dict) -> None:
    """Pair each expected DLL role with a real LLVM-identified import archive."""
    dlls, _ = provider_paths(prefix)
    records = []
    for artifact in item["shared_artifacts"]:
        matches = [name for name in dlls if fnmatch.fnmatchcase(name.lower(), artifact["dll"].lower())]
        if len(matches) != 1:
            raise ValueError(f"required shared DLL absent or ambiguous: {item['name']}: {artifact['dll']}")
        record = receipt.get("dlls", {}).get(matches[0], {})
        if record.get("owner") != item["name"] or record.get("sha256") != file_hash(dlls[matches[0]]):
            raise ValueError(f"required shared DLL not owned by this recipe: {item['name']}: {matches[0]}")
        library = prefix / "lib" / artifact["import_library"]
        if library.is_symlink() or not library.is_file():
            raise ValueError(f"required normal import library absent: {item['name']}: {library.name}")
        result = subprocess.run([str(llvm / "bin/llvm-dlltool"), "-I", str(library)],
                                capture_output=True, text=True, check=True)
        identified = {line.strip().lower() for line in result.stdout.splitlines() if line.strip()}
        if identified != {matches[0].lower()}:
            raise ValueError(f"import library does not identify expected DLL: {item['name']}: {library.name}")
        records.append({"dll": matches[0], "dll_sha256": file_hash(dlls[matches[0]]),
                        "import_library": library.name, "import_library_sha256": file_hash(library)})
    (destination / "shared-artifacts.json").write_text(json.dumps(records, indent=2) + "\n")


def run(lock: dict, prefix: Path, work: Path, llvm: Path, jobs: int, dry_run: bool, host_llvm: Path | None = None) -> None:
    host_prefix = work / "host"
    inventory = prefix / "share/atrinik/windows-dependencies"
    if not dry_run:
        if (inventory / "dependencies.json").exists():
            raise ValueError("dependency prefix is already populated; use a fresh prefix")
        inventory.mkdir(parents=True, exist_ok=True)
        receipt = initial_ownership(lock, prefix)
        save_ownership(prefix, receipt)
        work.mkdir(parents=True, exist_ok=True)
        (work / "llvm-native.ini").write_text("[binaries]\nc = 'clang'\ncpp = 'clang++'\nar = 'llvm-ar'\nstrip = 'llvm-strip'\npkg-config = 'pkg-config'\n"
            f"[properties]\npkg_config_libdir = ['{host_prefix}/lib/pkgconfig', '{host_prefix}/share/pkgconfig']\n")
        (work / "llvm-cross.ini").write_text(
            f"[binaries]\nc = '{TARGET}-clang'\ncpp = '{TARGET}-clang++'\nar = 'llvm-ar'\nstrip = 'llvm-strip'\nwindres = '{TARGET}-windres'\npkg-config = '{TARGET}-pkg-config'\n"
            "[host_machine]\nsystem = 'windows'\ncpu_family = 'x86_64'\ncpu = 'x86_64'\nendian = 'little'\n"
            "[properties]\nneeds_exe_wrapper = true\n"
            )
    recipe_source = None
    for item in lock["dependencies"]:
        host = item.get("host", False)
        selected_prefix = host_prefix if host else prefix
        build = work / "build" / item["name"]
        if not dry_run:
            assert_receipt(prefix, receipt)
            before = dll_snapshot(prefix)
            before_modules = module_snapshot(prefix)
        if dry_run:
            source = work / "sources" / item["name"] / item.get("directory", item["name"])
        else:
            archive = verified_archive(item, work / "archives")
            source = extract(archive, work / "sources" / item["name"])
            if item["name"] == "mxe-recipes":
                recipe_source = source
            for patch in item.get("patches", []):
                if recipe_source is None:
                    raise ValueError("recipe archive must precede patched sources")
                content = (recipe_source / patch["file"]).read_bytes()
                if hashlib.sha256(content).hexdigest() != patch["sha256"]:
                    raise ValueError(f"recipe patch checksum mismatch: {patch['file']}")
                for old, new in patch.get("replacements", {}).items():
                    content = content.replace(old.encode(), new.encode())
                subprocess.run(["patch", "--batch", "--fuzz=0", "-p1"], input=content, cwd=source, check=True)
            for edit in item.get("source_edits", []):
                path = source / edit["file"]
                content = path.read_text()
                if edit["old"] not in content:
                    raise ValueError(f"expected source edit absent: {item['name']}/{edit['file']}")
                path.write_text(content.replace(edit["old"], edit["new"]))
            build.mkdir(parents=True)
            shutil.copy2(archive, inventory / item["archive"])
            notices = prefix / "share/licenses" / item["name"]
            notices.mkdir(parents=True, exist_ok=True)
            for notice in item["licenses"]:
                path = source / notice
                if not path.is_file():
                    raise ValueError(f"missing upstream license {item['name']}: {notice}")
                shutil.copy2(path, notices / notice.replace("/", "_"))
        env = environment(prefix, host_prefix, llvm, host, host_llvm, item["build_system"])
        for key, value in item.get("environment", {}).items():
            env[key] = value.replace("{prefix}", str(prefix)).replace("{host_prefix}", str(host_prefix))
        recipe = commands(item, source, build, selected_prefix, jobs, host, env)
        configuration = inventory / "configuration" / item["name"]
        if not dry_run:
            configuration.mkdir(parents=True)
        for index, command in enumerate(recipe):
            if dry_run:
                print(json.dumps({"dependency": item["name"], "command": command,
                                  "environment": {key: env[key] for key in ("CC", "CXX", "AR", "PKG_CONFIG", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS")}}))
            else:
                print(f"{item['name']}: command {index + 1}/{len(recipe)}", flush=True)
                with (configuration / f"command-{index}.log").open("w") as output:
                    result = subprocess.run(command, cwd=build, env=env, stdout=output, stderr=subprocess.STDOUT)
                if result.returncode:
                    print((configuration / f"command-{index}.log").read_text()[-12000:], flush=True)
                    result.check_returncode()
                if index == 0 and not host and item["build_system"] == "autotools":
                    require_shared_configuration(item, build, configuration)
        if not dry_run:
            retain_configuration(item, build, configuration)
            receipt["notices"][item["name"]] = {item["name"] + "/" + notice.replace("/", "_"):
                file_hash(prefix / "share/licenses" / item["name"] / notice.replace("/", "_"))
                for notice in item["licenses"]}
            for name, digest in dll_snapshot(prefix).items():
                if before.get(name) != digest:
                    if host:
                        raise ValueError(f"host recipe wrote target DLL: {item['name']}/{name}")
                    receipt["dlls"][name] = {"sha256": digest, "owner": item["name"], "source_sha256": item["sha256"]}
            for name, digest in module_snapshot(prefix).items():
                if before_modules.get(name) != digest:
                    if host:
                        raise ValueError(f"host recipe wrote target PE module: {item['name']}/{name}")
                    receipt["modules"][name] = {"sha256": digest, "owner": item["name"], "source_sha256": item["sha256"]}
            if not host and item["build_system"] == "autotools":
                require_shared_artifacts(item, prefix, llvm, configuration, receipt)
            save_ownership(prefix, receipt)
        if not dry_run and item["name"] == "curl":
            config = inventory.parent / "curl"
            config.mkdir(exist_ok=True)
            for relative in ("lib/curl_config.h", "config.log"):
                shutil.copy2(build / relative, config / Path(relative).name)
    if not dry_run:
        (inventory / "dependencies.json").write_text(json.dumps(lock, indent=2) + "\n")


def parse_imports(output: str) -> set[str]:
    """Read normal/delay providers, including nested delayed-symbol rows."""
    imports = set()
    block = None
    outer_kind = None
    depth = 0
    for line in output.splitlines():
        line = line.strip()
        if line in {"Import {", "DelayImport {"}:
            if block is None:
                block = []
                outer_kind = line
                depth = 1
            elif outer_kind == "DelayImport {" and line == "Import {" and depth == 1:
                depth = 2
            else:
                raise ValueError("nested PE import block")
        elif block is not None:
            if line == "}":
                depth -= 1
                if depth == 0:
                    if len(block) != 1 or re.fullmatch(r"[A-Za-z0-9_+.\-]+", block[0]) is None:
                        raise ValueError("invalid PE import provider name")
                    imports.add(block[0].lower())
                    block = None
                    outer_kind = None
            elif line.startswith("Name:"):
                if depth != 1:
                    raise ValueError("delayed symbol has an unexpected import provider name")
                block.append(line.removeprefix("Name:").strip())
            elif line.endswith("{"):
                raise ValueError("unknown nested PE import block")
        elif line.startswith("Name:"):
            raise ValueError("PE import name outside an import block")
    if block is not None:
        raise ValueError("unterminated PE import block")
    return imports


def verify(prefix: Path, llvm: Path, lock: dict | None = None) -> dict:
    """Check root DLLs and every scoped provider against owned bytes/notices."""
    if lock is None:
        lock = load_lock(ownership_path(prefix).parent / "dependencies.json")
    receipt = json.loads(ownership_path(prefix).read_text())
    assert_receipt(prefix, receipt)
    sources = {item["name"]: item["sha256"] for item in lock["dependencies"] if not item.get("host", False)}
    sources.update({name: provider["sha256"] for name, provider in lock["runtime_providers"].items()})
    paths = provider_paths(prefix)
    if not {"SDL3.dll", "SDL3_image.dll", "SDL3_ttf.dll"}.issubset(paths[0]):
        raise ValueError("missing top-level SDL DLL closure")
    root_names = {name.lower() for name in paths[0]}
    imports = set()
    reports = {"dlls": {}, "modules": {}}
    for kind, scoped_paths in zip(("dlls", "modules"), paths):
        for name, dll in scoped_paths.items():
            record = receipt[kind][name]
            owner = record["owner"]
            if sources.get(owner) != record["source_sha256"] or not receipt["notices"].get(owner):
                raise ValueError(f"runtime has no verified source/notice owner: {name}")
            if owner in lock["runtime_providers"]:
                provider = lock["runtime_providers"][owner]
                if kind != "dlls" or name not in provider["dlls"]:
                    raise ValueError(f"unknown runtime provider DLL: {name}")
                if isinstance(provider["dlls"], dict) and provider["dlls"][name] != record["sha256"]:
                    raise ValueError(f"runtime provider bytes differ from archive: {name}")
            result = subprocess.run([str(llvm / "bin/llvm-readobj"), "--file-headers", "--coff-imports", str(dll)],
                                    capture_output=True, text=True, check=True)
            if "IMAGE_FILE_MACHINE_AMD64" not in result.stdout:
                raise ValueError(f"not an AMD64 PE DLL: {name}")
            names = parse_imports(result.stdout)
            for imported in names | {dll.name.lower()}:
                if imported == "msvcrt.dll" or imported.startswith(("libgcc", "libstdc++", "libssp", "libgomp", "libatomic", "libquadmath")):
                    raise ValueError(f"GNU or legacy CRT runtime in {name}: {imported}")
            siblings = {path.name.lower() for path in scoped_paths.values() if path.parent == dll.parent}
            available = root_names | siblings
            unresolved = {imported for imported in names if imported not in available and imported not in SYSTEM_DLLS
                          and not (imported.endswith(".dll") and imported.startswith(("api-ms-win-", "ext-ms-win-")))}
            if unresolved:
                raise ValueError(f"unresolved runtime imports in {name}: {sorted(unresolved)}")
            imports.update(names)
            reports[kind][name] = {**record, "imports": sorted(names)}
    if not any(name == "ucrtbase.dll" or name.startswith("api-ms-win-crt-") for name in imports):
        raise ValueError("dependency closure does not import UCRT")
    report_path = prefix / "share/atrinik/windows-dependencies/pe-closure.json"
    result = {"schema_version": 2, **reports, "notices": receipt["notices"]}
    report_path.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=Path(__file__).with_name("dependencies.json"))
    parser.add_argument("--prefix", type=Path, default=Path("/opt/atrinik-windows"))
    parser.add_argument("--llvm", type=Path, default=Path("/opt/llvm-mingw"))
    parser.add_argument("--host-llvm", type=Path, default=Path("/opt/llvm-23.1.3"))
    parser.add_argument("--work-dir", type=Path, default=Path("/tmp/windows-dependencies"))
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--register-audio", action="store_true")
    parser.add_argument("--audio-lock", type=Path)
    args = parser.parse_args()
    if args.jobs < 1 or not args.prefix.is_absolute() or not args.work_dir.is_absolute():
        parser.error("positive jobs and absolute prefix/work directory required")
    if args.register_audio:
        if args.audio_lock is None:
            parser.error("--register-audio requires --audio-lock")
        register_audio(load_lock(args.lock), args.audio_lock, args.prefix, args.work_dir)
    elif args.verify_only:
        verify(args.prefix, args.llvm, load_lock(args.lock))
    else:
        run(load_lock(args.lock), args.prefix, args.work_dir, args.llvm, args.jobs, args.dry_run, args.host_llvm)


if __name__ == "__main__":
    main()
