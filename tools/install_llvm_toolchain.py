#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the pinned Linux LLVM cohort with an explicit Clang bootstrap."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

VERSION = "23.1.3"
SOURCE_SHA256 = "c44186a7762ed28954be72e5ff6df9808e0779d4f1bf014ecc4e7e211d31ee34"
SOURCE_COMMIT = "0d261d1ca552c95a8f007e061c787ac7132fbcbc"
LICENSE_SHA256 = "8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee"
TOOLS = ["clang", "clang++", "clang-format", "clang-tidy", "clangd", "ld.lld",
         "llvm-ar", "llvm-ranlib", "llvm-nm", "llvm-strip", "llvm-objcopy",
         "llvm-objdump", "llvm-readelf", "llvm-readobj", "llvm-size", "llvm-cov",
         "llvm-profdata", "llvm-config"]


class ToolchainError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ToolchainError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_manifest(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ToolchainError("LLVM manifest must be an object")
    source = value.get("source", {})
    if value.get("schema_version") != 1 or value.get("version") != VERSION:
        raise ToolchainError("unsupported LLVM cohort")
    if value.get("platform") != "linux/amd64" or value.get("prefix") != f"/opt/llvm-{VERSION}":
        raise ToolchainError("unsupported LLVM platform or prefix")
    if source != {
        "repository": "llvm/llvm-project", "tag": f"llvmorg-{VERSION}",
        "commit": SOURCE_COMMIT,
        "url": f"https://github.com/llvm/llvm-project/releases/download/llvmorg-{VERSION}/llvm-project-{VERSION}.src.tar.xz",
        "sha256": SOURCE_SHA256, "archive_root": f"llvm-project-{VERSION}.src",
        "license": "Apache-2.0 WITH LLVM-exception", "license_path": "llvm/LICENSE.TXT",
        "license_sha256": LICENSE_SHA256,
    }:
        raise ToolchainError("LLVM source differs from the verified release")
    if value.get("tools") != TOOLS:
        raise ToolchainError("incomplete LLVM tool cohort")
    if value.get("defaults") != {"runtime": "compiler-rt", "unwind": "libunwind", "linker": "lld", "unwind_linkage": "static"}:
        raise ToolchainError("unsupported LLVM runtime/linker contract")
    if value.get("build") != {"projects": ["clang", "clang-tools-extra", "lld"],
        "runtimes": ["compiler-rt", "libunwind"], "targets": ["X86"],
        "build_type": "Release", "cxx_standard_library": "distribution libstdc++",
        "llvm_shared_libraries": False}:
        raise ToolchainError("unsupported LLVM build contract")
    bootstrap = value.get("bootstrap", {})
    if (bootstrap.get("cc"), bootstrap.get("cxx"), bootstrap.get("version"), bootstrap.get("linker")) != (
        "/usr/bin/clang-14", "/usr/bin/clang++-14", "14.0.6", "/usr/bin/ld.lld-14"):
        raise ToolchainError("unsupported LLVM bootstrap compiler")
    metadata = value.get("metadata", {})
    if metadata != {"manifest":"share/atrinik/llvm-toolchain.json", "sbom":"share/atrinik/llvm-toolchain.spdx.json",
        "source_archive":f"share/atrinik/sources/llvm-project-{VERSION}.src.tar.xz", "notices":"share/licenses/llvm"}:
        raise ToolchainError("unsupported LLVM metadata paths")
    return value


def download(source: dict, cache: Path) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / f"llvm-project-{VERSION}.src.tar.xz"
    if destination.is_symlink():
        raise ToolchainError("LLVM cache archive is a symlink")
    if not destination.exists():
        descriptor, temporary = tempfile.mkstemp(prefix="llvm-download-", dir=cache)
        try:
            with os.fdopen(descriptor, "wb") as output, urllib.request.urlopen(source["url"], timeout=60) as response:
                shutil.copyfileobj(response, output)
            if sha256(Path(temporary)) != source["sha256"]:
                raise ToolchainError("LLVM source archive SHA256 mismatch")
            os.chmod(temporary, 0o644)
            os.replace(temporary, destination)
        finally:
            Path(temporary).unlink(missing_ok=True)
    if not destination.is_file() or sha256(destination) != source["sha256"]:
        raise ToolchainError("LLVM cached source archive SHA256 mismatch")
    return destination


def safe_archive_path(name: str, root: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (not name or "\\" in name or "\x00" in name or path.is_absolute()
            or not path.parts or ".." in path.parts or path.parts[0] != root):
        raise ToolchainError(f"unsafe LLVM archive path: {name!r}")
    return path


def normalized_link_target(path: PurePosixPath, member: tarfile.TarInfo, root: str) -> PurePosixPath:
    target = member.linkname
    if not target or "\\" in target or "\x00" in target or PurePosixPath(target).is_absolute():
        raise ToolchainError(f"unsafe LLVM archive link: {member.name!r}")
    # Tar hardlink names start at the archive root; symlinks are relative to
    # their containing directory. Never let '..' pop the archive root.
    parts = list(path.parent.parts) if member.issym() else []
    for part in PurePosixPath(target).parts:
        if part == "..":
            if len(parts) <= 1:
                raise ToolchainError(f"LLVM archive link escapes source root: {member.name!r}")
            parts.pop()
        elif part != ".":
            parts.append(part)
    if not parts or parts[0] != root:
        raise ToolchainError(f"LLVM archive link escapes source root: {member.name!r}")
    return PurePosixPath(*parts)


def validate_archive_members(members: list[tarfile.TarInfo], root: str) -> dict[PurePosixPath, tarfile.TarInfo]:
    records: dict[PurePosixPath, tarfile.TarInfo] = {}
    expanded = 0
    if len(members) > 400000:
        raise ToolchainError("LLVM archive exceeds extraction limits")
    for member in members:
        path = safe_archive_path(member.name, root)
        if path in records:
            raise ToolchainError(f"duplicate LLVM archive path: {path}")
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise ToolchainError(f"unsupported LLVM archive member: {path}")
        if member.size < 0 or member.size > 512 * 1024**2:
            raise ToolchainError(f"invalid LLVM archive member size: {path}")
        expanded += member.size
        if expanded > 8 * 1024**3:
            raise ToolchainError("LLVM archive exceeds extraction limits")
        records[path] = member
    for path, member in records.items():
        for parent in path.parents:
            if parent in records and not records[parent].isdir():
                raise ToolchainError(f"LLVM archive member traverses non-directory parent: {path}")
        if member.issym() or member.islnk():
            target = normalized_link_target(path, member, root)
            raw_parts = list(path.parent.parts) if member.issym() else []
            for part in PurePosixPath(member.linkname).parts:
                if part == "..":
                    raw_parts.pop()
                elif part != ".":
                    raw_parts.append(part)
                intermediate = PurePosixPath(*raw_parts)
                if intermediate in records and (records[intermediate].issym() or records[intermediate].islnk()):
                    raise ToolchainError(f"LLVM archive link traverses another link: {path}")
            # Refuse link chains and link parents. Lexical '..' validation
            # alone is insufficient when an intermediate symlink rewrites it.
            for component in (target, *target.parents):
                if component in records and (records[component].issym() or records[component].islnk()):
                    raise ToolchainError(f"LLVM archive link traverses another link: {path}")
            if member.islnk() and (target not in records or not records[target].isfile()):
                raise ToolchainError(f"LLVM archive hardlink target is not a regular file: {path}")
    return records


def extract_source(archive: Path, destination: Path, source: dict) -> Path:
    if destination.is_symlink() or (destination.exists() and any(destination.iterdir())):
        raise ToolchainError("LLVM extraction requires a new or empty destination")
    with tarfile.open(archive, "r:xz") as stream:
        records = validate_archive_members(stream.getmembers(), source["archive_root"])
        destination.mkdir(parents=True, exist_ok=True)
        # Write directories and regular files first using exclusive creation.
        # All link parents were rejected before any archive contents are written.
        for path, member in records.items():
            output = destination.joinpath(*path.parts)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                output.parent.mkdir(parents=True, exist_ok=True)
                contents = stream.extractfile(member)
                if contents is None:
                    raise ToolchainError(f"cannot read LLVM archive member: {path}")
                with contents, output.open("xb") as target:
                    shutil.copyfileobj(contents, target)
                output.chmod(0o755 if member.mode & 0o111 else 0o644)
        for path, member in records.items():
            if not (member.issym() or member.islnk()):
                continue
            output = destination.joinpath(*path.parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                os.symlink(member.linkname, output)
            else:
                target = normalized_link_target(path, member, source["archive_root"])
                os.link(destination.joinpath(*target.parts), output, follow_symlinks=False)
    root = destination / source["archive_root"]
    license_path = root / source["license_path"]
    if license_path.is_symlink() or sha256(license_path) != source["license_sha256"]:
        raise ToolchainError("LLVM source license SHA256 mismatch")
    return root


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def build(source: Path, work: Path, prefix: Path, manifest: dict, jobs: int) -> None:
    bootstrap = manifest["bootstrap"]
    for compiler in (bootstrap["cc"], bootstrap["cxx"]):
        version = subprocess.check_output([compiler, "--version"], text=True)
        if not re.search(r"\bclang version " + re.escape(bootstrap["version"]) + r"\b", version):
            raise ToolchainError(f"bootstrap compiler identity mismatch: {compiler}")
    # Bootstrap packages may carry GNU headers/libraries. Their compiler is
    # never selected: every CMake compiler/binutils/linker path is explicit.
    llvm = work / "llvm-build"
    run(["cmake", "-S", str(source / "llvm"), "-B", str(llvm), "-G", "Ninja",
         "-DCMAKE_BUILD_TYPE=Release", f"-DCMAKE_INSTALL_PREFIX={prefix}",
         f"-DCMAKE_C_COMPILER={bootstrap['cc']}", f"-DCMAKE_CXX_COMPILER={bootstrap['cxx']}",
         "-DCMAKE_STRIP=/usr/bin/llvm-strip-14", "-DCMAKE_AR=/usr/bin/llvm-ar-14", "-DCMAKE_RANLIB=/usr/bin/llvm-ranlib-14",
         "-DLLVM_USE_LINKER=lld-14", "-DLLVM_ENABLE_PROJECTS=clang;clang-tools-extra;lld",
         "-DLLVM_TARGETS_TO_BUILD=X86", "-DLLVM_INCLUDE_TESTS=OFF", "-DLLVM_INCLUDE_BENCHMARKS=OFF",
         "-DLLVM_INCLUDE_EXAMPLES=OFF", "-DLLVM_ENABLE_ASSERTIONS=OFF",
         "-DLLVM_ENABLE_ZLIB=OFF", "-DLLVM_ENABLE_ZSTD=OFF", "-DLLVM_ENABLE_LIBXML2=OFF",
         "-DLLVM_ENABLE_TERMINFO=OFF", "-DLLVM_ENABLE_LIBEDIT=OFF",
         "-DLLVM_BUILD_LLVM_DYLIB=OFF", "-DLLVM_LINK_LLVM_DYLIB=OFF",
         "-DCMAKE_EXE_LINKER_FLAGS=-Wl,--build-id=sha1"])
    run(["cmake", "--build", str(llvm), "--parallel", str(jobs)])
    run(["cmake", "--install", str(llvm), "--strip"])
    build_runtimes(source, work, prefix, jobs)


def build_runtimes(source: Path, work: Path, prefix: Path, jobs: int) -> None:
    runtime = work / "runtime-build"
    # The just-built Clang compiles its own runtimes. Defaults are installed
    # only after this step, avoiding a circular dependency on compiler-rt.
    run(["cmake", "-S", str(source / "runtimes"), "-B", str(runtime), "-G", "Ninja",
         "-DCMAKE_BUILD_TYPE=Release", f"-DCMAKE_INSTALL_PREFIX={prefix}",
         f"-DCMAKE_C_COMPILER={prefix}/bin/clang", f"-DCMAKE_CXX_COMPILER={prefix}/bin/clang++",
         f"-DCMAKE_STRIP={prefix}/bin/llvm-strip", f"-DCMAKE_AR={prefix}/bin/llvm-ar", f"-DCMAKE_RANLIB={prefix}/bin/llvm-ranlib",
         f"-DCMAKE_C_COMPILER_TARGET=x86_64-unknown-linux-gnu",
         f"-DCMAKE_CXX_COMPILER_TARGET=x86_64-unknown-linux-gnu",
         "-DCMAKE_C_FLAGS=--no-default-config --rtlib=libgcc --unwindlib=libgcc -fuse-ld=lld",
         "-DCMAKE_CXX_FLAGS=--no-default-config --rtlib=libgcc --unwindlib=libgcc -fuse-ld=lld",
         "-DCMAKE_INSTALL_LIBDIR=lib", "-DLLVM_ENABLE_PER_TARGET_RUNTIME_DIR=OFF",
         f"-DCOMPILER_RT_INSTALL_PATH={prefix}/lib/clang/23",
         "-DLLVM_ENABLE_RUNTIMES=compiler-rt;libunwind", "-DLLVM_INCLUDE_TESTS=OFF",
         "-DCOMPILER_RT_BUILD_TESTS=OFF", "-DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON",
         "-DCOMPILER_RT_BUILD_XRAY=OFF", "-DCOMPILER_RT_BUILD_ORC=OFF",
         "-DLIBUNWIND_INCLUDE_TESTS=OFF", "-DLIBUNWIND_ENABLE_SHARED=OFF",
         "-DLIBUNWIND_ENABLE_STATIC=ON", "-DLIBUNWIND_USE_COMPILER_RT=OFF"])
    run(["cmake", "--build", str(runtime), "--parallel", str(jobs)])
    run(["cmake", "--install", str(runtime)])


def install_metadata(prefix: Path, manifest_path: Path, archive: Path, source: Path, manifest: dict) -> None:
    for tool in ("clang", "clang++"):
        (prefix / "bin" / f"{tool}.cfg").write_text(
            "--rtlib=compiler-rt\n--unwindlib=libunwind\n-fuse-ld=lld\n-L<CFGDIR>/../lib\n", encoding="utf-8")
    wrapper = prefix / "bin" / "llvm-gcov"
    wrapper.write_text('#!/bin/sh\nexec "$(dirname "$0")/llvm-cov" gcov "$@"\n', encoding="utf-8")
    wrapper.chmod(0o755)
    # Consumer images need compiler resource headers/runtimes and tools, not
    # the LLVM C++ SDK's large static libraries. Keep libclang for developer
    # bindings and libunwind for the explicit runtime contract.
    for library in (prefix / "lib").glob("*.a"):
        if library.name != "libunwind.a":
            library.unlink()
    for name in ("llvm", "llvm-c", "clang", "clang-c"):
        shutil.rmtree(prefix / "include" / name, ignore_errors=True)
    metadata = manifest["metadata"]
    for destination, original in [(metadata["manifest"], manifest_path), (metadata["source_archive"], archive)]:
        path = prefix / destination
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, path)
        path.chmod(0o644)
    notice_root = prefix / metadata["notices"]
    notice_root.mkdir(parents=True, exist_ok=True)
    for component in ("llvm", "clang", "clang-tools-extra", "lld", "compiler-rt", "libunwind"):
        shutil.copyfile(source / component / "LICENSE.TXT", notice_root / f"{component}-LICENSE.TXT")
    sbom = {"spdxVersion":"SPDX-2.3", "dataLicense":"CC0-1.0", "SPDXID":"SPDXRef-DOCUMENT",
        "name":"Atrinik LLVM toolchain", "documentNamespace":f"https://atrinik.org/spdx/llvm-{VERSION}-{SOURCE_SHA256}",
        "creationInfo":{"created":"2026-10-10T00:00:00Z", "creators":["Organization: Atrinik"]},
        "packages":[{"name":"LLVM", "SPDXID":"SPDXRef-LLVM", "versionInfo":VERSION,
            "downloadLocation":manifest["source"]["url"], "filesAnalyzed":False,
            "licenseConcluded":"NOASSERTION", "licenseDeclared":manifest["source"]["license"],
            "copyrightText":"NOASSERTION", "checksums":[{"algorithm":"SHA256", "checksumValue":SOURCE_SHA256}]}],
        "relationships":[{"spdxElementId":"SPDXRef-DOCUMENT", "relationshipType":"DESCRIBES", "relatedSpdxElement":"SPDXRef-LLVM"}]}
    (prefix / metadata["sbom"]).write_text(json.dumps(sbom, indent=2)+"\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    manifest = load_manifest(args.manifest)
    if args.jobs < 1 or not args.prefix.is_absolute() or args.prefix.is_symlink() or args.prefix.exists():
        raise ToolchainError("jobs must be positive and prefix must be a new absolute directory")
    archive = download(manifest["source"], args.cache)
    with tempfile.TemporaryDirectory(prefix="llvm-build-", dir=args.cache) as temporary:
        work = Path(temporary)
        source = extract_source(archive, work / "source", manifest["source"])
        build(source, work, args.prefix, manifest, args.jobs)
        install_metadata(args.prefix, args.manifest, archive, source, manifest)


if __name__ == "__main__":
    try:
        main()
    except (ToolchainError, OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"LLVM toolchain installation failed: {error}") from error
