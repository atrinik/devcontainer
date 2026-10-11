#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
"""Build the locked Classic Windows dependency closure with llvm-mingw.

Only verified archives enter the source directory. Recipes are argument arrays,
not shell fragments; host and target compiler environments are kept separate.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
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
        names.add(name)
    return lock


def environment(prefix: Path, host_prefix: Path, llvm: Path, host: bool = False, host_llvm: Path | None = None) -> dict:
    env = os.environ.copy()
    native_path = f"{host_llvm}/bin:" if host_llvm else ""
    env.update({"PATH": f"{native_path}{llvm}/bin:{host_prefix}/bin:{env.get('PATH', '')}",
                "CC": "clang" if host else f"{TARGET}-clang",
                "CXX": "clang++" if host else f"{TARGET}-clang++",
                "AR": "llvm-ar", "RANLIB": "llvm-ranlib", "STRIP": "llvm-strip",
                "LD": "ld.lld", "RC": f"{TARGET}-windres",
                "CC_FOR_BUILD": "clang", "CXX_FOR_BUILD": "clang++",
                "BUILD_CC": "clang", "HOSTCC": "clang",
                "PKG_CONFIG": "pkg-config" if host else f"{TARGET}-pkg-config",
                "PKG_CONFIG_PATH": "", "PKG_CONFIG_LIBDIR": os.pathsep.join(str((host_prefix if host else prefix) / path) for path in ("lib/pkgconfig", "share/pkgconfig")),
                "CFLAGS": "-O2", "CXXFLAGS": "-O2",
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


def extract(archive: Path, directory: Path) -> Path:
    directory.mkdir(parents=True)
    if archive.suffix == ".lz":
        content = subprocess.run(["lzip", "--decompress", "--stdout", str(archive)], capture_output=True, check=True).stdout
        opened = tarfile.open(fileobj=io.BytesIO(content))
    else:
        opened = tarfile.open(archive)
    with opened as tar:
        for member in tar.getmembers():
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or member.isdev():
                raise ValueError("unsafe source archive member")
            if member.issym() or member.islnk():
                destination = path.parent / member.linkname if member.issym() else Path(member.linkname)
                if destination.is_absolute() or not (directory / destination).resolve().is_relative_to(directory.resolve()):
                    raise ValueError("unsafe source archive link")
        tar.extractall(directory, filter="data")
    roots = list(directory.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
        raise ValueError("source archive must have one root directory")
    return roots[0]


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def provider_paths(prefix: Path) -> tuple[dict[str, Path], dict[str, Path]]:
    """Keep root runtime DLLs separate from scoped provider/engine modules."""
    dlls = {}
    modules = {}
    folded = set()
    # External Python is sealed separately; target DLL install roots are bin/lib.
    installed = [path for root in (prefix / "bin", prefix / "lib") for path in root.rglob("*")]
    for path in sorted(installed):
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
        env = environment(prefix, host_prefix, llvm, host, host_llvm)
        for key, value in item.get("environment", {}).items():
            env[key] = value.replace("{prefix}", str(prefix)).replace("{host_prefix}", str(host_prefix))
        recipe = commands(item, source, build, selected_prefix, jobs, host, env)
        configuration = inventory / "configuration" / item["name"]
        if not dry_run:
            configuration.mkdir(parents=True)
        for index, command in enumerate(recipe):
            if dry_run:
                print(json.dumps({"dependency": item["name"], "command": command,
                                  "environment": {key: env[key] for key in ("CC", "CXX", "AR", "PKG_CONFIG")}}))
            else:
                print(f"{item['name']}: command {index + 1}/{len(recipe)}", flush=True)
                with (configuration / f"command-{index}.log").open("w") as output:
                    result = subprocess.run(command, cwd=build, env=env, stdout=output, stderr=subprocess.STDOUT)
                if result.returncode:
                    print((configuration / f"command-{index}.log").read_text()[-12000:], flush=True)
                    result.check_returncode()
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
            save_ownership(prefix, receipt)
        if not dry_run and item["name"] == "curl":
            config = inventory.parent / "curl"
            config.mkdir(exist_ok=True)
            for relative in ("lib/curl_config.h", "config.log"):
                shutil.copy2(build / relative, config / Path(relative).name)
    if not dry_run:
        (inventory / "dependencies.json").write_text(json.dumps(lock, indent=2) + "\n")


def parse_imports(output: str) -> set[str]:
    """Read every normal and delay import name, including Windows .drv files."""
    imports = set()
    block = None
    for line in output.splitlines():
        line = line.strip()
        if line in {"Import {", "DelayImport {"}:
            if block is not None:
                raise ValueError("nested PE import block")
            block = []
        elif block is not None:
            if line == "}":
                if len(block) != 1 or re.fullmatch(r"[A-Za-z0-9_+.\-]+", block[0]) is None:
                    raise ValueError("invalid PE import provider name")
                imports.add(block[0].lower())
                block = None
            elif line.startswith("Name:"):
                block.append(line.removeprefix("Name:").strip())
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
                          and not imported.startswith(("api-ms-win-", "ext-ms-win-"))}
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
