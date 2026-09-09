#!/usr/bin/env python3
"""Build the locked application inputs on the Debian baseline."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))
from install_classic_shader_toolchain import (  # noqa: E402
    MAX_EXPANDED_BYTES, MAX_FILE_BYTES, MAX_MEMBERS, ToolchainError,
    copy_member, download, safe_archive_path,
)


def extract(archive_path: Path, destination: Path) -> None:
    """Extract Linux source inputs; retain full archives including unused Xcode links."""
    seen = set()
    roots = set()
    expanded = 0
    with tarfile.open(archive_path, "r:gz") as archive:
        for count, member in enumerate(archive, 1):
            if count > MAX_MEMBERS:
                raise ToolchainError("source archive has too many members")
            path = safe_archive_path(member.name)
            roots.add(path.parts[0])
            if len(roots) != 1:
                raise ToolchainError("source archive must have one root")
            if len(path.parts) == 1:
                continue
            relative = Path(*path.parts[1:])
            # Darwin framework symlinks are not inputs to these Linux builds.
            if relative.parts[0] == "Xcode":
                continue
            if str(relative).casefold() in seen:
                raise ToolchainError("duplicate source archive member")
            seen.add(str(relative).casefold())
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.size > MAX_FILE_BYTES:
                raise ToolchainError("unsupported source archive member")
            expanded += member.size
            if expanded > MAX_EXPANDED_BYTES:
                raise ToolchainError("source archive is too large")
            with archive.extractfile(member) as source:
                copy_member(source, target, member.size)
            target.chmod(member.mode & 0o755 or 0o644)


def run(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(args, cwd=cwd, check=True)


def main() -> None:
    contract = json.loads((ROOT / "contract.json").read_text())
    archives = ROOT / "sources"
    notices = ROOT / "notices"
    notices.mkdir(exist_ok=True)
    options = {
        "sdl3": ["-DSDL_DEPS_SHARED=OFF", "-DSDL_KMSDRM=OFF", "-DSDL_LIBDECOR=OFF", "-DSDL_TESTS=OFF", "-DSDL_TEST_LIBRARY=OFF", "-DSDL_STATIC=OFF",
                 "-DSDL_ALSA_SHARED=OFF", "-DSDL_PULSEAUDIO_SHARED=OFF",
                 "-DSDL_X11_SHARED=OFF", "-DSDL_WAYLAND_SHARED=OFF",
                 "-DSDL_JACK=OFF", "-DSDL_PIPEWIRE=OFF", "-DSDL_IBUS=OFF",
                 "-DSDL_FCITX=OFF", "-DSDL_LIBUDEV=OFF", "-DSDL_LIBDECOR_SHARED=OFF"],
        "sdl3-image": ["-DSDLIMAGE_STRICT=ON", "-DSDLIMAGE_VENDORED=OFF", "-DSDLIMAGE_DEPS_SHARED=OFF",
                       "-DSDLIMAGE_AVIF=OFF", "-DSDLIMAGE_JXL=OFF", "-DSDLIMAGE_TIF=OFF",
                       "-DSDLIMAGE_WEBP=ON", "-DSDLIMAGE_PNG=ON", "-DSDLIMAGE_JPG=ON",
                       "-DSDLIMAGE_SAMPLES=OFF", "-DSDLIMAGE_TESTS=OFF"],
        "sdl3-ttf": ["-DSDLTTF_VENDORED=OFF", "-DSDLTTF_HARFBUZZ=ON",
                     "-DSDLTTF_PLUTOSVG=OFF", "-DSDLTTF_SAMPLES=OFF"],
    }
    with tempfile.TemporaryDirectory(prefix="portable-build-") as temp:
        work = Path(temp)
        for entry in contract["sources"]:
            source = work / entry["name"]
            extract(download(entry["url"], entry["sha256"], archives), source)
            license_dir = notices / entry["name"]
            license_dir.mkdir()
            for candidate in source.iterdir():
                if candidate.is_file() and candidate.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE")):
                    shutil.copy2(candidate, license_dir / candidate.name)
            if not any(license_dir.iterdir()):
                raise RuntimeError(f"no upstream notice for {entry['name']}")
            if entry["name"] == "openssl":
                run("perl", "Configure", "linux-x86_64", "shared", "--prefix=/usr/local",
                    "--libdir=lib", "--openssldir=/etc/ssl", "-march=x86-64", "-mtune=generic", cwd=source)
                run("make", "-j2", cwd=source)
                run("make", "install_sw", cwd=source)
                run("ldconfig")
            else:
                build = work / (entry["name"] + "-build")
                run("cmake", "-S", str(source), "-B", str(build), "-G", "Ninja",
                    "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_PREFIX=/usr/local",
                    "-DCMAKE_INSTALL_LIBDIR=lib", "-DBUILD_SHARED_LIBS=ON",
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", *options[entry["name"]])
                run("cmake", "--build", str(build), "--parallel", "2")
                run("cmake", "--install", str(build))
        audio = json.loads((ROOT / "audio-toolchain.json").read_text())
        for entry in [audio["sdl_mixer"], *audio["dependencies"]]:
            download(entry["source"]["url"], entry["source"]["sha256"], archives)
        run("bash", str(ROOT / "tools/build-sdl3-mixer.sh"),
            str(ROOT / "audio-toolchain.json"), "cmake", "/usr/local", "2")
    run("ldconfig")
    run("cc", *contract["compiler"]["cflags"].split(), str(ROOT / "audio/sdl3-mixer-probe.c"),
        "-o", str(ROOT / "audio/sdl3-mixer-probe"),
        *subprocess.check_output(["pkg-config", "--cflags", "--libs", "sdl3-mixer"], text=True).split())


if __name__ == "__main__":
    main()
