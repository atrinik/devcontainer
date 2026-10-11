#!/usr/bin/env python3
"""Verify the deterministic fields in a Classic Check client package."""

from __future__ import annotations

from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import zipfile


DLL_NAME = re.compile(r"^\s*Name:\s*(\S+\.(?:dll|drv))\s*$", re.IGNORECASE | re.MULTILINE)
EXPECTED_RUNTIME_DLLS = {
    "sdl3.dll",
    "sdl3_image.dll",
    "sdl3_mixer.dll",
    "sdl3_ttf.dll",
}
SYSTEM_DLLS = {
    "advapi32.dll",
    "bcrypt.dll",
    "cabinet.dll",
    "comctl32.dll",
    "comdlg32.dll",
    "crypt32.dll",
    "d2d1.dll",
    "d3d11.dll",
    "d3d12.dll",
    "dbghelp.dll",
    "dinput8.dll",
    "dnsapi.dll",
    "dwmapi.dll",
    "dxgi.dll",
    "gdi32.dll",
    "imagehlp.dll",
    "imm32.dll",
    "iphlpapi.dll",
    "kernel32.dll",
    "msimg32.dll",
    "ucrtbase.dll",
    "ncrypt.dll",
    "normaliz.dll",
    "ole32.dll",
    "oleaut32.dll",
    "powrprof.dll",
    "psapi.dll",
    "rpcrt4.dll",
    "secur32.dll",
    "setupapi.dll",
    "shell32.dll",
    "shlwapi.dll",
    "user32.dll",
    "userenv.dll",
    "usp10.dll",
    "uxtheme.dll",
    "version.dll",
    "winhttp.dll",
    "winmm.dll",
    "winspool.drv",
    "wldap32.dll",
    "ws2_32.dll",
    "wsock32.dll",
}


def is_system_dll(name: str) -> bool:
    normalized = name.lower()
    return (
        normalized in SYSTEM_DLLS
        or normalized.startswith("api-ms-win-")
        or normalized.startswith("ext-ms-win-")
    )


def main() -> int:
    if len(sys.argv) != 4:
        print(
            f"usage: {Path(sys.argv[0]).name} PACKAGE READOBJ TOOLCHAIN_MANIFEST",
            file=sys.stderr,
        )
        return 2
    package = Path(sys.argv[1])
    readobj = sys.argv[2]
    manifest = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
    expected_payloads = {
        "ca-bundle.crt": manifest["verification"]["public_ca"]["sha256"],
        manifest["runtime_contract"]["cares_license"]["bundle_name"]:
            manifest["runtime_contract"]["cares_license"]["sha256"],
    }
    application_id = b"123456789012345678\n"
    with zipfile.ZipFile(package) as archive, tempfile.TemporaryDirectory() as temporary:
        names = archive.namelist()
        executable = next(name for name in names if name.endswith("/atrinik.exe"))
        config = next(
            name for name in names if name.endswith("/data/discord-application-id")
        )
        if archive.read(config) != application_id:
            raise RuntimeError("packaged Discord application ID is not normalized")
        if application_id.strip() in archive.read(executable):
            raise RuntimeError("Discord application ID was embedded in the executable")
        archive_by_basename: dict[str, list[str]] = {}
        for name in names:
            if not name.endswith("/"):
                archive_by_basename.setdefault(Path(name).name.lower(), []).append(name)
        for basename, expected_digest in expected_payloads.items():
            if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
                raise RuntimeError(f"invalid expected checksum for {basename}")
            matches = archive_by_basename.get(basename.lower(), [])
            if len(matches) != 1:
                raise RuntimeError(f"package must contain exactly one {basename}")
            if hashlib.sha256(archive.read(matches[0])).hexdigest() != expected_digest:
                raise RuntimeError(f"packaged {basename} checksum does not match toolchain contract")
        missing_expected = EXPECTED_RUNTIME_DLLS - archive_by_basename.keys()
        if missing_expected:
            raise RuntimeError(
                "package is missing expected runtime DLLs: "
                + ", ".join(sorted(missing_expected))
            )

        queue = [name for name in archive_by_basename
                 if name.endswith((".exe", ".dll", ".pyd"))]
        inspected: set[str] = set()
        while queue:
            basename = queue.pop()
            if basename in inspected:
                continue
            if basename == "msvcrt.dll" or basename.startswith(("libgcc", "libstdc++", "libssp", "libgomp", "libatomic", "libquadmath")):
                raise RuntimeError(f"packaged forbidden GCC or legacy CRT runtime: {basename}")
            matches = archive_by_basename.get(basename, [])
            if len(matches) != 1:
                raise RuntimeError(
                    f"packaged runtime must contain exactly one {basename}: {matches}"
                )
            binary = Path(temporary) / basename
            binary.write_bytes(archive.read(matches[0]))
            result = subprocess.run(
                [readobj, "--coff-imports", str(binary)],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode:
                raise RuntimeError(
                    f"cannot inspect packaged {basename}: "
                    f"{result.stderr.strip() or result.returncode}"
                )
            if "Format: COFF-x86-64" not in result.stdout:
                raise RuntimeError(f"packaged runtime is not x86_64 COFF: {basename}")
            inspected.add(basename)
            for dependency in DLL_NAME.findall(result.stdout):
                normalized = dependency.lower()
                if normalized == "msvcrt.dll" or normalized.startswith(("libgcc", "libstdc++", "libssp", "libgomp", "libatomic", "libquadmath")):
                    raise RuntimeError(f"packaged runtime imports forbidden GCC or legacy CRT runtime: {normalized}")
                if not is_system_dll(normalized) and normalized not in inspected:
                    queue.append(normalized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
