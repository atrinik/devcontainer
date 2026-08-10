#!/usr/bin/env python3
"""Verify the deterministic fields in a Classic Check client package."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile


DLL_NAME = re.compile(r"^\s*DLL Name:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
EXPECTED_RUNTIME_DLLS = {
    "libssp-0.dll",
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
    "msvcrt.dll",
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
    if len(sys.argv) != 3:
        print(
            f"usage: {Path(sys.argv[0]).name} PACKAGE OBJDUMP",
            file=sys.stderr,
        )
        return 2
    package = Path(sys.argv[1])
    objdump = sys.argv[2]
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
        missing_expected = EXPECTED_RUNTIME_DLLS - archive_by_basename.keys()
        if missing_expected:
            raise RuntimeError(
                "package is missing expected runtime DLLs: "
                + ", ".join(sorted(missing_expected))
            )

        queue = [Path(executable).name.lower()]
        inspected: set[str] = set()
        while queue:
            basename = queue.pop()
            if basename in inspected:
                continue
            matches = archive_by_basename.get(basename, [])
            if len(matches) != 1:
                raise RuntimeError(
                    f"packaged runtime must contain exactly one {basename}: {matches}"
                )
            binary = Path(temporary) / basename
            binary.write_bytes(archive.read(matches[0]))
            result = subprocess.run(
                [objdump, "-p", str(binary)],
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
            inspected.add(basename)
            for dependency in DLL_NAME.findall(result.stdout):
                normalized = dependency.lower()
                if not is_system_dll(normalized) and normalized not in inspected:
                    queue.append(normalized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
