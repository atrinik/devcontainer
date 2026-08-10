#!/usr/bin/env python3
"""Verify the deterministic fields in a Classic Check client package."""

from __future__ import annotations

from pathlib import Path
import sys
import zipfile


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} PACKAGE", file=sys.stderr)
        return 2
    package = Path(sys.argv[1])
    application_id = b"123456789012345678\n"
    with zipfile.ZipFile(package) as archive:
        names = archive.namelist()
        executable = next(name for name in names if name.endswith("/atrinik.exe"))
        config = next(
            name for name in names if name.endswith("/data/discord-application-id")
        )
        if archive.read(config) != application_id:
            raise RuntimeError("packaged Discord application ID is not normalized")
        if b"111111111111111111" in archive.read(config):
            raise RuntimeError("source Discord application ID leaked into the package")
        if application_id.strip() in archive.read(executable):
            raise RuntimeError("Discord application ID was embedded in the executable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
