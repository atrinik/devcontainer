from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile


SPEC = importlib.util.spec_from_file_location(
    "verify_classic_check_package",
    Path(__file__).resolve().parents[1] / "verify-classic-check-package.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PackageClosureTests(unittest.TestCase):
    def verify(self, application_imports: list[str], runtime_imports: list[str]) -> int:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "client.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("client/atrinik.exe", b"application")
                archive.writestr(
                    "client/data/discord-application-id", b"123456789012345678\n"
                )
                for name in MODULE.EXPECTED_RUNTIME_DLLS:
                    archive.writestr("client/" + name, b"runtime")

            def inspect(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                imports = (
                    application_imports
                    if Path(command[-1]).name == "atrinik.exe"
                    else runtime_imports
                )
                return subprocess.CompletedProcess(
                    command, 0, "".join("DLL Name: " + name + "\n" for name in imports), ""
                )

            with mock.patch.object(MODULE.sys, "argv", ["verify", str(package), "objdump"]), mock.patch.object(
                MODULE.subprocess, "run", side_effect=inspect
            ):
                return MODULE.main()

    def test_inbox_d3d12_is_not_required_in_client_package(self) -> None:
        self.assertEqual(self.verify(["D3D12.dll", "DXGI.dll", "SDL3.dll"], ["KERNEL32.dll", "MSIMG32.dll"]), 0)

    def test_transitive_private_runtime_still_must_be_packaged(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "libcares-2.dll"):
            self.verify(["D3D12.dll", "SDL3.dll"], ["libcares-2.dll"])


if __name__ == "__main__":
    unittest.main()
