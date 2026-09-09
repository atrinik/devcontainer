import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("portable_abi", Path(__file__).with_name("abi.py"))
abi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abi)


class Symbols(unittest.TestCase):
    def test_default_and_nondefault_versions_and_weak_imports(self):
        text = """
  1: 0000 0 FUNC GLOBAL DEFAULT UND memcpy@GLIBC_2.14 (2)
  2: 0010 4 FUNC GLOBAL DEFAULT 12 copy@@ABI_2
  3: 0020 4 FUNC GLOBAL DEFAULT 12 copy@ABI_1
  4: 0000 0 NOTYPE WEAK DEFAULT UND optional
"""
        exports, imports = abi.symbols(text)
        self.assertEqual(imports, {"memcpy@GLIBC_2.14"})
        self.assertEqual(exports, {"copy", "copy@ABI_1", "copy@ABI_2"})

    def test_wrong_version_provider_cannot_be_satisfied_by_unrelated_library(self):
        first, declared, unrelated = [Path("/usr/lib/") / name for name in ("first.so", "declared.so", "unrelated.so")]
        def info(path):
            return {"needed": ["declared.so", "unrelated.so"] if path == first else [],
                    "paths": [], "defined": {"copy@ABI_2"} if path == unrelated else set(),
                    "required": {"copy@ABI_2"} if path == first else set(),
                    "version_providers": {"ABI_2": "declared.so"} if path == first else {}}
        with patch.object(abi, "elf", side_effect=info), patch.object(abi, "resolve", side_effect=lambda name, paths: Path("/usr/lib") / name):
            with self.assertRaisesRegex(ValueError, "unmet versioned provider symbol"):
                abi.audit([first])

    def test_newer_glibc_requirement_is_rejected(self):
        def read(*args):
            if "-h" in args:
                return "ELF64 Advanced Micro Devices X86-64"
            if "--version-info" in args:
                return "Version needs section\n File: libc.so.6\n Name: GLIBC_2.38\n"
            return ""
        with patch.object(abi, "output", side_effect=read):
            with self.assertRaisesRegex(ValueError, "newer glibc requirement"):
                abi.elf(Path("/candidate"))

    def test_newer_cpu_note_is_rejected(self):
        def read(*args):
            return "ELF64 Advanced Micro Devices X86-64" if "-h" in args else "x86 ISA needed: x86-64-v3\n"
        with patch.object(abi, "output", side_effect=read):
            with self.assertRaisesRegex(ValueError, "newer CPU ISA"):
                abi.elf(Path("/candidate"))

    def test_loader_missing_dependency_is_failure(self):
        info = dict(needed=[], paths=[], defined=set(), required=set(), version_providers={})
        with patch.object(abi, "elf", return_value=info), patch.object(abi.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "libmissing.so => not found", "")):
            with self.assertRaisesRegex(ValueError, "relocation check failed"):
                abi.audit([Path("/candidate")])


if __name__ == "__main__":
    unittest.main()
