import importlib.util
from pathlib import Path
import subprocess
import struct
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

    def test_duplicate_version_names_bind_each_symbol_to_its_index_provider(self):
        text = """
  1: 0000 0 OBJECT GLOBAL DEFAULT UND _rtld_global_ro@GLIBC_PRIVATE (5)
  2: 0000 0 FUNC GLOBAL DEFAULT UND __libc_early_init@GLIBC_PRIVATE (7)
"""
        self.assertEqual(abi.symbol_providers(text, {5: "ld-linux-x86-64.so.2", 7: "libc.so.6"}), {
            "_rtld_global_ro@GLIBC_PRIVATE": {"version_index": 5, "provider": "ld-linux-x86-64.so.2"},
            "__libc_early_init@GLIBC_PRIVATE": {"version_index": 7, "provider": "libc.so.6"}})
        with self.assertRaisesRegex(ValueError, "missing ELF symbol version provider"):
            abi.symbol_providers(text, {7: "libc.so.6"})

    def test_same_version_namespace_still_requires_each_exact_provider_export(self):
        first, loader, libc = [Path("/usr/lib/") / name for name in ("first.so", "loader.so", "libc.so")]
        bindings = abi.symbol_providers("""
  1: 0000 0 OBJECT GLOBAL DEFAULT UND loader_symbol@GLIBC_PRIVATE (5)
  2: 0000 0 FUNC GLOBAL DEFAULT UND libc_symbol@GLIBC_PRIVATE (7)
""", {5: "loader.so", 7: "libc.so"})
        exports = {loader: {"loader_symbol@GLIBC_PRIVATE"}, libc: {"libc_symbol@GLIBC_PRIVATE"}}
        def info(path):
            return dict(needed=["loader.so", "libc.so"] if path == first else [], paths=[],
                        defined=exports.get(path, set()), required=set(bindings) if path == first else set(),
                        required_providers=bindings if path == first else {})
        with patch.object(abi, "elf", side_effect=info), patch.object(abi, "resolve", side_effect=lambda name, paths: Path("/usr/lib") / name), \
             patch.object(abi.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
             patch.object(Path, "read_bytes", return_value=b"fixture"):
            abi.audit([first])
            exports[loader], exports[libc] = exports[libc], exports[loader]
            with self.assertRaisesRegex(ValueError, "unmet versioned provider symbol"):
                abi.audit([first])

    def test_wrong_version_provider_cannot_be_satisfied_by_unrelated_library(self):
        first, declared, unrelated = [Path("/usr/lib/") / name for name in ("first.so", "declared.so", "unrelated.so")]
        def info(path):
            return {"needed": ["declared.so", "unrelated.so"] if path == first else [],
                    "paths": [], "defined": {"copy@ABI_2"} if path == unrelated else set(),
                    "required": {"copy@ABI_2"} if path == first else set(),
                    "required_providers": {"copy@ABI_2": {"version_index": 2, "provider": "declared.so"}} if path == first else {}}
        with patch.object(abi, "elf", side_effect=info), patch.object(abi, "resolve", side_effect=lambda name, paths: Path("/usr/lib") / name):
            with self.assertRaisesRegex(ValueError, "unmet versioned provider symbol"):
                abi.audit([first])

    def test_consumer_dependency_must_have_corresponding_image_closure(self):
        image = {"objects": [{"path": "/lib/libc.so.6", "sha256": "libc"}]}
        consumer = {"roots": ["/client"], "objects": [
            {"path": "/client", "sha256": "client"},
            {"path": "/lib/libc.so.6", "sha256": "libc"},
            {"path": "/lib/libcurl.so.4", "sha256": "curl"}]}
        with self.assertRaisesRegex(ValueError, "absent or changed"):
            abi.require_consumer_coverage(consumer, image)
        image["objects"].append({"path": "/lib/libcurl.so.4", "sha256": "curl"})
        abi.require_consumer_coverage(consumer, image)
        image["objects"][-1]["sha256"] = "changed"
        with self.assertRaisesRegex(ValueError, "absent or changed"):
            abi.require_consumer_coverage(consumer, image)

    def test_newer_glibc_requirement_is_rejected(self):
        def read(*args):
            if "-h" in args:
                return "ELF64 little endian Advanced Micro Devices X86-64"
            if "--version-info" in args:
                return "Version needs section\n File: libc.so.6\n Name: GLIBC_2.38\n"
            return ""
        with patch.object(abi, "output", side_effect=read):
            with self.assertRaisesRegex(ValueError, "newer glibc requirement"):
                abi.elf(Path("/candidate"))

    def test_cpu_notes_allow_baseline_and_absent_reject_newer_and_malformed(self):
        def note(mask):
            return struct.pack("<IIIIIIII", 4, 16, 5, 0x00554e47, 0xc0008002, 4, mask, 0)
        abi.cpu_notes(b"")
        abi.cpu_notes(note(1))
        for mask in (2, 4, 8, 0x80000000):
            with self.assertRaisesRegex(ValueError, "newer CPU ISA"):
                abi.cpu_notes(note(mask))
        for data in (note(1)[:-1], b"short", struct.pack("<III", 99, 4, 5)):
            with self.assertRaises(ValueError):
                abi.cpu_notes(data)

    def test_fdo_notes_validate_headers_json_and_alternative_providers(self):
        import json
        entry = {"feature": "x11-vulkan", "soname": ["libvulkan.so.1", "libvulkan.so"]}
        desc = json.dumps([entry]).encode() + b"\0"
        data = struct.pack("<III", 4, len(desc), 0x407c0c0a) + b"FDO\0" + desc
        data += b"\0" * (-len(data) % 4)
        self.assertEqual(abi.dlopen_notes(data), [entry])
        for malformed in (data[:-1], data[:12] + b"BAD\0" + data[16:], data[:16] + b"!" + data[17:]):
            with self.assertRaises((ValueError, UnicodeDecodeError)):
                abi.dlopen_notes(malformed)

    def test_missing_supported_dlopen_provider_and_changed_exclusion_fail(self):
        for entry in ({"feature": "x11-vulkan", "soname": ["missing.so"]},
                      {"feature": "storage-steam", "soname": ["changed.so"]}):
            info = dict(needed=[], paths=[], defined=set(), required=set(), required_providers={}, dlopen=[entry])
            with patch.object(abi, "elf", return_value=info), patch.object(abi, "resolve", side_effect=ValueError("missing")):
                with self.assertRaisesRegex(ValueError, "missing dlopen feature"):
                    abi.audit([Path("/usr/local/lib/libSDL3.so.0.4.2")])

    def test_empty_loader_search_entry_is_rejected(self):
        def read(*args):
            if "-h" in args:
                return "ELF64 little endian Advanced Micro Devices X86-64"
            if "-d" in args:
                return "(RUNPATH) Library runpath: [/usr/local/lib:]"
            return ""
        with patch.object(abi, "output", side_effect=read):
            with self.assertRaisesRegex(ValueError, "unsupported loader search path"):
                abi.elf(Path("/candidate"))

    def test_loader_missing_dependency_is_failure(self):
        info = dict(needed=[], paths=[], defined=set(), required=set(), required_providers={})
        with patch.object(abi, "elf", return_value=info), patch.object(abi.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "libmissing.so => not found", "")):
            with self.assertRaisesRegex(ValueError, "relocation check failed"):
                abi.audit([Path("/candidate")])


if __name__ == "__main__":
    unittest.main()
