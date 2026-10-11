from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("install_llvm_toolchain", ROOT / "tools/install_llvm_toolchain.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LLVMToolchainTests(unittest.TestCase):
    def test_loads_verified_source_cohort(self):
        manifest = MODULE.load_manifest(ROOT / "llvm-toolchain.json")
        self.assertEqual(manifest["source"]["commit"], MODULE.SOURCE_COMMIT)

    def test_rejects_changed_source_or_runtime_defaults(self):
        manifest = json.loads((ROOT / "llvm-toolchain.json").read_text())
        for section, key, value in [("source", "sha256", "f"*64), ("defaults", "unwind", "libgcc")]:
            modified = json.loads(json.dumps(manifest))
            modified[section][key] = value
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "manifest.json"
                path.write_text(json.dumps(modified))
                with self.assertRaises(MODULE.ToolchainError):
                    MODULE.load_manifest(path)

    def test_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text('{"version":"23.1.3", "version":"23.1.3"}')
            with self.assertRaisesRegex(MODULE.ToolchainError, "duplicate"):
                MODULE.load_manifest(path)

    def test_rejects_corrupt_cached_archive_before_build(self):
        manifest = MODULE.load_manifest(ROOT / "llvm-toolchain.json")
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            (cache / "llvm-project-23.1.3.src.tar.xz").write_bytes(b"corrupt")
            with self.assertRaisesRegex(MODULE.ToolchainError, "SHA256"):
                MODULE.download(manifest["source"], cache)

    def test_rejects_traversal_or_external_archive_links(self):
        for path in ["/outside", "root/../outside", "root\\outside"]:
            with self.assertRaises(MODULE.ToolchainError):
                MODULE.safe_archive_path(path, "root")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "source.tar.xz"
            with tarfile.open(archive, "w:xz") as stream:
                link = tarfile.TarInfo("root/link")
                link.type = tarfile.SYMTYPE
                link.linkname = "/outside"
                stream.addfile(link)
            with self.assertRaises(tarfile.FilterError):
                MODULE.extract_source(archive, base / "unpacked", {"archive_root":"root"})
            self.assertFalse((base / "unpacked/root/link").exists())

    def test_extraction_checks_license(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "source.tar.xz"
            content = b"upstream license"
            with tarfile.open(archive, "w:xz") as stream:
                member = tarfile.TarInfo("root/llvm/LICENSE.TXT")
                member.size = len(content)
                stream.addfile(member, io.BytesIO(content))
            source = {"archive_root":"root", "license_path":"llvm/LICENSE.TXT", "license_sha256":hashlib.sha256(content).hexdigest()}
            self.assertEqual(MODULE.extract_source(archive, base / "unpacked", source), base / "unpacked/root")

    def test_runtime_build_uses_new_clang_and_llvm_binutils(self):
        manifest = MODULE.load_manifest(ROOT / "llvm-toolchain.json")
        with mock.patch.object(MODULE.subprocess, "check_output", return_value="Debian clang version 14.0.6"), mock.patch.object(MODULE, "run") as run:
            MODULE.build(Path("/source"), Path("/work"), Path("/opt/llvm-23.1.3"), manifest, 2)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn("-DCMAKE_C_COMPILER=/usr/bin/clang-14", commands[0])
        self.assertIn("-DCMAKE_C_COMPILER=/opt/llvm-23.1.3/bin/clang", commands[3])
        self.assertIn("-DCMAKE_AR=/opt/llvm-23.1.3/bin/llvm-ar", commands[3])
        self.assertIn("-DLIBUNWIND_ENABLE_SHARED=OFF", commands[3])
        self.assertFalse(any("gcc" in flag for flag in commands[0]))


if __name__ == "__main__":
    unittest.main()
