from __future__ import annotations

import hashlib
import io
import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "install_classic_shader_toolchain",
    ROOT / "tools" / "install_classic_shader_toolchain.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def add_file(archive: tarfile.TarFile, name: str, content: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = mode
    archive.addfile(info, io.BytesIO(content))


class ClassicShaderToolchainTests(unittest.TestCase):
    def test_loads_the_qualified_manifest(self) -> None:
        manifest = MODULE.load_manifest(ROOT / "classic-shader-toolchain.json")
        self.assertEqual(manifest["dxc"]["tag"], "v1.9.2607")  # type: ignore[index]
        self.assertEqual(  # type: ignore[index]
            manifest["spirv_cross"]["commit"],
            "9c3c8e2cefdd8194b193bb8ed2fdff4d5527e382",
        )

    def test_rejects_a_different_qualified_dxc_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            value = (ROOT / "classic-shader-toolchain.json").read_text(encoding="utf-8")
            path.write_text(
                value.replace(
                    "0d3ee6b551b8fa768fbf825300ebab81047ef6a8",
                    "f" * 40,
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODULE.ToolchainError, "qualified release commit"):
                MODULE.load_manifest(path)

    def test_rejects_duplicate_json_keys(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as stream:
            stream.write('{"schema_version": 1, "schema_version": 1}\n')
            stream.flush()
            with self.assertRaisesRegex(MODULE.ToolchainError, "duplicate"):
                MODULE.load_manifest(Path(stream.name))

    def test_rejects_unsafe_archive_paths(self) -> None:
        for value in ("/etc/passwd", "root/../outside", "root\\outside", "root/\x00bad"):
            with self.subTest(value=value), self.assertRaisesRegex(
                MODULE.ToolchainError, "unsafe shader archive member"
            ):
                MODULE.safe_archive_path(value)

    def test_extracts_only_locked_dxc_files_and_checks_digests(self) -> None:
        contents = {
            "bin/dxc": b"dxc",
            "lib/libdxcompiler.so": b"compiler",
            "lib/libdxil.so": b"dxil",
            "LICENCE-MIT.txt": b"mit",
        }
        entry = {
            "archive_root": "dxc-root",
            "files": {name: digest(value) for name, value in contents.items()},
        }
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "dxc.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                for name, value in contents.items():
                    add_file(archive, f"dxc-root/{name}", value, 0o755 if name == "bin/dxc" else 0o644)
                    add_file(archive, "dxc-root/unused.txt", b"ignored")
                    break
                for name, value in list(contents.items())[1:]:
                    add_file(archive, f"dxc-root/{name}", value)
            destination = Path(temporary) / "dxc"
            MODULE.extract_dxc(archive_path, destination, entry)
            self.assertEqual((destination / "bin/dxc").read_bytes(), b"dxc")
            self.assertFalse((destination / "unused.txt").exists())

    def test_rejects_a_symlink_in_a_locked_dxc_member(self) -> None:
        entry = {"archive_root": "dxc-root", "files": {"bin/dxc": "0" * 64}}
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "dxc.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                info = tarfile.TarInfo("dxc-root/bin/dxc")
                info.type = tarfile.SYMTYPE
                info.linkname = "outside"
                archive.addfile(info)
            with self.assertRaisesRegex(MODULE.ToolchainError, "invalid DXC archive member"):
                MODULE.extract_dxc(archive_path, Path(temporary) / "dxc", entry)

    def test_extracts_spirv_cross_without_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "spirv-cross.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                directory = tarfile.TarInfo("SPIRV-Cross-root")
                directory.type = tarfile.DIRTYPE
                archive.addfile(directory)
                add_file(archive, "SPIRV-Cross-root/CMakeLists.txt", b"project(test)\n")
                add_file(archive, "SPIRV-Cross-root/LICENSE", b"Apache License\n")
            destination = Path(temporary) / "source"
            MODULE.extract_spirv_cross(archive_path, destination)
            self.assertTrue((destination / "CMakeLists.txt").is_file())
            self.assertEqual((destination / "LICENSE").read_text(), "Apache License\n")


if __name__ == "__main__":
    unittest.main()
