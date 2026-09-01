from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "install_classic_vulkan_toolchain",
    ROOT / "tools" / "install_classic_vulkan_toolchain.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def add_file(archive: tarfile.TarFile, name: str, content: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = mode
    archive.addfile(info, io.BytesIO(content))


class ClassicVulkanToolchainTests(unittest.TestCase):
    def test_loads_the_qualified_manifest(self) -> None:
        manifest = MODULE.load_manifest(ROOT / "classic-vulkan-toolchain.json")
        self.assertEqual(
            manifest["source"]["commit"],  # type: ignore[index]
            "60e95b787857afbc9a00b693b91c0d9c8923a430",
        )
        self.assertEqual(  # type: ignore[index]
            manifest["install"]["icd"],
            "/usr/share/vulkan/icd.d/dzn_icd.x86_64.json",
        )

    def test_rejects_a_different_mesa_archive_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            value = (ROOT / "classic-vulkan-toolchain.json").read_text(encoding="utf-8")
            path.write_text(
                value.replace(
                    "caf1c0061a68e88dfa74967a7e780c0e85d65b6c4e334cd69095a5dc54ad78bc",
                    "f" * 64,
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODULE.ToolchainError, "archive digest"):
                MODULE.load_manifest(path)

    def test_rejects_a_different_build_package_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            value = (ROOT / "classic-vulkan-toolchain.json").read_text(encoding="utf-8")
            path.write_text(
                value.replace("classic-vulkan-packages.lock", "other-packages.lock", 1),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODULE.ToolchainError, "package lock"):
                MODULE.load_manifest(path)

    def test_rejects_duplicate_json_keys(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as stream:
            stream.write('{"schema_version": 1, "schema_version": 1}\n')
            stream.flush()
            with self.assertRaisesRegex(MODULE.ToolchainError, "duplicate"):
                MODULE.load_manifest(Path(stream.name))

    def test_rejects_unsafe_archive_paths_and_links(self) -> None:
        for value in ("/etc/passwd", "root/../outside", "root\\outside", "root/\x00bad"):
            with self.subTest(value=value), self.assertRaisesRegex(
                MODULE.ToolchainError, "unsafe Mesa archive member"
            ):
                MODULE.safe_archive_path(value)
        with self.assertRaisesRegex(MODULE.ToolchainError, "escapes source root"):
            MODULE.normalize_link_target(
                MODULE.safe_archive_path("mesa-26.0.8/link"), "../../outside", "mesa-26.0.8"
            )

    def test_extracts_the_official_archive_shape_with_safe_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "mesa.tar.xz"
            with tarfile.open(archive_path, "w:xz") as archive:
                root = tarfile.TarInfo("mesa-26.0.8")
                root.type = tarfile.DIRTYPE
                archive.addfile(root)
                directory = tarfile.TarInfo("mesa-26.0.8/src")
                directory.type = tarfile.DIRTYPE
                archive.addfile(directory)
                add_file(archive, "mesa-26.0.8/VERSION", b"26.0.8\n")
                add_file(archive, "mesa-26.0.8/src/real.c", b"int main(void) {}\n")
                link = tarfile.TarInfo("mesa-26.0.8/src/alias.c")
                link.type = tarfile.SYMTYPE
                link.linkname = "real.c"
                archive.addfile(link)
                add_file(archive, "mesa-26.0.8/ignored.txt", b"ignored")
            destination = Path(temporary) / "source"
            MODULE.extract_source(
                archive_path,
                destination,
                {"archive_root": "mesa-26.0.8", "version": "26.0.8"},
            )
            self.assertEqual((destination / "VERSION").read_text(), "26.0.8\n")
            self.assertTrue((destination / "src/alias.c").is_symlink())
            self.assertEqual((destination / "src/alias.c").read_text(), "int main(void) {}\n")

    def test_installs_and_validates_only_declared_runtime_files(self) -> None:
        manifest = MODULE.load_manifest(ROOT / "classic-vulkan-toolchain.json")
        install = manifest["install"]
        assert isinstance(install, dict)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            stage = Path(temporary) / "stage"
            library = stage / "usr/lib/x86_64-linux-gnu/libvulkan_dzn.so"
            icd = stage / "usr/share/vulkan/icd.d/dzn_icd.x86_64.json"
            library.parent.mkdir(parents=True)
            icd.parent.mkdir(parents=True)
            library.write_bytes(b"driver")
            icd.write_text(
                json.dumps(
                    {
                        "ICD": {
                            "api_version": install["icd_api_version"],
                            "library_arch": "64",
                            "library_path": install["library"],
                        },
                        "file_format_version": "1.0.1",
                    }
                ),
                encoding="utf-8",
            )
            MODULE.install_runtime_files(manifest, stage, root)
            MODULE.validate_installed(manifest, root)
            self.assertEqual(
                (root / "usr/lib/x86_64-linux-gnu/libvulkan_dzn.so").read_bytes(),
                b"driver",
            )
            self.assertFalse((root / "usr/bin/spirv2dxil").exists())


if __name__ == "__main__":
    unittest.main()
