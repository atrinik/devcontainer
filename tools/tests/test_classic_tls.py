from __future__ import annotations

import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location("classic_tls_build", ROOT / "linux/tls/build.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ClassicTLSTests(unittest.TestCase):
    def test_manifest_matches_consumer_metadata(self):
        manifest = MODULE.load_manifest(ROOT / "linux/tls/manifest.json")
        for name in ("classic-toolchain.json", "toolchains.json"):
            metadata = json.loads((ROOT / name).read_text())["classic_tls"]
            self.assertEqual(metadata["prefix"], manifest["prefix"])
            self.assertEqual(metadata["openssl"], manifest["openssl"]["version"])
            self.assertEqual(metadata["libcurl"], manifest["curl"]["version"])
            self.assertEqual(metadata["required_api"], manifest["required_api"])

    def test_rejects_manifest_contract_changes(self):
        base = json.loads((ROOT / "linux/tls/manifest.json").read_text())
        changes = (("prefix", "/usr"), ("providers", ["default"]),
                   ("required_api", "SSL_get_rbio"), ("required_curl_features", []),
                   ("platform", "linux/arm64"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            for key, value in changes:
                manifest = copy.deepcopy(base)
                manifest[key] = value
                path.write_text(json.dumps(manifest))
                with self.subTest(key=key), self.assertRaises(MODULE.ToolchainError):
                    MODULE.load_manifest(path)
            for key, value in (("url", "https://example.org/source"), ("sha256", "bad"),
                               ("version", "4.0.3;false"), ("license", "unknown")):
                manifest = copy.deepcopy(base)
                manifest["openssl"][key] = value
                path.write_text(json.dumps(manifest))
                with self.subTest(key=key), self.assertRaises(MODULE.ToolchainError):
                    MODULE.load_manifest(path)

    def test_rejects_duplicate_manifest_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaises(MODULE.ToolchainError):
                MODULE.load_manifest(path)

    def archive(self, path, members, compression="gz"):
        with tarfile.open(path, "w:" + compression) as archive:
            for name, kind in members:
                info = tarfile.TarInfo(name)
                info.mode = 0o755
                if kind == "file":
                    info.size = 4
                    archive.addfile(info, io.BytesIO(b"test"))
                else:
                    info.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE,
                                 "fifo": tarfile.FIFOTYPE, "directory": tarfile.DIRTYPE}[kind]
                    info.linkname = "../../outside"
                    archive.addfile(info)

    def test_extracts_both_source_formats_and_executable_modes(self):
        for compression in ("gz", "xz"):
            with self.subTest(compression=compression), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "source.tar"
                destination = Path(tmp) / "output"
                self.archive(path, [("source", "directory"), ("source/configure", "file")], compression)
                MODULE.extract(path, destination, "source")
                self.assertEqual((destination / "configure").read_bytes(), b"test")
                self.assertEqual((destination / "configure").stat().st_mode & 0o777, 0o755)

    def test_rejects_unsafe_members(self):
        cases = [[(name, kind)] for name, kind in (
            ("source/../outside", "file"), ("/source/absolute", "file"),
            ("wrong/file", "file"), ("source/link", "symlink"),
            ("source/link", "hardlink"), ("source/fifo", "fifo"), ("source", "file"))]
        cases += [[("source/File", "file"), ("source/file", "file")],
                  [("source/file", "file"), ("source/file", "file")]]
        for members in cases:
            with self.subTest(members=members), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "source.tar"
                self.archive(path, members)
                with self.assertRaises(MODULE.ToolchainError):
                    MODULE.extract(path, Path(tmp) / "output", "source")
                self.assertFalse((Path(tmp) / "outside").exists())


if __name__ == "__main__":
    unittest.main()
