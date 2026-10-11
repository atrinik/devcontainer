# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("windows_dependencies", ROOT / "windows/build-dependencies.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class WindowsDependenciesTests(unittest.TestCase):
    def test_locked_sources_are_ordered_and_complete(self):
        lock = BUILDER.load_lock(ROOT / "windows/dependencies.json")
        entries = {item["name"]: item for item in lock["dependencies"]}
        for name, version in (("curl", "8.21.0"), ("c-ares", "1.34.6"), ("openssl", "3.5.5")):
            self.assertEqual(entries[name]["version"], version)
        self.assertTrue({"sdl3", "sdl3-image", "sdl3-ttf", "libxml2", "miniupnpc"}.issubset(entries))
        options = entries["curl"]["options"]
        self.assertIn("--disable-threaded-resolver", options)
        self.assertIn("--enable-ares={prefix}", options)
        self.assertIn("--with-openssl={prefix}", options)
        for feature in ("--with-nghttp2", "--with-libidn2", "--with-libpsl", "--with-brotli", "--with-zstd"):
            self.assertIn(feature, options)

    def test_compiler_environments_are_llvm_only(self):
        for host in (True, False):
            env = BUILDER.environment(Path("/target"), Path("/host"), Path("/llvm"), host)
            self.assertEqual(env["CC"], "clang" if host else "x86_64-w64-mingw32-clang")
            self.assertEqual(env["CXX"], "clang++" if host else "x86_64-w64-mingw32-clang++")
            self.assertEqual(env["AR"], "llvm-ar")
            self.assertEqual(env["LD"], "ld.lld")
            self.assertTrue(env["PATH"].startswith("/llvm/bin:/host/bin:"))
            self.assertEqual(env["PKG_CONFIG_PATH"], "")

    def test_target_cmake_is_fenced_to_toolchain(self):
        commands = BUILDER.commands({"build_system": "cmake"}, Path("/source"), Path("/build"), Path("/target"), 3)
        self.assertIn("-DCMAKE_TOOLCHAIN_FILE=/target/share/cmake/llvm-mingw.cmake", commands[0])
        self.assertEqual(commands[1][-2:], ["--parallel", "3"])
        host = BUILDER.commands({"build_system": "cmake"}, Path("/source"), Path("/build"), Path("/host"), 3, True)
        self.assertIn("-DCMAKE_C_COMPILER=clang", host[0])
        self.assertFalse(any("TOOLCHAIN_FILE" in arg for arg in host[0]))

    def test_checksum_mismatch_prevents_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            (cache / "source.tar.gz").write_bytes(b"untrusted")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                BUILDER.verified_archive({"name": "bad", "archive": "source.tar.gz", "sha256": "0" * 64}, cache)

    def test_archive_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "source.tar"
            with tarfile.open(archive, "w") as tar:
                entry = tarfile.TarInfo("../outside")
                entry.size = 1
                tar.addfile(entry, io.BytesIO(b"x"))
            with self.assertRaisesRegex(ValueError, "unsafe"):
                BUILDER.extract(archive, root / "source")
            self.assertFalse((root / "outside").exists())

    def test_host_cross_bootstrap_and_feature_cycle(self):
        lock = BUILDER.load_lock(ROOT / "windows/dependencies.json")
        entries = {item["name"]: item for item in lock["dependencies"]}
        self.assertTrue(entries["host-icu4c"]["host"])
        self.assertIn("host-icu4c", entries["icu4c"]["depends"])
        self.assertIn("--with-cross-build={work}/build/host-icu4c", entries["icu4c"]["options"])
        self.assertIn("freetype-bootstrap", entries["harfbuzz"]["depends"])
        self.assertIn("harfbuzz", entries["freetype"]["depends"])
        for feature in ("-Dcairo=enabled", "-Dglib=enabled", "-Dicu=enabled", "-Dfreetype=enabled"):
            self.assertIn(feature, entries["harfbuzz"]["options"])
        self.assertIn("-DSDLIMAGE_TIF=OFF", entries["sdl3-image"]["options"])
        for item in lock["dependencies"]:
            self.assertNotIn("gcc", " ".join(item.get("environment", {}).values()))
            self.assertNotIn("-lstdc++", " ".join(item.get("options", [])))

    def test_pe_verification_rejects_legacy_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            (prefix / "bin").mkdir()
            for name in ("SDL3.dll", "SDL3_image.dll", "SDL3_ttf.dll"):
                (prefix / "bin" / name).touch()
            notice = prefix / "share/licenses/test/COPYING"
            notice.parent.mkdir(parents=True)
            notice.write_text("test notice")
            receipt = {"schema_version": 1,
                "dlls": {name: {"sha256": BUILDER.file_hash(prefix / "bin" / name), "owner": "test", "source_sha256": "a" * 64}
                         for name in ("SDL3.dll", "SDL3_image.dll", "SDL3_ttf.dll")},
                "notices": {"test": {"test/COPYING": BUILDER.file_hash(notice)}}}
            BUILDER.ownership_path(prefix).parent.mkdir(parents=True)
            BUILDER.save_ownership(prefix, receipt)
            lock = {"dependencies": [{"name": "test", "sha256": "a" * 64}], "runtime_providers": {}}
            output = "Machine: IMAGE_FILE_MACHINE_AMD64\nImport {\n  Name: ucrtbase.dll\n}\n"
            with patch.object(BUILDER.subprocess, "run", return_value=SimpleNamespace(stdout=output)):
                self.assertEqual(len(BUILDER.verify(prefix, Path("/llvm"), lock)["dlls"]), 3)
            with patch.object(BUILDER.subprocess, "run", return_value=SimpleNamespace(stdout=output + "Import {\n  Name: missing-provider.dll\n}\n")):
                with self.assertRaisesRegex(ValueError, "unresolved"):
                    BUILDER.verify(prefix, Path("/llvm"), lock)
            for bad in ("msvcrt.dll", "libgcc_s_seh-1.dll", "libstdc++-6.dll", "libssp-0.dll"):
                with patch.object(BUILDER.subprocess, "run", return_value=SimpleNamespace(stdout=output + "Import {\n  Name: " + bad + "\n}\n")):
                    with self.assertRaisesRegex(ValueError, "runtime"):
                        BUILDER.verify(prefix, Path("/llvm"), lock)

    def test_runtime_ownership_detects_bytes_and_notice_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            dll = prefix / "bin/test.dll"
            dll.parent.mkdir()
            dll.write_bytes(b"built dependency")
            notice = prefix / "share/licenses/test/COPYING"
            notice.parent.mkdir(parents=True)
            notice.write_text("upstream notice")
            receipt = {"schema_version": 1, "dlls": {dll.name: {"sha256": BUILDER.file_hash(dll)}},
                       "notices": {"test": {"test/COPYING": BUILDER.file_hash(notice)}}}
            BUILDER.assert_receipt(prefix, receipt)
            (prefix / "bin/unowned.dll").touch()
            with self.assertRaisesRegex(ValueError, "unowned"):
                BUILDER.assert_receipt(prefix, receipt)
            (prefix / "bin/unowned.dll").unlink()
            notice.write_text("replacement notice")
            with self.assertRaisesRegex(ValueError, "notice"):
                BUILDER.assert_receipt(prefix, receipt)
            notice.write_text("upstream notice")
            dll.write_bytes(b"replacement binary")
            with self.assertRaisesRegex(ValueError, "changed"):
                BUILDER.assert_receipt(prefix, receipt)

    def test_meson_recipe_flags_reach_configuration(self):
        lock = BUILDER.load_lock(ROOT / "windows/dependencies.json")
        entries = {item["name"]: item for item in lock["dependencies"]}
        for name, option, expected in (("cairo", "c_args", "-Wno-incompatible-pointer-types"),
                                       ("libpsl", "c_link_args", "-liconv")):
            item = entries[name]
            env = BUILDER.environment(Path("/target"), Path("/host"), Path("/llvm"))
            env.update({key: value.replace("{prefix}", "/target") for key, value in item["environment"].items()})
            setup = BUILDER.commands(item, Path("/source"), Path("/work/build") / name, Path("/target"), 2, env=env)[0]
            value = next(argument.split("=", 1)[1] for argument in setup if argument.startswith("-D" + option + "="))
            self.assertIn(expected, json.loads(value))
        self.assertIn("-Os", entries["sqlite"]["environment"]["CFLAGS"].split())
        self.assertNotIn("-O2", entries["sqlite"]["environment"]["CFLAGS"].split())

    def test_emitted_meson_release_commands_preserve_original_optimization(self):
        lock = BUILDER.load_lock(ROOT / "windows/dependencies.json")
        output = io.StringIO()
        with redirect_stdout(output):
            BUILDER.run(lock, Path("/target"), Path("/work"), Path("/llvm"), 2, True)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        recipes = {item["name"]: item for item in lock["dependencies"]}
        for row in rows:
            item = recipes[row["dependency"]]
            if item["build_system"] == "meson":
                self.assertNotIn("-O2", row["environment"]["CFLAGS"].split())
                self.assertNotIn("-O2", row["environment"]["CXXFLAGS"].split())
                if row["command"][:2] == ["meson", "setup"]:
                    self.assertIn("--buildtype=release", row["command"])
                    for flag in row["command"]:
                        if flag.startswith(("-Dc_args=", "-Dcpp_args=")):
                            self.assertFalse(any(arg.startswith("-O") for arg in json.loads(flag.split("=", 1)[1])))
            elif item["build_system"] == "autotools":
                expected = "-Os" if item["name"] == "sqlite" else "-O2"
                self.assertIn(expected, row["environment"]["CFLAGS"].split())
        cairo = next(row for row in rows if row["dependency"] == "cairo")
        self.assertEqual(cairo["environment"]["CFLAGS"], "-Wno-incompatible-pointer-types")
        libpsl = next(row for row in rows if row["dependency"] == "libpsl")
        self.assertIn("-liconv", libpsl["environment"]["LDFLAGS"].split())

    def test_meson_quoted_flags_keep_argument_boundaries(self):
        args = BUILDER.meson_flags({"CPPFLAGS": '-I"/target directory/include"', "CFLAGS": "-O2 -Wno-incompatible-pointer-types",
                                    "LDFLAGS": "-L/target/lib -liconv"})
        values = {argument.split("=", 1)[0]: json.loads(argument.split("=", 1)[1]) for argument in args}
        self.assertIn("-I/target directory/include", values["-Dc_args"])
        self.assertIn("-liconv", values["-Dcpp_link_args"])

    def test_every_import_name_is_resolved_or_rejected(self):
        self.assertEqual(BUILDER.parse_imports("Import {\n Name: WINSPOOL.drv\n}\n"), {"winspool.drv"})
        self.assertEqual(BUILDER.parse_imports("DelayImport {\n Name: private-provider.pyd\n}\n"), {"private-provider.pyd"})
        for malformed in ("Import {\n Name: ../outside.dll\n}\n", "Import {\n Name: a.dll\n Name: b.dll\n}\n",
                          "Import {\n Name: a.dll\n", "Name: private.pyd\n"):
            with self.assertRaisesRegex(ValueError, "import"):
                BUILDER.parse_imports(malformed)

    def test_actual_llvm_delay_import_symbol_rows_are_not_providers(self):
        output = (ROOT / "tools/tests/fixtures/llvm23-wmi-coff-imports.txt").read_text()
        imports = BUILDER.parse_imports(output)
        self.assertIn("ole32.dll", imports)
        self.assertIn("python314.dll", imports)
        self.assertNotIn("CoCreateInstance", imports)
        for malformed in ("DelayImport {\n Name: a.dll\n Import {\n Name: hidden.dll\n }\n}\n",
                          "Import {\n Name: a.dll\n Import {\n Symbol: hidden\n }\n}\n"):
            with self.assertRaisesRegex(ValueError, "import"):
                BUILDER.parse_imports(malformed)

    def test_nested_modules_are_owned_and_inspected(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            for relative in ("bin/SDL3.dll", "bin/SDL3_image.dll", "bin/SDL3_ttf.dll", "lib/ossl-modules/legacy.dll", "bin/engines/capi.dll"):
                path = prefix / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative.encode())
            notice = prefix / "share/licenses/test/COPYING"
            notice.parent.mkdir(parents=True)
            notice.write_text("notice")
            receipt = {"schema_version": 1, "dlls": {}, "modules": {},
                       "notices": {"test": {"test/COPYING": BUILDER.file_hash(notice)}}}
            for kind, paths in zip(("dlls", "modules"), BUILDER.provider_paths(prefix)):
                receipt[kind] = {name: {"sha256": BUILDER.file_hash(path), "owner": "test", "source_sha256": "a" * 64}
                                 for name, path in paths.items()}
            BUILDER.ownership_path(prefix).parent.mkdir(parents=True)
            BUILDER.save_ownership(prefix, receipt)
            lock = {"dependencies": [{"name": "test", "sha256": "a" * 64}], "runtime_providers": {}}
            valid = "Machine: IMAGE_FILE_MACHINE_AMD64\nImport {\n Name: ucrtbase.dll\n}\n"
            with patch.object(BUILDER.subprocess, "run", return_value=SimpleNamespace(stdout=valid)) as inspect:
                result = BUILDER.verify(prefix, Path("/llvm"), lock)
                self.assertEqual(inspect.call_count, 5)
                self.assertEqual(set(result["modules"]), {"lib/ossl-modules/legacy.dll", "bin/engines/capi.dll"})
            with patch.object(BUILDER.subprocess, "run", return_value=SimpleNamespace(stdout=valid + "Import {\n Name: private-provider.pyd\n}\n")):
                with self.assertRaisesRegex(ValueError, "unresolved"):
                    BUILDER.verify(prefix, Path("/llvm"), lock)
            (prefix / "lib/ossl-modules/unowned.dll").touch()
            with self.assertRaisesRegex(ValueError, "unowned PE module"):
                BUILDER.assert_receipt(prefix, receipt)
            (prefix / "lib/ossl-modules/unowned.dll").unlink()
            (prefix / "lib/ossl-modules/legacy.dll").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "changed"):
                BUILDER.assert_receipt(prefix, receipt)

    def test_linked_provider_directories_and_roots_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix = root / "prefix"
            (prefix / "lib").mkdir(parents=True)
            outside = root / "outside"
            outside.mkdir()
            (outside / "unowned.dll").write_bytes(b"unowned provider")
            (prefix / "lib/ossl-modules").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                BUILDER.provider_paths(prefix)
            (prefix / "lib/ossl-modules").unlink()
            (prefix / "bin").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "provider root"):
                BUILDER.provider_paths(prefix)

    def test_internal_sdk_file_aliases_cannot_hide_dlls(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            (prefix / "lib/pkgconfig").mkdir(parents=True)
            real = prefix / "lib/pkgconfig/libpng16.pc"
            real.write_text("prefix=/target")
            alias = prefix / "lib/pkgconfig/libpng.pc"
            alias.symlink_to(real.name)
            self.assertEqual(BUILDER.provider_paths(prefix), ({}, {}))
            real.write_bytes(b"runtime")
            real.rename(real.with_suffix(".dll"))
            alias.unlink()
            alias.symlink_to("libpng16.dll")
            with self.assertRaisesRegex(ValueError, "unsafe symlink"):
                BUILDER.provider_paths(prefix)

    def test_resolved_configuration_is_retained_and_required_backends_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build, destination = root / "build", root / "receipt"
            build.mkdir()
            destination.mkdir()
            (build / "CMakeCache.txt").write_text("SDLTTF_HARFBUZZ:BOOL=ON")
            (destination / "command-0.log").write_text("-- SDL3_ttf backends:\n-- - enabled:  freetype harfbuzz\n-- - disabled: plutosvg\n")
            BUILDER.retain_configuration({"name": "sdl3-ttf"}, build, destination)
            self.assertEqual((destination / "CMakeCache.txt").read_text(), "SDLTTF_HARFBUZZ:BOOL=ON")
            (destination / "command-0.log").write_text("-- SDL3_ttf backends:\n-- - enabled: freetype\n")
            with self.assertRaisesRegex(ValueError, "required resolved backends"):
                BUILDER.retain_configuration({"name": "sdl3-ttf"}, build, destination)

    def test_invalid_graph_and_pins_fail_closed(self):
        item = {"name": "curl", "archive": "curl.tar.gz", "sha256": "a" * 64, "url": "https://example.test/source", "licenses": ["COPYING"],
                "license": "curl", "build_system": "autotools", "depends": ["missing"]}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            path.write_text(json.dumps({"schema_version": 1, "dependencies": [item]}))
            with self.assertRaisesRegex(ValueError, "precede"):
                BUILDER.load_lock(path)
            item["depends"] = []
            item["sha256"] = "mutable"
            path.write_text(json.dumps({"schema_version": 1, "dependencies": [item]}))
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                BUILDER.load_lock(path)


if __name__ == "__main__":
    unittest.main()
