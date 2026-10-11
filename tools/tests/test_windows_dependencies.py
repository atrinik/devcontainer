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
            self.assertEqual(env["LD"], "ld.lld" if host else "/llvm/bin/x86_64-w64-mingw32-ld")
            self.assertEqual(env["OBJDUMP"], "llvm-objdump" if host else "/llvm/bin/x86_64-w64-mingw32-objdump")
            self.assertTrue(env["PATH"].startswith("/llvm/bin:/host/bin:"))
            self.assertEqual(env["PKG_CONFIG_PATH"], "")

    def test_target_cmake_is_fenced_to_toolchain(self):
        commands = BUILDER.commands({"build_system": "cmake"}, Path("/source"), Path("/build"), Path("/target"), 3)
        self.assertIn("-DCMAKE_TOOLCHAIN_FILE=/target/share/cmake/llvm-mingw.cmake", commands[0])
        self.assertEqual(commands[1][-2:], ["--parallel", "3"])
        host = BUILDER.commands({"build_system": "cmake"}, Path("/source"), Path("/build"), Path("/host"), 3, True)
        self.assertIn("-DCMAKE_C_COMPILER=clang", host[0])
        self.assertFalse(any("TOOLCHAIN_FILE" in arg for arg in host[0]))

    def test_libpng_keeps_original_shared_autotools_recipe(self):
        lock = BUILDER.load_lock(ROOT / "windows/dependencies.json")
        item = next(item for item in lock["dependencies"] if item["name"] == "libpng")
        recipe = BUILDER.commands(item, Path("/source"), Path("/build"), Path("/target"), 2)
        self.assertEqual(recipe[0][0], "/source/configure")
        self.assertIn("--enable-shared", recipe[0])
        self.assertIn("--disable-static", recipe[0])
        self.assertIn("--host=x86_64-w64-mingw32", recipe[0])
        for command in recipe[1:]:
            for override in ("bin_PROGRAMS=", "sbin_PROGRAMS=", "noinst_PROGRAMS="):
                self.assertIn(override, command)

    def test_libffi_uses_mingw_exports_without_elf_symbol_versions(self):
        lock = BUILDER.load_lock(ROOT / "windows/dependencies.json")
        item = next(item for item in lock["dependencies"] if item["name"] == "libffi")
        configure = BUILDER.commands(item, Path("/source"), Path("/build"), Path("/target"), 2)[0]
        self.assertIn("--host=x86_64-w64-mingw32", configure)
        self.assertIn("--enable-shared", configure)
        self.assertIn("--disable-static", configure)
        self.assertIn("--disable-symvers", configure)
        self.assertFalse(any(option.startswith("--disable-") and option != "--disable-symvers"
                             for option in item["options"]))

    def test_icu_config_alias_preserves_lookup_bytes_and_strict_scanner(self):
        item = next(item for item in BUILDER.load_lock(ROOT / "windows/dependencies.json")["dependencies"]
                    if item["name"] == "icu4c")
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary) / "prefix"
            target = prefix / "lib/icu/74.2"
            target.mkdir(parents=True)
            contents = {"Makefile.inc": b"# ICU configuration\nICU_VERSION=74.2\n",
                        "pkgdata.inc": b"# ICU package configuration\nCC=clang\n"}
            for name, data in contents.items():
                (target / name).write_bytes(data)
                (target.parent / name).symlink_to("current/" + name)
            (target.parent / "current").symlink_to("74.2")
            evidence = Path(temporary) / "evidence"
            evidence.mkdir()
            with self.assertRaisesRegex(ValueError, "unsafe symlink"):
                BUILDER.provider_paths(prefix)
            BUILDER.materialize_config_alias(item, prefix, evidence)
            current = target.parent / "current"
            self.assertFalse(current.is_symlink())
            self.assertEqual(current.stat().st_mode & 0o777, 0o755)
            report = json.loads((evidence / "config-directory-alias.json").read_text())
            self.assertEqual(report["original_target"], "74.2")
            for name, data in contents.items():
                for directory in (target, current, target.parent):
                    self.assertEqual((directory / name).read_bytes(), data)
                self.assertEqual((current / name).stat().st_mode & 0o777, 0o644)
                self.assertEqual((target.parent / name).readlink().as_posix(), "current/" + name)
                self.assertEqual(report["files"][name]["before_sha256"], report["files"][name]["after_sha256"])
            self.assertEqual(BUILDER.provider_paths(prefix), ({}, {}))

    def test_icu_config_alias_rejects_drift_without_mutating_inputs(self):
        item = next(item for item in BUILDER.load_lock(ROOT / "windows/dependencies.json")["dependencies"]
                    if item["name"] == "icu4c")
        cases = ("wrong-version", "external", "chained-target", "linked-parent", "linked-prefix",
                 "missing-file", "extra-file", "nested-directory", "linked-file", "normal-current",
                 "pe", "elf", "archive", "thin-archive", "nul", "invalid-utf8", "oversized", "empty")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                prefix = root / "prefix"
                target = prefix / "lib/icu/74.2"
                target.mkdir(parents=True)
                for name in item["sdk_config_alias"]["files"]:
                    (target / name).write_text("# normal ICU config\n")
                alias = target.parent / "current"
                alias.symlink_to("74.2")
                evidence = root / "evidence"
                evidence.mkdir()
                if case in {"wrong-version", "external"}:
                    alias.unlink()
                    alias.symlink_to("75.1" if case == "wrong-version" else str(target))
                elif case == "chained-target":
                    target.rename(target.with_name("real"))
                    target.symlink_to("real")
                elif case in {"linked-parent", "linked-prefix"}:
                    linked = target.parent if case == "linked-parent" else prefix
                    outside = root / "relocated"
                    linked.rename(outside)
                    linked.symlink_to(outside)
                elif case == "missing-file":
                    (target / "pkgdata.inc").unlink()
                elif case == "extra-file":
                    (target / "unexpected.dll").write_bytes(b"MZpayload")
                elif case == "nested-directory":
                    (target / "nested").mkdir()
                elif case == "linked-file":
                    (target / "Makefile.inc").unlink()
                    (target / "Makefile.inc").symlink_to("pkgdata.inc")
                elif case == "normal-current":
                    alias.unlink()
                    alias.mkdir()
                else:
                    data = {"pe": b"MZpayload", "elf": b"\x7fELFpayload", "archive": b"!<arch>\npayload",
                            "thin-archive": b"!<thin>\npayload", "nul": b"config\0data", "invalid-utf8": b"\xff",
                            "oversized": b"x" * (1024**2 + 1), "empty": b""}[case]
                    (target / "Makefile.inc").write_bytes(data)

                def snapshot():
                    return {path.relative_to(root).as_posix():
                            ("link", path.readlink().as_posix()) if path.is_symlink() else
                            ("file", path.read_bytes()) if path.is_file() else ("directory",)
                            for path in root.rglob("*")}

                before = snapshot()
                with self.assertRaises(ValueError):
                    BUILDER.materialize_config_alias(item, prefix, evidence)
                self.assertEqual(snapshot(), before)

    def test_icu_config_alias_contract_cannot_expand_to_other_paths_or_recipes(self):
        item = next(item for item in BUILDER.load_lock(ROOT / "windows/dependencies.json")["dependencies"]
                    if item["name"] == "icu4c")
        for key, value in (("path", "lib/current"), ("target", "../74.2"), ("files", ["Makefile.inc", "extra.dll"])):
            changed = json.loads(json.dumps(item))
            changed["sdk_config_alias"][key] = value
            with self.assertRaisesRegex(ValueError, "source-declared"):
                BUILDER.config_alias_contract(changed)
        for changed in ({**item, "name": "another-recipe"}, {**item, "host": True},
                        {key: value for key, value in item.items() if key != "sdk_config_alias"}):
            with self.assertRaises(ValueError):
                BUILDER.config_alias_contract(changed)

    def test_shared_configuration_requires_actual_resolved_settings(self):
        libtool = ("# ### BEGIN LIBTOOL CONFIG\nbuild_libtool_libs=yes\nbuild_old_libs=no\n# ### END LIBTOOL CONFIG\n"
                   "# ### BEGIN LIBTOOL TAG CONFIG: disable-shared\nbuild_libtool_libs=no\nbuild_old_libs=yes\n"
                   "# ### END LIBTOOL TAG CONFIG: disable-shared\n")
        formats = [("libpng", "libtool", libtool),
                   ("freetype", "builds/unix/libtool", libtool),
                   ("icu4c", "icudefs.mk", "ENABLE_SHARED = YES\nENABLE_STATIC =\n"),
                   ("sqlite", "Makefile", "ENABLE_LIB_SHARED = 1\nENABLE_LIB_STATIC = 0\n")]
        for name, relative, valid in formats:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                build, evidence = root / "build", root / "evidence"
                path = build / relative
                path.parent.mkdir(parents=True)
                evidence.mkdir()
                with self.assertRaisesRegex(ValueError, "missing"):
                    BUILDER.require_shared_configuration({"name": name}, build, evidence)
                path.write_text(valid)
                BUILDER.require_shared_configuration({"name": name}, build, evidence)
                self.assertEqual((evidence / "shared" / relative).read_text(), valid)
                for invalid in (valid.replace("=yes", "=no").replace("= YES", "= NO").replace("= 1", "= 0"),
                                valid.replace("=no", "=yes").replace("ENABLE_STATIC =", "ENABLE_STATIC = YES").replace("= 0", "= 1"),
                                valid.splitlines()[0] + "\n", valid + valid):
                    path.write_text(invalid)
                    with self.assertRaisesRegex(ValueError, "configuration absent"):
                        BUILDER.require_shared_configuration({"name": name}, build, evidence)

    def test_import_archive_must_identify_the_required_component_dll(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            (prefix / "bin").mkdir()
            (prefix / "lib").mkdir()
            evidence = prefix / "evidence"
            evidence.mkdir()
            dll = prefix / "bin/libpng16-16.dll"
            archive = prefix / "lib/libpng16.dll.a"
            item = {"name": "libpng", "shared_artifacts": [{"dll": "libpng16-*.dll", "import_library": archive.name}]}
            receipt = {"dlls": {}}
            with self.assertRaisesRegex(ValueError, "shared DLL absent"):
                BUILDER.require_shared_artifacts(item, prefix, Path("/llvm"), evidence, receipt)
            dll.write_bytes(b"actual DLL")
            receipt["dlls"][dll.name] = {"owner": "libpng", "sha256": BUILDER.file_hash(dll)}
            with self.assertRaisesRegex(ValueError, "import library absent"):
                BUILDER.require_shared_artifacts(item, prefix, Path("/llvm"), evidence, receipt)
            archive.write_bytes(b"archive bytes")
            for invalid in ("", "different.dll\n", "libpng16-16.dll\ndifferent.dll\n"):
                with patch.object(BUILDER.subprocess, "run", return_value=SimpleNamespace(stdout=invalid)):
                    with self.assertRaisesRegex(ValueError, "does not identify"):
                        BUILDER.require_shared_artifacts(item, prefix, Path("/llvm"), evidence, receipt)
            with patch.object(BUILDER.subprocess, "run", return_value=SimpleNamespace(stdout=dll.name + "\n")) as run:
                BUILDER.require_shared_artifacts(item, prefix, Path("/llvm"), evidence, receipt)
                self.assertEqual(run.call_args.args[0], ["/llvm/bin/llvm-dlltool", "-I", str(archive)])
                self.assertEqual(json.loads((evidence / "shared-artifacts.json").read_text())[0]["dll_sha256"], BUILDER.file_hash(dll))
            (prefix / "bin/libpng16-17.dll").write_bytes(b"ambiguous old DLL")
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                BUILDER.require_shared_artifacts(item, prefix, Path("/llvm"), evidence, receipt)

    def test_every_target_autotools_recipe_requires_shared_components(self):
        lock = BUILDER.load_lock(ROOT / "windows/dependencies.json")
        recipes = {item["name"]: item for item in lock["dependencies"]}
        self.assertEqual(len(recipes["libwebp"]["shared_artifacts"]), 5)
        self.assertEqual(len(recipes["icu4c"]["shared_artifacts"]), 5)
        self.assertEqual(len(recipes["pcre2"]["shared_artifacts"]), 3)
        for item in recipes.values():
            if item["build_system"] == "autotools" and not item.get("host"):
                self.assertTrue(item["shared_artifacts"])

    def test_full_freetype_cannot_reuse_bootstrap_runtime_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            (prefix / "bin").mkdir()
            dll = prefix / "bin/libfreetype-6.dll"
            dll.write_bytes(b"unchanged bootstrap runtime")
            item = {"name": "freetype", "shared_artifacts": [{"dll": dll.name, "import_library": "libfreetype.dll.a"}]}
            receipt = {"dlls": {dll.name: {"owner": "freetype-bootstrap", "sha256": BUILDER.file_hash(dll)}}}
            with self.assertRaisesRegex(ValueError, "not owned by this recipe"):
                BUILDER.require_shared_artifacts(item, prefix, Path("/llvm"), prefix, receipt)

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

    def test_archive_links_order_ownership_and_permissions_are_safe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "source.tar"
            with tarfile.open(archive, "w") as tar:
                hard = tarfile.TarInfo("source/hard")
                hard.type = tarfile.LNKTYPE
                hard.linkname = "source/plain"
                tar.addfile(hard)
                for name, mode in (("plain", 0o6666), ("configure", 0o6755)):
                    member = tarfile.TarInfo("source/" + name)
                    member.size = 7
                    member.uid = member.gid = 4242
                    member.uname = member.gname = "untrusted-owner"
                    member.mode = mode
                    member.mtime = 1234567890
                    tar.addfile(member, io.BytesIO(b"payload"))
                link = tarfile.TarInfo("source/link")
                link.type = tarfile.SYMTYPE
                link.linkname = "plain"
                tar.addfile(link)
            source = BUILDER.extract(archive, root / "unpack")
            self.assertEqual((source / "hard").read_bytes(), b"payload")
            self.assertEqual((source / "hard").stat().st_ino, (source / "plain").stat().st_ino)
            self.assertEqual((source / "link").read_bytes(), b"payload")
            self.assertEqual((source / "plain").stat().st_mode & 0o7777, 0o644)
            self.assertEqual((source / "configure").stat().st_mode & 0o7777, 0o755)
            self.assertEqual((source / "plain").stat().st_uid, BUILDER.os.getuid())
            self.assertEqual((source / "plain").stat().st_gid, BUILDER.os.getgid())
            self.assertEqual((source / "plain").stat().st_mtime, 1234567890)

    def test_archive_safe_framework_symlinks_and_repeated_expansion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "source.tar"
            with tarfile.open(archive, "w") as tar:
                for name in ("source/Versions/A/Headers/api.h", "source/Versions/A/Resources/info", "source/Versions/A/SDL3.tbd"):
                    member = tarfile.TarInfo(name)
                    member.size = 7
                    tar.addfile(member, io.BytesIO(b"payload"))
                for name, target in (("Versions/Current", "A"), ("Headers", "Versions/Current/Headers"),
                                     ("Resources", "Versions/Current/Resources"), ("SDL3.tbd", "Versions/Current/SDL3.tbd"),
                                     ("again", "."), ("repeated", "again/again/Headers/api.h"),
                                     ("limit", "again/" * 39 + "Versions/A/SDL3.tbd")):
                    member = tarfile.TarInfo("source/" + name)
                    member.type = tarfile.SYMTYPE
                    member.linkname = target
                    tar.addfile(member)
            source = BUILDER.extract(archive, root / "unpack")
            for name in ("Headers/api.h", "Resources/info", "SDL3.tbd", "repeated", "limit"):
                self.assertEqual((source / name).read_bytes(), b"payload")
            self.assertEqual(BUILDER.os.readlink(source / "Headers"), "Versions/Current/Headers")

    def test_archive_symbolic_resolution_rejects_escape_cycles_and_file_parents(self):
        def entry(name, kind=tarfile.SYMTYPE, target=""):
            member = tarfile.TarInfo("source/" + name)
            member.type, member.linkname = kind, target
            return member
        cases = [
            [entry("dir", tarfile.DIRTYPE), entry("dir/up", target=".."), entry("alias", target="dir/up/../..")],
            [entry("a", target="b"), entry("b", target="a")],
            [entry("file", tarfile.REGTYPE), entry("alias", target="file/../safe")],
            [entry("file", tarfile.REGTYPE), entry("alias", target="file/.")],
            [entry("file", tarfile.REGTYPE), entry("alias", target="file/")],
            [entry("r", target="."), entry("alias", target="r/" * 40 + "safe")],
            [entry("dir", tarfile.DIRTYPE), entry("dir/alias", target="../../outside")],
        ]
        for members in cases:
            with self.subTest(names=[member.name for member in members]), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "source.tar"
                with tarfile.open(archive, "w") as tar:
                    for member in members:
                        tar.addfile(member)
                destination = root / "unpack"
                with self.assertRaises(ValueError):
                    BUILDER.extract(archive, destination)
                self.assertFalse(destination.exists())

    def test_archive_duplicates_types_and_invalid_links_fail_before_writes(self):
        bad_records = []
        first = tarfile.TarInfo("source/file")
        bad_records.append([first, tarfile.TarInfo("source/file")])
        for kind in (tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE, b"Z"):
            special = tarfile.TarInfo("source/special")
            special.type = kind
            bad_records.append([special])
        link = tarfile.TarInfo("source/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "dir"
        chain = tarfile.TarInfo("source/chain")
        chain.type = tarfile.SYMTYPE
        chain.linkname = "link/../file"
        bad_records.append([link, chain, first])
        child = tarfile.TarInfo("source/link/child")
        bad_records.append([link, child])
        outside = tarfile.TarInfo("source/outside")
        outside.type = tarfile.SYMTYPE
        outside.linkname = "../../escape"
        bad_records.append([outside])
        hard = tarfile.TarInfo("source/hard")
        hard.type = tarfile.LNKTYPE
        hard.linkname = "source/missing"
        bad_records.append([hard])
        for members in bad_records:
            with self.subTest(types=[member.type for member in members]), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "source.tar"
                with tarfile.open(archive, "w") as tar:
                    for member in members:
                        tar.addfile(member)
                destination = root / "unpack"
                with self.assertRaises(ValueError):
                    BUILDER.extract(archive, destination)
                self.assertFalse(destination.exists())

    def test_archive_stale_or_linked_destinations_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "source.tar"
            with tarfile.open(archive, "w") as tar:
                directory = tarfile.TarInfo("source")
                directory.type = tarfile.DIRTYPE
                tar.addfile(directory)
            destination = root / "unpack"
            destination.mkdir()
            sentinel = destination / "sentinel"
            sentinel.write_text("preserved")
            with self.assertRaisesRegex(ValueError, "new or empty"):
                BUILDER.extract(archive, destination)
            self.assertEqual(sentinel.read_text(), "preserved")
            linked = root / "linked"
            linked.symlink_to(destination, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "new or empty"):
                BUILDER.extract(archive, linked)

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
