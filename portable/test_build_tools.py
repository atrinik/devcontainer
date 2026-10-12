"""Producer receipts reject replaced code before probing or configuring it."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("build_tools", Path(__file__).with_name("build_tools.py"))
tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tools)


def installed_fixture():
    versions = {"cmake": "cmake version 3.25.1\n\nCMake suite maintained and supported by Kitware (kitware.com/cmake).\n",
                "ninja": "1.11.1\n", "pkg_config": "1.8.1\n"}
    return {"tools": {role: version.splitlines()[0] for role, version in versions.items()},
            "build_tools": {"schema_version": 1, "tools": {
                role: {"path": path, "resolved_path": path,
                       "sha256": hashlib.sha256(role.encode()).hexdigest(), "size": len(role),
                       "executable": True, "version": versions[role]}
                for role, path in tools.PATHS.items()}}}


class SchemaTests(unittest.TestCase):
    def test_complete_receipt(self):
        tools.validate(installed_fixture())

    def test_missing_receipt_is_actionable(self):
        with self.assertRaisesRegex(ValueError, "rebuild the portable SDK"):
            tools.validate({"tools": {"cmake": "cmake version 3.25.1", "ninja": "1.11.1"}})

    def test_strict_fields_roles_and_types(self):
        for value in (None, [], True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                tools.validate(value)
        mutations = [
            lambda v: v["build_tools"].update(extra=True),
            lambda v: v["build_tools"].update(schema_version=True),
            lambda v: v["build_tools"].update(schema_version=2),
            lambda v: v["build_tools"].update(tools=[]),
            lambda v: v["build_tools"]["tools"].pop("ninja"),
            lambda v: v["build_tools"]["tools"].pop("pkg_config"),
            lambda v: v["build_tools"]["tools"].update(ctest={}),
            lambda v: v.update(tools=[]),
        ]
        for mutate in mutations:
            value = installed_fixture()
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                tools.validate(value)
        changes = {"path": ["cmake", "/usr/local/bin/cmake", "/usr/bin/../bin/cmake"],
                   "resolved_path": ["relative", "/usr/bin/../bin/cmake", "//usr/bin/cmake", "/", None],
                   "sha256": ["x" * 64, "A" * 64, None], "size": [True, "5", 0, -1, tools.MAX_BINARY_SIZE + 1],
                   "executable": [False, 1, "true"], "version": ["", None, "wrong\n", "cmake version 3.25.1\r\n",
                                                                "cmake version 3.25.1\n\tcontrol\n", "cmake version 3.25.1\n\x7f"]}
        for field, values in changes.items():
            for replacement in values:
                value = installed_fixture()
                value["build_tools"]["tools"]["cmake"][field] = replacement
                with self.subTest(field=field, replacement=replacement), self.assertRaises(ValueError):
                    tools.validate(value)
        for role in tools.PATHS:
            value = installed_fixture()
            value["build_tools"]["tools"][role]["extra"] = True
            with self.subTest(role=role), self.assertRaises(ValueError):
                tools.validate(value)
            del value["build_tools"]["tools"][role]["extra"]
            value["tools"][role] += " changed"
            with self.subTest(role=role), self.assertRaises(ValueError):
                tools.validate(value)

    def test_every_required_entry_field(self):
        for field in tools.FIELDS:
            value = installed_fixture()
            del value["build_tools"]["tools"]["ninja"][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                tools.validate(value)


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="build-tools-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / "execution.log"
        self.paths = {}
        for role, version in (("cmake", "cmake version 3.25.1\n\ncomplete banner\n"), ("ninja", "1.11.1\n"),
                              ("pkg_config", "1.8.1\n")):
            path = self.root / role
            path.write_text("#!/usr/bin/python3\nimport sys\nfrom pathlib import Path\n"
                            f"with Path({str(self.log)!r}).open('a') as log: log.write({role!r} + ' ' + repr(sys.argv[1:]) + '\\n')\n"
                            f"if sys.argv[1:] == ['--version']: sys.stdout.write({version!r})\n"
                            "elif sys.argv[1:2] == ['--modversion']: sys.stdout.write('1.2.3\\n')\n")
            path.chmod(0o755)
            self.paths[role] = str(path)
        # A test-owned tree intentionally has a consumer UID and writable /tmp
        # ancestors. Bypass only OS ownership policy, retaining actual fd hashes,
        # resolution, stats, subprocesses and all admission/fencing behavior.
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(tools, "PATHS", self.paths).start()
        mock.patch.object(tools, "_protected_path", side_effect=lambda p: p.resolve(strict=True)).start()
        mock.patch.object(tools, "_identity", side_effect=self.fixture_identity).start()
        self.receipt = tools.record()
        self.installed = {"build_tools": self.receipt,
                          "tools": {role: item["version"].splitlines()[0]
                                    for role, item in self.receipt["tools"].items()}}
        self.log.unlink()

    @staticmethod
    def fixture_identity(fd):
        info = os.fstat(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        return info, digest.hexdigest()

    def test_record_actual_bytes_and_full_stdout_and_run_fixed_tool(self):
        for role, path in self.paths.items():
            item = self.receipt["tools"][role]
            self.assertEqual(item["sha256"], hashlib.sha256(Path(path).read_bytes()).hexdigest())
            self.assertEqual(item["size"], Path(path).stat().st_size)
            self.assertEqual(item["resolved_path"], str(Path(path).resolve()))
            self.assertTrue(item["version"].endswith("\n"))
        tools.verify(self.installed, role="cmake", arguments=["-S", "fixture", "-G", "Ninja"])
        self.assertEqual(self.log.read_text().splitlines(), ["cmake ['--version']", "ninja ['--version']",
                                                            "pkg_config ['--version']",
                                                            "cmake ['-S', 'fixture', '-G', 'Ninja']"])

    def test_changed_tool_or_size_rejected_before_any_probe(self):
        for role in self.paths:
            for field, change in (("sha256", "0" * 64), ("size", 1234), ("resolved_path", "/different")):
                value = copy.deepcopy(self.installed)
                value["build_tools"]["tools"][role][field] = change
                message = "invalid canonical" if field == "resolved_path" else "changed installed"
                with self.subTest(role=role, field=field), self.assertRaisesRegex(ValueError, message):
                    tools.verify(value, role="cmake", arguments=["--configure"])
                self.assertFalse(self.log.exists())

    def test_replaced_bytes_fail_before_version_or_configure(self):
        path = Path(self.paths["ninja"])
        path.write_bytes(path.read_bytes() + b"# changed bytes\n")
        with self.assertRaisesRegex(ValueError, "changed installed"):
            tools.verify(self.installed, role="cmake", arguments=["--configure"])
        self.assertFalse(self.log.exists())

    def test_missing_pkgconf_role_rejects_old_receipt_before_any_execution(self):
        value = copy.deepcopy(self.installed)
        del value["build_tools"]["tools"]["pkg_config"]
        with self.assertRaisesRegex(ValueError, "schema or roles"):
            tools.capture(value, "pkg_config", ["--modversion", "fixture"])
        self.assertFalse(self.log.exists())

    def test_replaced_pkgconf_bytes_fail_before_any_version_or_module_query(self):
        path = Path(self.paths["pkg_config"])
        path.write_bytes(path.read_bytes() + b"# changed pkgconf bytes\n")
        with self.assertRaisesRegex(ValueError, "changed installed"):
            tools.capture(self.installed, "pkg_config", ["--modversion", "fixture"])
        self.assertFalse(self.log.exists())

    def test_curl_consumer_changed_pkgconf_is_rejected_before_any_probe(self):
        import curl_evidence

        manifest = self.root / "curl-toolchain.json"
        manifest.write_text(json.dumps({"cares_manifest": "classic-curl-toolchain.json",
                                        "prefix": "/usr/local", "version": "7.88.1"}))
        (self.root / "classic-curl-toolchain.json").write_text(json.dumps({"cares": {"version": "1.34.6"}}))
        retained = self.root / "sources/curl"
        retained.mkdir(parents=True)
        (retained / "curl_config.h").write_text("#define USE_ARES 1\n")
        path = Path(self.paths["pkg_config"])
        path.write_bytes(path.read_bytes() + b"# changed before curl probe\n")
        with mock.patch.object(curl_evidence, "load_installed", return_value=self.installed) as loader, \
                mock.patch.object(curl_evidence, "capture", side_effect=tools.capture), \
                self.assertRaisesRegex(ValueError, "changed installed"):
            curl_evidence.record(manifest)
        loader.assert_called_once_with(self.root / "installed.json")
        self.assertFalse(self.log.exists())

    def test_module_query_uses_admitted_pkgconf_with_complete_stdout(self):
        self.assertEqual(tools.capture(self.installed, "pkg_config", ["--modversion", "fixture"]), "1.2.3\n")
        self.assertEqual(self.log.read_text().splitlines(), ["cmake ['--version']", "ninja ['--version']",
                                                            "pkg_config ['--version']",
                                                            "pkg_config ['--modversion', 'fixture']"])

    def test_module_query_mutation_is_fenced_including_failure(self):
        original = tools.subprocess.check_output
        for failed in (False, True):
            path = Path(self.paths["pkg_config"])
            before = path.read_bytes()

            def mutate_query(*args, **kwargs):
                if args[0][1:] == ["--modversion", "fixture"]:
                    path.write_bytes(before + b"# changed during module query\n")
                    if failed:
                        raise tools.subprocess.CalledProcessError(1, args[0])
                    return b"1.2.3\n"
                return original(*args, **kwargs)

            with self.subTest(failed=failed), mock.patch.object(tools.subprocess, "check_output", side_effect=mutate_query), \
                    self.assertRaisesRegex(ValueError, "changed across execution"):
                tools.capture(self.installed, "pkg_config", ["--modversion", "fixture"])
            path.write_bytes(before)

    def test_full_stdout_mismatch_fails_before_configure(self):
        value = copy.deepcopy(self.installed)
        value["build_tools"]["tools"]["cmake"]["version"] = "cmake version 3.25.1\n\nchanged later line\n"
        with self.assertRaisesRegex(ValueError, "changed installed producer build tool version"):
            tools.verify(value, role="cmake", arguments=["--configure"])
        self.assertEqual(self.log.read_text().splitlines(), ["cmake ['--version']"])

    def test_inode_replacement_during_probe_is_fenced(self):
        original = tools.subprocess.check_output

        def replace_after_probe(*args, **kwargs):
            version = original(*args, **kwargs)
            path = Path(self.paths["cmake"])
            replacement = path.with_suffix(".replacement")
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o755)
            replacement.replace(path)
            return version

        with mock.patch.object(tools.subprocess, "check_output", side_effect=replace_after_probe), \
                self.assertRaisesRegex(ValueError, "changed across execution"):
            tools.verify(self.installed, role="cmake", arguments=["--configure"])
        self.assertEqual(self.log.read_text().splitlines(), ["cmake ['--version']"])

    def test_mutation_during_configure_is_fenced(self):
        original = tools.subprocess.run

        def mutate_after_configure(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[0][1:] == ["--configure"]:
                path = Path(self.paths["ninja"])
                path.write_bytes(path.read_bytes() + b"# changed during configure\n")
            return result

        with mock.patch.object(tools.subprocess, "run", side_effect=mutate_after_configure), \
                self.assertRaisesRegex(ValueError, "changed across execution"):
            tools.verify(self.installed, role="cmake", arguments=["--configure"])

    def test_failed_configure_still_fences_mutation(self):
        original = tools.subprocess.run

        def fail_configure(*args, **kwargs):
            if args[0][1:] == ["--configure"]:
                path = Path(self.paths["ninja"])
                path.write_bytes(path.read_bytes() + b"# mutated failed configure\n")
                raise tools.subprocess.CalledProcessError(1, args[0])
            return original(*args, **kwargs)

        with mock.patch.object(tools.subprocess, "run", side_effect=fail_configure), \
                self.assertRaisesRegex(ValueError, "changed across execution"):
            tools.verify(self.installed, role="cmake", arguments=["--configure"])


class ProtectionTests(unittest.TestCase):
    def test_unprivileged_or_writable_files_fail_before_hashing(self):
        with tempfile.TemporaryFile() as file:
            original = os.fstat(file.fileno())
            for mode, uid in ((stat.S_IFREG | 0o755, 1000), (stat.S_IFREG | 0o775, 0),
                              (stat.S_IFREG | 0o644, 0), (stat.S_IFIFO | 0o755, 0),
                              (stat.S_IFREG | 0o4755, 0), (stat.S_IFREG | 0o2755, 0)):
                values = list(original)
                values[0], values[4], values[6] = mode, uid, 1
                with self.subTest(mode=mode, uid=uid), mock.patch.object(tools.os, "fstat", return_value=os.stat_result(values)), \
                        mock.patch.object(tools.os, "read") as read, self.assertRaises(ValueError):
                    tools._identity(file.fileno())
                read.assert_not_called()

    def test_protected_regular_executable_positive(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "regular"
            path.write_bytes(b"test-owned executable bytes")
            path.chmod(0o555)
            original_lstat, original_fstat = Path.lstat, os.fstat

            def protected_info(info):
                values = list(info)
                values[0], values[4] = info.st_mode & ~0o022, 0
                return os.stat_result(values)

            # Root ownership is modeled in a test-owned tree. Directory/file
            # traversal, opening, regular mode, size and bytes remain real.
            with mock.patch.object(tools.Path, "lstat", side_effect=lambda p: protected_info(original_lstat(p)), autospec=True), \
                    mock.patch.object(tools.os, "fstat", side_effect=lambda fd: protected_info(original_fstat(fd))):
                resolved = tools._protected_path(path)
                self.assertEqual(resolved, path.resolve(strict=True))
                fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    info, digest = tools._identity(fd)
                    self.assertEqual(info.st_size, len(resolved.read_bytes()))
                    self.assertEqual(digest, hashlib.sha256(resolved.read_bytes()).hexdigest())
                finally:
                    os.close(fd)

    def test_intermediate_symlink_expansion_cannot_skip_writable_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            trusted, untrusted = root / "trusted", root / "untrusted"
            trusted.mkdir()
            untrusted.mkdir()
            untrusted.chmod(0o777)
            real = trusted / "real"
            real.write_text("fixture")
            real.chmod(0o755)
            (trusted / "cmake").symlink_to(untrusted / "hop")
            (untrusted / "hop").symlink_to(real)
            original = Path.lstat
            seen = []

            def trusted_ancestor_info(path):
                info = original(path)
                seen.append(path)
                # Model root-owned protected fixture ancestors only. Keep the
                # actual writable intermediate directory's ownership/mode.
                if path == untrusted:
                    return info
                values = list(info)
                values[0], values[4] = info.st_mode & ~0o022, 0
                return os.stat_result(values)

            with mock.patch.object(tools.Path, "lstat", side_effect=trusted_ancestor_info, autospec=True):
                self.assertEqual(tools._protected_path(real), real)
                seen.clear()
                with self.assertRaisesRegex(ValueError, "symlink in installed build tool path"):
                    tools._protected_path(trusted / "cmake")
                self.assertIn(trusted / "cmake", seen)
                self.assertNotIn(real, seen)

    def test_parent_symlink_cannot_redirect_a_regular_tool_or_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "real").mkdir()
            (root / "real/tool").write_bytes(b"fixture")
            (root / "parent").symlink_to(root / "real", target_is_directory=True)
            original_lstat = Path.lstat

            def protected_info(path):
                info = original_lstat(path)
                values = list(info)
                values[0], values[4] = info.st_mode & ~0o022, 0
                return os.stat_result(values)

            with mock.patch.object(tools.Path, "lstat", side_effect=protected_info, autospec=True), \
                    self.assertRaisesRegex(ValueError, "symlink in installed build tool path"):
                tools._protected_path(root / "parent/tool")

    def test_consumer_owned_tree_is_not_protected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "executable"
            path.write_text("fixture")
            path.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "unprotected"):
                tools._protected_path(path)

    def test_consumer_uses_receipt_runner_for_configure_and_build(self):
        source = Path(__file__).with_name("consumer.sh").read_text()
        self.assertEqual(source.count('--run cmake --'), 2)
        self.assertNotIn('/usr/bin/cmake ', source)
        self.assertIn('-DCMAKE_MAKE_PROGRAM=/usr/bin/ninja', source)
        self.assertIn('-DPKG_CONFIG_EXECUTABLE=/usr/bin/pkgconf', source)
        self.assertLess(source.index('build_tools.py'), source.index('"${root}/smoke.sh"'))
        inventory = Path(__file__).with_name("inventory.py").read_text()
        self.assertIn('"build_tools": build_tools', inventory)
        self.assertNotIn('["cmake", "--version"]', inventory)
        self.assertNotIn('["ninja", "--version"]', inventory)
        self.assertIn('capture(producer_installed, "pkg_config", ["--modversion", name])', inventory)
        self.assertNotIn('output("pkg-config"', inventory)
        smoke = Path(__file__).with_name("smoke.sh").read_text()
        self.assertIn('--run pkg_config --', smoke)
        self.assertNotIn('$(pkg-config ', smoke)
        curl = Path(__file__).with_name("curl_evidence.py").read_text()
        self.assertNotIn('["pkg-config"', curl)
        self.assertEqual(curl.count('capture(installed, "pkg_config"'), 3)


class MetadataTests(unittest.TestCase):
    def test_protected_loader_rejects_consumer_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "installed.json"
            path.write_text(json.dumps(installed_fixture()))
            with self.assertRaisesRegex(ValueError, "unprotected"):
                tools.load_installed(path)

    def test_metadata_duplicates_and_invalid_types_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "installed.json"
            original_fstat, original_stat = os.fstat, Path.stat

            def root_info(info):
                values = list(info)
                values[4] = 0
                return os.stat_result(values)

            with mock.patch.object(tools, "_protected_path", side_effect=lambda p: p), \
                    mock.patch.object(tools.os, "fstat", side_effect=lambda fd: root_info(original_fstat(fd))), \
                    mock.patch.object(tools.Path, "stat", side_effect=lambda p: root_info(original_stat(p)), autospec=True):
                path.write_text(json.dumps(installed_fixture()))
                self.assertEqual(tools.load_installed(path), installed_fixture())
                for payload in ('{"build_tools": {}, "build_tools": {}}',
                                '{"build_tools": {"tools": {"cmake": {"path": "a", "path": "b"}}}}'):
                    path.write_text(payload)
                    with self.subTest(payload=payload), self.assertRaisesRegex(ValueError, "duplicate"):
                        tools.load_installed(path)
                path.write_text("[]")
                with self.assertRaisesRegex(ValueError, "metadata object"):
                    tools.verify(tools.load_installed(path))

    def test_cli_preserves_configure_argument_boundary(self):
        with mock.patch.object(tools, "load_installed", return_value=installed_fixture()), \
                mock.patch.object(tools, "verify") as verify, \
                mock.patch("sys.argv", ["build_tools.py", "--verify", "/installed.json", "--run", "cmake",
                                        "--", "-S", "/source with spaces", "-G", "Ninja"]):
            tools.main()
        self.assertEqual(verify.call_args.kwargs, {"role": "cmake", "arguments": ["-S", "/source with spaces", "-G", "Ninja"]})


if __name__ == "__main__":
    unittest.main()
