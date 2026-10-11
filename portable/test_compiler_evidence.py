"""Reject LLVM metadata that no longer proves the portable compile contract."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("compiler_evidence", Path(__file__).with_name("compiler_evidence.py"))
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class CompilerEvidence(unittest.TestCase):
    def setUp(self):
        prefix = "/opt/llvm-23.1.3/"
        self.value = {"schema_version": 2, "toolchain_version": "23.1.3", "flags": evidence.FLAGS,
                      "tools": {name: {"path": prefix + "bin/" + command, "version": "LLVM 23.1.3", "sha256": "a" * 64}
                                for name, command in {"compiler": "clang", "linker": "ld.lld", "readelf": "llvm-readelf"}.items()},
                      "runtime": {"path": prefix + "lib/clang/23/lib/linux/libclang_rt.builtins-x86_64.a", "sha256": "b" * 64},
                      "unwinder": {"path": prefix + "lib/libunwind.a", "sha256": "c" * 64}}
        command = [prefix + "bin/clang", *evidence.FLAGS, "/tmp/probe.c", "-o", "/tmp/probe"]
        self.value["compile"] = {"command": command, "driver_command": [command[0], "-###", *command[1:]],
                                 "driver_output": f'"{evidence.CC1_EXECUTABLE}" "-cc1" "-target-cpu" "x86-64" "-tune-cpu" "generic" "-O2"\n'
                                 f'"{prefix}bin/ld.lld" "{self.value["runtime"]["path"]}" "-L/opt/llvm-23.1.3/lib" "-lunwind"\n'}

    def test_baseline_invocations(self):
        evidence.validate(self.value)

    def test_actual_frozen_debian_clang_driver(self):
        fixture = Path(__file__).parent / "fixtures/llvm-readelf-23.1.3/debian-driver.json"
        evidence.validate(json.loads(fixture.read_text()))

    def test_changed_command_cpu_optimization_and_linker_are_rejected(self):
        for old, new in (("x86-64", "x86-64-v2"), ("generic", "native"), ("-O2", "-O3"),
                         ("bin/ld.lld", "bin/ld"), ("-lunwind", "-lgcc_s"),
                         ("libclang_rt.builtins-x86_64.a", "libgcc.a")):
            value = copy.deepcopy(self.value)
            value["compile"]["driver_output"] = value["compile"]["driver_output"].replace(old, new)
            with self.subTest(new=new), self.assertRaises(ValueError):
                evidence.validate(value)

    def test_lto_and_noncohort_identity_are_rejected(self):
        value = copy.deepcopy(self.value)
        value["compile"]["driver_output"] = value["compile"]["driver_output"].replace('"-cc1"', '"-cc1" "-flto=full"')
        with self.assertRaisesRegex(ValueError, "nonportable"):
            evidence.validate(value)
        for field in ("path", "sha256", "version"):
            value = copy.deepcopy(self.value)
            value["tools"]["readelf"][field] = {"path": "/usr/bin/readelf", "sha256": "bad", "version": "LLVM 14.0.6"}[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                evidence.validate(value)

    def test_compile_command_and_driver_command_must_agree(self):
        self.value["compile"]["command"].append("-flto=thin")
        with self.assertRaisesRegex(ValueError, "driver command"):
            evidence.validate(self.value)

    def test_foreign_cc1_executable_is_rejected(self):
        self.value["compile"]["driver_output"] = self.value["compile"]["driver_output"].replace(
            evidence.CC1_EXECUTABLE, "/tmp/foreign-clang")
        with self.assertRaisesRegex(ValueError, "foreign Clang cc1"):
            evidence.validate(self.value)

    def test_every_library_directory_is_checked(self):
        for option in ('"-L/tmp/foreign"', '"-L" "/tmp/foreign"',
                       '"--library-path=/tmp/foreign"', '"--library-path" "/tmp/foreign"',
                       '"-L/usr/local/lib/foreign"', '"-Lrelative"', '"-L$ORIGIN"', '"-L"'):
            value = copy.deepcopy(self.value)
            value["compile"]["driver_output"] = value["compile"]["driver_output"].rstrip() + " " + option + "\n"
            with self.subTest(option=option), self.assertRaises(ValueError):
                evidence.validate(value)

    def test_authentic_debian_driver_multilib_paths_and_sdk_prefix(self):
        value = copy.deepcopy(self.value)
        value["compile"]["driver_output"] = value["compile"]["driver_output"].rstrip() + (
            ' "-L/opt/llvm-23.1.3/bin/../lib" "-L/usr/lib/gcc/x86_64-linux-gnu/12"'
            ' "-L/usr/lib/gcc/x86_64-linux-gnu/12/../../../../lib64" "-L/lib/x86_64-linux-gnu"'
            ' "-L/lib/../lib64" "-L/usr/lib/x86_64-linux-gnu" "-L/usr/lib64" "-L/lib" "-L/usr/lib"'
            ' "-L" "/usr/local/lib"\n')
        evidence.validate(value)


if __name__ == "__main__":
    unittest.main()
