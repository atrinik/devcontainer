"""Reject LLVM metadata that no longer proves the portable compile contract."""
import copy
import importlib.util
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
                                 "driver_output": f'"{command[0]}" "-cc1" "-target-cpu" "x86-64" "-tune-cpu" "generic" "-O2"\n'
                                 f'"{prefix}bin/ld.lld" "{self.value["runtime"]["path"]}" "-L/opt/llvm-23.1.3/lib" "-lunwind"\n'}

    def test_baseline_invocations(self):
        evidence.validate(self.value)

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


if __name__ == "__main__":
    unittest.main()
