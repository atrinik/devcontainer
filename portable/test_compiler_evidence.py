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
        fixture = Path(__file__).parent / "fixtures/llvm-readelf-23.1.3/debian-driver.json"
        self.value = json.loads(fixture.read_text())

    def mutate_invocation(self, value, index, extra):
        lines = value["compile"]["driver_output"].splitlines()
        quoted = [i for i, line in enumerate(lines) if line.strip().startswith('"')]
        lines[quoted[index]] += " " + extra
        value["compile"]["driver_output"] = "\n".join(lines) + "\n"

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

    def test_library_paths_allow_only_observed_raw_spellings(self):
        value = copy.deepcopy(self.value)
        value["compile"]["driver_output"] = value["compile"]["driver_output"].replace(
            '"-L/opt/llvm-23.1.3/bin/../lib"', '"-L/opt/llvm-23.1.3/lib" "-L" "/usr/local/lib"')
        evidence.validate(value)
        value["compile"]["driver_output"] = value["compile"]["driver_output"].replace(
            '"-L/opt/llvm-23.1.3/lib"', '"-L/tmp/foreign-link/../../opt/llvm-23.1.3/lib"')
        with self.assertRaisesRegex(ValueError, "foreign LLD library"):
            evidence.validate(value)

    def test_later_cpu_optimization_features_and_extra_subprocess_are_rejected(self):
        for extra in ('"-target-cpu" "x86-64-v3"', '"-tune-cpu" "native"',
                      '"-triple" "aarch64-linux-gnu"', '"-target-feature" "+avx2"',
                      '"-O0"', '"-O2"', '"-load" "/tmp/plugin.so"',
                      '"-include" "/tmp/foreign.h"'):
            value = copy.deepcopy(self.value)
            self.mutate_invocation(value, 0, extra)
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                evidence.validate(value)
        self.value["compile"]["driver_output"] += '\n"/tmp/subprocess" "--run"\n'
        with self.assertRaises(ValueError):
            evidence.validate(self.value)

    def test_foreign_linker_inputs_and_role_traversal_are_rejected(self):
        for extra in ('"-L/tmp/foreign-link/../../usr/lib"', '"/tmp/foreign.a"',
                      '"@/tmp/foreign.rsp"', '"--script=/tmp/foreign.ld"', '"-T" "/tmp/foreign.ld"',
                      '"-lc"', '"/tmp/foreign.o"'):
            value = copy.deepcopy(self.value)
            self.mutate_invocation(value, 1, extra)
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                evidence.validate(value)
        for role in evidence.IDENTITY_PATHS:
            value = copy.deepcopy(self.value)
            entry = value["tools"][role] if role in value["tools"] else value[role]
            original = entry["path"]
            entry["path"] = "/opt/llvm-23.1.3/../../tmp/foreign"
            value["compile"]["driver_output"] = value["compile"]["driver_output"].replace(original, entry["path"])
            with self.subTest(role=role), self.assertRaises(ValueError):
                evidence.validate(value)

    def test_probe_source_output_and_temporary_object_are_bound(self):
        for field in ("source_sha256", "command"):
            value = copy.deepcopy(self.value)
            if field == "source_sha256":
                value["compile"][field] = "0" * 64
            else:
                value["compile"][field][9] = "/tmp/foreign-output"
                value["compile"]["driver_command"] = [value["compile"][field][0], "-###", *value["compile"][field][1:]]
            with self.subTest(field=field), self.assertRaises(ValueError):
                evidence.validate(value)
        import shlex
        line = next(line for line in self.value["compile"]["driver_output"].splitlines() if '"-cc1"' in line)
        args = shlex.split(line)
        object_path = args[args.index("-o") + 1]
        lines = self.value["compile"]["driver_output"].splitlines()
        lines[-1] = lines[-1].replace(object_path, "/tmp/foreign.o")
        self.value["compile"]["driver_output"] = "\n".join(lines)
        with self.assertRaises(ValueError):
            evidence.validate(self.value)


if __name__ == "__main__":
    unittest.main()
