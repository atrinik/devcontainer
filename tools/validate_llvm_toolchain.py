#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify installed LLVM identity, runtime selection and real compiler outputs."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def output(command: list[str]) -> str:
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)


def validate(manifest_path: Path, prefix: Path) -> None:
    manifest = json.loads(manifest_path.read_text())
    version = manifest["version"]
    installed = prefix / manifest["metadata"]["manifest"]
    if installed.read_bytes() != manifest_path.read_bytes():
        raise RuntimeError("installed LLVM inventory differs")
    if version != "23.1.3" or manifest["defaults"] != {
        "runtime":"compiler-rt", "unwind":"libunwind", "linker":"lld", "unwind_linkage":"static"}:
        raise RuntimeError("unexpected LLVM cohort")
    for name in manifest["tools"]:
        executable = prefix / "bin" / name
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise RuntimeError(f"missing LLVM executable: {name}")
        if Path(shutil.which(name) or "/missing").resolve() != executable.resolve():
            raise RuntimeError(f"PATH does not select cohort {name}")
        if not re.search(r"\b" + re.escape(version) + r"\b", output([str(executable), "--version"])):
            raise RuntimeError(f"LLVM executable identity mismatch: {name}")
    archive = prefix / manifest["metadata"]["source_archive"]
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != manifest["source"]["sha256"]:
            raise RuntimeError("LLVM corresponding source checksum differs")
    builtins = output([str(prefix / "bin/clang"), "--print-libgcc-file-name"]).strip()
    if not Path(builtins).is_file() or not str(Path(builtins).resolve()).startswith(str(prefix.resolve()) + "/") or "clang_rt.builtins" not in builtins:
        raise RuntimeError("Clang selected an external compiler runtime")
    if not (prefix / "lib/libunwind.a").is_file():
        raise RuntimeError("LLVM static libunwind is unavailable")
    with tempfile.TemporaryDirectory(prefix="llvm-smoke-") as temporary:
        work = Path(temporary)
        source = work / "probe.c"
        source.write_text("#include <stdio.h>\nint main(void) { puts(\"LLVM\"); return 0; }\n")
        command = [str(prefix / "bin/clang"), "-std=c17", str(source), "-o", str(work / "probe")]
        driver = output(command + ["-###"])
        if "ld.lld" not in driver or "clang_rt.builtins" not in driver or '"-lunwind"' not in driver:
            raise RuntimeError("Clang driver did not select LLD/compiler-rt/libunwind")
        if '"-lgcc"' in driver or '"-lgcc_s"' in driver:
            raise RuntimeError("Clang driver selected GNU compiler runtimes")
        subprocess.run(command, check=True)
        subprocess.run([str(work / "probe")], check=True)
        cpp = work / "exception.cpp"
        cpp.write_text(
            "#include <vector>\n#include <string>\n"
            "#ifdef _LIBCPP_VERSION\n#error unexpected libc++ provider\n#endif\n"
            "int main() { std::vector<std::string> words{\"LLVM\"}; "
            "try { throw words.at(0); } catch (const std::string& value) { return value != \"LLVM\"; } }\n")
        cpp_driver = output([str(prefix / "bin/clang++"), str(cpp), "-o", str(work / "exception"), "-###"])
        if '\"-lstdc++\"' not in cpp_driver or '\"-lc++\"' in cpp_driver:
            raise RuntimeError("Clang++ did not select the distribution libstdc++ provider")
        subprocess.run([str(prefix / "bin/clang++"), str(cpp), "-o", str(work / "exception")], check=True)
        subprocess.run([str(work / "exception")], check=True)
        # Exercise LLVM instrumentation and the actual coverage readers. Tool
        # presence/version alone cannot establish usable profile runtimes.
        covered = work / "covered"
        subprocess.run([str(prefix / "bin/clang"), "-fprofile-instr-generate", "-fcoverage-mapping", str(source), "-o", str(covered)], check=True)
        raw = work / "coverage.profraw"
        subprocess.run([str(covered)], env={**os.environ, "LLVM_PROFILE_FILE":str(raw)}, check=True)
        profile = work / "coverage.profdata"
        subprocess.run([str(prefix / "bin/llvm-profdata"), "merge", "-sparse", str(raw), "-o", str(profile)], check=True)
        report = json.loads(output([str(prefix / "bin/llvm-cov"), "export", str(covered), f"-instr-profile={profile}"]))
        if report["data"][0]["totals"]["lines"]["covered"] < 1:
            raise RuntimeError("LLVM coverage did not observe executed source")
    print(f"LLVM {version}: compiler, LLD, compiler-rt, libunwind and coverage verified")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, required=True)
    args = parser.parse_args()
    validate(args.manifest, args.prefix)


if __name__ == "__main__":
    main()
