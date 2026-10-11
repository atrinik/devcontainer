#!/usr/bin/env python3
"""Seal and check the portable Clang/LLD/compiler-rt compile invocation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import posixpath
import re
import shlex
import shutil
import subprocess
import tempfile

VERSION = "23.1.3"
FLAGS = ["-O2", "-march=x86-64", "-mtune=generic", "--rtlib=compiler-rt",
         "--unwindlib=libunwind", "-fuse-ld=lld"]
SOURCE = "int main(void) { return 0; }\n"
# Exact spellings emitted by the Debian 12 driver, plus their canonical roots.
# Arbitrary traversal is unsafe even when normpath would reach an allowed root.
LIBRARY_DIRECTORIES = frozenset({
    "/opt/llvm-23.1.3/lib", "/usr/local/lib", "/usr/lib/gcc/x86_64-linux-gnu/12",
    "/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu", "/usr/lib64", "/lib64",
    "/usr/lib", "/lib", "/opt/llvm-23.1.3/bin/../lib",
    "/usr/lib/gcc/x86_64-linux-gnu/12/../../../../lib64", "/lib/../lib64",
})
CC1_EXECUTABLE = "/opt/llvm-23.1.3/bin/clang-23"
IDENTITY_PATHS = {
    "compiler": "/opt/llvm-23.1.3/bin/clang",
    "linker": "/opt/llvm-23.1.3/bin/ld.lld",
    "readelf": "/opt/llvm-23.1.3/bin/llvm-readelf",
    "runtime": "/opt/llvm-23.1.3/lib/clang/23/lib/linux/libclang_rt.builtins-x86_64.a",
    "unwinder": "/opt/llvm-23.1.3/lib/libunwind.a",
}


def cc1_command(source: str, object_path: str, directory: str) -> list[str]:
    """The observed header-free probe invocation, with only temporary paths varying."""
    return [CC1_EXECUTABLE, "-cc1", "-triple", "x86_64-unknown-linux-gnu", "-O2", "-emit-obj",
            "-dumpdir", source[:-2] + "-", "-disable-free", "-clear-ast-before-backend",
            "-disable-llvm-verifier", "-discard-value-names", "-main-file-name", "probe.c",
            "-mrelocation-model", "pic", "-pic-level", "2", "-pic-is-pie", "-mframe-pointer=none",
            "-fmath-errno", "-ffp-contract=on", "-fno-rounding-math", "-mconstructor-aliases",
            "-funwind-tables=2", "-target-cpu", "x86-64", "-tune-cpu", "generic", "-debugger-tuning=gdb",
            "-fdebug-compilation-dir=" + directory, "-fcoverage-compilation-dir=" + directory,
            "-resource-dir", "/opt/llvm-23.1.3/lib/clang/23",
            "-internal-isystem", "/opt/llvm-23.1.3/lib/clang/23/include",
            "-internal-isystem", "/usr/local/include", "-internal-isystem",
            "/usr/lib/gcc/x86_64-linux-gnu/12/../../../../x86_64-linux-gnu/include",
            "-internal-externc-isystem", "/usr/include/x86_64-linux-gnu",
            "-internal-externc-isystem", "/include", "-internal-externc-isystem", "/usr/include",
            "-ferror-limit", "19", "-fgnuc-version=4.2.1", "-fskip-odr-check-in-gmf",
            "-vectorize-loops", "-vectorize-slp", "-faddrsig", "-fdwarf2-cfi-asm",
            "-o", object_path, "-x", "c", source]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tool(name: str) -> dict:
    executable = shutil.which(name)
    if executable is None:
        raise ValueError(f"missing LLVM tool: {name}")
    path = Path(executable).absolute()
    version = subprocess.check_output([str(path), "--version"], text=True).strip()
    if VERSION not in version:
        raise ValueError(f"wrong LLVM tool version: {name}: {version}")
    return {"path": str(path), "sha256": digest(path), "version": version}


def validate(value: dict, *, installed: bool = False) -> None:
    """Require actual baseline cc1 and LLD invocations, including compiler-rt."""
    if value["schema_version"] != 2 or value["toolchain_version"] != VERSION or value["flags"] != FLAGS:
        raise ValueError("wrong portable compiler evidence contract")
    tools = value["tools"]
    if set(tools) != {"compiler", "linker", "readelf"}:
        raise ValueError("wrong LLVM tool identity roles")
    for role, expected in IDENTITY_PATHS.items():
        entry = tools[role] if role in tools else value[role]
        if entry["path"] != expected:
            raise ValueError("wrong pinned LLVM identity: " + role)
        if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError("invalid LLVM identity digest")
        if installed and digest(Path(expected)) != entry["sha256"]:
            raise ValueError("changed installed LLVM identity: " + expected)
    if any(VERSION not in entry["version"] for entry in tools.values()):
        raise ValueError("wrong installed LLVM version")
    command = value["compile"]["command"]
    if value["compile"]["driver_command"] != [command[0], "-###", *command[1:]]:
        raise ValueError("changed portable compiler driver command")
    if (len(command) != 10 or command[:7] != [tools["compiler"]["path"], *FLAGS]
            or command[8] != "-o" or not re.fullmatch(r"/tmp/portable-compiler-[a-z0-9_]+/probe\.c", command[7])
            or command[9] != command[7][:-2]
            or value["compile"]["source_sha256"] != hashlib.sha256(SOURCE.encode()).hexdigest()
            or value["target"] != "x86_64-unknown-linux-gnu"):
        raise ValueError("wrong portable compiler command or probe source")
    lines = [shlex.split(line) for line in value["compile"]["driver_output"].splitlines()
             if line.strip().startswith('"')]
    if len(lines) != 2 or lines[0][0] != CC1_EXECUTABLE or lines[1][0] != tools["linker"]["path"]:
        raise ValueError("missing actual Clang/LLD invocation or foreign Clang cc1 executable")
    compiler, linker = lines
    if installed and Path(tools["compiler"]["path"]).resolve() != Path(CC1_EXECUTABLE):
        raise ValueError("Clang driver does not resolve to pinned cc1 executable")
    if any(arg.startswith(("-flto", "-mavx", "-march=native", "-mcpu=")) for arg in compiler):
        raise ValueError("nonportable compiler invocation")
    if compiler.count("-o") != 1 or compiler.index("-o") + 1 == len(compiler):
        raise ValueError("wrong cc1 object output")
    object_path = compiler[compiler.index("-o") + 1]
    directories = [arg.split("=", 1)[1] for arg in compiler if arg.startswith("-fdebug-compilation-dir=")]
    if (len(directories) != 1 or not directories[0].startswith("/")
            or not re.fullmatch(r"/tmp/probe-[a-z0-9]+\.o", object_path)
            or compiler != cc1_command(command[7], object_path, directories[0])):
        raise ValueError("changed portable cc1 invocation")
    prefix = [tools["linker"]["path"], "--hash-style=gnu", "--eh-frame-hdr", "-m", "elf_x86_64",
              "-pie", "-dynamic-linker", "/lib64/ld-linux-x86-64.so.2", "-o", command[9],
              "/lib/x86_64-linux-gnu/Scrt1.o", "/lib/x86_64-linux-gnu/crti.o",
              "/opt/llvm-23.1.3/lib/clang/23/lib/linux/clang_rt.crtbegin-x86_64.o"]
    if linker[:len(prefix)] != prefix:
        raise ValueError("changed portable LLD invocation")
    index = len(prefix)
    library_directories = []
    while index < len(linker):
        arg = linker[index]
        if arg in {"-L", "--library-path"}:
            index += 1
            if index == len(linker):
                raise ValueError("missing LLD library directory")
            directory = linker[index]
        elif arg.startswith("-L"):
            directory = arg[2:]
        elif arg.startswith("--library-path="):
            directory = arg.split("=", 1)[1]
        else:
            break
        if directory not in LIBRARY_DIRECTORIES:
            raise ValueError("foreign LLD library directory")
        library_directories.append(posixpath.normpath(directory))
        index += 1
    if "/opt/llvm-23.1.3/lib" not in library_directories:
        raise ValueError("LLVM runtime library directory missing from LLD invocation")
    runtime = value["runtime"]["path"]
    suffix = [object_path, runtime, "--as-needed", "-lunwind", "--no-as-needed", "-lc", runtime,
              "--as-needed", "-lunwind", "--no-as-needed",
              "/opt/llvm-23.1.3/lib/clang/23/lib/linux/clang_rt.crtend-x86_64.o",
              "/lib/x86_64-linux-gnu/crtn.o"]
    if linker[index:] != suffix:
        raise ValueError("changed portable LLD inputs or runtime selection")


def record() -> dict:
    tools = {key: tool(name) for key, name in
             {"compiler": "clang", "linker": "ld.lld", "readelf": "llvm-readelf"}.items()}
    runtime = Path(subprocess.check_output(
        [tools["compiler"]["path"], "--rtlib=compiler-rt", "--print-libgcc-file-name"], text=True).strip()).resolve()
    with tempfile.TemporaryDirectory(prefix="portable-compiler-") as temp:
        source, binary = Path(temp) / "probe.c", Path(temp) / "probe"
        source.write_text(SOURCE)
        command = [tools["compiler"]["path"], *FLAGS, str(source), "-o", str(binary)]
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True)
        driver_command = [command[0], "-###", *command[1:]]
        result = subprocess.run(driver_command, text=True, capture_output=True, check=True)
        value = {"schema_version": 2, "toolchain_version": VERSION, "flags": FLAGS,
                 "target": subprocess.check_output([command[0], "-dumpmachine"], text=True).strip(),
                 "tools": tools, "runtime": {"path": str(runtime), "sha256": digest(runtime)},
                 "unwinder": {"path": "/opt/llvm-23.1.3/lib/libunwind.a",
                              "sha256": digest(Path("/opt/llvm-23.1.3/lib/libunwind.a"))},
                 "compile": {"command": command, "driver_command": driver_command,
                             "driver_output": result.stdout + result.stderr,
                             "source_sha256": digest(source), "output_sha256": digest(binary)}}
    validate(value, installed=True)
    return value


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify:
        validate(json.loads(args.verify.read_text()), installed=True)
    else:
        print(json.dumps(record(), indent=2))
