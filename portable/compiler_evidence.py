#!/usr/bin/env python3
"""Seal and check the portable Clang/LLD/compiler-rt compile invocation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import posixpath
import shlex
import shutil
import subprocess
import tempfile

VERSION = "23.1.3"
FLAGS = ["-O2", "-march=x86-64", "-mtune=generic", "--rtlib=compiler-rt",
         "--unwindlib=libunwind", "-fuse-ld=lld"]
SOURCE = "int main(void) { return 0; }\n"
# Exact native search roots observed with the sealed Debian 12/LLVM cohort.
# Normalize the driver's bin/../lib and GCC multilib spellings without using
# the validating host's unrelated filesystem symlinks.
LIBRARY_DIRECTORIES = frozenset({
    "/opt/llvm-23.1.3/lib", "/usr/local/lib", "/usr/lib/gcc/x86_64-linux-gnu/12",
    "/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu", "/usr/lib64", "/lib64",
    "/usr/lib", "/lib",
})
CC1_EXECUTABLE = "/opt/llvm-23.1.3/bin/clang-23"


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
    command = value["compile"]["command"]
    if command[0] != tools["compiler"]["path"] or command[1:1 + len(FLAGS)] != FLAGS:
        raise ValueError("wrong portable compiler command")
    if value["compile"]["driver_command"] != [command[0], "-###", *command[1:]]:
        raise ValueError("changed portable compiler driver command")
    lines = [shlex.split(line) for line in value["compile"]["driver_output"].splitlines()
             if line.strip().startswith('"')]
    compilers = [line for line in lines if "-cc1" in line]
    linkers = [line for line in lines if line and line[0] == tools["linker"]["path"]]
    if len(compilers) != 1 or len(linkers) != 1:
        raise ValueError("missing actual Clang/LLD invocation")
    compiler = compilers[0]
    if compiler[0] != CC1_EXECUTABLE:
        raise ValueError("foreign Clang cc1 executable")
    if installed and Path(tools["compiler"]["path"]).resolve() != Path(CC1_EXECUTABLE):
        raise ValueError("Clang driver does not resolve to pinned cc1 executable")
    for option, expected in (("-target-cpu", "x86-64"), ("-tune-cpu", "generic")):
        if option not in compiler or compiler[compiler.index(option) + 1] != expected:
            raise ValueError(f"wrong portable CPU invocation: {option}")
    for line in [command, *lines]:
        if any(arg.startswith(("-flto", "-mavx", "-march=native", "-mcpu=")) for arg in line):
            raise ValueError("nonportable compiler invocation")
    if "-O2" not in compiler or any(arg in {"-O3", "-Ofast", "-Oz", "-Os"} for arg in compiler):
        raise ValueError("wrong portable optimization")
    if value["runtime"]["path"] not in linkers[0]:
        raise ValueError("compiler-rt missing from LLD invocation")
    if any("libgcc.a" in arg or arg in {"-lgcc", "-lgcc_s"} for arg in linkers[0]):
        raise ValueError("GNU compiler builtins selected")
    directories = []
    linker = linkers[0]
    index = 1
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
            index += 1
            continue
        if not directory.startswith("/") or "$" in directory:
            raise ValueError("invalid LLD library directory")
        directory = posixpath.normpath(directory)
        if directory not in LIBRARY_DIRECTORIES:
            raise ValueError("foreign LLD library directory")
        directories.append(directory)
        index += 1
    if "/opt/llvm-23.1.3/lib" not in directories:
        raise ValueError("LLVM runtime library directory missing from LLD invocation")
    if not any(arg in {"-lunwind", value["unwinder"]["path"]} for arg in linkers[0]):
        raise ValueError("LLVM unwinder missing from LLD invocation")
    for entry in [*tools.values(), value["runtime"], value["unwinder"]]:
        path = Path(entry["path"])
        if not path.is_absolute() or not str(path).startswith("/opt/llvm-23.1.3/"):
            raise ValueError("LLVM identity outside pinned prefix")
        if len(entry["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in entry["sha256"]):
            raise ValueError("invalid LLVM identity digest")
        if installed and digest(path) != entry["sha256"]:
            raise ValueError(f"changed installed LLVM identity: {path}")
    if not Path(value["runtime"]["path"]).name.startswith("libclang_rt.builtins-"):
        raise ValueError("wrong compiler runtime identity")
    if any(VERSION not in entry["version"] for entry in tools.values()):
        raise ValueError("wrong installed LLVM version")


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
