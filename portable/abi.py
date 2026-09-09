#!/usr/bin/env python3
"""Verify actual ELF providers, versioned symbols, loader closure and ISA notes."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent
DEFAULT_DIRS = [Path("/usr/local/lib"), Path("/lib/x86_64-linux-gnu"), Path("/usr/lib/x86_64-linux-gnu"), Path("/lib64")]


def output(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def symbols(text: str) -> tuple[set[str], set[str]]:
    defined, required = set(), set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].rstrip(":").isdigit():
            continue
        _, _, _, _, binding, visibility, index, name = fields[:8]
        if index == "UND" and binding == "GLOBAL":
            required.add(name.replace("@@", "@"))
        elif index != "UND" and visibility in {"DEFAULT", "PROTECTED"}:
            defined.add(name.replace("@@", "@"))
            if "@@" in name or "@" not in name:
                defined.add(name.split("@", 1)[0])
    return defined, required


def elf(path: Path) -> dict:
    header = output("readelf", "-h", str(path))
    if "Advanced Micro Devices X86-64" not in header or "ELF64" not in header:
        raise ValueError(f"wrong ELF target: {path}")
    notes = output("readelf", "-n", str(path))
    for isa in re.findall(r"x86 ISA needed: ([^\n]+)", notes):
        if isa.strip() != "x86-64-baseline":
            raise ValueError(f"newer CPU ISA required: {path}: {isa}")
    dynamic = output("readelf", "-d", str(path))
    needed = re.findall(r"\(NEEDED\).*\[([^\]]+)\]", dynamic)
    paths = []
    for value in re.findall(r"\((?:RUNPATH|RPATH)\).*\[([^\]]*)\]", dynamic):
        for item in value.split(":"):
            item = item.replace("${ORIGIN}", str(path.parent)).replace("$ORIGIN", str(path.parent))
            if not item.startswith("/") or "$" in item:
                raise ValueError(f"unsupported loader search path: {path}: {item}")
            paths.append(Path(item))
    versions = output("readelf", "--version-info", str(path))
    provider = None
    version_providers = {}
    in_needs = False
    for line in versions.splitlines():
        if line.startswith("Version needs section"):
            in_needs = True
        if not in_needs:
            continue
        match = re.search(r"File: (\S+)", line)
        if match:
            provider = match[1]
        match = re.search(r"Name: (\S+)", line)
        if match and provider:
            version = match[1]
            version_providers[version] = provider
            if version.startswith("GLIBC_") and version != "GLIBC_PRIVATE":
                value = version.removeprefix("GLIBC_")
                if value[0].isdigit() and tuple(map(int, value.split("."))) > (2, 36):
                    raise ValueError(f"newer glibc requirement: {path}: {version}")
    defined, required = symbols(output("readelf", "--dyn-syms", "--wide", str(path)))
    return dict(needed=needed, paths=paths, defined=defined, required=required,
                version_providers=version_providers)


def resolve(name: str, paths: list[Path]) -> Path:
    if "/" in name:
        raise ValueError(f"non-SONAME ELF dependency: {name}")
    for directory in [*paths, *DEFAULT_DIRS]:
        path = directory / name
        if path.is_file():
            resolved = path.resolve()
            if not any(resolved.is_relative_to(root) for root in [Path("/usr/local/lib"), Path("/usr/lib"), Path("/lib").resolve()]):
                raise ValueError(f"provider outside baseline roots: {resolved}")
            return resolved
    raise ValueError(f"missing baseline ELF provider: {name}")


def audit(roots: list[Path]) -> dict:
    graph = {}
    pending = list(roots)
    while pending:
        path = pending.pop().resolve()
        if path in graph:
            continue
        value = elf(path)
        value["providers"] = {name: resolve(name, value["paths"]) for name in value["needed"]}
        graph[path] = value
        pending.extend(value["providers"].values())
    exports = set().union(*(value["defined"] for value in graph.values()))
    for path, value in graph.items():
        for symbol in value["required"]:
            if "@" in symbol:
                version = symbol.split("@", 1)[1]
                provider = value["version_providers"].get(version)
                resolved = value["providers"].get(provider)
                if resolved is None or symbol not in graph[resolved]["defined"]:
                    raise ValueError(f"unmet versioned provider symbol: {path}: {symbol}: {provider}")
            elif symbol not in exports:
                raise ValueError(f"unresolved application symbol: {path}: {symbol}")
    # The baseline's actual loader also checks its search/order and relocations.
    for path in roots:
        result = subprocess.run(["ldd", "-r", str(path)], text=True, capture_output=True)
        text = result.stdout + result.stderr
        if result.returncode or "not found" in text or "undefined symbol:" in text:
            raise ValueError(f"baseline relocation check failed: {path}: {text}")
    return {"schema_version": 1, "glibc": "2.36", "cpu": "x86-64",
            "roots": [str(p) for p in roots], "objects": [
                {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                 "needed": {name: str(provider) for name, provider in value["providers"].items()},
                 "required_symbols": sorted(value["required"])}
                for path, value in sorted(graph.items())]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("elf", type=Path, nargs="*")
    args = parser.parse_args()
    contract = json.loads((ROOT / "contract.json").read_text())
    roots = list(args.elf)
    if not roots:
        roots = sorted({p.resolve() for p in Path("/usr/local/lib").glob("*.so*") if p.is_file()})
        roots += [Path(p) for p in contract["runtime"]["providers"]]
        roots += [resolve(name, []) for name in contract["runtime"]["graphics_loaders"]]
    args.output.write_text(json.dumps(audit(roots), indent=2) + "\n")


if __name__ == "__main__":
    main()
