#!/usr/bin/env python3
"""Verify actual ELF providers, versioned symbols, loader closure and ISA notes."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import struct

ROOT = Path(__file__).resolve().parent
DEFAULT_DIRS = [Path("/usr/local/lib"), Path("/lib/x86_64-linux-gnu"), Path("/usr/lib/x86_64-linux-gnu"), Path("/lib64")]


def output(*args: str) -> str:
    result = subprocess.run(args, text=True, capture_output=True)
    if result.returncode or result.stderr:
        raise ValueError(f"ELF inspection failed: {args}: {result.stdout}{result.stderr}")
    return result.stdout


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


def section_bytes(path: Path, name: str) -> bytes:
    sections = output("readelf", "-SW", str(path))
    if not re.search(r"\]\s+" + re.escape(name) + r"\s", sections):
        return b""
    # Binutils 2.40 returns failure for valid FDO dlopen notes with -n. Hex
    # section inspection preserves those bytes without interpreting note types.
    dump = output("readelf", "-x", name, str(path))
    chunks = []
    for line in dump.splitlines():
        match = re.match(r"\s+0x[0-9a-f]+\s+((?:[0-9a-f]{2,8}\s+){1,4})", line)
        if match:
            chunks.append(bytes.fromhex(match[1]))
    if not chunks:
        raise ValueError(f"empty ELF note section: {path}: {name}")
    return b"".join(chunks)


def notes(data: bytes, alignment: int) -> list[tuple[bytes, int, bytes]]:
    result, offset = [], 0
    while offset < len(data):
        if len(data) - offset < 12:
            raise ValueError("truncated ELF note header")
        namesz, descsz, kind = struct.unpack_from("<III", data, offset)
        start = offset + 12
        desc = (start + namesz + alignment - 1) & -alignment
        end = desc + descsz
        next_offset = (end + alignment - 1) & -alignment
        if not namesz or end > len(data) or next_offset > len(data):
            raise ValueError("invalid ELF note bounds")
        result.append((data[start:start + namesz], kind, data[desc:end]))
        offset = next_offset
    return result


def cpu_notes(data: bytes) -> None:
    for owner, kind, desc in notes(data, 8):
        if owner != b"GNU\0" or kind != 5:
            raise ValueError("unexpected GNU property note")
        offset = 0
        while offset < len(desc):
            if len(desc) - offset < 8:
                raise ValueError("truncated GNU property")
            kind, size = struct.unpack_from("<II", desc, offset)
            start = offset + 8
            end = start + size
            if end > len(desc):
                raise ValueError("invalid GNU property bounds")
            if kind == 0xc0008002:  # GNU_PROPERTY_X86_ISA_1_NEEDED
                if size != 4 or struct.unpack_from("<I", desc, start)[0] & ~1:
                    raise ValueError("newer CPU ISA required")
            offset = (end + 7) & -8
            if offset > len(desc):
                raise ValueError("invalid GNU property padding")


def dlopen_notes(data: bytes) -> list[dict]:
    result = []
    for owner, kind, desc in notes(data, 4):
        if owner != b"FDO\0" or kind != 0x407c0c0a or not desc.endswith(b"\0"):
            raise ValueError("unexpected FDO dlopen note")
        entries = json.loads(desc[:-1])
        if not isinstance(entries, list) or not entries:
            raise ValueError("invalid FDO dlopen entries")
        for entry in entries:
            if (not isinstance(entry, dict) or not isinstance(entry.get("feature"), str)
                    or not isinstance(entry.get("soname"), list) or not entry["soname"]
                    or not all(isinstance(name, str) and name and "/" not in name for name in entry["soname"])):
                raise ValueError("invalid FDO dlopen provider")
        result.extend(entries)
    return result


def elf(path: Path) -> dict:
    header = output("readelf", "-h", str(path))
    if "Advanced Micro Devices X86-64" not in header or "ELF64" not in header:
        raise ValueError(f"wrong ELF target: {path}")
    if "little endian" not in header:
        raise ValueError(f"wrong ELF byte order: {path}")
    properties = section_bytes(path, ".note.gnu.property")
    cpu_notes(properties)
    loaders = dlopen_notes(section_bytes(path, ".note.dlopen"))
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
                version_providers=version_providers, dlopen=loaders, gnu_property_present=bool(properties))


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
    contract = json.loads((ROOT / "contract.json").read_text())
    excluded = contract["runtime"].get("unsupported_dlopen_features", [])
    graph = {}
    pending = list(roots)
    while pending:
        path = pending.pop().resolve()
        if path in graph:
            continue
        value = elf(path)
        value["providers"] = {name: resolve(name, value["paths"]) for name in value["needed"]}
        value["dlopen_providers"] = {}
        for entry in value.get("dlopen", []):
            if any(item["object"] == str(path) and item["feature"] == entry["feature"]
                   and item["soname"] == entry["soname"] for item in excluded):
                continue
            candidates = []
            for name in entry["soname"]:
                try:
                    candidates.append(resolve(name, value["paths"]))
                except ValueError:
                    pass
            if not candidates:
                raise ValueError(f"missing dlopen feature provider: {path}: {entry}")
            value["dlopen_providers"].setdefault(entry["feature"], []).extend(candidates)
            pending.extend(candidates)
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
                 "gnu_property_present": value.get("gnu_property_present", False),
                 "dlopen": value.get("dlopen", []),
                 "dlopen_providers": {feature: [str(p) for p in paths] for feature, paths in value["dlopen_providers"].items()},
                 "required_symbols": sorted(value["required"])}
                for path, value in sorted(graph.items())]}


def default_roots(contract: dict) -> list[Path]:
    roots = sorted({p.resolve() for p in Path("/usr/local/lib").glob("*.so*") if p.is_file()})
    roots += [Path(p) for p in contract["runtime"]["providers"]]
    roots += [resolve(name, []) for name in [*contract["runtime"]["application_libraries"], *contract["runtime"]["graphics_loaders"]]]
    return sorted(set(roots))


def require_consumer_coverage(consumer: dict, image: dict) -> None:
    provided = {entry["path"]: entry["sha256"] for entry in image["objects"]}
    consumer_roots = {str(Path(path).resolve()) for path in consumer["roots"]}
    for entry in consumer["objects"]:
        if entry["path"] in consumer_roots:
            continue
        if provided.get(entry["path"]) != entry["sha256"]:
            raise ValueError(f"consumer dependency absent or changed in image source closure: {entry['path']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("elf", type=Path, nargs="*")
    args = parser.parse_args()
    contract = json.loads((ROOT / "contract.json").read_text())
    roots = list(args.elf)
    if not roots:
        roots = default_roots(contract)
    result = audit(roots)
    if args.elf:
        require_consumer_coverage(result, json.loads((ROOT / "runtime-abi.json").read_text()))
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
