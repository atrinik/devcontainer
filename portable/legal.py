#!/usr/bin/env python3
"""Retain signed-snapshot corresponding sources for the actual runtime closure."""
import hashlib
import json
from pathlib import Path
import subprocess

from abi import audit, default_roots

root = Path(__file__).resolve().parent
contract = json.loads((root / "contract.json").read_text())
roots = default_roots(contract)
closure = audit(roots)
(root / "runtime-abi.json").write_text(json.dumps(closure, indent=2) + "\n")
packages = {p["package"]: p for p in json.loads((root / "debian-sources.json").read_text())}
source_packages = {}
for entry in closure["objects"]:
    path = Path(entry["path"])
    if path.is_relative_to("/usr/local/lib"):
        continue
    candidates = [str(path)]
    if str(path).startswith("/usr/lib/"):
        candidates.append(str(path).removeprefix("/usr"))
    found = None
    for candidate in candidates:
        result = subprocess.run(["dpkg-query", "-S", candidate], text=True, capture_output=True)
        if result.returncode == 0:
            owners = {line.split(": ", 1)[0] for line in result.stdout.splitlines()}
            if len(owners) != 1:
                raise RuntimeError(f"ambiguous Debian provider ownership: {path}")
            found = packages[owners.pop()]
            break
    if found is None:
        raise RuntimeError(f"unowned baseline provider: {path}")
    source_packages[found["source"]] = found["source_version"]
source_root = root / "sources/debian"
source_root.mkdir(parents=True)
for name, version in sorted(source_packages.items()):
    subprocess.run(["apt-get", "-o", "Acquire::Retries=5", "source", "--download-only", "--only-source", name + "=" + version], cwd=source_root, check=True)
artifacts = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(source_root.iterdir()) if path.is_file()}
(root / "runtime-sources.json").write_text(json.dumps({"source_packages": source_packages, "archives": artifacts}, indent=2) + "\n")
