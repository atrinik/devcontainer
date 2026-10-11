#!/usr/bin/env python3
"""Record actual installed tools and Debian package/source coordinates."""
import hashlib
import json
from pathlib import Path
import subprocess

from compiler_evidence import record

root = Path(__file__).resolve().parent
contract = json.loads((root / "contract.json").read_text())

def output(*args):
    return subprocess.check_output(args, text=True).strip()

packages = []
for line in output("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n").splitlines():
    package, version, source, source_version = line.split("\t")
    packages.append({"package": package, "version": version, "source": source,
                     "source_version": source_version,
                     "snapshot": contract["base"]["apt_snapshot"],
                     "notice_directory": "/usr/share/doc/" + package.split(":")[0]})
(root / "debian-sources.json").write_text(json.dumps(packages, indent=2) + "\n")
evidence = record()
evidence_path = root / "compiler-evidence.json"
evidence_path.write_text(json.dumps(evidence, indent=2) + "\n")
actual = {"schema_version": 2, "contract_sha256": hashlib.sha256((root / "contract.json").read_bytes()).hexdigest(),
          "architecture": output("dpkg", "--print-architecture"), "glibc": output("getconf", "GNU_LIBC_VERSION"),
          "tools": {name: output(*args).splitlines()[0] for name, args in {
              "cc": ["clang", "--version"], "linker": ["ld.lld", "--version"],
              "readelf": ["llvm-readelf", "--version"], "cmake": ["cmake", "--version"],
              "ninja": ["ninja", "--version"], "python": ["python3", "--version"],
              "git-lfs": ["git", "lfs", "version"], "openssl": ["openssl", "version"]}.items()},
          "compiler_target": evidence["target"],
          "compiler_evidence_sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
          "pkg_config": {name: output("pkg-config", "--modversion", name) for name in contract["pkg_config"]}}
assert actual["architecture"] == "amd64"
assert actual["glibc"] == "glibc 2.36"
for name, version in contract["pkg_config"].items():
    assert actual["pkg_config"][name] == version, (name, actual["pkg_config"][name], version)
(root / "installed.json").write_text(json.dumps(actual, indent=2) + "\n")
