#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
"""Verify portable curl's original feature matrix and actual loaded resolver cohort."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def configuration(config: str) -> None:
    if not re.search(r"^#define USE_ARES 1$", config, re.MULTILINE):
        raise ValueError("portable curl does not select c-ares")
    if re.search(r"^#define USE_THREADS_(POSIX|WIN32) 1$", config, re.MULTILINE):
        raise ValueError("portable curl contains a threaded resolver")


def require_features(value: dict, manifest: dict, cares: dict) -> None:
    for key in ("protocols", "features"):
        actual = {name.upper() if key == "protocols" else name for name in value[key]}
        required = set(manifest["required_" + key])
        if not required <= actual:
            raise ValueError("portable curl lost " + key + ": " + ", ".join(sorted(required - actual)))
    if value["header_version"] != manifest["version"] or value["cares_header_version"] != cares["version"] or value["cares_version"] != cares["version"]:
        raise ValueError("portable curl header/runtime identity mismatch")
    for identity in ("libcurl/" + manifest["version"], "c-ares/" + cares["version"], "OpenSSL/" + manifest["openssl_version"]):
        if identity not in value["runtime_version"].split():
            raise ValueError("wrong loaded portable curl identity: " + identity)
    for key in ("curl_path", "cares_path"):
        if not Path(value[key]).resolve().is_relative_to(Path("/usr/local/lib")):
            raise ValueError("foreign active portable curl provider: " + key)


def record(manifest_path: Path) -> dict:
    root = manifest_path.parent
    manifest = json.loads(manifest_path.read_text())
    shared_path = root / manifest["cares_manifest"]
    shared = json.loads(shared_path.read_text())
    if manifest["prefix"] != "/usr/local":
        raise ValueError("wrong portable curl prefix")
    retained = root / "sources/curl"
    configuration((retained / "curl_config.h").read_text())
    for package, expected in (("libcurl", manifest["version"]), ("libcares", shared["cares"]["version"])):
        prefix = subprocess.check_output(["pkg-config", "--variable=prefix", package], text=True).strip()
        version = subprocess.check_output(["pkg-config", "--modversion", package], text=True).strip()
        if prefix != manifest["prefix"] or version != expected:
            raise ValueError("wrong active portable curl pkg-config: " + package)
    with tempfile.TemporaryDirectory(prefix="portable-curl-probe-") as temporary:
        binary = Path(temporary) / "probe"
        package_flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "libcurl", "libcares"], text=True))
        command = ["/opt/llvm-23.1.3/bin/clang", "-O2", "-march=x86-64", "-mtune=generic", "-Wall", "-Wextra", "-Werror",
                   str(root / "curl-runtime-probe.c"), "-o", str(binary), *package_flags, "-ldl"]
        subprocess.run(command, check=True)
        value = json.loads(subprocess.check_output([str(binary)], text=True))
    require_features(value, manifest, shared["cares"])
    readelf = subprocess.check_output(["/opt/llvm-23.1.3/bin/llvm-readelf", "--version-info", value["curl_path"]], text=True)
    if not re.search(r"Name: CURL_OPENSSL_4(?:\s|$)", readelf):
        raise ValueError("portable curl public OpenSSL ABI version node missing")
    providers = {package: {"path": str(Path(value[key]).resolve()), "sha256": digest(Path(value[key])), "version": version}
                 for package, key, version in (("libcurl", "curl_path", manifest["version"]),
                                               ("libcares", "cares_path", shared["cares"]["version"]))}
    return {"resolver": "c-ares", "threaded_resolver": False, "manifest_sha256": digest(manifest_path),
            "cares_manifest_sha256": digest(shared_path), "config_sha256": digest(retained / "curl_config.h"),
            "source_receipt_sha256": digest(root / "curl-source-receipt.json"), "runtime_version": value["runtime_version"],
            "header_version": value["header_version"], "features": value["features"], "protocols": value["protocols"],
            "public_version_node": "CURL_OPENSSL_4", "providers": providers}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    print(json.dumps(record(args.root / "curl-toolchain.json"), indent=2))
