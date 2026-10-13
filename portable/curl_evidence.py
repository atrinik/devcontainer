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

from build_tools import capture, load_installed


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


def pinned_public_ca(bundle: Path, manifest: dict) -> None:
    if manifest["public_ca"]["endpoint"] != "https://curl.se/" or digest(bundle) != manifest["public_ca"]["sha256"]:
        raise ValueError("changed pinned Classic public-CA qualification")


def tls_results(positive: dict, negative: dict) -> None:
    if (positive.get("passed") is not True or positive.get("expected_untrusted") is not False
            or positive.get("origin") != "curl.se" or positive.get("result") != 0
            or positive.get("verification") != 0 or not 200 <= positive.get("status", 0) < 400
            or negative.get("passed") is not True or negative.get("expected_untrusted") is not True
            or negative.get("origin") != "curl.se" or negative.get("result") != 60
            or negative.get("verification", 0) == 0):
        raise ValueError("portable public-CA qualification failed")


def record(manifest_path: Path, public_ca: Path | None = None, *, installed: dict | None = None) -> dict:
    root = manifest_path.parent
    if installed is None:
        installed = load_installed(root / "installed.json")
    manifest = json.loads(manifest_path.read_text())
    shared_path = root / manifest["cares_manifest"]
    shared = json.loads(shared_path.read_text())
    if manifest["prefix"] != "/usr/local":
        raise ValueError("wrong portable curl prefix")
    retained = root / "sources/curl"
    configuration((retained / "curl_config.h").read_text())
    for package, expected in (("libcurl", manifest["version"]), ("libcares", shared["cares"]["version"])):
        prefix = capture(installed, "pkg_config", ["--variable=prefix", package]).strip()
        version = capture(installed, "pkg_config", ["--modversion", package]).strip()
        if prefix != manifest["prefix"] or version != expected:
            raise ValueError("wrong active portable curl pkg-config: " + package)
    if public_ca is not None:
        pinned_public_ca(public_ca, manifest)
    tls = None
    with tempfile.TemporaryDirectory(prefix="portable-curl-probe-") as temporary:
        binary = Path(temporary) / "probe"
        package_flags = shlex.split(capture(installed, "pkg_config", ["--cflags", "--libs", "libcurl", "libcares"]))
        command = ["/opt/llvm-23.1.3/bin/clang", "-O2", "-march=x86-64", "-mtune=generic", "-Wall", "-Wextra", "-Werror",
                   str(root / "curl-runtime-probe.c"), "-o", str(binary), *package_flags, "-ldl"]
        subprocess.run(command, check=True)
        value = json.loads(subprocess.check_output([str(binary)], text=True))
        require_features(value, manifest, shared["cares"])
        if public_ca is not None:
            positive = json.loads(subprocess.check_output([str(binary), "--public-ca", str(public_ca)], text=True, timeout=15))
            # This private self-signed test certificate is unrelated to the public origin.
            # Its key is generated in this temporary directory and never exported.
            unrelated = Path(temporary) / "untrusted.pem"
            subprocess.run(["/usr/local/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=Atrinik qualification unrelated CA", "-keyout", str(Path(temporary) / "test.key"),
                            "-out", str(unrelated), "-config", "/dev/null"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            negative = json.loads(subprocess.check_output([str(binary), "--untrusted-ca", str(unrelated)], text=True, timeout=15))
            tls_results(positive, negative)
            tls = {"endpoint": manifest["public_ca"]["endpoint"], "ca_sha256": digest(public_ca),
                   "positive": positive, "untrusted_negative": negative}
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
            "public_version_node": "CURL_OPENSSL_4", "providers": providers, "public_ca": tls}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--public-ca", type=Path, help="Run mandatory positive and unrelated-CA negative TLS probes using the pinned Classic bundle")
    args = parser.parse_args()
    print(json.dumps(record(args.root / "curl-toolchain.json", args.public_ca), indent=2))
