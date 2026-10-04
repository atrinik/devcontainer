#!/usr/bin/env python3
"""Build Classic's isolated, checksum-pinned OpenSSL/libcurl provider cohort."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

from install_classic_shader_toolchain import (
    MAX_EXPANDED_BYTES, MAX_FILE_BYTES, MAX_MEMBERS, ToolchainError,
    copy_member, download, reject_duplicate_keys, safe_archive_path,
)

ROOT = Path(__file__).resolve().parent


def load_manifest(path: Path) -> dict:
    value = json.loads(path.read_text(), object_pairs_hook=reject_duplicate_keys)
    if (set(value) != {"schema_version", "platform", "prefix", "openssl", "curl",
                       "required_api", "providers", "required_curl_protocols", "required_curl_features"}
            or value["schema_version"] != 1 or value["platform"] != "linux/amd64"
            or value["prefix"] != "/opt/atrinik/tls"
            or value["required_api"] != "SSL_get_peer_addr"
            or value["providers"] != ["default", "legacy"]
            or value["required_curl_protocols"] != ["http", "https"]
            or value["required_curl_features"] != ["SSL", "IDN", "libz"]):
        raise ToolchainError("invalid Classic TLS contract")
    for name, host, license_name in (("openssl", "https://github.com/openssl/openssl/releases/download/", "Apache-2.0"),
                                     ("curl", "https://curl.se/download/", "curl")):
        entry = value[name]
        if (set(entry) != {"version", "url", "sha256", "license"}
                or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", entry["version"])
                or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
                or entry["license"] != license_name):
            raise ToolchainError("invalid Classic TLS source pin")
        version = entry["version"]
        expected = (f"{host}openssl-{version}/openssl-{version}.tar.gz" if name == "openssl"
                    else f"{host}curl-{version}.tar.xz")
        if entry["url"] != expected:
            raise ToolchainError("unexpected Classic TLS source URL")
    return value


def extract(archive_path: Path, destination: Path, root: str) -> None:
    seen, total = set(), 0
    with tarfile.open(archive_path, "r:*") as archive:
        for count, member in enumerate(archive, 1):
            if count > MAX_MEMBERS:
                raise ToolchainError("TLS archive member bound exceeded")
            path = safe_archive_path(member.name)
            if path.parts[0] != root:
                raise ToolchainError("TLS source root differs")
            if len(path.parts) == 1:
                if not member.isdir():
                    raise ToolchainError("TLS source root is not a directory")
                continue
            relative = Path(*path.parts[1:])
            key = relative.as_posix().casefold()
            if key in seen:
                raise ToolchainError("duplicate TLS archive member")
            seen.add(key)
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.size > MAX_FILE_BYTES:
                raise ToolchainError("unsupported TLS source member")
            total += member.size
            if total > MAX_EXPANDED_BYTES:
                raise ToolchainError("TLS source expansion bound exceeded")
            source = archive.extractfile(member)
            if source is None:
                raise ToolchainError("missing TLS source bytes")
            with source:
                copy_member(source, target, member.size)
            target.chmod(member.mode & 0o755 or 0o644)


def run(*args: str, cwd: Path | None = None, env: dict | None = None) -> None:
    subprocess.run(args, cwd=cwd, env=env, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "manifest.json")
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 2:
        parser.error("jobs must be 1 or 2")
    manifest = load_manifest(args.manifest)
    prefix = Path(manifest["prefix"])
    if prefix.is_symlink() or (prefix.exists() and any(prefix.iterdir())):
        raise ToolchainError("TLS installation requires an absent or empty prefix")
    args.build_root.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    # System tools keep their own TLS configuration and providers. Only the
    # explicitly selected Classic consumer uses this prefix.
    for name in ("OPENSSL_CONF", "OPENSSL_MODULES", "LD_LIBRARY_PATH", "CMAKE_PREFIX_PATH", "PKG_CONFIG_PATH"):
        environment.pop(name, None)
    with tempfile.TemporaryDirectory(prefix="classic-tls-", dir=args.build_root) as tmp:
        work = Path(tmp)
        for name in ("openssl", "curl"):
            entry = manifest[name]
            extract(download(entry["url"], entry["sha256"], args.cache), work / name, f"{name}-{entry['version']}")
        openssl = work / "openssl"
        run("perl", "Configure", "linux-x86_64", "shared", f"--prefix={prefix}", "--libdir=lib",
            f"--openssldir={prefix}/ssl", f"-Wl,--enable-new-dtags,-rpath,{prefix}/lib", cwd=openssl, env=environment)
        run("make", f"-j{args.jobs}", "build_sw", cwd=openssl, env=environment)
        run("make", f"-j{args.jobs}", "build_tests", cwd=openssl, env=environment)
        test_env = dict(environment, HARNESS_JOBS=str(args.jobs))
        run("make", "test", "TESTS=test_quicapi", cwd=openssl, env=test_env)
        run("make", "install_sw", "install_ssldirs", cwd=openssl, env=environment)
        environment["PKG_CONFIG_PATH"] = str(prefix / "lib/pkgconfig")
        run("cmake", "-S", str(work / "curl"), "-B", str(work / "curl-build"), "-G", "Ninja",
            "-DCMAKE_BUILD_TYPE=Release", f"-DCMAKE_INSTALL_PREFIX={prefix}", "-DCMAKE_INSTALL_LIBDIR=lib",
            "-DCMAKE_INSTALL_RPATH=$ORIGIN", "-DBUILD_SHARED_LIBS=ON", "-DBUILD_STATIC_LIBS=OFF",
            "-DBUILD_CURL_EXE=OFF", "-DBUILD_TESTING=OFF", "-DBUILD_LIBCURL_DOCS=OFF",
            "-DBUILD_MISC_DOCS=OFF", "-DENABLE_CURL_MANUAL=OFF", "-DCURL_USE_OPENSSL=ON",
            f"-DOPENSSL_ROOT_DIR={prefix}", "-DOPENSSL_USE_STATIC_LIBS=OFF",
            "-DCURL_USE_LIBSSH2=OFF", "-DCURL_USE_LIBSSH=OFF", "-DCURL_USE_GSSAPI=OFF",
            "-DCURL_DISABLE_LDAP=ON", "-DCURL_DISABLE_LDAPS=ON", "-DCURL_USE_LIBPSL=OFF",
            "-DUSE_NGHTTP2=OFF", "-DUSE_NGTCP2=OFF", "-DCURL_BROTLI=OFF", "-DCURL_ZSTD=OFF",
            "-DUSE_LIBIDN2=ON", "-DCURL_ZLIB=ON", env=environment)
        run("cmake", "--build", str(work / "curl-build"), "--parallel", str(args.jobs), env=environment)
        run("cmake", "--install", str(work / "curl-build"), env=environment)
        notices = prefix / "share/licenses"
        for name, filename in (("openssl", "LICENSE.txt"), ("curl", "COPYING")):
            target = notices / name
            target.mkdir(parents=True)
            shutil.copyfile(work / name / filename, target / filename)
        (prefix / "share/atrinik").mkdir(parents=True)
        shutil.copyfile(args.manifest, prefix / "share/atrinik/classic-tls.json")
    print(json.dumps({"installed": True, "prefix": str(prefix), "openssl": manifest["openssl"]["version"],
                      "curl": manifest["curl"]["version"], "upstream_quic_api_tests": True}))


if __name__ == "__main__":
    main()
