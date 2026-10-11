#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
"""Rebuild the authenticated Debian OpenSSL curl variant with bounded c-ares DNS."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checksum_table(text: str, field: str) -> dict[str, str]:
    lines = text.splitlines()
    start = lines.index(field + ":") + 1
    entries = {}
    for line in lines[start:]:
        if not line.startswith(" "):
            break
        match = re.fullmatch(r"\s+([0-9a-f]{64})\s+[0-9]+\s+(\S+)", line)
        if match is None or match[2] in entries:
            raise ValueError("malformed authenticated source checksum table")
        entries[match[2]] = match[1]
    return entries


def matching_source(text: str, manifest: dict) -> str | None:
    for paragraph in text.split("\n\n"):
        if (re.search(r"^Package: curl$", paragraph, re.MULTILINE)
                and re.search(r"^Version: " + re.escape(manifest["source_version"]) + "$", paragraph, re.MULTILINE)):
            if checksum_table(paragraph, "Checksums-Sha256") != manifest["archives"]:
                raise ValueError("changed authenticated Debian curl archives")
            return paragraph
    return None


def authenticate_source(manifest: dict, retained: Path) -> dict:
    """Verify InRelease -> decompressed Sources -> all four pinned archive digests."""
    lists = Path("/var/lib/apt/lists")
    for release in sorted(lists.glob("*InRelease")):
        prefix = release.name.removesuffix("InRelease")
        for index in sorted(lists.glob(prefix + "*_source_Sources*")):
            if manifest["apt_snapshot"] not in release.name:
                continue
            signature = subprocess.run(["gpgv", "--keyring", "/usr/share/keyrings/debian-archive-keyring.gpg", str(release)],
                                       text=True, capture_output=True, check=True)
            entries = checksum_table(release.read_text(), "SHA256")
            data = subprocess.check_output(["/usr/lib/apt/apt-helper", "cat-file", str(index)])
            relative = index.name.removeprefix(prefix).removesuffix(".lz4").replace("_", "/")
            index_hash = hashlib.sha256(data).hexdigest()
            if entries.get(relative) != index_hash:
                raise ValueError("Debian Sources index disagrees with signed InRelease")
            paragraph = matching_source(data.decode(), manifest)
            if paragraph is not None:
                (retained / "apt-source-record.txt").write_text(paragraph + "\n")
                (retained / "InRelease").write_bytes(release.read_bytes())
                (retained / "archive-signature.txt").write_text(signature.stdout + signature.stderr)
                return {"route": "gpgv-verified snapshot InRelease -> SHA256 Sources -> SHA256 archives",
                        "release_sha256": digest(release), "sources_path": relative, "sources_sha256": index_hash,
                        "source_record_sha256": digest(retained / "apt-source-record.txt"),
                        "archive_keyring_sha256": digest(Path("/usr/share/keyrings/debian-archive-keyring.gpg"))}
    raise ValueError("pinned curl source absent from authenticated snapshot indexes")


def openssl_series(series: str, applied: list[str], pop: list[str]) -> list[str]:
    expected = [shlex.split(line)[0] for line in series.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if applied != expected or expected[-len(pop):] != list(reversed(pop)) or pop != ["99_nss.patch", "90_gnutls.patch"]:
        raise ValueError("changed Debian OpenSSL variant patch preparation")
    return expected[:-len(pop)]


def main(root: Path, jobs: int) -> None:
    manifest_path = root / "curl-toolchain.json"
    manifest = json.loads(manifest_path.read_text())
    shared = json.loads((root / manifest["cares_manifest"]).read_text())
    if subprocess.check_output(["getconf", "GNU_LIBC_VERSION"], text=True).strip() != "glibc 2.36":
        raise ValueError("curl producer is outside the portable glibc baseline")
    for name in ("clang", "clang++"):
        if "clang version 23.1.3" not in subprocess.check_output(["/opt/llvm-23.1.3/bin/" + name, "--version"], text=True):
            raise ValueError("wrong portable curl LLVM compiler")
    prefix = manifest["prefix"]
    if prefix != "/usr/local" or jobs not in range(1, 9):
        raise ValueError("wrong portable curl prefix or job budget")
    retained = root / "sources/curl"
    retained.mkdir(parents=True, exist_ok=True)
    source_command = ["apt-get", "-o", "Acquire::Retries=5", "source", "--download-only", "--only-source",
                      manifest["source_package"] + "=" + manifest["source_version"]]
    with (retained / "apt-source.log").open("w") as log:
        subprocess.run(source_command, cwd=retained, check=True, stdout=log, stderr=subprocess.STDOUT)
    trust = authenticate_source(manifest, retained)
    for filename, expected in manifest["archives"].items():
        if digest(retained / filename) != expected:
            raise ValueError("changed Debian curl source archive: " + filename)
    sys.path.insert(0, str(root / "tools"))
    from install_classic_shader_toolchain import download
    cares_archive = download(shared["cares"]["url"], shared["cares"]["sha256"], root / "sources")
    with tempfile.TemporaryDirectory(prefix="portable-curl-") as temporary:
        work = Path(temporary)
        source = work / "curl"
        dsc = retained / ("curl_" + manifest["source_version"] + ".dsc")
        extraction = subprocess.run(["dpkg-source", "--require-strong-checksums", "-x", str(dsc), str(source)],
                                    text=True, capture_output=True, check=True)
        (retained / "extraction.log").write_text(extraction.stdout + extraction.stderr)
        series = (source / "debian/patches/series").read_text()
        applied = lambda: (source / ".pc/applied-patches").read_text().splitlines()
        expected = openssl_series(series, applied(), manifest["openssl_variant_pop"])
        quilt_env = {**os.environ, "QUILT_PATCHES": "debian/patches"}
        for patch in manifest["openssl_variant_pop"]:
            if applied()[-1] != patch:
                raise ValueError("wrong terminal Debian variant patch")
            subprocess.run(["quilt", "pop"], cwd=source, env=quilt_env, check=True)
        if applied() != expected:
            raise ValueError("Debian security patches changed during OpenSSL preparation")
        subprocess.run([str(source / "buildconf")], cwd=source, check=True)
        notices = root / "notices/curl"
        notices.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / "COPYING", notices / "COPYING")
        shutil.copy2(source / "debian/copyright", notices / "debian-copyright")
        from build import extract
        cares_source = work / "cares"
        extract(cares_archive, cares_source)
        subprocess.run(["cmake", "-S", str(cares_source), "-B", str(work / "cares-build"), "-G", "Ninja",
                        "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_C_FLAGS_RELEASE=-O2 -DNDEBUG", "-DCMAKE_CXX_FLAGS_RELEASE=-O2 -DNDEBUG",
                        "-DCMAKE_C_COMPILER=/opt/llvm-23.1.3/bin/clang", "-DCMAKE_CXX_COMPILER=/opt/llvm-23.1.3/bin/clang++",
                        "-DCMAKE_AR=/opt/llvm-23.1.3/bin/llvm-ar", "-DCMAKE_RANLIB=/opt/llvm-23.1.3/bin/llvm-ranlib",
                        "-DCMAKE_INSTALL_PREFIX=" + prefix, "-DCMAKE_INSTALL_LIBDIR=lib", "-DCARES_STATIC=OFF", "-DCARES_SHARED=ON",
                        "-DCARES_BUILD_TOOLS=OFF", "-DCARES_BUILD_TESTS=OFF", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"], check=True)
        subprocess.run(["cmake", "--build", str(work / "cares-build"), "--parallel", str(jobs)], check=True)
        subprocess.run(["cmake", "--install", str(work / "cares-build")], check=True)
        # Curl runs its newly linked CLI while generating shell completion data.
        subprocess.run(["ldconfig"], check=True)
        shutil.copy2(work / "cares-build/compile_commands.json", retained / "cares-compile-commands.json")
        cares_notices = root / "notices/c-ares"
        cares_notices.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cares_source / "LICENSE.md", cares_notices / "LICENSE.md")
        flags = "-O2 -march=x86-64 -mtune=generic -fstack-protector-strong -Wformat -Werror=format-security"
        flags += ' -DCURL_PATCHSTAMP=\\"' + manifest["source_version"] + '\\"'
        environment = {**os.environ, "CC": "/opt/llvm-23.1.3/bin/clang", "CXX": "/opt/llvm-23.1.3/bin/clang++",
                       "AR": "/opt/llvm-23.1.3/bin/llvm-ar", "RANLIB": "/opt/llvm-23.1.3/bin/llvm-ranlib", "LD": "/opt/llvm-23.1.3/bin/ld.lld",
                       "CFLAGS": flags, "CPPFLAGS": "-D_FORTIFY_SOURCE=2", "LDFLAGS": "-Wl,-z,relro -Wl,-z,now",
                       "PKG_CONFIG_PATH": prefix + "/lib/pkgconfig"}
        command = [str(source / "configure"), "--prefix=" + prefix, "--libdir=" + prefix + "/lib", "--with-openssl=" + prefix,
                   "--enable-ares=" + prefix, "--with-ca-bundle=" + manifest["ca_bundle"], "--with-ca-path=/etc/ssl/certs", *manifest["configure"]]
        subprocess.run(command, cwd=source, env=environment, check=True)
        from curl_evidence import configuration
        configuration((source / "lib/curl_config.h").read_text())
        subprocess.run(["make", "--jobs=" + str(jobs)], cwd=source, env=environment, check=True)
        subprocess.run(["make", "install"], cwd=source, env=environment, check=True)
        for name in ("lib/curl_config.h", "config.log", "debian/patches/series"):
            shutil.copy2(source / name, retained / Path(name).name)
        receipt = {"source_version": manifest["source_version"], "source_archives": manifest["archives"], "authentication": trust,
                   "dsc_signature_verified": "Good signature" in extraction.stdout + extraction.stderr,
                   "dsc_verification": "dpkg-source default signature verification and required strong checksums; exact signature diagnostic retained",
                   "applied_security_and_packaging_patches": expected,
                   "patch_sha256": {name: digest(source / "debian/patches" / name) for name in expected},
                   "removed_openssl_variant_patches": manifest["openssl_variant_pop"], "configure_command": command,
                   "cflags": flags, "cppflags": environment["CPPFLAGS"], "ldflags": environment["LDFLAGS"],
                   "cares_archive": {"path": str(cares_archive.relative_to(root)), "sha256": digest(cares_archive)},
                   "recipe_sha256": digest(Path(__file__)), "manifest_sha256": digest(manifest_path),
                   "cares_manifest_sha256": digest(root / manifest["cares_manifest"])}
        (root / "curl-source-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    subprocess.run(["ldconfig"], check=True)
    from curl_evidence import record
    record(root / "curl-toolchain.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    main(args.root, args.jobs)
