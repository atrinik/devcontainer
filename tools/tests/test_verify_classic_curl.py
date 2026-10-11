# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Execute curl verification against isolated target and native SDK fixtures."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'tools/verify-classic-curl.sh'
TARGET = 'x86_64-w64-mingw32'


class VerifyClassicCurlTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.prefix = Path(self.directory.name) / 'prefix with spaces'
        self.bin = self.prefix / 'bin'
        self.bin.mkdir(parents=True)
        config = self.prefix / 'share/atrinik/curl/curl_config.h'
        config.parent.mkdir(parents=True)
        config.write_text('#define USE_ARES 1\n')
        self.toolchain = self.prefix / 'share/cmake/llvm-mingw.cmake'
        self.toolchain.parent.mkdir()
        self.toolchain.write_text('# fixture\n')
        (self.bin / 'libcares-2.dll').write_bytes(b'fixture')
        self.executable(self.bin / 'curl-config', '''#!/usr/bin/env bash
set -eu
case "$1" in
 --configure) printf '%s\\n' "--disable-threaded-resolver --host=${FIXTURE_HOST}";;
 --ssl-backends) echo OpenSSL;;
 --features) printf '%s\\n' AsynchDNS HTTP2 IDN PSL SSL libz brotli zstd;;
 --protocols) printf '%s\\n' HTTP HTTPS WS WSS "${FIXTURE_EXTRA_PROTOCOL:-}";;
 *) exit 90;;
esac
''')
        self.pkg = self.bin / (TARGET + '-pkg-config')
        self.executable(self.pkg, '''#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$FIXTURE_PKG_CALLS"
case "$1:$2" in
 --modversion:libcurl) echo "${FIXTURE_CURL_VERSION:-8.21.0}";;
 --modversion:libcares) echo 1.34.6;;
 --modversion:openssl) echo 3.5.5;;
 --variable=prefix:*) echo "${FIXTURE_PROVIDER_PREFIX:-$FIXTURE_PREFIX}";;
 --variable=pcfiledir:*) echo "${FIXTURE_PC_ROOT:-$FIXTURE_PREFIX/lib/pkgconfig}";;
 *) exit 91;;
esac
''')
        ambient = Path(self.directory.name) / 'ambient'
        ambient.mkdir()
        self.executable(ambient / 'pkg-config', '#!/bin/sh\necho ambient-selected >&2\nexit 97\n')
        self.env = dict(os.environ, PATH=str(ambient) + ':' + os.environ['PATH'],
                        ATRINIK_WINDOWS_TARGET=TARGET,
                        ATRINIK_WINDOWS_RUNTIME_DIR=str(self.bin),
                        ATRINIK_WINDOWS_TOOLCHAIN_FILE=str(self.toolchain),
                        FIXTURE_PREFIX=str(self.prefix), FIXTURE_HOST=TARGET,
                        FIXTURE_PKG_CALLS=str(Path(self.directory.name) / 'pkg-calls'))

    @staticmethod
    def executable(path, content):
        path.write_text(content)
        path.chmod(0o755)

    def run_verifier(self, **env):
        return subprocess.run(['bash', str(SCRIPT), str(self.prefix)],
                              env=dict(self.env, **env), capture_output=True, text=True)

    def test_windows_uses_absolute_selected_wrapper_despite_hostile_path(self):
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = Path(self.env['FIXTURE_PKG_CALLS']).read_text().splitlines()
        self.assertIn('--modversion libcurl', calls)
        for package in ('libcurl', 'libcares', 'openssl'):
            self.assertIn('--variable=prefix ' + package, calls)
            self.assertIn('--variable=pcfiledir ' + package, calls)
        self.assertNotIn('ambient-selected', result.stderr)

    def test_missing_or_wrong_selected_target_and_paths_fail(self):
        for values in (
                {'ATRINIK_WINDOWS_TARGET': ''},
                {'ATRINIK_WINDOWS_TARGET': 'i686-w64-mingw32'},
                {'ATRINIK_WINDOWS_RUNTIME_DIR': '/wrong/bin'},
                {'ATRINIK_WINDOWS_TOOLCHAIN_FILE': '/wrong/toolchain'},
                {'FIXTURE_HOST': 'x86_64-pc-linux-gnu'},
                {'FIXTURE_HOST': TARGET + '-wrong'},
                {'FIXTURE_HOST': TARGET + ' --host=i686-w64-mingw32'},
                {'FIXTURE_PROVIDER_PREFIX': '/usr/local'},
                {'FIXTURE_PC_ROOT': '/usr/lib/pkgconfig'}):
            with self.subTest(values=values):
                self.assertNotEqual(self.run_verifier(**values).returncode, 0)
        self.toolchain.unlink()
        self.assertNotEqual(self.run_verifier().returncode, 0)

    def test_relative_prefix_is_rejected_and_actual_quoted_host_is_accepted(self):
        relative = self.prefix.name
        env = dict(self.env, ATRINIK_WINDOWS_RUNTIME_DIR=relative + '/bin',
                   ATRINIK_WINDOWS_TOOLCHAIN_FILE=relative + '/share/cmake/llvm-mingw.cmake',
                   FIXTURE_PREFIX=relative)
        result = subprocess.run(['bash', str(SCRIPT), relative], env=env,
                                cwd=self.prefix.parent, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        configure = self.bin / 'curl-config'
        configure.write_text(configure.read_text().replace('--host=${FIXTURE_HOST}', "'--host=${FIXTURE_HOST}'"))
        self.assertEqual(self.run_verifier().returncode, 0)
        self.assertNotEqual(self.run_verifier(FIXTURE_HOST=TARGET + '-wrong').returncode, 0)

    def test_absent_linked_or_nonexecutable_wrapper_fails_without_fallback(self):
        source = self.pkg.read_text()
        self.pkg.unlink()
        self.assertNotEqual(self.run_verifier().returncode, 0)
        other = self.bin / 'other-pkg-config'
        self.executable(other, source)
        self.pkg.symlink_to(other)
        self.assertNotEqual(self.run_verifier().returncode, 0)
        self.pkg.unlink()
        self.executable(self.pkg, source)
        self.pkg.chmod(0o644)
        self.assertNotEqual(self.run_verifier().returncode, 0)

    def test_existing_windows_feature_version_and_dll_gates_still_fail(self):
        self.assertNotEqual(self.run_verifier(FIXTURE_CURL_VERSION='8.18.0').returncode, 0)
        self.assertNotEqual(self.run_verifier(FIXTURE_EXTRA_PROTOCOL='LDAP').returncode, 0)
        (self.bin / 'libcares-2.dll').unlink()
        self.assertNotEqual(self.run_verifier().returncode, 0)

    def test_linux_branch_executes_existing_native_checks_unchanged(self):
        branch = SCRIPT.read_text().split('if [[ $prefix == /usr/local ]]; then\n', 1)[1].split('\nelse\n', 1)[0]
        expected = '''  test "$(pkg-config --modversion libcurl)" = 8.18.0
  test "$(pkg-config --variable=prefix libcurl)" = "$prefix"
  test "$(pkg-config --modversion libcares)" = 1.34.6
  test "$(pkg-config --modversion openssl)" = 3.5.5
  "$prefix/bin/curl" --version | grep -F 'c-ares/1.34.6'
  "$prefix/bin/curl" --version | grep -F 'OpenSSL/3.5.5' '''.rstrip()
        self.assertEqual(branch, expected)
        native = self.bin / 'pkg-config'
        self.executable(native, self.pkg.read_text())
        self.executable(self.bin / 'curl', '#!/bin/sh\necho "curl c-ares/1.34.6 OpenSSL/3.5.5"\n')
        env = dict(self.env, PATH=str(self.bin) + ':' + os.environ['PATH'],
                   FIXTURE_CURL_VERSION='8.18.0')
        result = subprocess.run(['bash', '-euo', 'pipefail', '-c', 'prefix=$1\n' + branch, 'fixture', str(self.prefix)],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        env['FIXTURE_CURL_VERSION'] = '8.21.0'
        self.assertNotEqual(subprocess.run(['bash', '-euo', 'pipefail', '-c', 'prefix=$1\n' + branch, 'fixture', str(self.prefix)],
                                          env=env, capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
