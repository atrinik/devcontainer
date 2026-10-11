# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Check scoped qualification fences without building or executing Windows code."""
import itertools
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/windows-glib-qualification.yml'


def script(step):
    block = WORKFLOW.read_text().split(f'      - name: {step}\n', 1)[1]
    block = block.split('\n      - name:', 1)[0]
    body = block.split('        run: |\n', 1)[1]
    return '\n'.join(line[10:] for line in body.splitlines()) + '\n'


class ScopedWindowsGLibWorkflow(unittest.TestCase):
    def test_changed_source_digest_fails_before_network(self):
        for library, field in itertools.product(('glib', 'cairo'), ('sha256', 'url')):
            with self.subTest(library=library, field=field):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'windows').mkdir()
                    manifest = json.loads((ROOT / 'windows/dependencies.json').read_text())
                    for package in manifest['dependencies']:
                        if package['name'] == library:
                            package[field] = 'invalid'
                    (root / 'windows/dependencies.json').write_text(json.dumps(manifest))
                    git = root / 'git'
                    git.write_text('#!/bin/sh\ntar -cf - --files-from /dev/null\n')
                    git.chmod(0o755)
                    curl = root / 'curl'
                    curl.write_text('#!/bin/sh\ntouch curl-was-called\nexit 99\n')
                    curl.chmod(0o755)
                    result = subprocess.run(
                        ['bash', '-euo', 'pipefail', '-c', script('Stage and verify immutable library source')],
                        cwd=root, env=dict(os.environ, PATH=f'{root}:' + os.environ['PATH'], LIBRARY=library),
                        capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Library source differs', result.stderr)
                    self.assertFalse((root / 'curl-was-called').exists())
    def test_worker_failure_stops_bundle_and_always_cleans_owned_container(self):
        for build_status in (0, 19):
            with self.subTest(status=build_status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'windows').mkdir()
                for name in ('qualify-glib-tls.py', 'run-glib-tls-qualification.ps1'):
                    (root / 'windows' / name).write_text('# source fixture')
                (root / 'build/glib-qualification/provenance').mkdir(parents=True)
                (root / 'build/glib-qualification/downloads').mkdir()
                for library in ('glib', 'cairo'):
                    (root / f'build/glib-qualification/downloads/{library}.tar.xz').write_bytes(b'fixture')
                docker = root / 'docker'
                docker.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with Path('docker-calls.jsonl').open('a') as handle:
    handle.write(json.dumps(args) + '\\n')
if args[0] == 'create':
    print('fixture-owned-container')
elif args[0] == 'inspect':
    print(os.environ['BUILD_STATUS'])
elif args[0] == 'cp' and args[1].endswith(':/tmp/qualification/bundle'):
    root = Path(args[2])
    for library in ('glib', 'cairo'):
        for lane in ('original', 'relinked', 'candidate'):
            (root / library / lane).mkdir(parents=True)
        (root / library / 'qualification.json').write_text('{}')
        (root / library / 'run-glib-tls-qualification.ps1').write_text('# fixture')
''')
                docker.chmod(0o755)
                result = subprocess.run(
                    ['bash', '-euo', 'pipefail', '-c', script('Cross-build in an isolated LLVM SDK worker')],
                    cwd=root, env=dict(os.environ, PATH=f'{root}:' + os.environ['PATH'],
                                       SDK_IMAGE='fixture@sha256:' + '1' * 64,
                                       BUILD_STATUS=str(build_status), LIBRARY=library), capture_output=True, text=True)
                self.assertEqual(result.returncode, build_status, result.stderr)
                calls = [json.loads(line) for line in (root / 'docker-calls.jsonl').read_text().splitlines()]
                create, = [call for call in calls if call[0] == 'create']
                for flag, value in (('--network', 'none'), ('--user', '1000:1000'),
                                    ('--cpus', '2'), ('--memory', '8g'), ('--memory-swap', '8g'),
                                    ('--pids-limit', '512'), ('--cap-drop', 'ALL'),
                                    ('--security-opt', 'no-new-privileges'), ('--ulimit', 'nofile=4096:4096')):
                    self.assertEqual(create[create.index(flag) + 1], value)
                self.assertNotIn('--volume', create)
                self.assertNotIn('--mount', create)
                command = create[-1]
                self.assertIn('--source-archive /tmp/qualification/downloads/glib.tar.xz', command)
                self.assertIn('--source-archive /tmp/qualification/downloads/cairo.tar.xz', command)
                self.assertLess(command.index('--library glib'), command.index('--library cairo'))
                self.assertIn('--glib-bundle /tmp/qualification/bundle/glib', command)
                self.assertIn('sh', create)
                self.assertIn('-eu', create)
                self.assertEqual(calls[-1], ['rm', '--force', 'fixture-owned-container'])
                self.assertEqual((root / 'build/glib-native-bundle').exists(), build_status == 0)

    def test_cairo_is_not_built_after_glib_failure(self):
        command = script('Cross-build in an isolated LLVM SDK worker').split("sh -eu -c '", 1)[1].split("\n  ')", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            python = root / 'python3'
            python.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> calls\nexit 23\n')
            python.chmod(0o755)
            result = subprocess.run(['sh', '-eu', '-c', command], cwd=root,
                                    env=dict(os.environ, PATH=f'{root}:' + os.environ['PATH']),
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 23, result.stderr)
            calls = (root / 'calls').read_text().splitlines()
            self.assertEqual(len(calls), 1)
            self.assertIn('--library glib', calls[0])
            self.assertNotIn('--library cairo', calls[0])

    def test_native_job_requires_build_and_strict_native_runner(self):
        text = WORKFLOW.read_text()
        native = text.split('  native-windows:', 1)[1]
        self.assertIn('needs: cross-build', native)
        self.assertIn('runs-on: windows-2025', native)
        self.assertIn('run-glib-tls-qualification.ps1', native)
        self.assertIn("foreach ($library in @('glib', 'cairo'))", native)
        self.assertIn('$metadata.library -ne $library', native)
        self.assertIn('$results.Count -ne 3', native)
        self.assertIn("'candidate,original,relinked'", native)
        self.assertIn('name: windows-glib-cairo-tls-native-bundle', native)
        self.assertNotIn('matrix.library', text)
        self.assertIn('if ($LASTEXITCODE -ne 0)', native)
        self.assertNotIn('continue-on-error', text)
        self.assertNotIn('packages:', text)
        self.assertNotIn('secrets.', text)
        self.assertNotIn('login-action', text)
        self.assertIn('  pull_request:\n    paths:', text)


if __name__ == '__main__':
    unittest.main()
