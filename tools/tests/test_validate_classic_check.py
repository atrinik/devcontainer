# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Run the Classic producer harness with command-capture tool fixtures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOL = '''#!/usr/bin/python3
import json, os, sys
from pathlib import Path

name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['CALL_LOG'], 'a') as log:
    log.write(json.dumps([Path.cwd().name, name, args]) + '\\n')
if name == 'python3' and 'export' in args:
    if os.environ.get('FAIL_EXPORT') == 'true':
        sys.exit(19)
    Path(args[args.index('--output') + 1]).write_text('fixture coverage\\n')
if name == 'ccache' and args == ['--print-stats']:
    counter = Path(os.environ['HIT_COUNTER'])
    hits = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(str(hits))
    print('direct_cache_hit\\t' + str(hits))
'''


class ClassicCheckHarnessTests(unittest.TestCase):
    def run_harness(self, *, fail_export=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'classic'
            for relative in ('cmake/toolchains/llvm.cmake', 'tools/ci/llvm_coverage.py'):
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            for component in ('server', 'client'):
                (source / component).mkdir()
            tools = root / 'bin'
            tools.mkdir()
            for name in ('python3', 'cmake', 'ctest', 'ccache'):
                executable = tools / name
                executable.write_text(TOOL)
                executable.chmod(0o755)
            cache = root / 'cache'
            cache.mkdir()
            cache.chmod(0o1777)
            log = root / 'calls.jsonl'
            env = dict(os.environ, PATH=str(tools) + ':' + os.environ['PATH'],
                       HOME=str(root / 'home'), CCACHE_DIR=str(cache),
                       CALL_LOG=str(log), HIT_COUNTER=str(root / 'hits'),
                       FAIL_EXPORT=str(fail_export).lower())
            result = subprocess.run(['bash', str(ROOT / 'tools/validate-classic-check.sh'),
                                     str(source)], cwd=root, env=env,
                                    capture_output=True, text=True)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            return result, calls, str(source)

    def test_server_coverage_disables_pch_and_preserves_strict_pipeline(self):
        result, calls, source = self.run_harness()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[0][1:], ['python3', [
            '/usr/local/bin/atrinik-validate-llvm-toolchain', '--manifest',
            '/opt/llvm-23.1.3/share/atrinik/llvm-toolchain.json', '--prefix',
            '/opt/llvm-23.1.3']])
        for component in ('server', 'client'):
            with self.subTest(component=component):
                commands = [(name, args) for cwd, name, args in calls if cwd == component]
                self.assertEqual(commands[:3], [
                    ('python3', ['-m', 'unittest', 'discover', '-s', 'tools/tests', '-p', 'test_*.py']),
                    ('python3', ['tools/dependencies.py', 'sync']),
                    ('python3', ['tools/dependencies.py', 'verify'])])
                configure = commands[3]
                options = ['-DENABLE_PRECOMPILED_HEADERS=OFF'] if component == 'server' else []
                self.assertEqual(configure, ('cmake', ['--preset', 'llvm-coverage'] + options + [
                    '-DCMAKE_TOOLCHAIN_FILE=' + source + '/cmake/toolchains/llvm.cmake',
                    '-DCMAKE_C_COMPILER_LAUNCHER=ccache',
                    '-DFETCHCONTENT_SOURCE_DIR_ATRINIK_PROTOCOL=' + source + '/protocol',
                    '-DFETCHCONTENT_SOURCE_DIR_LIBATRINIK=' + source + '/libatrinik']))
                build = commands[4]
                self.assertEqual(build[0], 'cmake')
                self.assertEqual(build[1][:-1], ['--build', '--preset', 'llvm-coverage',
                                                '--clean-first', '--parallel'])
                self.assertGreater(int(build[1][-1]), 0)
                self.assertEqual(commands[5:8], [
                    ('python3', [source + '/tools/ci/llvm_coverage.py', 'prepare',
                                 '--build-dir', 'build/llvm-coverage']),
                    ('ctest', ['--preset', 'llvm-coverage']),
                    ('python3', [source + '/tools/ci/llvm_coverage.py', 'export',
                                 '--build-dir', 'build/llvm-coverage', '--source-root', source,
                                 '--component', component, '--output', component + '-coverage.lcov'])])
                self.assertEqual(commands[8:], [
                    ('ccache', ['--print-stats']), build, ('ccache', ['--print-stats'])])

    def test_strict_export_failure_stops_before_warm_rebuild_and_client(self):
        result, calls, _ = self.run_harness(fail_export=True)
        self.assertEqual(result.returncode, 19, result.stderr)
        self.assertEqual(calls[-1][0], 'server')
        self.assertIn('export', calls[-1][2])
        self.assertFalse(any(cwd == 'client' for cwd, _, _ in calls))
        self.assertFalse(any(name == 'ccache' and args == ['--print-stats']
                             for _, name, args in calls))


if __name__ == '__main__':
    unittest.main()
