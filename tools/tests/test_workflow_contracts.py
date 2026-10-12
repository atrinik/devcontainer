# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Exercise workflow tag selection and image-selection fences without GitHub."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def workflow(name):
    return (ROOT / '.github/workflows' / name).read_text()


def step_script(name, step):
    text = workflow(name)
    start = text.index(f'      - name: {step}\n')
    block = text[start:].split('\n      - name: ', 1)[0]
    script = block.split('        run: |\n', 1)[1]
    lines = []
    for line in script.splitlines():
        if line.strip() and not line.startswith('          '):
            break
        lines.append(line[10:])
    return '\n'.join(lines) + '\n'


class WorkflowContracts(unittest.TestCase):
    def test_portable_public_ca_command_and_failure_are_mandatory(self):
        for name, image in (('validate.yml', 'atrinik-classic-portable:validation'),
                            ('publish-linux.yml', 'sha256:' + 'a' * 64)):
            for docker_exit in (0, 17):
                with self.subTest(workflow=name, docker_exit=docker_exit), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    docker = root / 'docker'
                    docker.write_text('#!/usr/bin/env python3\nimport json, os, sys\n'
                                      'from pathlib import Path\n'
                                      'Path(os.environ["DOCKER_CALL"]).write_text(json.dumps(sys.argv[1:]))\n'
                                      'print(json.dumps({"fixture": "public-ca"}))\n'
                                      'sys.exit(int(os.environ["DOCKER_EXIT"]))\n')
                    docker.chmod(0o755)
                    env = dict(os.environ, PATH=directory + ':' + os.environ['PATH'],
                               GITHUB_WORKSPACE=directory, DOCKER_CALL=str(root / 'docker-call.json'),
                               DOCKER_EXIT=str(docker_exit), IMAGE_ID=image, HTTPS_PROXY='http://fixture-user:fixture-password@invalid')
                    result = subprocess.run(['bash', '-euo', 'pipefail', '-c',
                                             step_script(name, 'Verify portable candidate public CA')],
                                            cwd=directory, env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, docker_exit, result.stderr)
                    argv = json.loads((root / 'docker-call.json').read_text())
                    self.assertEqual(argv[:4], ['run', '--rm', '--network', 'bridge'])
                    self.assertEqual(argv[argv.index('--user') + 1], f'{os.getuid()}:{os.getgid()}')
                    forwarded = [argv[index + 1] for index, value in enumerate(argv) if value == '--env']
                    self.assertEqual(set(forwarded), {'HOME=/tmp/portable-tls-home'} |
                                     {key + '=' for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
                                                           'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')})
                    mounts = [argv[index + 1] for index, value in enumerate(argv) if value == '--volume']
                    self.assertEqual(mounts, [directory + '/build/portable-classic/client/ca-bundle.crt:'
                                             '/workspace/client/ca-bundle.crt:ro'])
                    self.assertEqual(argv[argv.index(image):], [image, 'python3',
                                     '/opt/atrinik-portable/curl_evidence.py', '--public-ca',
                                     '/workspace/client/ca-bundle.crt'])
                    self.assertEqual(json.loads((root / 'build/portable-reports/public-ca.json').read_text()),
                                     {'fixture': 'public-ca'})

    def test_portable_public_ca_gate_precedes_consumer_and_publication(self):
        for name, loaded, consumer in (
                ('validate.yml', 'Load portable image', 'Build and test real non-root Classic client on the baseline'),
                ('publish-linux.yml', 'Load portable release candidate', 'Validate real portable consumer before publication')):
            text = workflow(name)
            load = text.index('      - name: ' + loaded)
            gate = text.index('      - name: Verify portable candidate public CA')
            consume = text.index('      - name: ' + consumer)
            self.assertLess(load, gate)
            self.assertLess(gate, consume)
            block = text[gate:consume]
            self.assertNotIn('continue-on-error', block)
            self.assertNotIn('        if:', block)
            self.assertIn('        shell: bash', block)
            self.assertIn('set -euo pipefail', block)
            if name == 'publish-linux.yml':
                self.assertLess(gate, text.index('      - name: Publish immutable portable candidate'))
                self.assertLess(gate, text.index('      - name: Promote validated Linux aliases'))

    def run_step(self, name, step, **values):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            env = dict(os.environ, GITHUB_OUTPUT=str(output),
                       GITHUB_REPOSITORY_OWNER='Atrinik', GITHUB_SHA='a' * 40,
                       GITHUB_REF_TYPE='branch', GITHUB_REF_NAME='review',
                       CANDIDATE_ONLY='false')
            env.update(values)
            subprocess.run(['bash', '-euo', 'pipefail', '-c',
                            step_script(name, step)], env=env, check=True,
                           capture_output=True, text=True)
            return output.read_text()

    def test_linux_candidates_never_include_release_aliases(self):
        for step, image in (('Select image tags', 'linux-build'),
                            ('Select Classic image tags', 'classic-build')):
            for ref_type in ('branch', 'tag'):
                with self.subTest(step=step, ref_type=ref_type):
                    result = self.run_step('publish-linux.yml', step,
                                           IMAGE_NAME=image, CANDIDATE_ONLY='true',
                                           GITHUB_REF_TYPE=ref_type,
                                           GITHUB_REF_NAME='v9.8.7')
                    tags = result.split('tags<<EOF\n')[1].split('\nEOF')[0]
                    self.assertEqual(tags, f'ghcr.io/atrinik/{image}:candidate-sha-' + 'a' * 40)
        portable = self.run_step('publish-linux.yml', 'Select immutable portable tag',
                                 CANDIDATE_ONLY='true')
        self.assertEqual(portable, 'tag=ghcr.io/atrinik/classic-portable-build:candidate-sha-' + 'a' * 40 + '\n')

    def test_linux_release_preserves_version_and_platform_tags(self):
        result = self.run_step('publish-linux.yml', 'Select image tags',
                               IMAGE_NAME='linux-build', GITHUB_REF_TYPE='tag',
                               GITHUB_REF_NAME='v9.8.7')
        self.assertIn('linux-build:latest', result)
        self.assertIn('linux-build:ubuntu-26.04', result)
        self.assertIn('linux-build:9.8.7', result)
        self.assertNotIn('candidate-sha-', result)

    def test_windows_candidate_and_release_tag_names(self):
        for candidate in ('true', 'false'):
            with self.subTest(candidate=candidate):
                result = self.run_step('publish-windows.yml', 'Select image tags',
                                       CANDIDATE_ONLY=candidate,
                                       GITHUB_REF_TYPE='tag', GITHUB_REF_NAME='v9.8.7')
                prefix = 'candidate-' if candidate == 'true' else ''
                self.assertIn(f'general_sha_tag=ghcr.io/atrinik/windows-build:{prefix}sha-' + 'a' * 40, result)
                self.assertIn(f'check_sha_tag=ghcr.io/atrinik/windows-build:classic-check-{prefix}sha-' + 'a' * 40, result)
                self.assertNotIn(':latest', result)
                self.assertNotIn(':llvm', result)
                self.assertNotIn(':9.8.7', result)

    def test_candidate_mode_keeps_qualification_and_fences_promotion(self):
        linux = workflow('publish-linux.yml')
        self.assertEqual(linux.count('if: ${{ !inputs.candidate_only }}'), 1)
        self.assertIn('Promote validated Linux aliases\n        if: ${{ !inputs.candidate_only }}', linux)
        for target in ('target: classic-validation', 'target: validation',
                       'target: portable-validation'):
            self.assertIn(target, linux)
        self.assertIn('/image-source/tools/validate-classic-check.sh /workspace', linux)
        self.assertIn('/opt/atrinik-portable/consumer.sh /classic /reports', linux)
        windows = workflow('publish-windows.yml')
        self.assertIn('name: Promote verified Windows image aliases\n    if: ${{ !inputs.candidate_only }}', windows)
        native = windows.split('  windows-native:', 1)[1].split('  promote:', 1)[0]
        self.assertNotIn('candidate_only', native)
        self.assertIn('run-classic-native-tests.ps1', native)

    def test_linux_publish_uses_only_sha_tags_then_fences_every_alias(self):
        text = workflow('publish-linux.yml')
        for step, output in (('Build and publish Linux image', 'metadata.outputs.publish_tag'),
                             ('Build and publish Classic image', 'classic-metadata.outputs.publish_tag'),
                             ('Publish immutable portable candidate', 'portable-metadata.outputs.tag')):
            block = text.split('      - name: ' + step + '\n')[1].split('\n      - name: ')[0]
            self.assertIn('tags: ${{ steps.' + output + ' }}', block)
            self.assertNotIn('outputs.tags', block)
        fence = text.index('      - name: Verify all published image identities')
        upload = text.index('      - name: Retain published identity evidence')
        promote = text.index('      - name: Promote validated Linux aliases')
        self.assertLess(text.index('      - name: Publish immutable portable candidate'), fence)
        self.assertLess(fence, upload)
        self.assertLess(upload, promote)
        for block in (text[fence:upload], text[upload:promote]):
            self.assertNotIn('continue-on-error', block)
            self.assertNotIn('        if:', block)
        self.assertIn('if-no-files-found: error', text[upload:promote])
        for candidate in ('false', 'true'):
            for step, image in (('Select image tags', 'linux-build'),
                                ('Select Classic image tags', 'classic-build')):
                result = self.run_step('publish-linux.yml', step, IMAGE_NAME=image,
                                       CANDIDATE_ONLY=candidate)
                prefix = 'candidate-' if candidate == 'true' else ''
                self.assertIn(f'publish_tag=ghcr.io/atrinik/{image}:{prefix}sha-' + 'a' * 40, result)

    def test_linux_runtime_checks_use_captured_ids(self):
        text = workflow('publish-linux.yml')
        checks = {
            'classic': ['Qualify Classic cancellation and public TLS before publication',
                        'Run Classic client and server checks before publication'],
            'broad': ['Qualify broad Linux cancellation and public TLS before publication'],
            'portable': ['Verify portable candidate public CA',
                         'Validate real portable consumer before publication'],
        }
        for target, names in checks.items():
            captured = text.index('      - name: Capture loaded ' + target + ' image identity')
            for name in names:
                start = text.index('      - name: ' + name + '\n')
                self.assertLess(captured, start)
                block = text[start:].split('\n      - name: ')[0]
                self.assertIn('IMAGE_ID: ${{ steps.' + target + '-identity.outputs.image_id }}', block)
                self.assertIn('"${IMAGE_ID}"', block)
                self.assertNotIn(':qualification', block)
                self.assertNotIn(':release-validation', block)

    def test_published_fence_stops_on_first_failed_identity(self):
        for failed in ('none', 'broad', 'classic', 'portable'):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                command = root / 'python3'
                command.write_text('#!/usr/bin/env python3\nimport os, sys\n'
                    'from pathlib import Path\n'
                    'target = sys.argv[sys.argv.index("--target") + 1]\n'
                    'with Path(os.environ["CALLS"]).open("a") as out: out.write(target + "\\n")\n'
                    'sys.exit(19 if target == os.environ["FAIL_TARGET"] else 0)\n')
                # Avoid recursively selecting the fake python interpreter.
                command.write_text(command.read_text().replace('#!/usr/bin/env python3', '#!/usr/bin/python3'))
                command.chmod(0o755)
                env = dict(os.environ, PATH=directory + ':' + os.environ['PATH'],
                           CALLS=str(root / 'calls'), FAIL_TARGET=failed,
                           BROAD_DIGEST='sha256:' + 'a' * 64, CLASSIC_DIGEST='sha256:' + 'b' * 64,
                           PORTABLE_DIGEST='sha256:' + 'c' * 64)
                result = subprocess.run(['bash', '-euo', 'pipefail', '-c',
                    step_script('publish-linux.yml', 'Verify all published image identities')],
                    env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0 if failed == 'none' else 19)
                targets = ['broad', 'classic', 'portable']
                expected = targets if failed == 'none' else targets[:targets.index(failed) + 1]
                self.assertEqual((root / 'calls').read_text().splitlines(), expected)

    def test_linux_alias_promotion_uses_verified_digests_and_stops_on_failure(self):
        for fail_call in (0, 2):
            with self.subTest(fail_call=fail_call), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                docker = root / 'docker'
                docker.write_text('#!/usr/bin/python3\nimport json, os, sys\n'
                    'from pathlib import Path\n'
                    'path = Path(os.environ["CALLS"])\n'
                    'calls = json.loads(path.read_text()) if path.exists() else []\n'
                    'calls.append(sys.argv[1:]); path.write_text(json.dumps(calls))\n'
                    'sys.exit(17 if len(calls) == int(os.environ["FAIL_CALL"]) else 0)\n')
                docker.chmod(0o755)
                digests = ['sha256:' + char * 64 for char in 'abc']
                env = dict(os.environ, PATH=directory + ':' + os.environ['PATH'],
                    CALLS=str(root / 'calls'), FAIL_CALL=str(fail_call),
                    BROAD_DIGEST=digests[0], CLASSIC_DIGEST=digests[1], PORTABLE_DIGEST=digests[2],
                    GITHUB_REPOSITORY_OWNER='Atrinik', GITHUB_REF_TYPE='tag', GITHUB_REF_NAME='v9.8.7',
                    GITHUB_STEP_SUMMARY=str(root / 'summary'))
                result = subprocess.run(['bash', '-euo', 'pipefail', '-c',
                    step_script('publish-linux.yml', 'Promote validated Linux aliases')],
                    env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0 if fail_call == 0 else 1, result.stderr)
                calls = json.loads((root / 'calls').read_text())
                self.assertEqual(len(calls), 3 if fail_call == 0 else 2)
                for index, call in enumerate(calls):
                    image = 'ghcr.io/atrinik/' + ['linux-build', 'classic-build', 'classic-portable-build'][index]
                    platform = ['ubuntu-26.04', 'ubuntu-26.04', 'debian-12'][index]
                    self.assertEqual(call, ['buildx', 'imagetools', 'create', '--tag', image + ':latest',
                        '--tag', image + ':' + platform, '--tag', image + ':9.8.7', image + '@' + digests[index]])
                if fail_call:
                    self.assertIn('Rerun the failed job in this workflow run', result.stderr)

    def test_shared_llvm_inputs_select_every_image(self):
        script = step_script('validate.yml', 'Detect image changes')
        inputs = ('llvm-toolchain.json', 'llvm-bootstrap-packages.lock',
                  'tools/install_llvm_toolchain.py', 'tools/validate_llvm_toolchain.py',
                  'tools/tests/test_install_llvm_toolchain.py',
                  'tools/tests/test_workflow_contracts.py')
        for changed in inputs:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                git = Path(directory) / 'git'
                git.write_text('#!/bin/sh\nprintf "%s\\n" "$CHANGED_PATH"\n')
                git.chmod(0o755)
                output = Path(directory) / 'output'
                env = dict(os.environ, PATH=directory + ':' + os.environ['PATH'],
                           GITHUB_OUTPUT=str(output), CHANGED_PATH=changed,
                           BASE_SHA='b' * 40, HEAD_SHA='a' * 40)
                subprocess.run(['bash', '-euo', 'pipefail', '-c', script],
                               env=env, check=True, capture_output=True, text=True)
                self.assertEqual(set(output.read_text().splitlines()),
                                 {'portable=true', 'classic=true', 'linux=true', 'windows=true'})

    def test_pr_workflow_remains_private_package_free_and_strict(self):
        text = workflow('validate.yml')
        self.assertNotIn('packages:', text)
        self.assertNotIn('docker/login-action', text)
        self.assertNotIn('type=registry', text)
        self.assertIn('name: Required checks', text)
        self.assertIn('if: always()', text.split('  required:', 1)[1])
        self.assertIn('name: Shared LLVM source toolchain', text)
        self.assertIn('target: llvm-toolchain', text)
        self.assertEqual(text.count('needs: [changes, llvm]'), 4)
        self.assertIn('      - llvm', text.split('  required:', 1)[1])
        self.assertIn('WINDOWS_NATIVE_RESULT:', text)
        self.assertIn('PORTABLE_RESULT:', text)
        for name in ('validate.yml', 'publish-linux.yml', 'publish-windows.yml',
                     'measure-classic-check.yml'):
            uses = re.findall(r'uses: ([^\s]+)', workflow(name))
            self.assertTrue(all(re.search(r'@[0-9a-f]{40}$', action) for action in uses))
            self.assertNotIn('MXE_BUILD_JOBS', workflow(name))
            self.assertNotIn('scope=windows-build-image\n', workflow(name))


if __name__ == '__main__':
    unittest.main()
