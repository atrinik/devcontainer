# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Exercise workflow tag selection and image-selection fences without GitHub."""
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
    return '\n'.join(line[10:] for line in script.splitlines()) + '\n'


class WorkflowContracts(unittest.TestCase):
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
        self.assertIn('Promote validated portable aliases\n        if: ${{ !inputs.candidate_only }}', linux)
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
