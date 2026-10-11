# Copyright 2026 The Atrinik Project
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'verify-pe-imports.sh'

class PEImportContractTests(unittest.TestCase):
    def inspect(self, output, expected):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / 'example.dll'; pe.write_bytes(b'fixture')
            reader = root / 'reader'; reader.write_text('#!/bin/sh\ncat <<\'EOF\'\n' + output + '\nEOF\n'); reader.chmod(0o755)
            return subprocess.run(['bash', str(SCRIPT), str(reader), str(pe), *expected], capture_output=True, text=True)

    def test_llvm_import_and_delay_import_contract(self):
        result = self.inspect('Format: COFF-x86-64\nImport {\n Name: KERNEL32.dll\n}\nDelayImport {\n Name: SDL3.dll\n}\n', ['SDL3.dll','kernel32.dll'])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_architecture_fails(self):
        result = self.inspect('Format: COFF-i386\nImport {\n Name: KERNEL32.dll\n}\n', ['kernel32.dll'])
        self.assertNotEqual(result.returncode, 0)

    def test_missing_runtime_fails(self):
        result = self.inspect('Format: COFF-x86-64\nImport {\n Name: KERNEL32.dll\n}\n', ['kernel32.dll','SDL3.dll'])
        self.assertNotEqual(result.returncode, 0)
