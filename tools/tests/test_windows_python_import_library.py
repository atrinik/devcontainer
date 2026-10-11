# Copyright 2026 The Atrinik Project
from pathlib import Path
import importlib.util
import unittest

SPEC = importlib.util.spec_from_file_location('python_import', Path(__file__).resolve().parents[2] / 'windows/python-import-library.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

EXPORTS = '''Format: COFF-x86-64
Export {
 Name: Py_Initialize
 RVA: 0x1010
}
Export {
 Name: PyExc_RuntimeError
 RVA: 0x2010
}
'''
SECTIONS = '''Section {
 VirtualAddress: 0x1000
 VirtualSize: 0x100
 Characteristics [
 IMAGE_SCN_MEM_EXECUTE
 ]
}
Section {
 VirtualAddress: 0x2000
 VirtualSize: 0x100
  }
'''

class DefinitionTests(unittest.TestCase):
    def test_data_export_is_preserved(self):
        result = MODULE.definition(EXPORTS, SECTIONS, 'python314.dll')
        self.assertIn('PyExc_RuntimeError DATA\n', result)
        self.assertIn('Py_Initialize\n', result)

    def test_unknown_rva_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'Unresolved'):
            MODULE.definition(EXPORTS.replace('0x2010','0x9010'), SECTIONS, 'python314.dll')

    def test_wrong_architecture_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'x86_64'):
            MODULE.definition(EXPORTS.replace('COFF-x86-64','COFF-i386'), SECTIONS, 'python314.dll')
