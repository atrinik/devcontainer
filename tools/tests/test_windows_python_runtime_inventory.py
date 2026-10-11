# Copyright 2026 The Atrinik Project
from pathlib import Path
import hashlib
import importlib.util
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('python_runtime_inventory', Path(__file__).resolve().parents[2] / 'windows/python-runtime-inventory.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

class RuntimeInventoryTests(unittest.TestCase):
    def fixture(self, root):
        root.mkdir()
        (root / 'python314.dll').write_bytes(b'python')
        (root / 'vcruntime140.dll').write_bytes(b'external runtime')
        (root / 'nested').mkdir()
        (root / 'nested/module.pyd').write_bytes(b'extension')

    def test_nested_runtime_files_are_hashed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'runtime'; self.fixture(root)
            value = MODULE.inventory(root, Path(temporary) / 'inventory.json')
            self.assertEqual(value['files']['nested/module.pyd']['sha256'], hashlib.sha256(b'extension').hexdigest())

    def test_inventory_inside_runtime_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'runtime'; self.fixture(root)
            with self.assertRaisesRegex(ValueError, 'outside'):
                MODULE.inventory(root, root / 'inventory.json')

    def test_symlink_runtime_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'runtime'; self.fixture(root)
            (root / 'alias.dll').symlink_to('python314.dll')
            with self.assertRaisesRegex(ValueError, 'Symlinks'):
                MODULE.inventory(root, Path(temporary) / 'inventory.json')
