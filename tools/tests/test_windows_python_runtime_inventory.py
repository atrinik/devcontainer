# Copyright 2026 The Atrinik Project
from pathlib import Path
import hashlib
import importlib.util
import os
import stat
import tempfile
import unittest
from unittest import mock

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

    def test_permissions_preserve_bytes_owner_and_executable_bits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'runtime'; self.fixture(root)
            (root / 'python.exe').write_bytes(b'executable')
            paths = [root, *root.rglob('*')]
            for path in paths:
                path.chmod(0o777 if path.is_dir() or path.suffix == '.exe' else 0o666)
            before = {path: path.stat() for path in paths}
            contents = {path: path.read_bytes() for path in paths if path.is_file()}
            value = MODULE.inventory(root, Path(temporary) / 'inventory.json')
            for path in paths:
                info = path.stat()
                self.assertEqual(stat.S_IMODE(info.st_mode), stat.S_IMODE(before[path].st_mode) & ~0o022)
                self.assertEqual((info.st_uid, info.st_gid, info.st_ino),
                                 (before[path].st_uid, before[path].st_gid, before[path].st_ino))
            for path, data in contents.items():
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(value['files'][path.relative_to(root).as_posix()]['sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(MODULE.inventory(root, Path(temporary) / 'inventory.json'), value)

    def test_invalid_complete_inputs_never_partially_change_modes(self):
        cases = ('symlink', 'fifo', 'hardlink', 'collision', 'directory_collision',
                 'unsafe_name', 'missing_python', 'missing_vcruntime', 'inside_output',
                 'linked_output', 'linked_output_parent', 'special_output')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = base / 'runtime'; self.fixture(root)
                output = base / 'inventory.json'
                if case == 'symlink': (root / 'zz-bad').symlink_to('python314.dll')
                elif case == 'fifo': os.mkfifo(root / 'zz-bad')
                elif case == 'hardlink': os.link(root / 'python314.dll', root / 'zz-bad')
                elif case == 'collision': (root / 'PYTHON314.dll').write_bytes(b'collision')
                elif case == 'directory_collision': (root / 'NESTED').mkdir()
                elif case == 'unsafe_name': (root / 'zz:bad').write_bytes(b'bad')
                elif case == 'missing_python': (root / 'python314.dll').unlink()
                elif case == 'missing_vcruntime': (root / 'vcruntime140.dll').unlink()
                elif case == 'inside_output': output = root / 'receipt.json'
                elif case == 'linked_output': output.symlink_to(base / 'outside')
                elif case == 'linked_output_parent':
                    (base / 'alias').symlink_to(base, target_is_directory=True)
                    output = base / 'alias' / 'receipt.json'
                elif case == 'special_output': os.mkfifo(output)
                paths = [root, *root.rglob('*')]
                for path in paths:
                    if not path.is_symlink(): path.chmod(0o777 if path.is_dir() else 0o666)
                modes = {path: stat.S_IMODE(path.lstat().st_mode) for path in paths}
                with mock.patch.object(MODULE.os, 'fchmod', wraps=os.fchmod) as chmod:
                    with self.assertRaises(ValueError): MODULE.inventory(root, output)
                    chmod.assert_not_called()
                self.assertEqual({path: stat.S_IMODE(path.lstat().st_mode) for path in paths}, modes)

    def test_linked_root_and_parent_traversal_rejected_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / 'runtime'; self.fixture(root)
            root.chmod(0o777)
            (base / 'alias').symlink_to(root, target_is_directory=True)
            (base / 'parent_alias').symlink_to(base, target_is_directory=True)
            for candidate in (base / 'alias', base / 'parent_alias/runtime', root / '..' / 'runtime'):
                with self.subTest(candidate=candidate), mock.patch.object(MODULE.os, 'fchmod') as chmod:
                    with self.assertRaises(ValueError): MODULE.inventory(candidate, base / 'receipt.json')
                    chmod.assert_not_called()
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o777)

    def test_changed_tree_is_rejected_before_mode_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / 'runtime'; self.fixture(root)
            (root / 'python314.dll').chmod(0o666)
            original_read = os.read
            inserted = False
            def changing_read(fd, size):
                nonlocal inserted
                data = original_read(fd, size)
                if not inserted:
                    (root / 'late.pyd').write_bytes(b'late')
                    inserted = True
                return data
            with mock.patch.object(MODULE.os, 'read', side_effect=changing_read), mock.patch.object(MODULE.os, 'fchmod') as chmod:
                with self.assertRaisesRegex(ValueError, 'changed'): MODULE.inventory(root, base / 'receipt.json')
                chmod.assert_not_called()
            self.assertEqual(stat.S_IMODE((root / 'python314.dll').stat().st_mode), 0o666)
