# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_pe_tls import fixture, TLS

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'windows'))
try:
    SPEC = importlib.util.spec_from_file_location('tls_qualification', ROOT / 'windows/qualify-glib-tls.py')
    QUALIFY = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(QUALIFY)
finally:
    sys.path.pop(0)


class RepairedDependencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / 'bundle'
        self.candidate = self.bundle / 'candidate/libglib-2.0-0.dll'
        self.candidate.parent.mkdir(parents=True)
        (self.bundle / 'build-evidence').mkdir()
        data, self.symbols = fixture()
        self.candidate.write_bytes(data)
        (self.candidate.parent / 'atrinik-glib-tls-probe.exe').write_bytes(b'probe fixture')
        self.tls = TLS.inspect_callback(data, self.symbols, 'glib')
        (self.bundle / 'build-evidence/glib-tls.json').write_text(json.dumps(self.tls))
        lock = QUALIFY.BUILDER.load_lock(ROOT / 'windows/dependencies.json')
        self.items = {item['name']: item for item in lock['dependencies']}
        self.metadata = {'schema_version': 1, 'library': 'glib', 'source_sha256': self.items['glib']['sha256'],
                         'provenance': QUALIFY.source_provenance(self.items, 'glib'), 'tls': self.tls}
        self.seal()
        self.inspect = patch.object(QUALIFY, 'inspect_file', side_effect=lambda path, llvm, library:
                                    TLS.inspect_callback(path.read_bytes(), self.symbols, library))
        self.inspect.start()
        self.addCleanup(self.inspect.stop)

    def seal(self):
        self.metadata['files'] = {p.relative_to(self.bundle).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in self.bundle.rglob('*') if p.is_file() and p.name != 'qualification.json'}
        (self.bundle / 'qualification.json').write_text(json.dumps(self.metadata))

    def validate(self):
        return QUALIFY.validated_glib_dependency(self.bundle, self.items, Path('/llvm'), self.root / 'sdk')

    def test_accepts_sealed_registered_dependency(self):
        path, record = self.validate()
        self.assertEqual(path, self.candidate)
        self.assertEqual(record['sha256'], self.tls['sha256'])

    def test_rejects_missing_or_wrong_source_bundle(self):
        with self.assertRaisesRegex(ValueError, 'requires --glib-bundle'):
            QUALIFY.validated_glib_dependency(None, self.items, Path('/llvm'), self.root)
        self.metadata['source_sha256'] = '0' * 64
        self.seal()
        with self.assertRaisesRegex(ValueError, 'source/provenance'):
            self.validate()

    def test_rejects_tampered_dependency_bytes(self):
        self.candidate.write_bytes(self.candidate.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'changed GLib dependency evidence'):
            self.validate()

    def test_rejects_resealed_missing_registration(self):
        data = bytearray(self.candidate.read_bytes())
        struct.pack_into('<II', data, 0x98 + 184, 0, 0)
        self.candidate.write_bytes(data)
        self.seal()
        with self.assertRaisesRegex(ValueError, 'TLS directory'):
            self.validate()

    def test_rejects_stale_recipe_and_mixed_supporting_runtime(self):
        self.metadata['provenance']['recipe_sha256'] = '0' * 64
        self.seal()
        with self.assertRaisesRegex(ValueError, 'source/provenance'):
            self.validate()
        self.metadata['provenance'] = QUALIFY.source_provenance(self.items, 'glib')
        (self.candidate.parent / 'different.dll').write_bytes(b'foreign runtime')
        self.seal()
        with self.assertRaisesRegex(ValueError, 'different supporting SDK runtime'):
            self.validate()


if __name__ == '__main__':
    unittest.main()
