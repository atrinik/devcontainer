# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Offline exact-filesystem versus Docker-stream acceptance fixtures."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


C = load('collector_for_scanner', 'tools/collect-released-sdk-metadata.py')
S = load('filesystem_scanner', 'tools/scan-released-sdk-filesystem.py')
I = S.I
TARGET = 'portable-final-fixture'
POLICY = {'producer_revision': 'a' * 40, 'consumer_commit': 'b' * 40,
          'manifest_digest': 'sha256:' + 'c' * 64, 'config_digest': 'sha256:' + 'd' * 64}


class Response(io.BytesIO):
    chunked = True
    length = None


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # Fixture permissions remain real/non-root; emulate root-owned image
        # stat ownership only, with explicit wrong-owner/drift controls below.
        self.stat_uid = 0
        self.stat_gid = 0
        for name in ('stat', 'fstat'):
            original = getattr(S.os, name)
            def owned_stat(*args, _original=original, **kwargs):
                info = _original(*args, **kwargs)
                fields = {key: getattr(info, key) for key in dir(info) if key.startswith('st_')}
                return SimpleNamespace(**(fields | {'st_uid': self.stat_uid, 'st_gid': self.stat_gid}))
            operation = patch.object(S.os, name, side_effect=owned_stat)
            operation.start()
            self.addCleanup(operation.stop)
        self.root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.root_fd)
        for operation in (patch.object(C, 'https_get', side_effect=AssertionError('network forbidden')),
                          patch.object(C.LocalConnection, 'connect', side_effect=AssertionError('Docker forbidden'))):
            operation.start()
            self.addCleanup(operation.stop)

    def put(self, path, raw, mode=0o644):
        result = self.root / path.removeprefix('/')
        result.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        result.write_bytes(raw)
        result.chmod(mode)
        return result

    def fixture(self):
        source = b'fixture corresponding source'
        sha = hashlib.sha256(source).hexdigest()
        # Reuse actual producer schemas and complete declared archive families.
        archive_fixtures = load('scanner_source_fixtures', 'tools/tests/test_released_sdk_inventory.py')
        payloads, runtime, contract = archive_fixtures.InventoryTests().manifest_fixture()
        for path, raw in payloads.items():
            self.put(I.ROOT + '/' + path, raw)
        tools = {}
        for role, path in I.BUILD_TOOLS.items():
            raw = ('fixture ' + role).encode()
            self.put(path, raw, 0o755)
            tools[role] = {'path': path, 'resolved_path': path, 'sha256': hashlib.sha256(raw).hexdigest(),
                           'size': len(raw), 'executable': True,
                           'version': 'cmake version 3.25.1\n' if role == 'cmake' else '1.11.1'}
        for declared, canonical in I.LLVM_TOOL_FILES.values():
            self.put(I.LLVM_PREFIX + '/' + canonical, b'llvm fixture', 0o755 if '/bin/' in '/' + canonical else 0o644)
            if declared != canonical:
                link = self.root / (I.LLVM_PREFIX + '/' + declared).removeprefix('/')
                if not link.exists():
                    link.symlink_to(Path(canonical).name)
        docs = {name: {} for name in I.METADATA_FILES}
        docs['contract.json'] = contract
        docs['contract.json']['consumer']['commit'] = POLICY['consumer_commit']
        docs['installed.json'] = {'build_tools': {'schema_version': 1, 'tools': tools},
                                  'tools': {role: item['version'].splitlines()[0] for role, item in tools.items()}}
        docs['runtime-sources.json'] = {**runtime, 'source_packages': {'foo': '1'}}
        for role, provider in runtime['custom_providers'].items():
            self.put(provider['path'], role.encode())
        docs['debian-sources.json'] = [{'package': 'foo', 'source': 'foo', 'source_version': '1',
                                       'notice_directory': I.DOC + '/foo'}]
        docs['shader-generation.json'] = {'source_commit': POLICY['consumer_commit'],
                                         'source_inputs': {'client/shaders/source': sha}}
        self.put(I.ROOT + '/sources/classic-shaders/client/shaders/source', source)
        for name, data in docs.items():
            self.put(I.ROOT + '/' + name, encoded(data))
        self.put(I.ROOT + '/unrelated-empty', b'')
        self.put(I.DOC + '/foo/copyright', b'copyright')
        for name in I.COMMON_LICENSE_NAMES:
            self.put(I.COMMON + '/' + name, name.encode())
        return docs

    def test_complete_scan_and_independent_omitted_file_detection(self):
        self.fixture()
        actual = S.scan(self.root_fd)
        self.assertEqual(set(actual['metadata']), set(I.METADATA_FILES))
        self.assertEqual(len(actual['build_tools']), 3)
        self.assertEqual(len(actual['llvm_tools']), 12)
        self.assertTrue(actual['image_code_executed'])
        I.compare_scan(actual, actual)
        omitted = copy.deepcopy(actual)
        del omitted['inventories']['producer']['unrelated-empty']
        omitted['inventory_sha256']['producer'] = I.inventory_digest(omitted['inventories']['producer'])
        with self.assertRaisesRegex(I.InventoryError, 'scanner-inventory-mismatch'):
            I.compare_scan(actual, omitted)
        for section in ('producer', 'debian_notices', 'common_licenses'):
            altered = copy.deepcopy(actual)
            del altered['inventories'][section][next(iter(altered['inventories'][section]))]
            with self.subTest(section=section), self.assertRaises(I.InventoryError):
                I.compare_scan(actual, altered)

    def test_source_manifests_retained_and_bound_without_serializing_payloads(self):
        self.fixture()
        producer = S.Filesystem(self.root_fd).tree()
        self.assertIsInstance(producer, I.ProducerInventory)
        self.assertEqual(set(producer.source_manifests), set(I.SOURCE_MANIFESTS))
        for name, raw in producer.source_manifests.items():
            self.assertEqual(producer[name]['size'], len(raw))
            self.assertEqual(producer[name]['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertNotIn('source_manifests', json.loads(encoded(producer)))
        self.assertEqual(producer['unrelated-empty']['size'], 0)

    def test_manifest_missing_empty_and_oversize_fail_before_payload_read(self):
        self.fixture()
        for name in I.SOURCE_MANIFESTS:
            path = self.root / (I.ROOT + '/' + name).removeprefix('/')
            saved = path.read_bytes()
            for size in (None, 0, I.MAX_MANIFEST + 1):
                with self.subTest(name=name, size=size):
                    if size is None:
                        path.unlink()
                    else:
                        path.write_bytes(b'x' * size)
                    fs = S.Filesystem(self.root_fd)
                    record = fs.record
                    def bounded(path, **kwargs):
                        if path == I.ROOT + '/' + name:
                            with patch.object(S.os, 'read', side_effect=AssertionError('payload read forbidden')):
                                return record(path, **kwargs)
                        return record(path, **kwargs)
                    with patch.object(fs, 'record', side_effect=bounded):
                        with self.assertRaises((I.InventoryError, FileNotFoundError)):
                            fs.tree()
                    path.write_bytes(saved)

    def test_manifest_replacement_between_preread_and_tree_is_rejected(self):
        self.fixture()
        for name in I.SOURCE_MANIFESTS:
            fs = S.Filesystem(self.root_fd)
            original = fs.record
            def record(path, **kwargs):
                result = original(path, **kwargs)
                if path == I.ROOT + '/' + name and kwargs.get('retain'):
                    actual = self.root / path.removeprefix('/')
                    replacement = actual.with_suffix('.replacement')
                    replacement.write_bytes(actual.read_bytes())
                    replacement.replace(actual)
                return result
            with self.subTest(name=name), patch.object(fs, 'record', side_effect=record):
                with self.assertRaises(I.InventoryError):
                    fs.tree()

    def test_retained_manifest_payload_hash_and_size_must_match_tree(self):
        self.fixture()
        for name in I.SOURCE_MANIFESTS:
            for mismatch in ('hash', 'size'):
                fs = S.Filesystem(self.root_fd)
                original = fs.record
                def record(path, **kwargs):
                    identity, raw = original(path, **kwargs)
                    if path == I.ROOT + '/' + name and kwargs.get('retain'):
                        raw = bytes([raw[0] ^ 1]) + raw[1:] if mismatch == 'hash' else b''
                    return identity, raw
                with self.subTest(name=name, mismatch=mismatch), patch.object(fs, 'record', side_effect=record):
                    with self.assertRaisesRegex(I.InventoryError, 'scanner-manifest-bytes-mismatch'):
                        fs.tree()

    def test_every_declared_archive_missing_empty_or_changed_fails_scan(self):
        self.fixture()
        fixtures = load('scanner_archive_negatives', 'tools/tests/test_released_sdk_inventory.py')
        payloads, _, _ = fixtures.InventoryTests().manifest_fixture()
        for name, saved in payloads.items():
            if not name.startswith('sources/'):
                continue
            path = self.root / (I.ROOT + '/' + name).removeprefix('/')
            for raw in (None, b'', b'changed source archive'):
                with self.subTest(name=name, raw=raw):
                    if raw is None:
                        path.unlink()
                    else:
                        path.write_bytes(raw)
                    with self.assertRaisesRegex(I.InventoryError, 'inventory-source-bytes-mismatch'):
                        S.scan(self.root_fd)
                    path.write_bytes(saved)

    def test_scanner_rejects_missing_mandatory_manifest_and_provider_declarations(self):
        docs = self.fixture()
        for document, key in (('contract.json', 'audio_manifest'), ('contract.json', 'compiler'),
                              ('contract.json', 'curl_manifest'), ('runtime-sources.json', 'custom_providers')):
            bad = copy.deepcopy(docs[document])
            del bad[key]
            self.put(I.ROOT + '/' + document, encoded(bad))
            with self.subTest(document=document, key=key), self.assertRaises(I.InventoryError):
                S.scan(self.root_fd)
            self.put(I.ROOT + '/' + document, encoded(docs[document]))
        for role in ('libcurl', 'libcares'):
            bad = copy.deepcopy(docs['runtime-sources.json'])
            del bad['custom_providers'][role]
            self.put(I.ROOT + '/runtime-sources.json', encoded(bad))
            with self.subTest(role=role), self.assertRaisesRegex(I.InventoryError, 'inventory-custom-providers'):
                S.scan(self.root_fd)
        self.put(I.ROOT + '/runtime-sources.json', encoded(docs['runtime-sources.json']))

    def test_provider_namespace_ownership_and_uid_gid_fences(self):
        docs = self.fixture()
        path = docs['runtime-sources.json']['custom_providers']['libcurl']['path']
        for bad in ('/usr/local/lib/libcurl.so', '/usr/lib/libcurl.so.1',
                    '/usr/local/lib/libother.so.1', '/usr/local/lib/../lib/libcurl.so.1'):
            with self.subTest(path=bad), self.assertRaisesRegex(I.InventoryError, 'scanner-provider-path'):
                S.Filesystem(self.root_fd).read_provider(bad)
        for target in ('/', '/usr', '/usr/local', '/usr/local/lib', path):
            fs = S.Filesystem(self.root_fd)
            # Inject each ancestor/file owner at the stat boundary, before guards.
            original_stat, original_fstat = S.os.stat, S.os.fstat
            def wrong_owner(*args, _call, **kwargs):
                info = _call(*args, **kwargs)
                fd = args[0] if _call is original_fstat else kwargs.get('dir_fd')
                actual = os.readlink('/proc/self/fd/' + str(fd)) if fd is not None else str(args[0])
                if _call is original_stat and fd is not None:
                    actual += '/' + str(args[0])
                if actual == str(self.root) + ('' if target == '/' else target):
                    info.st_uid = 1000
                return info
            with self.subTest(owner=target), patch.object(S.os, 'stat', side_effect=lambda *a, **k: wrong_owner(*a, _call=original_stat, **k)), \
                    patch.object(S.os, 'fstat', side_effect=lambda *a, **k: wrong_owner(*a, _call=original_fstat, **k)):
                with self.assertRaisesRegex(I.InventoryError, 'scanner-provider-owner'):
                    fs.read_provider(path)
        for field in ('stat_uid', 'stat_gid'):
            fs = S.Filesystem(self.root_fd)
            fs.read_provider(path)
            setattr(self, field, 17)
            with self.subTest(field=field), self.assertRaises(I.InventoryError):
                fs.fence()
            setattr(self, field, 0)

    def test_provider_read_fences_gid_drift_and_rejects_writable_root(self):
        docs = self.fixture()
        path = docs['runtime-sources.json']['custom_providers']['libcurl']['path']
        fs = S.Filesystem(self.root_fd)
        original = fs.record
        def drift(*args, **kwargs):
            value = original(*args, **kwargs)
            self.stat_gid = 17
            return value
        with patch.object(fs, 'record', side_effect=drift), self.assertRaises(I.InventoryError):
            fs.read_provider(path)
        self.stat_gid = 0
        self.root.chmod(0o777)
        self.addCleanup(self.root.chmod, 0o700)
        with self.assertRaisesRegex(I.InventoryError, 'scanner-provider-owner'):
            S.Filesystem(self.root_fd).read_provider(path)

    def test_provider_missing_changed_empty_symlink_and_unsafe_mode_fail(self):
        docs = self.fixture()
        for role, provider in docs['runtime-sources.json']['custom_providers'].items():
            actual = self.root / provider['path'].removeprefix('/')
            for state in ('missing', 'changed', 'empty', 'symlink', 'writable'):
                saved = actual.read_bytes()
                actual.unlink()
                if state == 'symlink':
                    actual.symlink_to('another-library')
                elif state != 'missing':
                    actual.write_bytes(b'' if state == 'empty' else b'wrong' if state == 'changed' else saved)
                    actual.chmod(0o666 if state == 'writable' else 0o644)
                with self.subTest(role=role, state=state), self.assertRaises((I.InventoryError, FileNotFoundError)):
                    S.scan(self.root_fd)
                if actual.exists() or actual.is_symlink():
                    actual.unlink()
                actual.write_bytes(saved)
                actual.chmod(0o644)

    def test_notices_and_common_licenses_remain_nonempty(self):
        self.fixture()
        for path in (I.DOC + '/foo/copyright', I.COMMON + '/' + I.COMMON_LICENSE_NAMES[0]):
            actual = self.root / path.removeprefix('/')
            original = actual.read_bytes()
            actual.write_bytes(b'')
            with self.subTest(path=path), self.assertRaisesRegex(I.InventoryError, 'scanner-file-limit'):
                S.scan(self.root_fd)
            actual.write_bytes(original)

    def test_unreadable_directory_fails_instead_of_silent_omission(self):
        self.fixture()
        denied = self.root / (I.ROOT + '/unreadable').removeprefix('/')
        denied.mkdir()
        denied.chmod(0)
        self.addCleanup(denied.chmod, 0o755)
        # Real kernel permission failure under the required native non-root UID.
        self.assertNotEqual(os.geteuid(), 0)
        with self.assertRaises(PermissionError):
            S.scan(self.root_fd)

    def test_special_link_tree_and_unreadable_regular_fail(self):
        self.fixture()
        extra = self.root / (I.ROOT + '/unexpected').removeprefix('/')
        extra.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(I.InventoryError, 'scanner-tree-special-or-link'):
            S.scan(self.root_fd)
        extra.unlink()
        os.mkfifo(extra)
        with self.assertRaises(I.InventoryError):
            S.scan(self.root_fd)
        extra.unlink()
        extra.write_bytes(b'unreadable')
        extra.chmod(0)
        with self.assertRaises(I.InventoryError):
            S.scan(self.root_fd)

    def test_tree_directory_replaced_with_link_is_rejected(self):
        self.fixture()
        directory = self.root / (I.ROOT + '/sources/debian').removeprefix('/')
        directory.rename(directory.with_name('moved'))
        directory.symlink_to('moved', target_is_directory=True)
        with self.assertRaises(I.InventoryError):
            S.scan(self.root_fd)

    def test_limits_and_post_read_identity_fence(self):
        self.fixture()
        for name, limit in (('MAX_MEMBERS', 2), ('MAX_TOTAL', 1), ('MAX_FILE', 1), ('MAX_SECONDS', 0)):
            with self.subTest(name=name), patch.object(I, name, limit), self.assertRaises(I.InventoryError):
                S.scan(self.root_fd)
        fs = S.Filesystem(self.root_fd)
        fs.record(I.ROOT + '/unrelated-empty', allow_empty=True)
        self.put(I.ROOT + '/unrelated-empty', b'changed')
        with self.assertRaisesRegex(I.InventoryError, 'scanner-path-drift'):
            fs.fence()

    def test_notice_alias_resolution_and_escape_cycle_drift(self):
        self.fixture()
        copyright_path = self.root / (I.DOC + '/foo/copyright').removeprefix('/')
        copyright_path.unlink()
        self.put(I.DOC + '/bar/copyright', b'copyright')
        copyright_path.symlink_to('../bar/copyright')
        actual = S.scan(self.root_fd)
        self.assertEqual(actual['inventories']['debian_notices'][I.DOC + '/foo/copyright']['resolved_path'],
                         I.DOC + '/bar/copyright')
        for raw in ('../../../etc/passwd', 'copyright', '/etc/passwd'):
            copyright_path.unlink()
            copyright_path.symlink_to(raw)
            with self.subTest(raw=raw), self.assertRaises(I.InventoryError):
                S.scan(self.root_fd)
        copyright_path.unlink()
        copyright_path.symlink_to('../bar/copyright')
        fs = S.Filesystem(self.root_fd)
        fs.resolve(I.DOC + '/foo/copyright', I.DOC)
        copyright_path.unlink()
        copyright_path.symlink_to('../bar/other')
        with self.assertRaises(I.InventoryError):
            fs.fence()

    def test_metadata_tools_and_report_exact_field_mismatches(self):
        self.fixture()
        actual = S.scan(self.root_fd)
        for edit in ('metadata', 'build_tools', 'llvm_tools', 'inventory_sha256', 'bool-type', 'extra'):
            altered = copy.deepcopy(actual)
            if edit == 'bool-type':
                altered['image_code_executed'] = 1
            elif edit == 'extra':
                altered['unexpected'] = True
            else:
                del altered[edit][next(iter(altered[edit]))]
            with self.subTest(edit=edit), self.assertRaises(I.InventoryError):
                I.compare_scan(altered, actual)
        for role, path in I.BUILD_TOOLS.items():
            with self.subTest(role=role):
                original = (self.root / path[1:]).read_bytes()
                self.put(path, b'changed', 0o755)
                with self.assertRaisesRegex(I.InventoryError, 'build-tool-bytes-mismatch'):
                    S.scan(self.root_fd)
                self.put(path, original, 0o755)

    def test_collector_inventory_binding_consumer_and_shader_checks(self):
        docs = self.fixture()
        actual = S.scan(self.root_fd)
        raw = {I.ROOT + '/' + name: encoded(value) for name, value in docs.items()}
        records = {I.ROOT + '/' + name: value for name, value in actual['metadata'].items()}
        llvm = {role: {**item, 'mode': '0o755' if item['executable'] else '0o644'}
                for role, item in actual['llvm_tools'].items()}
        reader = C.INVENTORY.InstalledInventory(Mock(), Mock())
        reader.producer = Mock()
        reader.debian_notices = Mock()
        reader.common_licenses = Mock()
        reader.build_tools = Mock()
        fixtures = load('collector_provider_archives', 'tools/tests/test_released_sdk_inventory.py')
        image = fixtures.InventoryTests().installed_image()
        reader.producer.return_value = actual['inventories']['producer']
        reader.debian_notices.return_value = actual['inventories']['debian_notices']
        reader.common_licenses.return_value = actual['inventories']['common_licenses']
        reader.build_tools.return_value = actual['build_tools']
        # The combined dependency test uses the real provider-reader interface.
        source_check = C.INVENTORY.crosscheck_archives
        def reader_check(producer, runtime, contract, *, reader):
            self.assertIs(reader, expected_reader)
            return source_check(producer, runtime, contract, reader=reader)
        expected_reader = reader
        reader_class = C.INVENTORY.InstalledInventory
        def new_reader(cls, *args):
            return expected_reader
        with patch.object(reader_class, '__new__', new_reader), \
                patch.object(C.INVENTORY, 'crosscheck_archives', side_effect=reader_check) as crosscheck:
            self.assertEqual(C.collect_final_inventory(image, raw, records, llvm, POLICY), actual)
            self.assertIs(crosscheck.call_args.kwargs['reader'], reader)
            # Real _regular/read_provider and the collector's actual protocol
            # stream root/ancestor headers and both binary payloads. No helper
            # provider-read method is mocked, so a missing adapter field fails here.
            routes = [call.args[1] for call in image.docker.request.call_args_list]
            self.assertTrue(any('path=%2F' == route.split('?')[1] for route in routes))
            for role in ('libcurl', 'libcares'):
                self.assertTrue(any(role + '.so.1.0.0' in route for route in routes))
            for connection in image.connections:
                connection.close.assert_called_once()
            self.assertGreaterEqual(image.fence.call_count, 4)
            for path in ('/', '/usr', '/usr/local', '/usr/local/lib',
                         '/usr/local/lib/libcurl.so.1.0.0', '/usr/local/lib/libcares.so.1.0.0'):
                wrong_owner = fixtures.InventoryTests().installed_image(metadata={path: {'uid': 1000}})
                with self.subTest(owner=path), self.assertRaisesRegex(
                        (C.INVENTORY.InventoryError, C.Stop),
                        'inventory-directory-owner|archive-owner-mismatch'):
                    C.collect_final_inventory(wrong_owner, raw, records, llvm, POLICY)
                for connection in wrong_owner.connections:
                    connection.close.assert_called_once()
            payloads = {'/usr/local/lib/' + role + '.so.1.0.0': role.encode()
                        for role in ('libcurl', 'libcares')}
            for role in ('libcurl', 'libcares'):
                bad_bytes = {**payloads, '/usr/local/lib/' + role + '.so.1.0.0': b'changed'}
                wrong_bytes = fixtures.InventoryTests().installed_image(payloads=bad_bytes)
                with self.subTest(bytes=role), self.assertRaisesRegex(
                        C.INVENTORY.InventoryError, 'inventory-provider-bytes-mismatch'):
                    C.collect_final_inventory(wrong_bytes, raw, records, llvm, POLICY)
            reader.debian_notices.reset_mock()
            reader.common_licenses.reset_mock()
            reader.build_tools.reset_mock()
            with patch.object(C.INVENTORY, 'crosscheck_archives', side_effect=C.INVENTORY.InventoryError(
                    'inventory-provider-bytes-mismatch')):
                with self.assertRaisesRegex(C.INVENTORY.InventoryError, 'inventory-provider-bytes-mismatch'):
                    C.collect_final_inventory(image, raw, records, llvm, POLICY)
            reader.debian_notices.assert_not_called()
            reader.common_licenses.assert_not_called()
            reader.build_tools.assert_not_called()
            for name in ('contract.json', 'shader-generation.json'):
                changed = copy.deepcopy(docs)
                if name == 'contract.json':
                    changed[name]['consumer']['commit'] = '1' * 40
                else:
                    changed[name]['source_commit'] = '1' * 40
                bad = {**raw, I.ROOT + '/' + name: encoded(changed[name])}
                with self.subTest(name=name), self.assertRaisesRegex(C.Stop, 'final-consumer-mismatch'):
                    C.collect_final_inventory(image, bad, records, llvm, POLICY)
            changed = copy.deepcopy(actual['inventories']['producer'])
            changed['sources/classic-shaders/client/shaders/source']['sha256'] = '0' * 64
            reader.producer.return_value = changed
            with self.assertRaisesRegex(C.Stop, 'final-shader-input-bytes'):
                C.collect_final_inventory(image, raw, records, llvm, POLICY)

    def test_duplicate_metadata_json_rejected(self):
        self.fixture()
        self.put(I.ROOT + '/runtime-abi.json', b'{"a":1,"a":2}')
        with self.assertRaisesRegex(I.InventoryError, 'scanner-duplicate-json-key'):
            S.scan(self.root_fd)

    def test_metadata_bind_rejects_missing_fields_and_different_bytes(self):
        raw = {name: b'{}' for name in I.METADATA_FILES}
        records = {name: {'sha256': hashlib.sha256(value).hexdigest(), 'size': len(value), 'executable': False}
                   for name, value in raw.items()}
        I.bind_metadata(records, raw, records)
        for edit in ('missing', 'size', 'bool-type'):
            changed = copy.deepcopy(records)
            if edit == 'missing':
                del changed['contract.json']
            elif edit == 'size':
                changed['contract.json']['size'] = 1
            else:
                changed['contract.json']['executable'] = 0
            with self.subTest(edit=edit), self.assertRaises(I.InventoryError):
                I.bind_metadata(records, raw, changed)


class QualificationTests(unittest.TestCase):
    def setUp(self):
        for operation in (
            patch.dict(C.TARGETS, {TARGET: ('atrinik/classic-portable-build', 'fixture-only', 'sha256:' + 'e' * 64)}),
            patch.dict(C.FINAL_TARGETS, {TARGET: POLICY}),
            patch.object(C.LocalConnection, 'connect', side_effect=AssertionError('Docker forbidden')),
            patch.object(C.signal, 'alarm')):
            operation.start()
            self.addCleanup(operation.stop)
        self.context = {'run_id': '1', 'run_attempt': '1'}
        self.verified = {'config_digest': POLICY['config_digest'], 'manifest_digest': POLICY['manifest_digest'],
                         'config_object': {'config': {}}}

    def scanner(self):
        sources = C.scanner_sources()
        docker = Mock()
        scanner = C.ScannerImage(docker, TARGET, self.context, self.verified, sources)
        scanner.identifier, scanner.attempted = 'f' * 64, True
        value = {'Id': scanner.identifier, 'Name': '/' + scanner.name,
                 'Config': {'Labels': {C.OWNER_LABEL: scanner.owner}, 'Image': scanner.reference,
                            'Entrypoint': scanner.entrypoint, 'Cmd': [], 'User': '65534:65534', 'WorkingDir': '/'},
                 'HostConfig': {'ReadonlyRootfs': True, 'NetworkMode': 'none', 'Privileged': False,
                                'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'], 'RestartPolicy': {'Name': 'no'}},
                 'Mounts': [{'Source': row['Source'], 'Destination': row['Target'], 'Type': 'bind', 'RW': False}
                            for row in scanner.mounts],
                 'State': {'Status': 'created', 'Running': False, 'Pid': 0}, 'Image': POLICY['config_digest']}
        docker.get.return_value = value
        return scanner, value

    def test_no_actual_final_target_is_admitted_and_old_rows_unchanged(self):
        originals = {'broad', 'classic', 'portable-preliminary'}
        self.assertEqual(set(C.TARGETS) - {TARGET}, originals)
        self.assertEqual(set(C.FINAL_TARGETS), {TARGET})
        for target in originals:
            self.assertEqual(C.target_policy(target), {'producer_revision': C.REVISION})
            with self.assertRaisesRegex(C.Stop, 'final-target-required'):
                C.ScannerImage(Mock(), target, self.context, self.verified, C.scanner_sources())
        self.assertEqual(C.TOOL_FILES, C.INVENTORY.LLVM_TOOL_FILES)

    def test_wrong_final_platform_config_and_policy_rejected_before_create(self):
        for field in ('manifest_digest', 'config_digest'):
            bad = copy.deepcopy(self.verified)
            bad[field] = 'sha256:' + '1' * 64
            with self.subTest(field=field), self.assertRaisesRegex(C.Stop, 'final-image-coordinate-mismatch'):
                C.ScannerImage(Mock(), TARGET, self.context, bad, C.scanner_sources())
        with patch.dict(C.FINAL_TARGETS, {TARGET: {}}), self.assertRaises(C.Stop):
            C.target_policy(TARGET)

    def test_scanner_create_exact_readonly_command_mounts_and_no_credentials(self):
        scanner, value = self.scanner()
        scanner.identifier, scanner.attempted = None, False
        value['Id'] = 'a' * 64
        scanner.docker.request.return_value = (Mock(), Response(encoded({'Id': value['Id']})))
        scanner.create()
        call = scanner.docker.request.call_args
        body = json.loads(call.args[3])
        self.assertEqual(body['Entrypoint'], ['/usr/bin/python3', '-I', '-B', '/scan/scan-released-sdk-filesystem.py'])
        self.assertEqual(body['Env'], [])
        self.assertEqual(body['User'], '65534:65534')
        self.assertTrue(body['HostConfig']['ReadonlyRootfs'])
        self.assertEqual({row['Target'] for row in body['HostConfig']['Mounts']},
                         {'/scan/' + name for name in C.SCANNER_FILES})
        self.assertTrue(all(row['ReadOnly'] for row in body['HostConfig']['Mounts']))
        self.assertNotIn('X-Registry-Auth', call.args[2])

    def test_fences_reject_wrong_owner_write_mount_network_and_image(self):
        changes = [('Config', 'User', '0'), ('Config', 'Entrypoint', ['/bin/sh']),
                   ('HostConfig', 'ReadonlyRootfs', False), ('HostConfig', 'NetworkMode', 'bridge')]
        for section, key, bad in changes:
            scanner, value = self.scanner()
            value[section][key] = bad
            with self.subTest(key=key), self.assertRaises(C.Stop):
                scanner.fence()
        scanner, value = self.scanner()
        value['Mounts'][0]['RW'] = True
        with self.assertRaises(C.Stop):
            scanner.fence()
        value['Mounts'][0]['RW'] = False
        value['Config']['Labels'][C.OWNER_LABEL] = 'foreign'
        with self.assertRaises(C.Stop):
            scanner.cleanup()
        scanner.docker.request.assert_not_called()

    def test_logs_complete_framing_stderr_extra_and_limit(self):
        raw = encoded({'schema_version': 1})
        frame = b'\x01\0\0\0' + struct.pack('>I', len(raw)) + raw
        self.assertEqual(C.scanner_logs(Response(frame)), {'schema_version': 1})
        for bad in (frame[:-1], frame + b'x', b'\x02' + frame[1:], frame + frame):
            with self.subTest(raw=bad), self.assertRaises(C.Stop):
                C.scanner_logs(Response(bad))
        with patch.object(C, 'SCANNER_LIMIT', 1), self.assertRaises(C.Stop):
            C.scanner_logs(Response(frame))

    def test_execute_waits_for_success_and_parses_bounded_output(self):
        scanner, value = self.scanner()
        payload = encoded({'observed': True})
        frame = b'\x01\0\0\0' + struct.pack('>I', len(payload)) + payload
        def request(method, path, **kwargs):
            if path.endswith('/start'):
                value['State'] = {'Status': 'running', 'Running': True, 'Pid': 123}
                return Mock(), Response()
            if '/wait?' in path:
                value['State'] = {'Status': 'exited', 'Running': False, 'Pid': 0}
                self.assertEqual(kwargs['timeout'], I.MAX_SECONDS + 30)
                return Mock(), Response(encoded({'StatusCode': 0}))
            if '/logs?' in path:
                return Mock(), Response(frame)
            self.fail('unexpected Docker method')
        scanner.docker.request.side_effect = request
        self.assertEqual(scanner.execute(), {'observed': True})
        self.assertEqual(scanner.docker.request.call_count, 3)

    def test_missing_policy_wrong_target_and_registry_coordinate_fail_before_fetch(self):
        with patch.dict(C.FINAL_TARGETS, {}, clear=True), self.assertRaisesRegex(C.Stop, 'final-target-policy-missing'):
            C.target_policy(TARGET)
        with patch.object(C, 'registry_object') as fetch, self.assertRaisesRegex(C.Stop, 'fixed-target-mismatch'):
            C.verified_registry('atrinik/classic-portable-build', 'sha256:' + '0' * 64,
                                'fixture-bearer', target=TARGET)
        fetch.assert_not_called()

    def test_qualification_identity_comparison_and_cleanup_failure(self):
        expected = {'fixture': True}
        for failure in ('none', 'compare', 'cleanup', 'source'):
            scanner = Mock()
            scanner.identifier = 'f' * 64
            scanner.execute.return_value = expected if failure != 'compare' else {'fixture': False}
            if failure == 'cleanup':
                scanner.cleanup.side_effect = RuntimeError('hostile secret')
            sources = C.scanner_sources()
            readings = [sources, {} if failure == 'source' else sources]
            with self.subTest(failure=failure), patch.object(C, 'ScannerImage', return_value=scanner), \
                    patch.object(C, 'scanner_sources', side_effect=readings):
                result = C.qualify_filesystem(Mock(), TARGET, self.context, self.verified, expected)
            self.assertEqual(result['status'], 'verified-filesystem-equality' if failure == 'none' else 'stopped')
            self.assertTrue(result['image_code_executed'])
            self.assertFalse(result['final_portable_cohort'])
            self.assertEqual(result['index_digest'], C.TARGETS[TARGET][2])
            self.assertEqual(result['producer_revision'], POLICY['producer_revision'])
            scanner.cleanup.assert_called_once()
            self.assertNotIn('hostile secret', encoded(result).decode())

    def test_final_collection_retains_separate_receipt_and_cleanup_failure_stops(self):
        baseline = load('historical_collector_fixtures', 'tools/tests/test_collect_released_sdk_metadata.py')
        data, binaries = baseline.OfflineTests().portable_fixture()
        verified = dict(self.verified, index=b'{}', manifest=b'{}', config=b'{}')
        context = dict(self.context, actor='fixture-actor')
        owned = Mock()
        owned.identifier = 'f' * 64
        owned.docker.negotiate.return_value = {}
        owned.docker.inspect.return_value = {}
        owned.docker.pull.return_value = 1
        def read(path, *, retain, executable=False):
            raw = data[path] if retain else binaries[path]
            return {'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw),
                    'mode': '0o755' if executable else '0o644'}, raw if retain else None
        owned.read.side_effect = read
        report = {'inventories': {'producer': {}, 'debian_notices': {}, 'common_licenses': {}},
                  'inventory_sha256': {'producer': 'fixture', 'debian_notices': 'fixture', 'common_licenses': 'fixture'},
                  'metadata': {name: {'sha256': hashlib.sha256(data[I.ROOT + '/' + name]).hexdigest()}
                               for name in I.METADATA_FILES}, 'build_tools': {}}
        for failure in ('none', 'qualification', 'cleanup'):
            qualification = {'status': 'stopped' if failure == 'qualification' else 'verified-filesystem-equality',
                             'image_code_executed': True, 'final_portable_cohort': False}
            owned.cleanup.side_effect = RuntimeError('private detail') if failure == 'cleanup' else None
            with (
                tempfile.TemporaryDirectory() as temp,
                self.subTest(failure=failure),
                patch.object(C, 'runner_docker', return_value=owned.docker),
                patch.object(C, 'scoped_bearer', return_value='fixture-bearer'),
                patch.object(C, 'verified_registry', return_value=verified),
                patch.object(C, 'StoppedImage', return_value=owned),
                patch.object(C, 'collect_final_inventory', return_value=report),
                patch.object(C, 'qualify_filesystem', return_value=qualification),
            ):
                receipt = C.collect(TARGET, context, 'fixture-original', Path(temp))
                self.assertEqual(receipt['status'], 'verified-installed-identity' if failure == 'none' else 'stopped')
                self.assertFalse(receipt['image_code_executed'])
                self.assertFalse(receipt['final_portable_cohort'])
                retained = json.loads((Path(temp) / 'filesystem-qualification.json').read_bytes())
                self.assertTrue(retained['image_code_executed'])
                self.assertEqual(set(receipt['metadata_sha256']), set(I.METADATA_FILES))
                self.assertEqual(len(receipt['tool_bytes']), 12)
                self.assertEqual({p.name for p in (Path(temp) / 'inventories').iterdir()},
                                 {'producer.json', 'debian_notices.json', 'common_licenses.json'})
                self.assertNotIn('private detail', json.dumps(receipt))

    def test_cleanup_stops_only_owned_running_scanner_then_deletes(self):
        scanner, value = self.scanner()
        value['State'] = {'Status': 'running', 'Running': True, 'Pid': 123}
        def request(method, path, **kwargs):
            if '/stop?' in path:
                value['State'] = {'Status': 'exited', 'Running': False, 'Pid': 0}
            return Mock(), Response()
        scanner.docker.request.side_effect = request
        scanner.cleanup()
        self.assertEqual([call.args[1] for call in scanner.docker.request.call_args_list],
                         ['/containers/' + scanner.identifier + '/stop?t=10', '/containers/' + scanner.identifier])
        self.assertFalse(scanner.attempted)


if __name__ == '__main__':
    unittest.main()
