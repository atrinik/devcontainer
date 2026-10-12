# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Offline bounded inventory trust tests. No Docker, network or credentials."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import Mock, patch
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = load('released_sdk_inventory', ROOT / 'tools/released_sdk_inventory.py')
P = load('inventory_collector', ROOT / 'tools/collect-released-sdk-metadata.py')


class Response(io.BytesIO):
    chunked = True
    length = None

    def __init__(self, raw, expected=None):
        super().__init__(raw)
        self.headers = {'Content-Type': 'application/x-tar'}
        if expected is not None:
            self.headers['X-Docker-Container-Path-Stat'] = base64.b64encode(json.dumps(expected).encode()).decode()

    def getheader(self, name, default=None):
        return self.headers.get(name, default)


def directory(path):
    return {'name': Path(path).name, 'mode': M.GO_DIRECTORY | 0o755,
            'size': 4096, 'mtime': 'fixed', 'linkTarget': ''}


def regular(path, raw):
    return {'name': Path(path).name, 'mode': 0o644, 'size': len(raw),
            'mtime': 'fixed', 'linkTarget': ''}


def tar(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as out:
        for name, data, kind, extra in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
            member.size = len(data)
            for key, value in extra.items():
                setattr(member, key, value)
            out.addfile(member, io.BytesIO(data))
    return raw.getvalue()


DIR = ('atrinik-portable', b'', tarfile.DIRTYPE, {})
FILE = ('atrinik-portable/a', b'abc', tarfile.REGTYPE, {})
EMPTY = ('atrinik-portable/empty', b'', tarfile.REGTYPE, {})


class InventoryTests(unittest.TestCase):
    def setUp(self):
        for item in (patch.object(P, 'https_get', side_effect=AssertionError('network forbidden')),
                     patch.object(P.LocalConnection, 'connect', side_effect=AssertionError('Docker forbidden'))):
            item.start()
            self.addCleanup(item.stop)

    def parse(self, entries=None, raw=None):
        return M.tree_archive(Response(raw if raw is not None else tar(entries)), P, directory(M.ROOT))

    def denied(self, entries=None, raw=None, code=None):
        with self.assertRaises((M.InventoryError, P.Stop)) as caught:
            self.parse(entries=entries, raw=raw)
        if code:
            self.assertEqual(str(caught.exception), code)

    def test_complete_inventory_and_zero_byte_file(self):
        result = self.parse([DIR, FILE, EMPTY])
        self.assertEqual(result, {
            'a': {'sha256': hashlib.sha256(b'abc').hexdigest(), 'size': 3, 'executable': False},
            'empty': {'sha256': hashlib.sha256(b'').hexdigest(), 'size': 0, 'executable': False}})
        self.assertEqual(M.inventory_digest(result),
                         hashlib.sha256(json.dumps(result, sort_keys=True, separators=(',', ':')).encode()).hexdigest())

    def test_executable_bit_and_pax_times(self):
        result = self.parse([DIR, ('atrinik-portable/run', b'x', tarfile.REGTYPE,
                                  {'mode': 0o755, 'pax_headers': {'mtime': '123.25'}})])
        self.assertTrue(result['run']['executable'])

    def test_all_links_special_sparse_and_extensions_fail(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE,
                     tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.GNUTYPE_SPARSE,
                     tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME):
            with self.subTest(kind=kind):
                self.denied([DIR, ('atrinik-portable/bad', b'', kind, {})])
        for key in ('path', 'linkpath', 'size', 'GNU.sparse.map', 'SCHILY.xattr.secret'):
            with self.subTest(pax=key):
                self.denied([DIR, ('atrinik-portable/a', b'x', tarfile.REGTYPE,
                                  {'pax_headers': {key: '0'}})], code='unsafe-pax-header')

    def test_paths_duplicates_and_collisions_fail(self):
        for name in ('/atrinik-portable/a', 'atrinik-portable/../a', 'atrinik-portable/./a',
                     'atrinik-portable//a', 'other/a', 'atrinik-portable/a\\b',
                     'atrinik-portable/a\nb', 'atrinik-portable/d/file'):
            with self.subTest(name=name):
                self.denied([DIR, (name, b'x', tarfile.REGTYPE, {})])
        self.denied([DIR, FILE, FILE], code='inventory-duplicate')
        self.denied([DIR, FILE, ('atrinik-portable/a', b'', tarfile.DIRTYPE, {})],
                    code='inventory-duplicate')
        self.denied([FILE], code='inventory-parent-missing')
        self.denied([DIR], code='inventory-empty')
        for name in ('atrinik-portable//', 'atrinik-portable///'):
            self.denied([(name, b'', tarfile.DIRTYPE, {}), FILE], code='inventory-path-invalid')

    def test_truncation_extra_members_and_framing(self):
        raw = tar([DIR, FILE])
        for size in (0, 511, 512, 1024, 1535, 1536, 2048):
            with self.subTest(size=size):
                self.denied(raw=raw[:size])
        self.denied(raw=raw[:1536] + bytes(512) + b'x' + bytes(511), code='inventory-end-markers')
        self.denied(raw=raw + b'x', code='inventory-tail')
        self.denied(raw=raw + bytes(1), code='inventory-tail-alignment')
        self.denied(raw=raw + tar([FILE]), code='inventory-tail')
        response = Response(raw)
        response.chunked = False
        with self.assertRaisesRegex(M.InventoryError, 'inventory-unframed'):
            M.tree_archive(response, P, directory(M.ROOT))
        response = Response(raw)
        response.length = 123
        with self.assertRaisesRegex(M.InventoryError, 'inventory-truncated'):
            M.tree_archive(response, P, directory(M.ROOT))

    def test_limits_and_deadline(self):
        for name, value in (('MAX_MEMBERS', 1), ('MAX_FILE', 2), ('MAX_TOTAL', 2), ('MAX_PATH', 2)):
            with self.subTest(limit=name), patch.object(M, name, value):
                self.denied([DIR, FILE])
        with patch.object(M.time, 'monotonic', side_effect=[0, 1000]):
            self.denied([DIR, FILE], code='inventory-deadline')
        response = Response(tar([DIR, FILE]))
        budget = M.Budget()
        with patch.object(M.time, 'monotonic', side_effect=[budget.deadline - 1, budget.deadline]):
            with self.assertRaisesRegex(M.InventoryError, 'inventory-deadline'):
                budget.read(response, 512)

    def test_single_file_zero_and_extra_member(self):
        raw = tar([('empty', b'', tarfile.REGTYPE, {})])
        record, data = P.single_file_archive(Response(raw), '/empty', regular('/empty', b''), retain=False)
        self.assertEqual(record['size'], 0)
        self.assertIsNone(data)
        with self.assertRaises(P.Stop):
            P.single_file_archive(Response(tar([('a', b'x', tarfile.REGTYPE, {}),
                                               ('extra', b'x', tarfile.REGTYPE, {})])),
                                  '/a', regular('/a', b'x'), retain=False)

    def fake_image(self):
        image = Mock()
        image.identifier = 'a' * 64
        image.stat.side_effect = lambda path: directory(path)
        return image

    def test_created_image_fences_and_connection_close(self):
        image = self.fake_image()
        conn = Mock()
        image.docker.request.return_value = (conn, Response(tar([DIR, FILE]), directory(M.ROOT)))
        result = M.InstalledInventory(image, P).producer()
        self.assertIn('a', result)
        self.assertEqual(image.fence.call_count, 2)
        self.assertEqual(image.stat.call_count, 4)
        conn.close.assert_called_once()
        request = image.docker.request.call_args
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(request.args[1]).query), {'path': [M.ROOT]})

    def test_root_stat_drift_and_archive_failure_close(self):
        for drift in ('root', 'parent', 'get', 'tar'):
            image = self.fake_image()
            conn = Mock()
            states = {'/opt': 0, M.ROOT: 0}
            def stat(path):
                states[path] += 1
                value = directory(path)
                if states[path] == 2 and ((drift == 'root' and path == M.ROOT) or (drift == 'parent' and path == '/opt')):
                    value['mtime'] = 'changed'
                return value
            image.stat.side_effect = stat
            expected = directory(M.ROOT)
            if drift == 'get':
                expected['mtime'] = 'changed'
            image.docker.request.return_value = (conn, Response(b'bad' if drift == 'tar' else tar([DIR, FILE]), expected))
            with self.subTest(drift=drift), self.assertRaises(M.InventoryError):
                M.InstalledInventory(image, P).producer()
            conn.close.assert_called_once()

    def documents(self):
        return {'source_packages': {'foo': '1.0'}, 'archives': {'foo.tar.xz': 'a' * 64}}, [
            {'source': 'foo', 'source_version': '1.0', 'package': 'foo:amd64', 'notice_directory': M.DOC + '/foo'},
            {'source': 'unrelated', 'notice_directory': '/secret'}]

    def test_notice_request_selection_and_no_descriptor_path_extension(self):
        runtime, debian = self.documents()
        self.assertEqual(M.notice_requests(runtime, debian), [M.DOC + '/foo/copyright'])
        for key, bad in (('notice_directory', '/secret'), ('package', '../foo'), ('source_version', '2.0')):
            rows = copy.deepcopy(debian)
            rows[0][key] = bad
            with self.subTest(key=key), self.assertRaises(M.InventoryError):
                M.notice_requests(runtime, rows)
        with self.assertRaisesRegex(M.InventoryError, 'notice-source-missing'):
            M.notice_requests(runtime, [])

    def test_archive_crosschecks(self):
        runtime, _ = self.documents()
        contract = {'sources': [{'sha256': 'b' * 64}]}
        records = {'sources/debian/foo.tar.xz': {'sha256': 'a' * 64},
                   'sources/' + 'b' * 64 + '.tar.gz': {'sha256': 'b' * 64}}
        M.crosscheck_archives(records, runtime, contract)
        for path in records:
            bad = copy.deepcopy(records)
            bad[path]['sha256'] = 'c' * 64
            with self.assertRaisesRegex(M.InventoryError, 'inventory-source-bytes-mismatch'):
                M.crosscheck_archives(bad, runtime, contract)
        runtime['archives'] = {'../secret': 'a' * 64}
        with self.assertRaises(M.InventoryError):
            M.crosscheck_archives(records, runtime, contract)


    def notice_image(self, links=None, drift=False):
        links = links or {}
        image = self.fake_image()
        payload = b'notice'
        link_reads = {}
        def stat(path):
            if path in links:
                raw, target = links[path]
                return {'name': Path(path).name, 'mode': M.GO_SYMLINK | 0o777,
                        'size': len(raw), 'mtime': 'fixed', 'linkTarget': target}
            if path.endswith('/copyright') or path.startswith(M.COMMON + '/'):
                return regular(path, payload)
            return directory(path)
        def request(method, route, headers):
            self.assertEqual(method, 'GET')
            path = urllib.parse.parse_qs(urllib.parse.urlsplit(route).query)['path'][0]
            if path in links:
                raw, _ = links[path]
                link_reads[path] = link_reads.get(path, 0) + 1
                if drift and link_reads[path] > 1:
                    raw = raw.replace('bar', 'baz')
                data = tar([(Path(path).name, b'', tarfile.SYMTYPE, {'linkname': raw, 'mode': 0o777})])
            else:
                data = tar([(Path(path).name, payload, tarfile.REGTYPE, {})])
            return Mock(), Response(data, stat(path))
        image.stat.side_effect = stat
        image.docker.request.side_effect = request
        return image

    def test_notices_resolve_directory_and_file_links_beneath_doc(self):
        runtime, debian = self.documents()
        for links, canonical in (({}, M.DOC + '/foo/copyright'),
                ({M.DOC + '/foo': ('bar', M.DOC + '/bar')}, M.DOC + '/bar/copyright'),
                ({M.DOC + '/foo/copyright': ('../bar/copyright', M.DOC + '/bar/copyright')},
                 M.DOC + '/bar/copyright')):
            with self.subTest(links=links):
                result = M.InstalledInventory(self.notice_image(links), P).debian_notices(runtime, debian)
                self.assertEqual(set(result), {M.DOC + '/foo/copyright'})
                self.assertEqual(result[M.DOC + '/foo/copyright']['resolved_path'], canonical)
                self.assertEqual(result[M.DOC + '/foo/copyright']['sha256'], hashlib.sha256(b'notice').hexdigest())

    def test_notice_escape_cycle_limit_wrong_resolved_target_and_drift(self):
        runtime, debian = self.documents()
        cases = [
            {M.DOC + '/foo': ('/secret', '/secret')},
            {M.DOC + '/foo': ('../../../usr/share/doc/bar', M.DOC + '/bar')},
            {M.DOC + '/foo': ('bar', M.DOC + '/bar'), M.DOC + '/bar': ('foo', M.DOC + '/foo')},
            {M.DOC + '/foo': ('bar', M.DOC + '/wrong')},
            {M.DOC + '/foo': ('bar/../baz', M.DOC + '/baz'),
             M.DOC + '/bar': ('/outside/dir', '/outside/dir')},
        ]
        for links in cases:
            with self.subTest(links=links), self.assertRaises(M.InventoryError):
                M.InstalledInventory(self.notice_image(links), P).debian_notices(runtime, debian)
        links = {M.DOC + '/foo': ('bar', M.DOC + '/bar')}
        with patch.object(M, 'MAX_HOPS', 0), self.assertRaises(M.InventoryError):
            M.InstalledInventory(self.notice_image(links), P).debian_notices(runtime, debian)
        with self.assertRaisesRegex(M.InventoryError, 'notice-alias-drift'):
            M.InstalledInventory(self.notice_image(links, drift=True), P).debian_notices(runtime, debian)

    def test_common_license_exact_fixed_names_and_format(self):
        image = self.notice_image()
        result = M.InstalledInventory(image, P).common_licenses()
        self.assertEqual(set(result), set(M.COMMON_LICENSE_NAMES))
        self.assertEqual(len(result), 14)
        self.assertEqual(set(result['MIT'] if 'MIT' in result else result['BSD']),
                         {'sha256', 'size', 'executable'})
        paths = [urllib.parse.parse_qs(urllib.parse.urlsplit(call.args[1]).query)['path'][0]
                 for call in image.docker.request.call_args_list]
        self.assertEqual(set(paths), {M.COMMON + '/' + name for name in M.COMMON_LICENSE_NAMES})

    def build_receipt(self):
        entries = {role: {'path': path, 'resolved_path': path, 'sha256': hashlib.sha256(b'tool').hexdigest(),
                         'size': 4, 'executable': True, 'version': role + ' fixture\nsecond line\n'}
                   for role, path in M.BUILD_TOOLS.items()}
        return {'build_tools': {'schema_version': 1, 'tools': entries},
                'tools': {role: entry['version'].splitlines()[0] for role, entry in entries.items()}}

    def test_build_tools_require_nonroot_executable_before_get(self):
        for mode in (0o744, 0o644):
            image = self.fake_image()
            image.stat.side_effect = lambda path: (
                {**regular(path, b'tool'), 'mode': mode}
                if path in M.BUILD_TOOLS.values() else directory(path))
            with self.subTest(mode=mode), self.assertRaisesRegex(P.Stop, 'tool-not-executable'):
                M.InstalledInventory(image, P).build_tools(self.build_receipt())
            image.docker.request.assert_not_called()

    def test_build_tools_exact_schema_paths_and_streamed_bytes(self):
        installed = self.build_receipt()
        reader = M.InstalledInventory(self.fake_image(), P)
        identity = {'sha256': hashlib.sha256(b'tool').hexdigest(), 'size': 4, 'executable': True}
        with patch.object(reader, '_regular', return_value=identity) as read:
            self.assertEqual(reader.build_tools(installed), installed['build_tools']['tools'])
            self.assertEqual([call.args[0] for call in read.call_args_list], list(M.BUILD_TOOLS.values()))
        for key, value in (('path', '/secret'), ('resolved_path', '/secret'), ('sha256', 'a' * 64),
                           ('size', True), ('executable', 1), ('version', 'wrong\n')):
            bad = copy.deepcopy(installed)
            bad['build_tools']['tools']['cmake'][key] = value
            with self.subTest(key=key), patch.object(reader, '_regular', return_value=identity), self.assertRaises(M.InventoryError):
                reader.build_tools(bad)
        bad = copy.deepcopy(installed)
        bad['build_tools']['tools']['extra'] = {}
        with self.assertRaisesRegex(M.InventoryError, 'build-tool-schema'):
            reader.build_tools(bad)


if __name__ == '__main__':
    unittest.main()
