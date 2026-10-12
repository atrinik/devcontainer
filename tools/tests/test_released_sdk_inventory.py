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
        with self.assertRaisesRegex(P.Stop, 'file-size-limit'):
            P.single_file_archive(Response(raw), '/empty', regular('/empty', b''), retain=False)
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

    def manifest_fixture(self):
        # Use the producer's actual schemas and path declarations, with small
        # stand-ins for the source archives so tests never download or execute.
        contract = json.loads((ROOT / 'portable/contract.json').read_text())
        audio = json.loads((ROOT / 'audio-toolchain.json').read_text())
        llvm = json.loads((ROOT / 'llvm-toolchain.json').read_text())
        payloads = {'sources/debian/foo.tar.xz': b'debian source'}
        runtime = {'archives': {'foo.tar.xz': hashlib.sha256(b'debian source').hexdigest()}}
        for entry in contract['sources']:
            raw = ('source ' + entry['name']).encode()
            entry['sha256'] = hashlib.sha256(raw).hexdigest()
            payloads['sources/' + entry['sha256'] + '.tar.gz'] = raw
        for entry in [audio['sdl_mixer'], *audio['dependencies']]:
            raw = ('source ' + entry['name']).encode()
            entry['source']['sha256'] = hashlib.sha256(raw).hexdigest()
            payloads['sources/' + entry['source']['sha256'] + '.tar.gz'] = raw
        llvm['source']['sha256'] = hashlib.sha256(b'llvm source').hexdigest()
        payloads['sources/llvm/' + Path(llvm['metadata']['source_archive']).name] = b'llvm source'
        payloads['audio-toolchain.json'] = json.dumps(audio).encode()
        payloads['llvm-toolchain.json'] = json.dumps(llvm).encode()
        return payloads, runtime, contract

    def producer_fixture(self, payloads):
        entries = [DIR]
        directories = set()
        for name, raw in sorted(payloads.items()):
            for parent in reversed(Path(name).parents):
                if str(parent) != '.' and str(parent) not in directories:
                    entries.append(('atrinik-portable/' + str(parent), b'', tarfile.DIRTYPE, {}))
                    directories.add(str(parent))
            entries.append(('atrinik-portable/' + name, raw, tarfile.REGTYPE, {}))
        return self.parse(entries)

    def test_authenticated_manifests_close_audio_and_llvm_sources(self):
        payloads, runtime, contract = self.manifest_fixture()
        records = self.producer_fixture(payloads)
        M.crosscheck_archives(records, runtime, contract)
        self.assertEqual(set(records.source_manifests), set(M.SOURCE_MANIFESTS))
        self.assertEqual(M.inventory_digest(records), M.inventory_digest(dict(records)))
        # A hash-only inventory cannot manufacture authenticated manifest data.
        with self.assertRaisesRegex(M.InventoryError, 'inventory-manifest-missing-or-size'):
            M.crosscheck_archives(dict(records), runtime, contract)

    def test_each_declared_audio_and_llvm_source_missing_or_replaced_fails(self):
        payloads, runtime, contract = self.manifest_fixture()
        audio = json.loads(payloads['audio-toolchain.json'])
        paths = ['sources/' + entry['source']['sha256'] + '.tar.gz'
                 for entry in [audio['sdl_mixer'], *audio['dependencies']]]
        paths += [path for path in payloads if path.startswith('sources/llvm/')]
        for path in paths:
            for missing in (True, False):
                bad = dict(payloads)
                if missing:
                    del bad[path]
                else:
                    bad[path] = b'replaced archive'
                # Even equal whole-tree inventories cannot bless missing bytes.
                records = self.producer_fixture(bad)
                self.assertEqual(M.inventory_digest(records), M.inventory_digest(self.producer_fixture(bad)))
                with self.subTest(path=path, missing=missing), self.assertRaisesRegex(
                        M.InventoryError, 'inventory-source-bytes-mismatch'):
                    M.crosscheck_archives(records, runtime, contract)

    def test_manifest_missing_replaced_identity_and_limits_fail(self):
        payloads, runtime, contract = self.manifest_fixture()
        for name in M.SOURCE_MANIFESTS:
            bad = dict(payloads)
            del bad[name]
            with self.subTest(name=name), self.assertRaisesRegex(
                    M.InventoryError, 'inventory-manifest-missing-or-size'):
                M.crosscheck_archives(self.producer_fixture(bad), runtime, contract)
            records = self.producer_fixture(payloads)
            records.source_manifests[name] += b' '
            with self.assertRaisesRegex(M.InventoryError, 'inventory-manifest-bytes-mismatch'):
                M.crosscheck_archives(records, runtime, contract)
            for raw in (b'', b' ' * (M.MAX_MANIFEST + 1)):
                with self.subTest(name=name, size=len(raw)), self.assertRaisesRegex(
                        M.InventoryError, 'inventory-manifest-size'):
                    self.producer_fixture({name: raw})

    def test_manifest_json_duplicates_types_and_depth_fail(self):
        payloads, runtime, contract = self.manifest_fixture()
        for name in M.SOURCE_MANIFESTS:
            for raw in (b'{', b'\xff', b'[]', b'null', b'{"schema_version":true}',
                        b'{"schema_version":2}', b'{"schema_version":1,"schema_version":1}',
                        b'{"schema_version":1,"extra":{"sha256":1,"sha256":2}}',
                        b'{"schema_version":1,"extra":NaN}', b'[' * 2000 + b']' * 2000):
                bad = dict(payloads)
                bad[name] = raw
                with self.subTest(name=name, raw=raw[:80]), self.assertRaises(M.InventoryError):
                    M.crosscheck_archives(self.producer_fixture(bad), runtime, contract)

    def test_manifest_references_cannot_escape_fixed_boundary(self):
        payloads, runtime, contract = self.manifest_fixture()
        for reference in ('/etc/passwd', '../audio-toolchain.json', 'sub/audio-toolchain.json',
                          'sources/../audio-toolchain.json', 'audio-toolchain.json/extra',
                          'audio-toolchain.json\\extra', None, [], {}):
            for role in ('audio', 'llvm'):
                bad = copy.deepcopy(contract)
                if role == 'audio':
                    bad['audio_manifest'] = reference
                else:
                    bad['compiler']['toolchain_manifest'] = reference
                with self.subTest(role=role, reference=reference), self.assertRaisesRegex(
                        M.InventoryError, 'inventory-manifest-path'):
                    M.crosscheck_archives(self.producer_fixture(payloads), runtime, bad)

    def test_audio_manifest_invalid_sources_and_duplicate_names_fail(self):
        payloads, runtime, contract = self.manifest_fixture()
        original = json.loads(payloads['audio-toolchain.json'])
        variants = []
        for key, values in (('dependencies', [None, {}, [], [None], [original['dependencies'][0]] * 128]),
                            ('sdl_mixer', [None, [], {}, {'name': '../escape', 'source': {}},
                                           {'name': 'mixer', 'source': None}])):
            for value in values:
                bad = copy.deepcopy(original)
                bad[key] = value
                variants.append(bad)
        bad = copy.deepcopy(original)
        bad['dependencies'].append(copy.deepcopy(bad['sdl_mixer']))
        variants.append(bad)
        for sha in (None, 1, [], 'A' * 64, '../escape', 'a' * 63):
            bad = copy.deepcopy(original)
            bad['dependencies'][0]['source']['sha256'] = sha
            variants.append(bad)
        for value in variants:
            bad = dict(payloads)
            bad['audio-toolchain.json'] = json.dumps(value).encode()
            with self.subTest(value=value), self.assertRaises(M.InventoryError):
                M.crosscheck_archives(self.producer_fixture(bad), runtime, contract)

    def test_llvm_manifest_invalid_sources_and_archive_paths_fail(self):
        payloads, runtime, contract = self.manifest_fixture()
        original = json.loads(payloads['llvm-toolchain.json'])
        for key, values in (('version', [None, True, '../escape', '23.1.3/../escape']),
                            ('source', [None, [], {}, {'sha256': 'A' * 64}]),
                            ('metadata', [None, [], {}, *[{'source_archive': path} for path in (
                                '/etc/passwd', 'share/atrinik/sources/../escape.tar.xz',
                                'share/atrinik/sources/nested/llvm-project-23.1.3.src.tar.xz',
                                'share/atrinik/sources/llvm-project-23.1.3.src.tar.xz/extra',
                                'share/atrinik/sources/llvm-project-23.1.3.src.tar.xz\\extra',
                                'share/atrinik/sources/llvm-project-22.1.0.src.tar.xz')]])):
            for value in values:
                llvm = copy.deepcopy(original)
                llvm[key] = value
                bad = dict(payloads)
                bad['llvm-toolchain.json'] = json.dumps(llvm).encode()
                with self.subTest(key=key, value=value), self.assertRaises(M.InventoryError):
                    M.crosscheck_archives(self.producer_fixture(bad), runtime, contract)


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

    def test_empty_inventory_notices_and_build_tools_are_rejected(self):
        runtime, debian = self.documents()
        for path in (M.DOC + '/foo/copyright', M.COMMON + '/BSD', *M.BUILD_TOOLS.values()):
            image = self.fake_image()
            executable = path in M.BUILD_TOOLS.values()
            expected = regular(path, b'')
            if executable:
                expected['mode'] = 0o755
            image.stat.side_effect = lambda value: expected if value == path else directory(value)
            conn = Mock()
            image.docker.request.return_value = (
                conn, Response(tar([(Path(path).name, b'', tarfile.REGTYPE,
                                     {'mode': expected['mode']})]), expected))
            reader = M.InstalledInventory(image, P)
            with self.subTest(path=path), self.assertRaisesRegex(P.Stop, 'file-size-limit'):
                if path.startswith(M.DOC + '/'):
                    reader.debian_notices(runtime, debian)
                else:
                    reader._regular(path, executable=executable)
            conn.close.assert_called_once()

    def build_receipt(self):
        entries = {role: {'path': path, 'resolved_path': path, 'sha256': hashlib.sha256(b'tool').hexdigest(),
                         'size': 4, 'executable': True,
                         'version': {'cmake': 'cmake version 3.25.1', 'ninja': '1.11.1',
                                     'pkg_config': '1.8.1'}[role] + '\nsecond line\n'}
                   for role, path in M.BUILD_TOOLS.items()}
        return {'build_tools': {'schema_version': 1, 'tools': entries},
                'tools': {role: entry['version'].splitlines()[0] for role, entry in entries.items()}}

    def test_build_tools_accept_full_stdout_with_or_without_final_newline(self):
        for cmake, ninja in (('cmake version 3.25.1', '1.11'),
                             ('cmake version 3.25.1\n\nCMake suite maintained and supported by Kitware.',
                              '1.11.1\n'),
                             ('cmake version 3.25.1\nfull stdout\n', '1.11.1')):
            installed = self.build_receipt()
            for role, version in (('cmake', cmake), ('ninja', ninja),
                                  ('pkg_config', ninja.replace('1.11', '1.8'))):
                installed['build_tools']['tools'][role]['version'] = version
                installed['tools'][role] = version.splitlines()[0]
            reader = M.InstalledInventory(self.fake_image(), P)
            identity = {'sha256': hashlib.sha256(b'tool').hexdigest(), 'size': 4, 'executable': True}
            with self.subTest(cmake=cmake, ninja=ninja), patch.object(reader, '_regular', return_value=identity):
                self.assertEqual(reader.build_tools(installed), installed['build_tools']['tools'])

    def test_build_tools_enforce_shared_512_mib_boundary(self):
        for size in (512 * 1024 * 1024, 512 * 1024 * 1024 + 1):
            installed = self.build_receipt()
            for entry in installed['build_tools']['tools'].values():
                entry['size'] = size
            identity = {'sha256': hashlib.sha256(b'tool').hexdigest(), 'size': size, 'executable': True}
            reader = M.InstalledInventory(self.fake_image(), P)
            with self.subTest(size=size), patch.object(reader, '_regular', return_value=identity) as read:
                if size == 512 * 1024 * 1024:
                    self.assertEqual(reader.build_tools(installed), installed['build_tools']['tools'])
                else:
                    with self.assertRaisesRegex(M.InventoryError, 'build-tool-identity'):
                        reader.build_tools(installed)
                    read.assert_not_called()

    def test_build_tools_reject_role_grammar_controls_and_del(self):
        cases = {'cmake': ('3.25.1', 'cmake version 3.25', 'cmake version 3.25.1-rc1'),
                 'ninja': ('ninja 1.11.1', 'cmake version 3.25.1', '1.11.1-rc1'),
                 'pkg_config': ('pkgconf 1.8.1', 'cmake version 3.25.1', '1.8.1-rc1')}
        for role in M.BUILD_TOOLS:
            valid = 'cmake version 3.25.1' if role == 'cmake' else '1.11.1'
            cases[role] += tuple(valid + '\nextra' + chr(code)
                                 for code in (*range(10), *range(11, 32), 127))
            for version in cases[role]:
                installed = self.build_receipt()
                installed['build_tools']['tools'][role]['version'] = version
                installed['tools'][role] = version.splitlines()[0]
                reader = M.InstalledInventory(self.fake_image(), P)
                identity = {'sha256': hashlib.sha256(b'tool').hexdigest(), 'size': 4, 'executable': True}
                with self.subTest(role=role, version=version), patch.object(reader, '_regular', return_value=identity) as read:
                    with self.assertRaisesRegex(M.InventoryError, 'build-tool-identity'):
                        reader.build_tools(installed)
                    self.assertNotIn(M.BUILD_TOOLS[role], [call.args[0] for call in read.call_args_list])

    def test_build_tools_require_nonroot_executable_before_get(self):
        for mode in (0o744, 0o644):
            image = self.fake_image()
            image.stat.side_effect = lambda path: (
                {**regular(path, b'tool'), 'mode': mode}
                if path in M.BUILD_TOOLS.values() else directory(path))
            with self.subTest(mode=mode), self.assertRaisesRegex(P.Stop, 'tool-not-executable'):
                M.InstalledInventory(image, P).build_tools(self.build_receipt())
            image.docker.request.assert_not_called()

    def test_pkg_config_is_mandatory_and_alias_cannot_replace_fixed_pkgconf(self):
        self.assertEqual(M.BUILD_TOOLS, {'cmake': '/usr/bin/cmake', 'ninja': '/usr/bin/ninja',
                                       'pkg_config': '/usr/bin/pkgconf'})
        installed = self.build_receipt()
        reader = M.InstalledInventory(self.fake_image(), P)
        for role in M.BUILD_TOOLS:
            bad = copy.deepcopy(installed)
            del bad['build_tools']['tools'][role]
            with self.subTest(missing=role), patch.object(reader, '_regular') as read:
                with self.assertRaisesRegex(M.InventoryError, 'build-tool-schema'):
                    reader.build_tools(bad)
                read.assert_not_called()
        identity = {'sha256': hashlib.sha256(b'tool').hexdigest(), 'size': 4, 'executable': True}
        for key in ('path', 'resolved_path'):
            bad = copy.deepcopy(installed)
            bad['build_tools']['tools']['pkg_config'][key] = '/usr/bin/pkg-config'
            with self.subTest(key=key), patch.object(reader, '_regular', return_value=identity) as read:
                with self.assertRaisesRegex(M.InventoryError, 'build-tool-path'):
                    reader.build_tools(bad)
                self.assertNotIn('/usr/bin/pkgconf', [call.args[0] for call in read.call_args_list])
        bad = copy.deepcopy(installed)
        del bad['tools']['pkg_config']
        with patch.object(reader, '_regular', return_value=identity), self.assertRaisesRegex(M.InventoryError, 'build-tool-identity'):
            reader.build_tools(bad)

    def test_build_tools_exact_schema_paths_and_streamed_bytes(self):
        installed = self.build_receipt()
        reader = M.InstalledInventory(self.fake_image(), P)
        identity = {'sha256': hashlib.sha256(b'tool').hexdigest(), 'size': 4, 'executable': True}
        with patch.object(reader, '_regular', return_value=identity) as read:
            self.assertEqual(reader.build_tools(installed), installed['build_tools']['tools'])
            self.assertEqual([call.args[0] for call in read.call_args_list], list(M.BUILD_TOOLS.values()))
        for role in M.BUILD_TOOLS:
            for key, value in (('path', '/secret'), ('resolved_path', '/secret'), ('sha256', 'a' * 64),
                               ('size', True), ('executable', 1), ('version', 'wrong\n')):
                bad = copy.deepcopy(installed)
                bad['build_tools']['tools'][role][key] = value
                with self.subTest(role=role, key=key), patch.object(reader, '_regular', return_value=identity), self.assertRaises(M.InventoryError):
                    reader.build_tools(bad)
        bad = copy.deepcopy(installed)
        bad['build_tools']['tools']['extra'] = {}
        with self.assertRaisesRegex(M.InventoryError, 'build-tool-schema'):
            reader.build_tools(bad)


if __name__ == '__main__':
    unittest.main()
