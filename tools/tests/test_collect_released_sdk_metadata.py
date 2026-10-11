# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Offline trust-boundary tests; never read real credentials or access Docker."""
import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('released_sdk', ROOT / 'tools/collect-released-sdk-metadata.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
PACKAGE, TAG, INDEX_DIGEST = M.TARGETS['broad']
SECRET = 'FAKE_ORIGINAL_TOKEN_NEVER_RETAIN'
BEARER = 'FAKE_SCOPED_PULL_BEARER'


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


def descriptor(raw, kind):
    return {'digest': M.digest(raw), 'size': len(raw), 'mediaType': kind}


def registry_fixture():
    config = {'os': 'linux', 'architecture': 'amd64', 'config': {'Labels': {
        'org.opencontainers.image.revision': M.REVISION,
        'org.opencontainers.image.source': M.SOURCE}},
        'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + 'a' * 64]}}
    manifest = {'schemaVersion': 2, 'mediaType': M.MANIFEST,
                'config': descriptor(encoded(config), M.CONFIG),
                'layers': [{'digest': 'sha256:' + 'b' * 64, 'size': 1024,
                            'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip'}]}
    selected = dict(descriptor(encoded(manifest), M.MANIFEST),
                    platform={'os': 'linux', 'architecture': 'amd64'})
    index = {'schemaVersion': 2, 'mediaType': M.INDEX, 'manifests': [selected,
        dict(selected, platform={'os': 'unknown', 'architecture': 'unknown'},
             annotations={'vnd.docker.reference.type': 'attestation-manifest'})]}
    return config, manifest, index


def context_env():
    return {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
            'GITHUB_REPOSITORY': M.REPOSITORY, 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': M.BRANCH,
            'GITHUB_WORKFLOW_REF': M.REPOSITORY + '/' + M.WORKFLOW + '@' + M.BRANCH,
            'GITHUB_SHA': '1' * 40, 'GITHUB_ACTOR': 'trusted-actor',
            'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}


class Response(io.BytesIO):
    chunked = True
    length = None
    status = 200

    def __init__(self, raw=b'', **headers):
        super().__init__(raw)
        self.headers = {'Content-Type': 'application/x-tar', **headers}

    def getheader(self, key, default=None):
        return self.headers.get(key, default)


def file_stat(path, raw, mode=0o644):
    return {'name': Path(path).name, 'size': len(raw), 'mode': mode,
            'mtime': '2026-10-10T00:00:00Z', 'linkTarget': ''}


def archive(path, raw, *, mode=0o644, kind=tarfile.REGTYPE, name=None, extra=False, pax=None):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w', format=tarfile.PAX_FORMAT) as stream:
        member = tarfile.TarInfo(name or Path(path).name)
        member.size, member.mode, member.type = len(raw), mode, kind
        if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            member.size, member.linkname = 0, '/host/secret'
        if pax:
            member.pax_headers = pax
        stream.addfile(member, io.BytesIO(raw))
        if extra:
            other = tarfile.TarInfo('unexpected')
            other.size = 1
            stream.addfile(other, io.BytesIO(b'x'))
    return result.getvalue()


class OfflineTests(unittest.TestCase):
    def setUp(self):
        for target in (patch.object(M, 'https_get', side_effect=AssertionError('network forbidden')),
                       patch.object(M.subprocess, 'run', side_effect=AssertionError('subprocess forbidden')),
                       patch.object(M.LocalConnection, 'connect', side_effect=AssertionError('Docker forbidden'))):
            target.start()
            self.addCleanup(target.stop)

    def verified(self, config=None, manifest=None, index=None):
        if config is None:
            config, manifest, index = registry_fixture()
        raw_config = encoded(config)
        manifest['config'] = descriptor(raw_config, M.CONFIG)
        raw_manifest = encoded(manifest)
        for item in index['manifests']:
            item.update(descriptor(raw_manifest, M.MANIFEST))
        raw_index = encoded(index)
        objects = {M.digest(raw_config): raw_config, M.digest(raw_manifest): raw_manifest,
                   M.digest(raw_index): raw_index}
        with patch.object(M, 'registry_object', side_effect=lambda p, kind, sha, b: objects[sha]):
            return M.verified_registry(PACKAGE, M.digest(raw_index), BEARER)

    def test_trusted_runner_context(self):
        self.assertEqual(M.runner_context(context_env())['repository'], 'atrinik/devcontainer')
        env = context_env()
        env.update(GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REF='refs/heads/main',
                   GITHUB_WORKFLOW_REF=M.REPOSITORY + '/' + M.WORKFLOW + '@refs/heads/main')
        M.runner_context(env)

    def test_pr_fork_wrong_branch_or_tls_override_rejected(self):
        changes = [('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_EVENT_NAME', 'pull_request_target'),
                   ('GITHUB_REPOSITORY', 'fork/devcontainer'), ('GITHUB_REF', 'refs/heads/other'),
                   ('RUNNER_ENVIRONMENT', 'self-hosted'), ('GITHUB_WORKFLOW_REF', 'wrong'),
                   ('GITHUB_RUN_ID', '../escape'), ('GITHUB_ACTOR', 'bad\nactor'),
                   ('OPENSSL_CONF', '/tmp/untrusted'), ('SSLKEYLOGFILE', '/tmp/keys'),
                   ('OPENSSL_MODULES', '/tmp/modules')]
        for key, value in changes:
            with self.subTest(key=key, value=value), self.assertRaises(M.Stop):
                M.runner_context(dict(context_env(), **{key: value}))

    def test_exact_pull_scope_basic_destination_and_scoped_header(self):
        with patch.object(M, 'https_get', return_value=(200, None, encoded({'token': BEARER}))) as http:
            self.assertEqual(M.scoped_bearer(PACKAGE, SECRET, 'trusted-actor'), BEARER)
        host, path, headers = http.call_args.args
        self.assertEqual(host, 'ghcr.io')
        parsed = urllib.parse.urlsplit(path)
        self.assertEqual(parsed.path, '/token')
        self.assertEqual(urllib.parse.parse_qs(parsed.query),
                         {'service': ['ghcr.io'], 'scope': ['repository:' + PACKAGE + ':pull']})
        self.assertEqual(base64.b64decode(headers['Authorization'].removeprefix('Basic ')),
                         ('trusted-actor:' + SECRET).encode())
        payload = json.loads(base64.urlsafe_b64decode(M.auth_header(BEARER)))
        self.assertEqual(payload, {'serveraddress': 'ghcr.io', 'registrytoken': BEARER})
        self.assertNotIn(SECRET, json.dumps(payload))

    def test_token_denial_redirect_scope_and_original_reuse_fail(self):
        with self.assertRaisesRegex(M.Stop, 'package-not-allowed'):
            M.scoped_bearer('other/private', SECRET, 'trusted-actor')
        with patch.object(M, 'https_get', return_value=(302, 'https://evil/' + SECRET, b'')) as http:
            with self.assertRaisesRegex(M.Stop, 'token-redirect-denied'):
                M.scoped_bearer(PACKAGE, SECRET, 'trusted-actor')
            self.assertEqual(http.call_count, 1)
        for payload in ({'token': BEARER, 'scope': 'repository:' + PACKAGE + ':pull,push'},
                        {'token': SECRET}, {'token': BEARER, 'access_token': 'different'}):
            with patch.object(M, 'https_get', return_value=(200, None, encoded(payload))):
                with self.assertRaises(M.Stop):
                    M.scoped_bearer(PACKAGE, SECRET, 'trusted-actor')

    def test_blob_redirect_has_no_credentials_and_verifies_bytes(self):
        raw = b'public config'
        sha = M.digest(raw)
        for namespace in ('ghcr1', 'ghcrblobs15', 'ghcrblobs1', 'ghcrblobs99', 'ghcrblobs999',
                          'ghcrblobs0', 'ghcrblobs015', 'ghcrblobs1000', 'ghcrblobs' + '9' * 128):
            location = 'https://pkg-containers.githubusercontent.com/' + namespace + '/blobs/' + sha + '?sig=FAKE_PRIVATE_URL'
            with self.subTest(namespace=namespace), patch.object(M, 'https_get', side_effect=[
                    (307, location, b''), (200, None, raw)]) as http:
                self.assertEqual(M.registry_object(PACKAGE, 'blobs', sha, BEARER), raw)
                self.assertEqual(http.call_args_list[1].args[2], {'Accept-Encoding': 'identity'})
                self.assertNotIn(BEARER, str(http.call_args_list[1]))
                self.assertNotIn(SECRET, str(http.call_args_list[1]))
        with patch.object(M, 'https_get', return_value=(200, None, b'altered')):
            with self.assertRaisesRegex(M.Stop, 'registry-digest-mismatch'):
                M.registry_object(PACKAGE, 'manifests', INDEX_DIGEST, BEARER)
        location = 'https://pkg-containers.githubusercontent.com/ghcrblobs15/blobs/' + sha
        with patch.object(M, 'https_get', side_effect=[(307, location, b''), (200, None, b'altered')]):
            with self.assertRaisesRegex(M.Stop, 'registry-digest-mismatch'):
                M.registry_object(PACKAGE, 'blobs', sha, BEARER)

    def test_manifest_redirect_and_untrusted_blob_redirect_rejected(self):
        good = 'https://pkg-containers.githubusercontent.com/ghcrblobs15/blobs/' + INDEX_DIGEST
        bad = [good.replace('https://', 'http://'), good.replace('pkg-containers.githubusercontent.com', 'evil'),
               good.replace('.com/', '.com:443/'), good.replace('https://', 'https://user@'),
               good.replace('https://', 'https://user:password@'),
               good.replace('.com/', '.com.evil/'), good.replace('.com/', '.com./'),
               good + '#fragment', ' ' + good, good + '\n']
        for kind, location in [('manifests', good)] + [('blobs', url) for url in bad]:
            with patch.object(M, 'https_get', return_value=(307, location, b'')) as http:
                with self.assertRaises(M.Stop):
                    M.registry_object(PACKAGE, kind, INDEX_DIGEST, BEARER)
                self.assertEqual(http.call_count, 1)
        with patch.object(M, 'https_get', side_effect=[(307, good, b''), (307, good, b'')]) as http:
            with self.assertRaisesRegex(M.Stop, 'blob-redirect-chain-denied'):
                M.registry_object(PACKAGE, 'blobs', INDEX_DIGEST, BEARER)
            self.assertEqual(http.call_count, 2)
            self.assertEqual(http.call_args_list[1].args[2], {'Accept-Encoding': 'identity'})

    def test_blob_redirect_binds_exact_object_and_bounded_storage_namespace(self):
        prefix = 'https://pkg-containers.githubusercontent.com'
        valid = '/ghcrblobs15/blobs/' + INDEX_DIGEST
        paths = [valid.replace(INDEX_DIGEST, 'sha256:' + '0' * 64),
                 valid + '/suffix', valid + '/', valid.replace('/blobs/', '/blobs/../blobs/'),
                 valid.replace('/blobs/', '/blobs/%2e%2e/blobs/'),
                 valid.replace('sha256:', 'sha256%3A'), valid.replace('/blobs/', '/blobs%2F'),
                 valid.replace('/ghcrblobs15/', '/ghcrblobs15//'),
                 valid.replace('/blobs/', '/objects/'), valid.replace('/blobs/', '/blobs/./'),
                 valid.replace('/ghcrblobs15/', '/ghcrblobs/'),
                 valid.replace('/ghcrblobs15/', '/ghcrblobs+15/'),
                 valid.replace('/ghcrblobs15/', '/ghcrblobs%31%35/'),
                 valid.replace('/ghcrblobs15/', '/ghcrblobs１５/'),
                 valid.replace('/ghcrblobs15/', '/ghcrblobs-1/'),
                 valid.replace('/ghcrblobs15/', '/ghcrblobsA/'),
                 valid.replace('/ghcrblobs15/', '/ghcr2/'),
                 valid.replace('/ghcrblobs15/', '/arbitrary/'),
                 '/ghcr1/blobs/not-the-requested-digest']
        for path in paths:
            with self.subTest(path=path), patch.object(M, 'https_get', return_value=(
                    307, prefix + path + '?sig=FAKE_PRIVATE_URL', b'')) as http:
                with self.assertRaisesRegex(M.Stop, 'blob-redirect-denied') as error:
                    M.registry_object(PACKAGE, 'blobs', INDEX_DIGEST, BEARER)
                self.assertEqual(http.call_count, 1)
                self.assertNotIn('FAKE_PRIVATE_URL', str(error.exception))
                self.assertNotIn(path, str(error.exception))

    def test_blob_redirect_url_bound_covers_numeric_path_and_signed_query(self):
        raw = b'public config'
        sha = M.digest(raw)
        prefix = 'https://pkg-containers.githubusercontent.com/ghcrblobs'
        suffix = '/blobs/' + sha + '?sig=FAKE_PRIVATE_URL'
        # Numeric identifiers are opaque strings, including zero/leading zeros.
        # The full URL bound limits both path and signed-query processing.
        locations = [prefix + '9' * (M.REDIRECT_URL_LIMIT - len(prefix + suffix)) + suffix,
                     prefix + '15' + suffix]
        locations[1] += 'x' * (M.REDIRECT_URL_LIMIT - len(locations[1]))
        for index, location in enumerate(locations):
            self.assertEqual(len(location), M.REDIRECT_URL_LIMIT)
            with self.subTest(kind=index), patch.object(M, 'https_get', side_effect=[
                    (307, location, b''), (200, None, raw)]) as http:
                self.assertEqual(M.registry_object(PACKAGE, 'blobs', sha, BEARER), raw)
                self.assertEqual(http.call_args_list[1].args[2], {'Accept-Encoding': 'identity'})
            with self.subTest(kind=index), patch.object(M, 'https_get', return_value=(
                    307, location + 'x', b'')) as http:
                with self.assertRaises(M.BlobRedirectDenied) as caught:
                    M.registry_object(PACKAGE, 'blobs', sha, BEARER)
                self.assertEqual(http.call_count, 1)
                self.assertEqual(caught.exception.diagnostics['url_parse'], 'overlong')
                self.assertNotIn('FAKE_PRIVATE_URL', json.dumps(vars(caught.exception)))
                self.assertNotIn(location, str(caught.exception))

    def test_redirect_diagnostics_report_only_fixed_categories_and_booleans(self):
        sha = INDEX_DIGEST
        prefix = 'https://pkg-containers.githubusercontent.com/'
        cases = [
            (prefix + 'ghcrblobs15/blobs/' + sha, {'namespace': 'ghcrblobs-numbered',
             'path_format': 'namespace-blobs-sha256', 'requested_digest_path_exact': True}),
            (prefix + 'ghcrblobs15/blobs/' + sha.replace(':', '%3A'), {
             'path_format': 'namespace-blobs-encoded-sha256', 'requested_digest_path_exact': False,
             'encoded_requested_digest_in_path': True, 'requested_digest_in_path': False}),
            (prefix + 'ghcrblobs15/blobs/' + sha.removeprefix('sha256:'), {
             'path_format': 'namespace-blobs-hex', 'requested_digest_path_exact': False}),
            (prefix + 'ghcr2/blobs/' + sha, {'namespace': 'legacy-ghcr-numbered-other',
             'requested_digest_in_path': True, 'requested_digest_suffix': True,
             'path_segment_count_capped_at_16': 3}),
            (prefix + 'ghcrblobs1000/blobs/' + sha, {
             'namespace': 'ghcrblobs-numbered', 'requested_digest_path_exact': True}),
            (prefix.replace('.com/', '.com:443/') + 'ghcr1/blobs/' + sha, {
             'host_exact': True, 'authority_exact': False, 'port_default': True, 'port_omitted': False}),
            (prefix.replace('.com/', '.com:8443/') + 'ghcr1/blobs/' + sha, {
             'host_exact': True, 'authority_exact': False, 'port_default': False, 'port_omitted': False})]
        for location, fields in cases:
            with self.subTest(fields=fields):
                result = M.redirect_diagnostics(location, sha)
                for key, value in fields.items():
                    self.assertEqual(result[key], value)
                self.assertNotIn(location, json.dumps(result))
        result = M.redirect_diagnostics('x' * (M.REDIRECT_URL_LIMIT + 1), sha)
        self.assertEqual(result['url_parse'], 'overlong')

    def test_denied_redirect_receipt_and_exception_discard_hostile_url_secrets(self):
        secret = 'FAKE_SENSITIVE_REDIRECT_VALUE'
        base = 'https://pkg-containers.githubusercontent.com'
        suffix = '/ghcrblobs15/blobs/' + INDEX_DIGEST
        locations = [
            'https://' + secret + ':password@pkg-containers.githubusercontent.com' + suffix,
            'https://' + secret + '.invalid' + suffix,
            base + ':' + secret + suffix,
            base + '/ghcrblobs15/blobs/' + secret,
            base + suffix + '?signed=' + secret + '#' + secret,
            secret + '://pkg-containers.githubusercontent.com' + suffix,
            'https://[' + secret,
            base + '/unknown/blobs/' + INDEX_DIGEST + '?signed=' + secret,
            base + '/ghcrblobs15/blobs/' + INDEX_DIGEST.replace(':', '%3A') + '?signed=' + secret,
            base + suffix + '\n' + secret]
        for location in locations:
            with self.subTest(kind=locations.index(location)), patch.object(M, 'https_get', return_value=(
                    307, location, b'')) as http:
                with self.assertRaises(M.BlobRedirectDenied) as caught:
                    M.registry_object(PACKAGE, 'blobs', INDEX_DIGEST, BEARER)
                error = caught.exception
                self.assertEqual(http.call_count, 1)
                self.assertNotIn(secret, str(error))
                self.assertNotIn(secret, json.dumps(vars(error)))
                self.assertNotIn(location, json.dumps(vars(error)))
                docker = Mock()
                docker.negotiate.return_value = {}
                with tempfile.TemporaryDirectory() as temp, patch.object(M, 'runner_docker', return_value=docker), \
                     patch.object(M, 'scoped_bearer', return_value=BEARER), \
                     patch.object(M, 'verified_registry', side_effect=error), patch.object(M, 'StoppedImage') as create:
                    receipt = M.collect('broad', M.runner_context(context_env()), SECRET, Path(temp))
                self.assertEqual(receipt['status'], 'stopped')
                self.assertEqual(receipt['reason'], 'blob-redirect-denied')
                self.assertEqual(receipt['redirect_rejection'], error.diagnostics)
                self.assertNotIn(secret, json.dumps(receipt))
                self.assertNotIn(SECRET, json.dumps(receipt))
                self.assertNotIn(BEARER, json.dumps(receipt))
                self.assertEqual(receipt['artifacts'], [])
                docker.pull.assert_not_called()
                create.assert_not_called()

    def test_registry_chain_ignores_attestation_and_rejects_ambiguity(self):
        result = self.verified()
        self.assertEqual(result['config_digest'], M.digest(result['config']))
        config, manifest, index = registry_fixture()
        index['manifests'].append(copy.deepcopy(index['manifests'][0]))
        with self.assertRaisesRegex(M.Stop, 'ambiguous-linux-amd64-manifest'):
            self.verified(config, manifest, index)

    def test_registry_wrong_producer_platform_foreign_layer_rejected(self):
        for change in ('revision', 'source', 'architecture', 'layer'):
            config, manifest, index = registry_fixture()
            if change in ('revision', 'source'):
                config['config']['Labels']['org.opencontainers.image.' + change] = 'wrong'
            elif change == 'architecture':
                config['architecture'] = 'arm64'
            else:
                manifest['layers'][0]['urls'] = ['https://evil/credential-bait']
            with self.subTest(change=change), self.assertRaises(M.Stop):
                self.verified(config, manifest, index)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(M.Stop, 'duplicate-json-key'):
            M.decode(b'{"token":"one","token":"two"}')

    def good_pull(self):
        return (encoded({'status': 'Digest: ' + INDEX_DIGEST}) + b'\n' +
                encoded({'status': 'Status: Downloaded newer image for ghcr.io/' + PACKAGE}) + b'\n')

    def test_pull_complete_and_every_error_fails(self):
        self.assertEqual(M.parse_pull_stream(Response(self.good_pull()), INDEX_DIGEST), 2)
        streams = [b'', b'{"status":"Pulling"}\n', self.good_pull()[:-1],
                   self.good_pull().replace(INDEX_DIGEST.encode(), ('sha256:' + '0'*64).encode())]
        streams.extend(self.good_pull() + encoded({key: SECRET}) + b'\n' for key in ('error', 'errorDetail'))
        for raw in streams:
            with self.subTest(length=len(raw)), self.assertRaises(M.Stop) as result:
                M.parse_pull_stream(Response(raw), INDEX_DIGEST)
            self.assertNotIn(SECRET, str(result.exception))
        response = Response(self.good_pull())
        response.chunked = False
        with self.assertRaisesRegex(M.Stop, 'unframed-pull-stream'):
            M.parse_pull_stream(response, INDEX_DIGEST)
        response.length = 1
        with self.assertRaisesRegex(M.Stop, 'truncated-pull-stream'):
            M.parse_pull_stream(response, INDEX_DIGEST)
        with patch.object(response, 'readline', side_effect=socket.timeout(SECRET)):
            with self.assertRaises(socket.timeout):
                M.parse_pull_stream(response, INDEX_DIGEST)

    def test_pull_request_is_exact_digest_platform_and_registrytoken(self):
        docker = M.Docker('/unused', (1, 2, 0))
        conn = Mock()
        with patch.object(docker, 'request', return_value=(conn, Response(self.good_pull()))) as req:
            docker.pull(PACKAGE, INDEX_DIGEST, BEARER)
        method, path, headers = req.call_args.args
        self.assertEqual(method, 'POST')
        parsed = urllib.parse.urlsplit(path)
        self.assertEqual(parsed.path, '/images/create')
        self.assertEqual(urllib.parse.parse_qs(parsed.query),
                         {'fromImage': ['ghcr.io/' + PACKAGE + '@' + INDEX_DIGEST], 'platform': ['linux/amd64']})
        self.assertEqual(set(headers), {'X-Registry-Auth'})
        with self.assertRaisesRegex(M.Stop, 'pull-target-not-allowed'):
            docker.pull(PACKAGE, 'sha256:' + '0'*64, BEARER)

    def test_regular_file_archive_retained_or_hashed_without_extraction(self):
        path, raw = M.LLVM_MANIFEST, b'normal metadata'
        for retain in (True, False):
            result, value = M.single_file_archive(Response(archive(path, raw)), path,
                                                   file_stat(path, raw), retain=retain)
            self.assertEqual(result['sha256'], M.hashlib.sha256(raw).hexdigest())
            self.assertEqual(value, raw if retain else None)

    def test_archive_rejects_links_types_paths_and_extra_members(self):
        path, raw = M.LLVM_MANIFEST, b'normal metadata'
        options = [{'kind': kind} for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE,
                    tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.GNUTYPE_SPARSE)]
        options += [{'name': name} for name in ('../llvm-toolchain.json', '/etc/hosts', 'other', 'dir/llvm-toolchain.json')]
        options += [{'extra': True}, {'pax': {'path': 'another'}}, {'pax': {'linkpath': '/etc/hosts'}},
                    {'pax': {'GNU.sparse.size': '100'}}, {'pax': {'SCHILY.xattr.user.test': 'anything'}}]
        for option in options:
            with self.subTest(option=option), self.assertRaises((M.Stop, tarfile.TarError)):
                M.single_file_archive(Response(archive(path, raw, **option)), path,
                                      file_stat(path, raw), retain=True)

    def test_archive_pax_timestamps_only(self):
        path, raw = M.LLVM_MANIFEST, b'normal metadata'
        result, actual = M.single_file_archive(Response(archive(path, raw, pax={'mtime': '123.456'})),
                                               path, file_stat(path, raw), retain=True)
        self.assertEqual(actual, raw)
        self.assertEqual(result['size'], len(raw))

    def test_archive_permissions_sizes_truncation_and_trailing_garbage(self):
        path, raw = M.LLVM_MANIFEST, b'metadata'
        for mode in (0o666, 0o664, 0o600, 0o4755):
            with self.subTest(mode=mode), self.assertRaises(M.Stop):
                M.single_file_archive(Response(archive(path, raw, mode=mode)), path,
                                      file_stat(path, raw, mode), retain=True)
        bad_streams = [archive(path, raw)[:500], archive(path, raw)[:515],
                       archive(path, raw)[:1024], archive(path, raw) + b'garbage',
                       archive(path, raw) + b'\0' * 11000]
        for stream in bad_streams:
            with self.subTest(length=len(stream)), self.assertRaises(M.Stop):
                M.single_file_archive(Response(stream), path, file_stat(path, raw), retain=True)
        for size in (0, M.METADATA_LIMIT+1, len(raw)+1):
            expected = dict(file_stat(path, raw), size=size)
            with self.assertRaises(M.Stop):
                M.single_file_archive(Response(archive(path, raw)), path, expected, retain=True)

    def test_go_modes_and_fixed_aliases(self):
        path, canonical = M.PREFIX + '/bin/clang', M.PREFIX + '/bin/clang-23'
        good = {'name': 'clang', 'mode': M.GO_SYMLINK | 0o777, 'linkTarget': canonical}
        M.stat_matches(good, path, canonical=canonical)
        for value in (dict(good, linkTarget='/etc/secret'), dict(good, mode=0o777),
                      dict(good, name='different')):
            with self.assertRaises(M.Stop):
                M.stat_matches(value, path, canonical=canonical)
        for mode in (M.GO_SYMLINK | 0o755, M.GO_DIRECTORY | 0o777, 0o755):
            with self.assertRaises(M.Stop):
                M.stat_matches({'name': 'opt', 'mode': mode}, '/opt', directory=True)
        M.stat_matches({'name': 'opt', 'mode': M.GO_DIRECTORY | 0o755}, '/opt', directory=True)

    def stopped(self):
        verified = self.verified()
        docker = Mock()
        owned = M.StoppedImage(docker, 'broad', M.runner_context(context_env()), verified)
        owned.identifier = 'c' * 64
        owned.attempted = True
        value = {'Id': owned.identifier, 'Name': '/' + owned.name,
                 'Config': {'Labels': {M.OWNER_LABEL: owned.owner}, 'Image': owned.reference},
                 'State': {'Status': 'created', 'Running': False, 'Pid': 0}, 'Mounts': [],
                 'HostConfig': {'ReadonlyRootfs': True, 'NetworkMode': 'none', 'Privileged': False},
                 'Image': verified['config_digest']}
        docker.get.return_value = value
        return owned, value

    def test_container_config_index_identity_and_stopped_state(self):
        owned, value = self.stopped()
        owned.fence()
        value['Image'] = owned.index_digest
        with self.assertRaisesRegex(M.Stop, 'container-manifest-mismatch'):
            owned.fence()
        value['ImageManifestDescriptor'] = dict(descriptor(owned.verified['manifest'], M.MANIFEST),
                                                platform={'os': 'linux', 'architecture': 'amd64'})
        owned.fence()
        for field, changed in [('Image', 'sha256:' + 'd'*64),
                               ('State', {'Status': 'running', 'Running': True, 'Pid': 100}),
                               ('Mounts', [{'Source': '/secret'}]),
                               ('Config', {'Labels': {M.OWNER_LABEL: 'foreign'}, 'Image': owned.reference})]:
            owned.docker.get.return_value = dict(value, **{field: changed})
            with self.subTest(field=field), self.assertRaises(M.Stop):
                owned.fence()

    def test_container_create_has_no_credentials_mounts_or_start(self):
        owned, _ = self.stopped()
        response = Response(encoded({'Id': owned.identifier}))
        owned.docker.request.return_value = (Mock(), response)
        owned.create()
        method, path, headers, body = owned.docker.request.call_args.args
        config = json.loads(body)
        self.assertEqual(method, 'POST')
        self.assertTrue(path.startswith('/containers/create?'))
        self.assertEqual(config['Env'], [])
        self.assertEqual(config['Entrypoint'], ['/bin/false'])
        self.assertEqual(config['HostConfig']['NetworkMode'], 'none')
        self.assertTrue(config['HostConfig']['ReadonlyRootfs'])
        self.assertNotIn('Mounts', config['HostConfig'])
        self.assertNotIn(SECRET, str(owned.docker.mock_calls))
        self.assertFalse(any('/start' in str(call) for call in owned.docker.mock_calls))

    def test_image_path_and_alias_allowlist_before_archive(self):
        owned, _ = self.stopped()
        with self.assertRaisesRegex(M.Stop, 'image-path-not-allowed'):
            owned.read('/root/.docker/config.json', retain=True)
        with self.assertRaisesRegex(M.Stop, 'tool-alias-not-allowed'):
            owned.alias(M.PREFIX + '/bin/clang', '/etc/secret')
        owned.docker.request.assert_not_called()

    def test_cleanup_fences_owner_and_never_forces_or_prunes(self):
        owned, value = self.stopped()
        owned.docker.request.return_value = (Mock(), Response())
        owned.cleanup()
        owned.docker.request.assert_called_once_with('DELETE', '/containers/' + owned.identifier, expected=204)
        self.assertFalse(owned.attempted)
        owned, value = self.stopped()
        value['Config']['Labels'][M.OWNER_LABEL] = 'foreign'
        with self.assertRaisesRegex(M.Stop, 'container-ownership-mismatch'):
            owned.cleanup()
        owned.docker.request.assert_not_called()

    def test_cleanup_failure_overrides_success_and_errors_stay_sanitized(self):
        owned, _ = self.stopped()
        owned.cleanup = Mock(side_effect=RuntimeError(SECRET))
        owned.docker.negotiate.return_value = {}
        owned.docker.inspect.return_value = {}
        owned.docker.pull.return_value = 2
        with tempfile.TemporaryDirectory() as temp, patch.object(M, 'runner_docker', return_value=owned.docker), \
             patch.object(M, 'scoped_bearer', return_value=BEARER), \
             patch.object(M, 'verified_registry', return_value=owned.verified), \
             patch.object(M, 'StoppedImage', return_value=owned), \
             patch.object(owned, 'create', side_effect=ValueError(SECRET)), \
             patch.object(M.signal, 'alarm'):
            result = M.collect('broad', M.runner_context(context_env()), SECRET, Path(temp))
        self.assertEqual(result['status'], 'stopped')
        self.assertEqual(result['reason'], 'owned-cleanup-failed')
        self.assertNotIn(SECRET, json.dumps(result))

    def test_successful_collection_binds_files_hashes_and_removes_owned_container(self):
        owned, _ = self.stopped()
        owned.docker.negotiate.return_value = {}
        owned.docker.inspect.return_value = {}
        owned.docker.pull.return_value = 2
        data = {path: b'public fixture' for path in M.COMMON_FILES + M.BROAD_FILES}
        data[M.LLVM_MANIFEST] = (ROOT / 'llvm-toolchain.json').read_bytes()
        data['/usr/local/share/atrinik/llvm-toolchain.json'] = data[M.LLVM_MANIFEST]
        manifest = json.loads(data[M.LLVM_MANIFEST])
        data[M.LLVM_SBOM] = encoded({'spdxVersion': 'SPDX-2.3', 'packages': [{
            'name': 'LLVM', 'versionInfo': '23.1.3', 'licenseDeclared': manifest['source']['license'],
            'checksums': [{'algorithm': 'SHA256', 'checksumValue': manifest['source']['sha256']}]}]})
        for name in ('clang', 'clang++'):
            data[M.PREFIX + '/bin/' + name + '.cfg'] = M.CFG
        def read(path, *, retain, executable=False):
            raw = data[path] if retain else b'fixed binary bytes'
            return {'sha256': M.hashlib.sha256(raw).hexdigest(), 'size': len(raw), 'mode': '0o644'}, (
                raw if retain else None)
        with tempfile.TemporaryDirectory() as temp, patch.object(M, 'runner_docker', return_value=owned.docker), \
             patch.object(M, 'scoped_bearer', return_value=BEARER), \
             patch.object(M, 'verified_registry', return_value=owned.verified), \
             patch.object(M, 'StoppedImage', return_value=owned), \
             patch.object(owned, 'create'), patch.object(owned, 'read', side_effect=read), \
             patch.object(owned, 'alias') as aliases, patch.object(owned, 'cleanup') as cleanup, \
             patch.object(M.signal, 'alarm'):
            result = M.collect('broad', M.runner_context(context_env()), SECRET, Path(temp))
            for item in result['artifacts']:
                raw = (Path(temp) / item['path']).read_bytes()
                self.assertEqual(M.hashlib.sha256(raw).hexdigest(), item['sha256'])
                self.assertNotIn(SECRET.encode(), raw)
                self.assertNotIn(BEARER.encode(), raw)
        self.assertEqual(result['status'], 'verified-installed-identity')
        self.assertEqual(set(result['tool_bytes']), set(M.TOOL_FILES))
        self.assertEqual(aliases.call_count, len(M.TOOL_FILES))
        cleanup.assert_called_once()
        self.assertTrue(result['owned_container_removed'])
        self.assertFalse(result['image_code_executed'])
        self.assertFalse(result['final_portable_cohort'])

    def portable_fixture(self):
        """Synthetic file bytes, using the producer's recorded compiler schema."""
        base = '/opt/atrinik-portable/'
        data = {path: b'{}' for path in M.COMMON_FILES + M.PORTABLE_FILES}
        data[M.LLVM_MANIFEST] = (ROOT / 'llvm-toolchain.json').read_bytes()
        data[base + 'llvm-toolchain.json'] = data[M.LLVM_MANIFEST]
        manifest = json.loads(data[M.LLVM_MANIFEST])
        data[M.LLVM_SBOM] = encoded({'spdxVersion': 'SPDX-2.3', 'packages': [{
            'name': 'LLVM', 'versionInfo': '23.1.3', 'licenseDeclared': manifest['source']['license'],
            'checksums': [{'algorithm': 'SHA256', 'checksumValue': manifest['source']['sha256']}]}]})
        for name in ('clang', 'clang++'):
            data[M.PREFIX + '/bin/' + name + '.cfg'] = M.CFG
        data[base + 'contract.json'] = (ROOT / 'portable/contract.json').read_bytes()
        binary = {M.PREFIX + '/' + canonical: b'synthetic tool bytes: ' + canonical.encode()
                  for _, canonical in M.TOOL_FILES.values()}
        compiler = json.loads((ROOT / 'portable/fixtures/llvm-readelf-23.1.3/debian-driver.json').read_bytes())
        for role, (declared, canonical) in M.TOOL_FILES.items():
            entry = compiler['tools'][role] if role in compiler['tools'] else compiler[role]
            self.assertEqual(entry['path'], M.PREFIX + '/' + declared)
            entry['sha256'] = M.hashlib.sha256(binary[M.PREFIX + '/' + canonical]).hexdigest()
        data[base + 'compiler-evidence.json'] = encoded(compiler)
        data[base + 'installed.json'] = encoded({
            'schema_version': 2, 'architecture': 'amd64', 'glibc': 'glibc 2.36',
            'contract_sha256': M.hashlib.sha256(data[base + 'contract.json']).hexdigest(),
            'compiler_evidence_sha256': M.hashlib.sha256(data[base + 'compiler-evidence.json']).hexdigest(),
            'compiler_target': compiler['target'], 'tools': {}, 'pkg_config': {}, 'curl': {}})
        data[base + 'shaders/SHA256SUMS'] = b'0' * 64 + b'  fixed-shader.bin\n'
        shader_sha = M.hashlib.sha256(data[base + 'shaders/SHA256SUMS']).hexdigest()
        data[base + 'shader-generation.json'] = encoded({
            'schema_version': 1, 'output_manifest_sha256': shader_sha,
            'expected_manifest_sha256': shader_sha, 'llvm_toolchain_manifest_sha256': M.LLVM_MANIFEST_SHA})
        return data, binary

    def reseal_compiler_fixture(self, data, compiler):
        base = '/opt/atrinik-portable/'
        data[base + 'compiler-evidence.json'] = encoded(compiler)
        installed = json.loads(data[base + 'installed.json'])
        installed['compiler_evidence_sha256'] = M.hashlib.sha256(data[base + 'compiler-evidence.json']).hexdigest()
        data[base + 'installed.json'] = encoded(installed)

    def collect_portable_fixture(self, data, binary):
        """Mock only transport/lifecycle creation; real HEAD, tar and hash checks."""
        docker = Mock()
        docker.negotiate.return_value = {}
        docker.inspect.return_value = {}
        docker.pull.return_value = 2
        verified = self.verified()
        context = M.runner_context(context_env())
        owned = M.StoppedImage(docker, 'portable-preliminary', context, verified)
        owned.identifier, owned.attempted = 'c' * 64, True
        docker.get.return_value = {
            'Id': owned.identifier, 'Name': '/' + owned.name,
            'Config': {'Labels': {M.OWNER_LABEL: owned.owner}, 'Image': owned.reference},
            'State': {'Status': 'created', 'Running': False, 'Pid': 0}, 'Mounts': [],
            'HostConfig': {'ReadonlyRootfs': True, 'NetworkMode': 'none', 'Privileged': False},
            'Image': verified['config_digest']}
        files = {**data, **binary}
        aliases = {M.PREFIX + '/' + declared: M.PREFIX + '/' + canonical
                   for declared, canonical in M.TOOL_FILES.values() if declared != canonical}
        parents = {str(parent) for path in files for parent in Path(path).parents}
        copied = []
        deleted = []
        def request(method, path, headers=None, body=None, expected=200):
            if method == 'DELETE':
                self.assertEqual(path, '/containers/' + owned.identifier)
                self.assertEqual(expected, 204)
                deleted.append(path)
                return Mock(), Response()
            self.assertIn(method, ('HEAD', 'GET'))
            parsed = urllib.parse.urlsplit(path)
            self.assertEqual(parsed.path, '/containers/' + owned.identifier + '/archive')
            source = urllib.parse.parse_qs(parsed.query)['path'][0]
            if source in aliases:
                info = {'name': Path(source).name, 'mode': M.GO_SYMLINK | 0o777,
                        'size': 8, 'linkTarget': aliases[source]}
            elif source in parents:
                info = {'name': Path(source).name, 'mode': M.GO_DIRECTORY | 0o755, 'size': 4096, 'linkTarget': ''}
            else:
                self.assertIn(source, files)
                mode = 0o755 if source in binary and '/bin/' in source else 0o644
                info = file_stat(source, files[source], mode)
            raw = b''
            if method == 'GET':
                self.assertNotIn(source, aliases)
                self.assertIn(source, files)
                copied.append(source)
                raw = archive(source, files[source], mode=info['mode'])
            return Mock(), Response(raw, **{'X-Docker-Container-Path-Stat': base64.b64encode(encoded(info)).decode()})
        docker.request.side_effect = request
        with tempfile.TemporaryDirectory() as temp, patch.object(M, 'runner_docker', return_value=docker), \
             patch.object(M, 'scoped_bearer', return_value=BEARER), \
             patch.object(M, 'verified_registry', return_value=verified), \
             patch.object(M, 'StoppedImage', return_value=owned), patch.object(owned, 'create'), \
             patch.object(M.signal, 'alarm'):
            result = M.collect('portable-preliminary', context, SECRET, Path(temp))
            for record in result['artifacts']:
                raw = (Path(temp) / record['path']).read_bytes()
                self.assertEqual(M.hashlib.sha256(raw).hexdigest(), record['sha256'])
                self.assertNotIn(SECRET.encode(), raw)
                self.assertNotIn(BEARER.encode(), raw)
                self.assertNotIn(record['path'].removeprefix('files'), binary)
        self.assertEqual(deleted, ['/containers/' + owned.identifier])
        self.assertTrue(result['owned_container_removed'])
        self.assertNotIn(SECRET, json.dumps(result))
        return result, copied

    def test_portable_collection_checks_all_tool_roles_against_streamed_bytes(self):
        data, binary = self.portable_fixture()
        result, copied = self.collect_portable_fixture(data, binary)
        self.assertEqual(result['status'], 'verified-installed-identity')
        self.assertEqual(set(result['tool_bytes']), set(M.TOOL_FILES))
        self.assertEqual(len(json.loads(data['/opt/atrinik-portable/compiler-evidence.json'])['tools']), 10)
        for role, (declared, canonical) in M.TOOL_FILES.items():
            identity = result['tool_bytes'][role]
            expected = binary[M.PREFIX + '/' + canonical]
            self.assertEqual(identity['path'], M.PREFIX + '/' + declared)
            self.assertEqual(identity['canonical_path'], M.PREFIX + '/' + canonical)
            self.assertEqual(identity['sha256'], M.hashlib.sha256(expected).hexdigest())
            self.assertEqual(identity['size'], len(expected))
            self.assertTrue(identity['producer_descriptor_verified'])
        self.assertEqual(set(copied), set(data) | set(binary))
        self.assertEqual(len(copied), len(data) + len(binary))
        self.assertFalse(result['image_code_executed'])
        self.assertFalse(result['final_portable_cohort'])

    def test_portable_contract_and_compiler_receipt_hashes_are_required(self):
        base = '/opt/atrinik-portable/'
        for name in ('contract.json', 'compiler-evidence.json'):
            data, binary = self.portable_fixture()
            data[base + name] += b' '
            with self.subTest(name=name):
                result, copied = self.collect_portable_fixture(data, binary)
                self.assertEqual(result['status'], 'stopped')
                self.assertEqual(result['reason'], 'portable-metadata-binding-mismatch')
                self.assertFalse(set(copied) & set(binary))

    def test_portable_each_tool_requires_producer_version_banner(self):
        base = '/opt/atrinik-portable/'
        invalid_versions = ('missing', None, 23, {}, [], '', 'LLVM version 22.1.3',
                            'LLVM version 23.1.30', 'LLVM version 123.1.3')
        for role in set(M.TOOL_FILES) - {'runtime', 'unwinder'}:
            for version in invalid_versions:
                data, binary = self.portable_fixture()
                compiler = json.loads(data[base + 'compiler-evidence.json'])
                if version == 'missing':
                    del compiler['tools'][role]['version']
                else:
                    compiler['tools'][role]['version'] = version
                # Keep the outer byte binding valid to exercise the version gate.
                self.reseal_compiler_fixture(data, compiler)
                with self.subTest(role=role, version=version):
                    result, copied = self.collect_portable_fixture(data, binary)
                    self.assertEqual(result['status'], 'stopped')
                    self.assertEqual(result['reason'], 'portable-tool-version-mismatch')
                    self.assertFalse(set(copied) & set(binary))

    def test_portable_missing_extra_and_misidentified_roles_are_rejected(self):
        base = '/opt/atrinik-portable/'
        for change in ('missing', 'extra'):
            data, binary = self.portable_fixture()
            compiler = json.loads(data[base + 'compiler-evidence.json'])
            if change == 'missing':
                del compiler['tools']['cxx_compiler']
            else:
                compiler['tools']['foreign'] = dict(compiler['tools']['compiler'])
            self.reseal_compiler_fixture(data, compiler)
            with self.subTest(change=change):
                result, copied = self.collect_portable_fixture(data, binary)
                self.assertEqual(result['reason'], 'portable-tool-roles-mismatch')
                self.assertEqual(result['status'], 'stopped')
                self.assertFalse(set(copied) & set(binary))
        # Recompute the enclosing receipt so every mismatch reaches the actual
        # path/digest comparison after the canonical bytes have been streamed.
        for role in M.TOOL_FILES:
            for field in ('path', 'sha256'):
                data, binary = self.portable_fixture()
                compiler = json.loads(data[base + 'compiler-evidence.json'])
                entry = compiler['tools'][role] if role in compiler['tools'] else compiler[role]
                entry[field] = M.PREFIX + '/bin/clang' if field == 'path' and role == 'cxx_compiler' else (
                    '/tmp/foreign-tool' if field == 'path' else '0' * 64)
                self.reseal_compiler_fixture(data, compiler)
                with self.subTest(role=role, field=field):
                    result, copied = self.collect_portable_fixture(data, binary)
                    self.assertEqual(result['status'], 'stopped')
                    self.assertEqual(result['reason'], 'installed-tool-bytes-mismatch')
                    self.assertIn(M.PREFIX + '/' + M.TOOL_FILES[role][1], copied)
                    self.assertNotIn(role, result['tool_bytes'])

    def test_portable_changed_canonical_binary_bytes_are_rejected(self):
        for canonical in {pair[1] for pair in M.TOOL_FILES.values()}:
            data, binary = self.portable_fixture()
            binary[M.PREFIX + '/' + canonical] += b' changed'
            with self.subTest(canonical=canonical):
                result, copied = self.collect_portable_fixture(data, binary)
                self.assertEqual(result['status'], 'stopped')
                self.assertEqual(result['reason'], 'installed-tool-bytes-mismatch')
                self.assertIn(M.PREFIX + '/' + canonical, copied)

    def test_portable_shader_manifest_and_generation_bindings_are_required(self):
        base = '/opt/atrinik-portable/'
        for change in ('manifest-bytes', 'output_manifest_sha256', 'expected_manifest_sha256',
                       'llvm_toolchain_manifest_sha256'):
            data, binary = self.portable_fixture()
            if change == 'manifest-bytes':
                data[base + 'shaders/SHA256SUMS'] += b'changed'
            else:
                generation = json.loads(data[base + 'shader-generation.json'])
                generation[change] = '0' * 64
                data[base + 'shader-generation.json'] = encoded(generation)
            with self.subTest(change=change):
                result, copied = self.collect_portable_fixture(data, binary)
                self.assertEqual(result['status'], 'stopped')
                self.assertEqual(result['reason'], 'shader-metadata-binding-mismatch')
                self.assertFalse(set(copied) & set(binary))

    def local_image_fixture(self):
        verified = self.verified()
        reference = 'ghcr.io/' + PACKAGE + '@' + INDEX_DIGEST
        local = {'Id': verified['config_digest'], 'Os': 'linux', 'Architecture': 'amd64',
                 'RepoDigests': [reference],
                 'RootFS': {'Type': 'layers', 'Layers': verified['config_object']['rootfs']['diff_ids']},
                 'Config': copy.deepcopy(verified['config_object']['config'])}
        selected = dict(descriptor(verified['manifest'], M.MANIFEST),
                        platform={'os': 'linux', 'architecture': 'amd64'})
        return verified, reference, local, selected

    def test_local_image_legacy_and_platform_manifest_identity_modes(self):
        verified, reference, local, selected = self.local_image_fixture()
        index = {'digest': INDEX_DIGEST, 'mediaType': M.INDEX, 'size': len(verified['index'])}
        for desc in (None, index, selected):
            legacy = dict(local, Descriptor=desc)
            self.assertEqual(M.verify_local(legacy, reference, INDEX_DIGEST, verified), 'config-digest')
        local.update(Id=verified['manifest_digest'], Descriptor=selected)
        self.assertEqual(M.verify_local(local, reference, INDEX_DIGEST, verified), 'platform-manifest-digest')
        docker = M.Docker('/unused', (0, 0, 0))
        with patch.object(docker, 'get', return_value=local) as get:
            result = docker.inspect(PACKAGE, INDEX_DIGEST, verified)
        request = urllib.parse.urlsplit(get.call_args.args[0])
        self.assertEqual(json.loads(urllib.parse.parse_qs(request.query)['platform'][0]),
                         {'os': 'linux', 'architecture': 'amd64'})
        self.assertEqual(result['local_image_id'], verified['manifest_digest'])
        self.assertEqual(result['local_image_identity_kind'], 'platform-manifest-digest')
        self.assertNotIn('image_config_id', result)

    def test_local_image_identity_and_platform_fences(self):
        verified, reference, local, selected = self.local_image_fixture()
        for identity in (verified['config_digest'], verified['manifest_digest']):
            good = dict(local, Id=identity, Descriptor=selected)
            for key, wrong in [('Id', INDEX_DIGEST), ('Id', 'sha256:' + 'c' * 64),
                               ('Os', 'windows'), ('Architecture', 'arm64'), ('RepoDigests', []),
                               ('RootFS', {'Type': 'layers', 'Layers': []}), ('Config', {'Labels': {}})]:
                with self.subTest(identity=identity, key=key), self.assertRaises(M.Stop):
                    M.verify_local(dict(good, **{key: wrong}), reference, INDEX_DIGEST, verified)

    def test_local_manifest_descriptor_requires_every_bound_field(self):
        verified, reference, local, selected = self.local_image_fixture()
        descriptors = [None, {}, dict(selected, mediaType=M.INDEX), dict(selected, size=True),
                       dict(selected, size=selected['size'] + 1), dict(selected, digest=INDEX_DIGEST),
                       dict(selected, platform={'os': 'linux', 'architecture': 'arm64'}),
                       dict(selected, platform={'os': 'linux', 'architecture': 'amd64', 'variant': 'v2'}),
                       dict(selected, urls=['https://foreign.invalid']), dict(selected, data='foreign')]
        descriptors += [{key: value for key, value in selected.items() if key != missing}
                        for missing in ('mediaType', 'size', 'digest', 'platform')]
        for identity in (verified['config_digest'], verified['manifest_digest']):
            for index, desc in enumerate(descriptors):
                if identity == verified['config_digest'] and desc is None:
                    continue
                with self.subTest(identity=identity, case=index), self.assertRaisesRegex(M.Stop, 'local-descriptor-mismatch'):
                    M.verify_local(dict(local, Id=identity, Descriptor=desc), reference, INDEX_DIGEST, verified)
        legacy_index = {'digest': INDEX_DIGEST, 'mediaType': M.INDEX, 'size': len(verified['index'])}
        for key, value in (('mediaType', M.MANIFEST), ('size', 0), ('platform', {'os': 'linux'}),
                           ('urls', ['https://foreign.invalid']), ('data', 'foreign')):
            with self.subTest(key=key), self.assertRaisesRegex(M.Stop, 'local-descriptor-mismatch'):
                M.verify_local(dict(local, Descriptor=dict(legacy_index, **{key: value})), reference, INDEX_DIGEST, verified)

    def test_local_config_fields_are_bound_even_when_labels_match(self):
        verified, reference, local, selected = self.local_image_fixture()
        for identity in (verified['config_digest'], verified['manifest_digest']):
            for key, value in (('Env', ['FOREIGN=1']), ('Cmd', ['/bin/foreign']), ('User', 'foreign'),
                               ('WorkingDir', '/foreign'), ('Entrypoint', ['/bin/foreign'])):
                changed = dict(local['Config'], **{key: value})
                self.assertEqual(changed['Labels'], local['Config']['Labels'])
                with self.subTest(identity=identity, key=key), self.assertRaisesRegex(M.Stop, 'local-config-mismatch'):
                    M.verify_local(dict(local, Id=identity, Descriptor=selected, Config=changed),
                                   reference, INDEX_DIGEST, verified)
        cfg = copy.deepcopy(verified['config_object'])
        cfg['rootfs']['diff_ids'] = ['sha256:' + 'a' * 64, 'sha256:' + 'b' * 64]
        verified = dict(verified, config_object=cfg)
        with self.assertRaisesRegex(M.Stop, 'local-rootfs-mismatch'):
            M.verify_local(dict(local, RootFS={'Type': 'layers', 'Layers': list(reversed(cfg['rootfs']['diff_ids']))}),
                           reference, INDEX_DIGEST, verified)

    def test_local_config_documented_api_absence_defaults_only(self):
        defaults = {'Cmd': None, 'Entrypoint': None, 'Env': None, 'Labels': None,
                    'OnBuild': None, 'Volumes': None, 'User': '', 'WorkingDir': ''}
        for key, default in defaults.items():
            self.assertTrue(M.local_config_matches({key: default}, {}))
            for value in (None, [], {}, '', False, 0, ['foreign'], {'foreign': {}}, 'foreign'):
                if type(value) is type(default) and value == default:
                    continue
                with self.subTest(key=key, value=value):
                    self.assertFalse(M.local_config_matches({key: value}, {}))
        self.assertTrue(M.local_config_matches(defaults, {}))
        self.assertFalse(M.local_config_matches({'Unknown': None}, {}))
        self.assertFalse(M.local_config_matches({'Unknown': ''}, {}))
        verified, reference, local, selected = self.local_image_fixture()
        actual = {**defaults, **local['Config']}
        for identity in (verified['config_digest'], verified['manifest_digest']):
            M.verify_local(dict(local, Id=identity, Descriptor=selected, Config=actual),
                           reference, INDEX_DIGEST, verified)
        self.assertEqual(set(actual), set(defaults) | set(local['Config']))

    def test_local_config_broad_shape_preserves_declared_fields(self):
        # Retained broad OCI config has exactly Cmd, Env and Labels. Use that
        # shape here; the private replay separately checks the actual raw bytes.
        expected = {'Cmd': ['/bin/bash'], 'Env': ['CC=clang'], 'Labels': {'fixed': 'label'}}
        actual = dict(expected, Entrypoint=None, OnBuild=None, Volumes=None, User='', WorkingDir='')
        self.assertTrue(M.local_config_matches(actual, expected))
        for key in expected:
            changed = dict(actual, **{key: None})
            self.assertFalse(M.local_config_matches(changed, expected))
        self.assertFalse(M.local_config_matches(dict(actual, Unknown=None), expected))
        self.assertFalse(M.local_config_matches(dict(actual, User='foreign'), expected))
        self.assertFalse(M.local_config_matches(dict(actual, WorkingDir='/foreign'), expected))

    def test_local_config_preserves_every_raw_declared_field(self):
        for key in ('Cmd', 'Entrypoint', 'Env', 'Labels', 'OnBuild', 'Volumes', 'User', 'WorkingDir'):
            for expected_value in (None, [], {}, '', ['declared'], {'declared': {}}):
                expected = {key: expected_value}
                self.assertTrue(M.local_config_matches(copy.deepcopy(expected), expected))
                self.assertFalse(M.local_config_matches({}, expected))
                for actual_value in (None, [], {}, '', ['different'], {'different': {}}):
                    if actual_value == expected_value:
                        continue
                    with self.subTest(key=key, expected=expected_value, actual=actual_value):
                        self.assertFalse(M.local_config_matches(dict(expected, **{key: actual_value}), expected))
        for wrong in (None, [], '', 0):
            self.assertFalse(M.local_config_matches(wrong, {}))
            self.assertFalse(M.local_config_matches({}, wrong))

    def test_container_selected_descriptor_rejects_wrong_type_size_and_platform(self):
        owned, value = self.stopped()
        selected = dict(descriptor(owned.verified['manifest'], M.MANIFEST),
                        platform={'os': 'linux', 'architecture': 'amd64'})
        for identity in (owned.index_digest, owned.verified['manifest_digest'], owned.verified['config_digest']):
            value['Image'] = identity
            for key, wrong in (('mediaType', M.INDEX), ('size', 0), ('size', True),
                               ('platform', {'os': 'linux', 'architecture': 'amd64', 'variant': 'v2'}),
                               ('urls', ['https://foreign.invalid']), ('data', 'foreign')):
                value['ImageManifestDescriptor'] = dict(selected, **{key: wrong})
                with self.subTest(identity=identity, key=key), self.assertRaisesRegex(M.Stop, 'container-manifest-mismatch'):
                    owned.fence()

    def test_access_denial_stops_without_container_or_retry(self):
        docker = Mock()
        docker.negotiate.return_value = {}
        with tempfile.TemporaryDirectory() as temp, patch.object(M, 'runner_docker', return_value=docker), \
             patch.object(M, 'scoped_bearer', side_effect=M.Stop('registry-request-denied')) as exchange, \
             patch.object(M, 'StoppedImage') as create:
            result = M.collect('broad', M.runner_context(context_env()), SECRET, Path(temp))
        self.assertEqual(result['status'], 'stopped')
        self.assertEqual(exchange.call_count, 1)
        create.assert_not_called()
        docker.pull.assert_not_called()

    def test_artifact_path_links_and_overwrite_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            record = M.save(root, 'files/metadata.json', b'public metadata')
            self.assertEqual(record['size'], 15)
            self.assertEqual((root / record['path']).stat().st_mode & 0o777, 0o600)
            for path in ('../escape', '/absolute'):
                with self.assertRaises(M.Stop):
                    M.save(root, path, b'anything')
            with self.assertRaises(FileExistsError):
                M.save(root, 'files/metadata.json', b'overwrite')
            (root / 'link').symlink_to(root / 'files', target_is_directory=True)
            with self.assertRaises(M.Stop):
                M.save(root, 'link/secret', b'anything')

    def test_workflow_is_same_repo_push_dispatch_read_only_and_pinned(self):
        text = (ROOT / M.WORKFLOW).read_text()
        self.assertNotIn('  pull_request:', text)
        self.assertNotIn('pull_request_target:', text)
        self.assertIn('      - build/llvm-released-sdk-verification-final', text)
        self.assertIn('  workflow_dispatch:', text)
        self.assertIn("github.repository == 'atrinik/devcontainer'", text)
        self.assertIn('      packages: read', text)
        self.assertNotIn(': write', text)
        self.assertIn('persist-credentials: false', text)
        self.assertIn('python3 -I tools/collect-released-sdk-metadata.py', text)
        self.assertIn('env -u SSLKEYLOGFILE -u OPENSSL_CONF -u OPENSSL_MODULES', text)
        for line in text.splitlines():
            if 'uses:' in line:
                self.assertRegex(line, r'uses: [^@]+@[0-9a-f]{40}(?: |$)')


if __name__ == '__main__':
    unittest.main()
