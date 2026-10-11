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
        location = 'https://pkg-containers.githubusercontent.com/ghcr1/blobs/x?sig=FAKE_PRIVATE_URL'
        with patch.object(M, 'https_get', side_effect=[(307, location, b''), (200, None, raw)]) as http:
            self.assertEqual(M.registry_object(PACKAGE, 'blobs', M.digest(raw), BEARER), raw)
        self.assertEqual(http.call_args_list[1].args[2], {'Accept-Encoding': 'identity'})
        with patch.object(M, 'https_get', return_value=(200, None, b'altered')):
            with self.assertRaisesRegex(M.Stop, 'registry-digest-mismatch'):
                M.registry_object(PACKAGE, 'manifests', INDEX_DIGEST, BEARER)

    def test_manifest_redirect_and_untrusted_blob_redirect_rejected(self):
        good = 'https://pkg-containers.githubusercontent.com/ghcr1/blobs/x'
        bad = ['http://pkg-containers.githubusercontent.com/ghcr1/blobs/x',
               'https://evil/ghcr1/blobs/x', good.replace('.com/', '.com:443/'),
               good.replace('https://', 'https://user@'), good + '#fragment', ' ' + good, good + '\n']
        for kind, location in [('manifests', good)] + [('blobs', url) for url in bad]:
            with patch.object(M, 'https_get', return_value=(307, location, b'')) as http:
                with self.assertRaises(M.Stop):
                    M.registry_object(PACKAGE, kind, INDEX_DIGEST, BEARER)
                self.assertEqual(http.call_count, 1)
        with patch.object(M, 'https_get', side_effect=[(307, good, b''), (307, good, b'')]):
            with self.assertRaisesRegex(M.Stop, 'blob-redirect-chain-denied'):
                M.registry_object(PACKAGE, 'blobs', INDEX_DIGEST, BEARER)

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
        value['ImageManifestDescriptor'] = {'digest': owned.verified['manifest_digest'],
                                           'platform': {'os': 'linux', 'architecture': 'amd64'}}
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
        self.assertIn('      - build/llvm-released-sdk-verification', text)
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
