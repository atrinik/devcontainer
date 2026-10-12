#!/usr/bin/python3 -I
# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Collect bounded installed identity from three fixed released Linux SDKs.

Only trusted same-repository push/dispatch on GitHub-hosted Linux may acquire.
No image code runs: a task-owned container stays in created state until removal.
Artifacts prove installed identity, not runtime health or a final portable cohort.

RegistryToken semantics: moby/moby v28.5.1 api/types/registry/authconfig.go and
 distribution/registry.go. Archive HEAD resolves LinkTarget in daemon/containerfs_linux.go;
GET returns a tar stream (daemon/archive_unix.go). No archive is extracted.
"""
import argparse
import base64
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import urllib.parse
import uuid
from types import SimpleNamespace

_INVENTORY_SPEC = importlib.util.spec_from_file_location('released_sdk_inventory',
    Path(__file__).resolve().with_name('released_sdk_inventory.py'))
INVENTORY = importlib.util.module_from_spec(_INVENTORY_SPEC)
_INVENTORY_SPEC.loader.exec_module(INVENTORY)

REVISION = '4af130578df18a1944880cd279c7f23afe9cc668'
SOURCE = 'https://github.com/atrinik/devcontainer'
REPOSITORY = 'atrinik/devcontainer'
WORKFLOW = '.github/workflows/qualify-released-linux-sdk.yml'
BRANCH = 'refs/heads/build/llvm-sdk118-collector-refresh'
TARGETS = {
    'broad': ('atrinik/linux-build', '1.18.0',
              'sha256:613cf43ab07634db005a28462a009c4c28c90dccb1b5175e13e8072b6dfe8d72'),
    'classic': ('atrinik/classic-build', '1.18.0',
              'sha256:86d3c4182dc786db8ace56d9d8dc57ff4f14c1c4f517b728547626f576280449'),
    'portable-preliminary': ('atrinik/classic-portable-build', '1.18.0',
              'sha256:ece5d3892db0ae7c8a13141720fdc62775b02cf67cf2b6df15bff9ccdb039527'),
}
HISTORICAL_TARGETS = frozenset(TARGETS)
# No final image is admitted until the actual released coordinates are reviewed.
# Each future entry requires exactly producer_revision, consumer_commit,
# manifest_digest and config_digest; TARGETS must separately pin its index.
FINAL_TARGETS = {}
SCANNER_FILES = ('scan-released-sdk-filesystem.py', 'released_sdk_inventory.py')
SCANNER_LIMIT = 64 * 1024 * 1024

INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
CONFIG = 'application/vnd.oci.image.config.v1+json'
LAYERS = {'application/vnd.oci.image.layer.v1.tar+gzip',
          'application/vnd.oci.image.layer.v1.tar+zstd',
          'application/vnd.oci.image.layer.v1.tar'}
LIMIT = 16 * 1024 * 1024
METADATA_LIMIT = 4 * 1024 * 1024
BINARY_LIMIT = 1024 * 1024 * 1024
REDIRECT_URL_LIMIT = 65536
PREFIX = '/opt/llvm-23.1.3'
LLVM_MANIFEST = PREFIX + '/share/atrinik/llvm-toolchain.json'
LLVM_SBOM = PREFIX + '/share/atrinik/llvm-toolchain.spdx.json'
LLVM_MANIFEST_SHA = 'a98d2cecb17e8da941b20051ea6d4ff48cdf5db5f45fe31d21f739538eaa9bc7'
CFG = b'--rtlib=compiler-rt\n--unwindlib=libunwind\n-fuse-ld=lld\n-L<CFGDIR>/../lib\n'
LLVM_NOTICES = tuple(PREFIX + '/share/licenses/llvm/' + component + '-LICENSE.TXT'
                     for component in ('llvm', 'clang', 'clang-tools-extra', 'lld',
                                       'compiler-rt', 'libunwind'))
COMMON_FILES = (LLVM_MANIFEST, LLVM_SBOM, PREFIX + '/bin/clang.cfg',
                PREFIX + '/bin/clang++.cfg') + LLVM_NOTICES
BROAD_FILES = tuple('/usr/local/share/atrinik/' + path for path in (
    'llvm-toolchain.json', 'toolchains.json', 'audio-toolchain.json', 'audio-toolchain.spdx.json',
    'classic-vulkan-toolchain.json', 'classic-vulkan-toolchain.spdx.json',
    'classic-vulkan-packages.lock', 'classic-curl-toolchain.json',
    'curl/curl_config.h', 'curl/config.log')) + ('/usr/local/bin/curl-config',)
CLASSIC_FILES = tuple('/usr/local/share/atrinik/' + path for path in (
    'llvm-toolchain.json', 'classic-toolchain.json', 'classic-packages.lock',
    'audio-toolchain.json', 'audio-toolchain.spdx.json',
    'classic-shader-toolchain.json', 'classic-shader-toolchain.spdx.json',
    'classic-vulkan-toolchain.json', 'classic-vulkan-toolchain.spdx.json',
    'classic-vulkan-packages.lock', 'classic-curl-toolchain.json',
    'curl/curl_config.h', 'curl/config.log')) + ('/usr/local/bin/curl-config',)
PORTABLE_FILES = tuple('/opt/atrinik-portable/' + path for path in (
    'llvm-toolchain.json', 'contract.json', 'installed.json', 'compiler-evidence.json',
    'runtime-abi.json', 'runtime-sources.json', 'debian-sources.json', 'curl-source-receipt.json',
    'shader-generation.json', 'shader-inputs.txt', 'shaders/SHA256SUMS',
    'audio-toolchain.json', 'audio-toolchain.spdx.json',
    'classic-shader-toolchain.json', 'classic-shader-toolchain.spdx.json',
    'classic-curl-toolchain.json', 'curl-toolchain.json', 'packages.lock',
    'sources/curl/curl_config.h', 'sources/curl/config.log',
    'sources/curl/apt-source-record.txt', 'sources/curl/archive-signature.txt'))
TARGET_FILES = {'broad': BROAD_FILES, 'classic': CLASSIC_FILES,
                'portable-preliminary': PORTABLE_FILES}
# Role spellings and canonical targets are fixed; descriptors cannot extend this set.
TOOL_FILES = {
    'compiler': ('bin/clang', 'bin/clang-23'),
    'cxx_compiler': ('bin/clang++', 'bin/clang-23'),
    'linker': ('bin/ld.lld', 'bin/lld'),
    'readelf': ('bin/llvm-readelf', 'bin/llvm-readobj'),
    'archiver': ('bin/llvm-ar', 'bin/llvm-ar'),
    'ranlib': ('bin/llvm-ranlib', 'bin/llvm-ar'),
    'nm': ('bin/llvm-nm', 'bin/llvm-nm'),
    'strip': ('bin/llvm-strip', 'bin/llvm-objcopy'),
    'objcopy': ('bin/llvm-objcopy', 'bin/llvm-objcopy'),
    'objdump': ('bin/llvm-objdump', 'bin/llvm-objdump'),
    'runtime': ('lib/clang/23/lib/linux/libclang_rt.builtins-x86_64.a',
                'lib/clang/23/lib/linux/libclang_rt.builtins-x86_64.a'),
    'unwinder': ('lib/libunwind.a', 'lib/libunwind.a'),
}
OWNER_LABEL = 'io.atrinik.released-sdk-evidence.owner'
GO_DIRECTORY = 1 << 31
GO_SYMLINK = 1 << 27


class Stop(Exception):
    """Only fixed codes, never remote error bodies or exception strings."""


class BlobRedirectDenied(Stop):
    """A fixed failure code plus bounded routing diagnostics."""

    def __init__(self, location, sha):
        super().__init__('blob-redirect-denied')
        self.diagnostics = redirect_diagnostics(location, sha)


def redirect_diagnostics(location, sha):
    # Never return any input substring: query signatures, userinfo, hostnames,
    # fragments and object paths can all contain secrets. This does not authorize
    # a redirect; the independent allowlist below remains the only routing gate.
    result = {'schema_version': 1, 'url_parse': 'invalid', 'ascii_clean': False,
              'scheme_https': False, 'host_exact': False, 'authority_exact': False,
              'port_valid': False, 'port_default': False, 'port_omitted': False,
              'userinfo_present': False, 'fragment_present': False,
              'namespace': 'unknown', 'path_format': 'other',
              'requested_digest_path_exact': False, 'requested_digest_in_path': False,
              'requested_digest_suffix': False, 'encoded_requested_digest_in_path': False,
              'path_segment_count_capped_at_16': 0}
    if not isinstance(location, str):
        return result
    if len(location) > REDIRECT_URL_LIMIT:
        result['url_parse'] = 'overlong'
        return result
    result['ascii_clean'] = all(32 < ord(c) < 127 for c in location) and '\\' not in location
    try:
        dest = urllib.parse.urlsplit(location)
        result.update({'url_parse': 'parsed', 'scheme_https': dest.scheme == 'https',
                       'host_exact': dest.hostname == 'pkg-containers.githubusercontent.com',
                       'authority_exact': dest.netloc == 'pkg-containers.githubusercontent.com',
                       'userinfo_present': '@' in dest.netloc, 'fragment_present': '#' in location})
        try:
            port = dest.port
        except ValueError:
            pass
        else:
            result.update({'port_valid': True, 'port_default': port in (None, 443),
                           'port_omitted': port is None})
        parts = dest.path.split('/')
        namespace = parts[1] if len(parts) > 1 else ''
        if namespace == 'ghcr1':
            result['namespace'] = 'ghcr1'
        elif re.fullmatch(r'ghcr[0-9]+', namespace):
            result['namespace'] = 'legacy-ghcr-numbered-other'
        elif re.fullmatch(r'ghcrblobs[0-9]+', namespace):
            result['namespace'] = 'ghcrblobs-numbered'
        for pattern, category in (
                (r'/[^/]+/blobs/sha256:[0-9a-f]{64}', 'namespace-blobs-sha256'),
                (r'/[^/]+/blobs/sha256%3[Aa][0-9a-f]{64}', 'namespace-blobs-encoded-sha256'),
                (r'/[^/]+/blobs/[0-9a-f]{64}', 'namespace-blobs-hex')):
            if re.fullmatch(pattern, dest.path):
                result['path_format'] = category
                break
        result['requested_digest_path_exact'] = dest.path == '/' + namespace + '/blobs/' + sha
        result['requested_digest_in_path'] = sha in dest.path
        result['requested_digest_suffix'] = dest.path.endswith('/' + sha)
        result['encoded_requested_digest_in_path'] = (sha not in dest.path and
            sha.encode('ascii') in urllib.parse.unquote_to_bytes(dest.path))
        result['path_segment_count_capped_at_16'] = min(16, sum(bool(part) for part in parts))
    except ValueError:
        # Parsing errors can quote hostile input; retain no exception text.
        result['url_parse'] = 'invalid'
    return result


def require(condition, code):
    if not condition:
        raise Stop(code)


def decode(raw):
    # Reject duplicate keys rather than trusting inconsistent JSON parsers.
    def pairs(items):
        obj = {}
        for key, value in items:
            require(key not in obj, 'duplicate-json-key')
            obj[key] = value
        return obj
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError):
        raise Stop('invalid-json') from None


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None


class LocalConnection(http.client.HTTPConnection):
    def __init__(self, path, identity, timeout=90):
        super().__init__('localhost', timeout=timeout)
        self.path, self.identity = path, identity

    def connect(self):
        info = os.stat(self.path, follow_symlinks=False)
        require(stat.S_ISSOCK(info.st_mode) and
                (info.st_dev, info.st_ino, info.st_uid) == self.identity,
                'docker-socket-changed')
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)
        _, uid, _ = struct.unpack('3i', self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(uid == self.identity[2], 'docker-peer-mismatch')


def bounded_read(response):
    raw = response.read(LIMIT + 1)
    require(len(raw) <= LIMIT, 'response-too-large')
    return raw


def https_get(host, path, headers):
    # http.client neither follows redirects nor consults proxy environment.
    context = ssl.create_default_context(cafile='/etc/ssl/certs/ca-certificates.crt')
    context.keylog_filename = None
    connection = http.client.HTTPSConnection(host, timeout=60, context=context)
    try:
        connection.request('GET', path, headers=headers)
        response = connection.getresponse()
        status = response.status
        if 300 <= status < 400:
            return status, response.getheader('Location'), b''
        require(status == 200, 'registry-request-denied')
        return status, None, bounded_read(response)
    finally:
        connection.close()


def scoped_bearer(package, original, actor):
    require(package in {value[0] for value in TARGETS.values()}, 'package-not-allowed')
    scope = 'repository:' + package + ':pull'
    path = '/token?' + urllib.parse.urlencode({'service': 'ghcr.io', 'scope': scope})
    basic = base64.b64encode((actor + ':' + original).encode()).decode('ascii')
    status, _, raw = https_get('ghcr.io', path, {'Authorization': 'Basic ' + basic})
    require(status == 200, 'token-redirect-denied')
    payload = decode(raw)
    require(isinstance(payload, dict), 'invalid-token-response')
    if 'scope' in payload:
        require(payload['scope'] == scope, 'unexpected-token-scope')
    token = payload.get('token') or payload.get('access_token')
    require(isinstance(token, str) and 0 < len(token) < 32768 and
            all(32 < ord(c) < 127 for c in token) and token != original,
            'invalid-scoped-token')
    if payload.get('token') and payload.get('access_token'):
        require(payload['token'] == payload['access_token'], 'ambiguous-token-response')
    return token


def registry_object(package, kind, sha, bearer):
    require(package in {value[0] for value in TARGETS.values()} and kind in ('manifests', 'blobs')
            and valid_digest(sha), 'registry-target-invalid')
    path = '/v2/' + package + '/' + kind + '/' + sha
    status, location, raw = https_get('ghcr.io', path, {
        'Authorization': 'Bearer ' + bearer, 'Accept': INDEX + ', ' + MANIFEST,
        'Accept-Encoding': 'identity'})
    if status != 200:
        # GHCR blob storage only; never forward Basic/Bearer to a redirect.
        require(kind == 'blobs' and status in (302, 307) and isinstance(location, str),
                'registry-redirect-denied')
        if not (len(location) <= REDIRECT_URL_LIMIT and
                all(32 < ord(c) < 127 for c in location) and '\\' not in location):
            raise BlobRedirectDenied(location, sha)
        try:
            dest = urllib.parse.urlsplit(location)
        except ValueError:
            raise BlobRedirectDenied(location, sha) from None
        if not (dest.scheme == 'https' and dest.netloc == 'pkg-containers.githubusercontent.com'
                and not dest.username and not dest.password and not dest.fragment
                # Treat observed numeric storage identifiers as opaque strings.
                # Bound URL length, not numeric value; keep the legacy namespace
                # and bind the object path to the exact requested config digest.
                and re.fullmatch(r'/(?:ghcr1|ghcrblobs[0-9]+)/blobs/' +
                                 re.escape(sha), dest.path)):
            raise BlobRedirectDenied(location, sha)
        status, _, raw = https_get(dest.hostname, dest.path + ('?' + dest.query if dest.query else ''),
                                   {'Accept-Encoding': 'identity'})
        require(status == 200, 'blob-redirect-chain-denied')
    require(digest(raw) == sha, 'registry-digest-mismatch')
    return raw


def descriptor(value, media_types):
    require(isinstance(value, dict) and value.get('mediaType') in media_types and
            valid_digest(value.get('digest')) and type(value.get('size')) is int and
            0 < value['size'] and not value.get('urls') and not value.get('data'),
            'invalid-oci-descriptor')
    return value


def verified_registry(package, index_digest, bearer, *, target=None):
    policy = target_policy(target) if target is not None else {'producer_revision': REVISION}
    if target is not None:
        require(TARGETS[target][0] == package and TARGETS[target][2] == index_digest, 'fixed-target-mismatch')
    index_raw = registry_object(package, 'manifests', index_digest, bearer)
    index = decode(index_raw)
    require(isinstance(index, dict) and index.get('schemaVersion') == 2 and
            index.get('mediaType') == INDEX and isinstance(index.get('manifests'), list),
            'invalid-oci-index')
    candidates = []
    for item in index['manifests']:
        require(isinstance(item, dict), 'invalid-oci-index')
        platform = item.get('platform', {})
        annotations = item.get('annotations', {})
        if (platform.get('os') == 'linux' and platform.get('architecture') == 'amd64' and
            annotations.get('vnd.docker.reference.type') != 'attestation-manifest'):
            require(not platform.get('variant'), 'unexpected-platform-variant')
            candidates.append(descriptor(item, {MANIFEST}))
    require(len(candidates) == 1, 'ambiguous-linux-amd64-manifest')
    selected = candidates[0]
    manifest_raw = registry_object(package, 'manifests', selected['digest'], bearer)
    require(len(manifest_raw) == selected['size'], 'manifest-size-mismatch')
    manifest = decode(manifest_raw)
    require(isinstance(manifest, dict) and manifest.get('schemaVersion') == 2 and
            manifest.get('mediaType') == MANIFEST and not manifest.get('artifactType') and
            not manifest.get('subject'), 'invalid-image-manifest')
    cfg_descriptor = descriptor(manifest.get('config'), {CONFIG})
    require(isinstance(manifest.get('layers'), list) and manifest['layers'], 'invalid-image-layers')
    for item in manifest['layers']:
        descriptor(item, LAYERS)
    config_raw = registry_object(package, 'blobs', cfg_descriptor['digest'], bearer)
    require(len(config_raw) == cfg_descriptor['size'], 'config-size-mismatch')
    config = decode(config_raw)
    require(config.get('os') == 'linux' and config.get('architecture') == 'amd64', 'config-platform-mismatch')
    labels = config.get('config', {}).get('Labels', {})
    if target in FINAL_TARGETS:
        require(selected['digest'] == policy['manifest_digest'] and
                cfg_descriptor['digest'] == policy['config_digest'], 'final-image-coordinate-mismatch')
    require(labels.get('org.opencontainers.image.revision') == policy['producer_revision'] and
            labels.get('org.opencontainers.image.source') == SOURCE, 'producer-label-mismatch')
    rootfs = config.get('rootfs', {})
    require(rootfs.get('type') == 'layers' and isinstance(rootfs.get('diff_ids'), list) and
            len(rootfs['diff_ids']) == len(manifest['layers']) and
            all(valid_digest(value) for value in rootfs['diff_ids']), 'invalid-config-rootfs')
    return {'index': index_raw, 'manifest': manifest_raw, 'config': config_raw,
            'manifest_digest': selected['digest'], 'config_digest': cfg_descriptor['digest'],
            'config_object': config}


def auth_header(bearer):
    return base64.urlsafe_b64encode(json.dumps({'serveraddress': 'ghcr.io',
        'registrytoken': bearer}, separators=(',', ':')).encode()).decode('ascii')


def parse_pull_stream(response, expected_digest):
    # HTTP framing must prove completeness, in addition to terminal pull status.
    require(response.chunked or response.length is not None, 'unframed-pull-stream')
    seen_digest = False
    seen_complete = False
    count = 0
    while True:
        raw = response.readline(1024 * 1024 + 1)
        if not raw:
            break
        count += 1
        require(count <= 100000 and len(raw) <= 1024 * 1024 and raw.endswith(b'\n'),
                'invalid-pull-stream')
        entry = decode(raw)
        require(isinstance(entry, dict), 'invalid-pull-stream')
        require('errorDetail' not in entry and 'error' not in entry, 'docker-pull-error')
        status = entry.get('status', '')
        require(isinstance(status, str), 'invalid-pull-stream')
        if status.startswith('Digest: '):
            require(status == 'Digest: ' + expected_digest, 'pull-digest-mismatch')
            seen_digest = True
        if status.startswith(('Status: Downloaded newer image for ', 'Status: Image is up to date for ')):
            seen_complete = True
    require(response.length in (None, 0), 'truncated-pull-stream')
    require(count > 0 and seen_digest and seen_complete, 'incomplete-pull-stream')
    return count


class Docker:
    def __init__(self, path, identity):
        self.path, self.identity = path, identity
        self.api = ''

    def request(self, method, path, headers=None, body=None, expected=200, timeout=90):
        conn = LocalConnection(self.path, self.identity, timeout=timeout)
        try:
            conn.request(method, self.api + path, body=body, headers=headers or {})
            response = conn.getresponse()
            require(response.status == expected, 'docker-request-denied')
            return conn, response
        except BaseException:
            conn.close()
            raise

    def get(self, path):
        conn, response = self.request('GET', path)
        try:
            return decode(bounded_read(response))
        finally:
            conn.close()

    def negotiate(self):
        version = self.get('/version')
        def api_tuple(value):
            require(isinstance(value, str) and re.fullmatch(r'1\.[0-9]{2}', value), 'unsupported-docker-api')
            return tuple(map(int, value.split('.')))
        maximum = api_tuple(version.get('ApiVersion'))
        minimum = api_tuple(version.get('MinAPIVersion'))
        # 1.49 adds platform-specific image inspection; never use newer unknown APIs.
        selected = min(maximum, (1, 51))
        require(selected >= max(minimum, (1, 49)), 'unsupported-docker-api')
        self.api = '/v' + '.'.join(map(str, selected))
        info = self.get('/info')
        require(version.get('Os') == 'linux' and version.get('Arch') in ('amd64', 'x86_64') and
                info.get('OSType') == 'linux', 'docker-platform-mismatch')
        require(not info.get('HttpProxy') and not info.get('HttpsProxy'), 'daemon-proxy-not-allowed')
        value = version.get('Version')
        require(isinstance(value, str) and re.fullmatch(r'[0-9A-Za-z.+~-]{1,64}', value), 'invalid-docker-version')
        return {'docker_version': value, 'docker_api': self.api[2:]}

    def pull(self, package, sha, bearer):
        require(package in {value[0] for value in TARGETS.values()} and
                (package, sha) in {(value[0], value[2]) for value in TARGETS.values()}, 'pull-target-not-allowed')
        query = urllib.parse.urlencode({'fromImage': 'ghcr.io/' + package + '@' + sha,
                                       'platform': 'linux/amd64'})
        conn, response = self.request('POST', '/images/create?' + query,
                                      {'X-Registry-Auth': auth_header(bearer)})
        try:
            return parse_pull_stream(response, sha)
        finally:
            conn.close()

    def inspect(self, package, sha, verified):
        reference = 'ghcr.io/' + package + '@' + sha
        query = urllib.parse.urlencode({'platform': json.dumps({'os': 'linux', 'architecture': 'amd64'},
                                                               separators=(',', ':'))})
        local = self.get('/images/' + urllib.parse.quote(reference, safe='') + '/json?' + query)
        kind = verify_local(local, reference, sha, verified)
        return {'local_image_id': local['Id'], 'local_image_identity_kind': kind,
                'os': 'linux', 'architecture': 'amd64'}


def local_descriptor_matches(value, raw, sha, media_type, platform):
    return (isinstance(value, dict) and value.get('mediaType') == media_type and
            value.get('digest') == sha and type(value.get('size')) is int and
            value['size'] == len(raw) and value.get('platform') == platform and
            not value.get('urls') and not value.get('data'))


def selected_manifest_matches(value, verified):
    return local_descriptor_matches(value, verified['manifest'], verified['manifest_digest'],
                                    MANIFEST, {'os': 'linux', 'architecture': 'amd64'})


def local_config_matches(local, expected):
    if not isinstance(local, dict) or not isinstance(expected, dict):
        return False
    local = dict(local)
    # API <=1.51 emits these empty defaults; API 1.52 omits unset fields:
    # https://docs.docker.com/reference/api/engine/version-history/#v152-api-changes
    # Normalize only API-side absence defaults; preserve every raw-declared key.
    defaults = {'Cmd': None, 'Entrypoint': None, 'Env': None, 'Labels': None,
                'OnBuild': None, 'Volumes': None, 'User': '', 'WorkingDir': ''}
    for key, default in defaults.items():
        if (key not in expected and key in local and type(local[key]) is type(default)
                and local[key] == default):
            del local[key]
    return local == expected


def verify_local(local, reference, sha, verified):
    # Platform-qualified Docker 29 containerd inspection identifies the selected
    # manifest. Legacy stores identify its config. Neither accepts the index ID;
    # container-inspect Image has a separate descriptor-bound check below.
    identity = local.get('Id')
    desc = local.get('Descriptor')
    if identity == verified['config_digest']:
        kind = 'config-digest'
        if desc is not None:
            require(selected_manifest_matches(desc, verified) or
                    local_descriptor_matches(desc, verified['index'], sha, INDEX, None),
                    'local-descriptor-mismatch')
    elif identity == verified['manifest_digest']:
        kind = 'platform-manifest-digest'
        require(selected_manifest_matches(desc, verified), 'local-descriptor-mismatch')
    else:
        raise Stop('local-image-id-mismatch')
    require(local.get('Os') == 'linux' and local.get('Architecture') == 'amd64', 'local-platform-mismatch')
    require(reference in (local.get('RepoDigests') or []), 'local-repodigest-mismatch')
    cfg = verified['config_object']
    require(local.get('RootFS', {}).get('Type') == 'layers' and
            local.get('RootFS', {}).get('Layers') == cfg['rootfs']['diff_ids'], 'local-rootfs-mismatch')
    require(local_config_matches(local.get('Config'), cfg['config']), 'local-config-mismatch')
    return kind



def runner_context(env):
    require(env.get('GITHUB_ACTIONS') == 'true' and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and sys.platform == 'linux', 'hosted-runner-required')
    require(env.get('GITHUB_REPOSITORY') == REPOSITORY, 'repository-not-allowed')
    event, ref = env.get('GITHUB_EVENT_NAME'), env.get('GITHUB_REF')
    require((event == 'push' and ref == BRANCH) or
            (event == 'workflow_dispatch' and ref in (BRANCH, 'refs/heads/main')),
            'untrusted-workflow-event')
    require(env.get('GITHUB_WORKFLOW_REF') == REPOSITORY + '/' + WORKFLOW + '@' + ref,
            'workflow-identity-mismatch')
    head = env.get('GITHUB_SHA', '')
    require(re.fullmatch(r'[0-9a-f]{40}', head) is not None, 'invalid-workflow-head')
    actor = env.get('GITHUB_ACTOR', '')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?', actor) is not None,
            'invalid-workflow-actor')
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        require(re.fullmatch(r'[1-9][0-9]{0,19}', env.get(key, '')) is not None, 'invalid-workflow-run')
    require(not any(env.get(key) for key in ('OPENSSL_CONF', 'OPENSSL_MODULES', 'SSLKEYLOGFILE')),
            'tls-override-not-allowed')
    return {'repository': REPOSITORY, 'workflow': WORKFLOW, 'event': event, 'ref': ref,
            'head': head, 'actor': actor, 'run_id': env['GITHUB_RUN_ID'],
            'run_attempt': env['GITHUB_RUN_ATTEMPT']}


def verify_checkout(context):
    root = Path(__file__).resolve().parents[1]
    require(Path.cwd().resolve() == root and
            Path(os.environ['GITHUB_WORKSPACE']).resolve() == root, 'checkout-path-mismatch')
    result = subprocess.run(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=root,
        env={'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'},
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
    require(result.returncode == 0 and result.stdout.strip() == context['head'].encode(),
            'checkout-head-mismatch')
    return root


def runner_docker():
    # Hosted runner's existing local daemon only; no contexts or credential stores.
    require(not any(os.environ.get(key) for key in
                    ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')),
            'docker-endpoint-override-not-allowed')
    path = Path('/var/run/docker.sock').resolve(strict=True)
    require(str(path) == '/run/docker.sock', 'local-runner-socket-required')
    info = path.stat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and
            not info.st_mode & stat.S_IWOTH, 'unsafe-docker-socket')
    return Docker(str(path), (info.st_dev, info.st_ino, info.st_uid))


def regular_mode(mode, executable=False):
    require(type(mode) is int and 0 <= mode <= 0o777 and mode & 0o022 == 0 and
            mode & 0o444 == 0o444, 'unsafe-file-permissions')
    if executable:
        require(mode & 0o111 == 0o111, 'tool-not-executable')


def path_stat(response):
    value = response.getheader('X-Docker-Container-Path-Stat')
    require(isinstance(value, str) and len(value) <= 8192, 'missing-path-stat')
    try:
        result = decode(base64.b64decode(value, validate=True))
    except (ValueError, UnicodeError):
        raise Stop('invalid-path-stat') from None
    require(isinstance(result, dict), 'invalid-path-stat')
    return result


def stat_matches(value, path, *, directory=False, canonical=None):
    require(value.get('name') == PurePosixPath(path).name, 'path-stat-name-mismatch')
    mode = value.get('mode')
    if directory:
        require(type(mode) is int and mode & ~0o777 == GO_DIRECTORY and
                mode & 0o022 == 0 and mode & 0o555 == 0o555 and not value.get('linkTarget'),
                'unsafe-image-directory')
    elif canonical is not None and canonical != path:
        require(type(mode) is int and mode & ~0o777 == GO_SYMLINK and
                value.get('linkTarget') == canonical, 'tool-alias-mismatch')
    else:
        regular_mode(mode)
        require(not value.get('linkTarget') and type(value.get('size')) is int and
                value['size'] >= 0, 'invalid-regular-file')


def exact_read(stream, amount):
    pieces = []
    remaining = amount
    while remaining:
        part = stream.read(min(65536, remaining))
        require(bool(part), 'truncated-archive')
        pieces.append(part)
        remaining -= len(part)
    return b''.join(pieces)


def pax_times(raw):
    # PAX timestamps are harmless. Path/size/link/sparse/xattr overrides are not.
    seen = set()
    while raw:
        space = raw.find(b' ')
        require(0 < space < 8 and raw[:space].isdigit(), 'invalid-pax-header')
        length = int(raw[:space])
        require(space + 4 <= length <= len(raw) and raw[length-1:length] == b'\n', 'invalid-pax-header')
        entry = raw[space+1:length-1]
        key, separator, value = entry.partition(b'=')
        require(separator and key in (b'mtime', b'atime', b'ctime') and key not in seen and
                re.fullmatch(rb'-?[0-9]+(?:\.[0-9]+)?', value) is not None, 'unsafe-pax-header')
        seen.add(key)
        raw = raw[length:]


def single_file_archive(response, path, expected, *, retain, executable=False, allow_empty=False, root_owned=False):
    """Read one regular file; reject all links/extensions/path changes, never extract."""
    require(response.chunked or response.length is not None, 'unframed-archive')
    require(response.getheader('Content-Encoding') in (None, 'identity') and
            response.getheader('Content-Type', '').split(';')[0] == 'application/x-tar',
            'unexpected-archive-encoding')
    stat_matches(expected, path)
    regular_mode(expected['mode'], executable)
    limit = METADATA_LIMIT if retain else BINARY_LIMIT
    # Only producer-tree inventory reads opt in to legitimate empty source files.
    # Curated metadata, notices and canonical tools must always contain bytes.
    require((0 if allow_empty else 1) <= expected['size'] <= limit, 'file-size-limit')
    header = exact_read(response, 512)
    info = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
    if info.type == tarfile.XHDTYPE:
        require(0 < info.size <= 8192 and not info.linkname, 'invalid-pax-header')
        pax_times(exact_read(response, info.size))
        require(not any(exact_read(response, (-info.size) % 512)), 'invalid-archive-padding')
        info = tarfile.TarInfo.frombuf(exact_read(response, 512), 'utf-8', 'strict')
    require(info.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not info.linkname and
            info.name == PurePosixPath(path).name and info.size == expected['size'] and
            not info.pax_headers and not info.sparse, 'unexpected-archive-entry')
    regular_mode(info.mode, executable)
    require(info.mode == expected['mode'] and info.uid >= 0 and info.gid >= 0,
            'archive-metadata-mismatch')
    require(not root_owned or info.uid == 0, 'archive-owner-mismatch')
    sha = hashlib.sha256()
    saved = bytearray() if retain else None
    remaining = info.size
    while remaining:
        raw = exact_read(response, min(65536, remaining))
        remaining -= len(raw)
        sha.update(raw)
        if saved is not None:
            saved.extend(raw)
    require(not any(exact_read(response, (-info.size) % 512)), 'invalid-archive-padding')
    # Exactly one member. Require tar end markers, then only bounded zero padding
    # through the complete HTTP framing; extra entries/bytes cannot hide afterward.
    require(not any(exact_read(response, 1024)), 'unexpected-archive-tail')
    trailing = response.read(10241)
    require(len(trailing) <= 10240 and not any(trailing), 'unexpected-archive-tail')
    require(response.length in (None, 0), 'truncated-archive')
    return {'sha256': sha.hexdigest(), 'size': info.size, 'mode': oct(info.mode)}, (
        bytes(saved) if saved is not None else None)


class StoppedImage:
    def __init__(self, docker, target, context, verified):
        self.docker, self.target, self.verified = docker, target, verified
        package, _, sha = TARGETS[target]
        self.reference = 'ghcr.io/' + package + '@' + sha
        self.index_digest = sha
        self.owner = context['run_id'] + '-' + context['run_attempt'] + '-' + uuid.uuid4().hex
        self.name = 'atrinik-sdk-evidence-' + self.owner
        self.identifier = None
        self.attempted = False
        self.directories = set()

    def create(self):
        require(not self.verified['config_object'].get('config', {}).get('Volumes'),
                'image-volumes-not-allowed')
        body = {'Image': self.reference, 'Entrypoint': ['/bin/false'], 'Cmd': [],
                'Env': [], 'Labels': {OWNER_LABEL: self.owner}, 'User': '65534:65534',
                'WorkingDir': '/', 'NetworkDisabled': True, 'Healthcheck': {'Test': ['NONE']},
                'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'CapDrop': ['ALL'],
                               'SecurityOpt': ['no-new-privileges'], 'RestartPolicy': {'Name': 'no'}}}
        path = '/containers/create?' + urllib.parse.urlencode({'name': self.name, 'platform': 'linux/amd64'})
        self.attempted = True
        conn, response = self.docker.request('POST', path, {'Content-Type': 'application/json'},
                                              json.dumps(body).encode(), expected=201)
        try:
            result = decode(bounded_read(response))
        finally:
            conn.close()
        identifier = result.get('Id')
        require(isinstance(identifier, str) and re.fullmatch(r'[0-9a-f]{64}', identifier),
                'invalid-created-container')
        self.identifier = identifier
        self.fence()

    def fence(self):
        require(self.identifier is not None, 'container-not-created')
        value = self.docker.get('/containers/' + self.identifier + '/json')
        require(value.get('Id') == self.identifier and value.get('Name') == '/' + self.name and
                value.get('Config', {}).get('Labels', {}).get(OWNER_LABEL) == self.owner and
                value.get('Config', {}).get('Image') == self.reference, 'container-ownership-mismatch')
        require(value.get('State', {}).get('Status') == 'created' and
                value['State'].get('Running') is False and value['State'].get('Pid') == 0 and
                not value.get('Mounts'), 'container-not-pristine-stopped')
        hc = value.get('HostConfig', {})
        require(hc.get('ReadonlyRootfs') is True and hc.get('NetworkMode') == 'none' and
                not hc.get('Privileged') and not hc.get('Binds'), 'container-isolation-mismatch')
        # Docker 29 containerd store may put the index in Container.Image. Require
        # its selected manifest descriptor independently, never compare to config alone.
        image = value.get('Image')
        require(image in (self.verified['config_digest'], self.index_digest,
                          self.verified['manifest_digest']), 'container-image-mismatch')
        selected = value.get('ImageManifestDescriptor')
        if selected is not None or image != self.verified['config_digest']:
            require(selected_manifest_matches(selected, self.verified), 'container-manifest-mismatch')
        return value

    def stat(self, path):
        conn, response = self.docker.request('HEAD', '/containers/' + self.identifier + '/archive?' +
                                             urllib.parse.urlencode({'path': path}))
        try:
            return path_stat(response)
        finally:
            conn.close()

    def parents(self, path):
        # Known parents, checked once per stopped container, cannot redirect a
        # curated filename through an image-controlled directory symlink.
        for parent in reversed(PurePosixPath(path).parents):
            if str(parent) == '/' or str(parent) in self.directories:
                continue
            stat_matches(self.stat(str(parent)), str(parent), directory=True)
            self.directories.add(str(parent))

    def read(self, path, *, retain, executable=False):
        allowed = set(COMMON_FILES + (PORTABLE_FILES if self.target in FINAL_TARGETS else TARGET_FILES[self.target])) if retain else {
            PREFIX + '/' + pair[1] for pair in TOOL_FILES.values()}
        require(path in allowed, 'image-path-not-allowed')
        self.fence()
        self.parents(path)
        expected = self.stat(path)
        stat_matches(expected, path)
        conn, response = self.docker.request('GET', '/containers/' + self.identifier + '/archive?' +
            urllib.parse.urlencode({'path': path}), {'Accept-Encoding': 'identity'})
        try:
            require(path_stat(response) == expected, 'image-file-changed')
            return single_file_archive(response, path, expected, retain=retain, executable=executable)
        finally:
            conn.close()

    def alias(self, path, canonical):
        require((path.removeprefix(PREFIX + '/'), canonical.removeprefix(PREFIX + '/'))
                in TOOL_FILES.values(), 'tool-alias-not-allowed')
        self.fence()
        self.parents(path)
        stat_matches(self.stat(path), path, canonical=canonical)

    def cleanup(self):
        if not self.attempted:
            return
        # A failed create response may still have created our exact unique name.
        # Resolve only that name, and prove our label/image/state before deletion.
        if self.identifier is None:
            conn = LocalConnection(self.docker.path, self.docker.identity)
            try:
                conn.request('GET', self.docker.api + '/containers/' + self.name + '/json')
                response = conn.getresponse()
                if response.status == 404:
                    return
                require(response.status == 200, 'cleanup-inspection-failed')
                value = decode(bounded_read(response))
            finally:
                conn.close()
            identifier = value.get('Id')
            require(isinstance(identifier, str) and re.fullmatch(r'[0-9a-f]{64}', identifier),
                    'cleanup-identity-invalid')
            self.identifier = identifier
        self.fence()
        conn, response = self.docker.request('DELETE', '/containers/' + self.identifier,
                                              expected=204)
        conn.close()
        self.attempted = False


def output_directory(root, target):
    current = root
    for name in ('build', 'released-sdk-evidence'):
        current = current / name
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                not info.st_mode & 0o022, 'unsafe-output-directory')
    current = current / target
    current.mkdir(mode=0o700)
    return current


def save(folder, relative, raw):
    path = PurePosixPath(relative)
    require(not path.is_absolute() and path.parts and
            all(part not in ('', '.', '..') for part in path.parts), 'invalid-artifact-path')
    destination = folder
    for part in path.parts[:-1]:
        destination = destination / part
        try:
            destination.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = destination.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                not info.st_mode & 0o077, 'unsafe-artifact-directory')
    fd = os.open(destination / path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}


def validate_metadata(target, data):
    require(hashlib.sha256(data[LLVM_MANIFEST]).hexdigest() == LLVM_MANIFEST_SHA,
            'installed-llvm-manifest-mismatch')
    secondary = ('/usr/local/share/atrinik/' if target in ('broad', 'classic') else '/opt/atrinik-portable/') + 'llvm-toolchain.json'
    require(data[secondary] == data[LLVM_MANIFEST], 'installed-llvm-descriptors-disagree')
    for name in ('clang', 'clang++'):
        require(data[PREFIX + '/bin/' + name + '.cfg'] == CFG, 'installed-clang-defaults-mismatch')
    sbom = decode(data[LLVM_SBOM])
    manifest = decode(data[LLVM_MANIFEST])
    require(sbom.get('spdxVersion') == 'SPDX-2.3' and len(sbom.get('packages', [])) == 1,
            'invalid-llvm-spdx')
    package = sbom['packages'][0]
    require(package.get('name') == 'LLVM' and package.get('versionInfo') == '23.1.3' and
            package.get('licenseDeclared') == manifest['source']['license'] and
            package.get('checksums') == [{'algorithm': 'SHA256', 'checksumValue': manifest['source']['sha256']}],
            'llvm-spdx-identity-mismatch')
    if target in ('broad', 'classic'):
        return None
    base = '/opt/atrinik-portable/'
    installed = decode(data[base + 'installed.json'])
    compiler = decode(data[base + 'compiler-evidence.json'])
    for key, name in (('contract_sha256', 'contract.json'),
                      ('compiler_evidence_sha256', 'compiler-evidence.json')):
        require(installed.get(key) == hashlib.sha256(data[base + name]).hexdigest(),
                'portable-metadata-binding-mismatch')
    require(installed.get('architecture') == 'amd64' and installed.get('glibc') == 'glibc 2.36' and
            compiler.get('schema_version') == 2 and compiler.get('toolchain_version') == '23.1.3',
            'portable-identity-mismatch')
    require(set(compiler.get('tools', {})) == set(TOOL_FILES) - {'runtime', 'unwinder'},
            'portable-tool-roles-mismatch')
    for entry in compiler['tools'].values():
        require(isinstance(entry, dict) and isinstance(entry.get('version'), str) and
                re.search(r'\b23\.1\.3\b', entry['version']), 'portable-tool-version-mismatch')
    generation = decode(data[base + 'shader-generation.json'])
    require(generation.get('output_manifest_sha256') == hashlib.sha256(data[base + 'shaders/SHA256SUMS']).hexdigest()
            and generation.get('expected_manifest_sha256') == generation['output_manifest_sha256']
            and generation.get('llvm_toolchain_manifest_sha256') == LLVM_MANIFEST_SHA,
            'shader-metadata-binding-mismatch')
    return compiler



def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def target_policy(target):
    require(target in TARGETS, 'target-not-allowed')
    if target not in FINAL_TARGETS:
        require(target in HISTORICAL_TARGETS, 'final-target-policy-missing')
        return {'producer_revision': REVISION}
    value = FINAL_TARGETS[target]
    require(isinstance(value, dict) and set(value) == {
        'producer_revision', 'consumer_commit', 'manifest_digest', 'config_digest'}
        and TARGETS[target][0] == 'atrinik/classic-portable-build'
        and all(isinstance(value[key], str) and re.fullmatch(r'[0-9a-f]{40}', value[key])
                for key in ('producer_revision', 'consumer_commit'))
        and all(valid_digest(value[key]) for key in ('manifest_digest', 'config_digest')),
        'final-target-policy-incomplete')
    return value


def collect_final_inventory(container, data, file_records, llvm_tools, policy):
    protocol = SimpleNamespace(stat_matches=stat_matches, regular_mode=regular_mode,
        path_stat=path_stat, single_file_archive=single_file_archive, pax_times=pax_times)
    reader = INVENTORY.InstalledInventory(container, protocol)
    raw = {path.removeprefix(INVENTORY.ROOT + '/'): value for path, value in data.items()
           if path.startswith(INVENTORY.ROOT + '/')}
    records = {name: file_records[INVENTORY.ROOT + '/' + name] for name in raw}
    documents = {name: decode(raw[name]) for name in INVENTORY.METADATA_FILES}
    contract, shader = documents['contract.json'], documents['shader-generation.json']
    require(contract.get('consumer', {}).get('commit') == policy['consumer_commit'] and
            contract['consumer'].get('repository') == 'atrinik/classic' and
            shader.get('source_commit') == policy['consumer_commit'], 'final-consumer-mismatch')
    maps = {'producer': reader.producer()}
    INVENTORY.bind_metadata(maps['producer'], raw, records)
    INVENTORY.crosscheck_archives(maps['producer'], documents['runtime-sources.json'], contract)
    inputs = shader.get('source_inputs')
    require(isinstance(inputs, dict) and 0 < len(inputs) <= INVENTORY.MAX_MEMBERS, 'final-shader-inputs')
    for path, sha in inputs.items():
        INVENTORY.relative_path(path)
        item = maps['producer'].get('sources/classic-shaders/' + path)
        require(isinstance(item, dict) and item.get('sha256') == sha, 'final-shader-input-bytes')
    maps['debian_notices'] = reader.debian_notices(documents['runtime-sources.json'], documents['debian-sources.json'])
    maps['common_licenses'] = reader.common_licenses()
    tools = reader.build_tools(documents['installed.json'])
    require(set(llvm_tools) == set(TOOL_FILES) == set(INVENTORY.LLVM_TOOL_FILES), 'final-llvm-roles')
    llvm = {role: {key: item[key] for key in ('path', 'canonical_path', 'sha256', 'size')}
            | {'executable': bool(int(item['mode'], 8) & 0o111)} for role, item in llvm_tools.items()}
    return INVENTORY.expected_scan(maps, {name: records[name] for name in INVENTORY.METADATA_FILES}, tools, llvm)


def scanner_sources():
    result = {}
    for name in SCANNER_FILES:
        path = Path(__file__).resolve().with_name(name)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                    and before.st_mode & 0o022 == 0 and 0 < before.st_size <= 1024 * 1024,
                    'unsafe-scanner-source')
            raw = os.read(fd, before.st_size + 1)
            def identity(value):
                return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                        value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            require(len(raw) == before.st_size and identity(os.fstat(fd)) == identity(before)
                    and identity(path.stat(follow_symlinks=False)) == identity(before), 'scanner-source-changed')
            result[name] = {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}
        finally:
            os.close(fd)
    return result


def scanner_logs(response):
    require(response.chunked or response.length is not None, 'scanner-logs-unframed')
    result = bytearray()
    while True:
        header = response.read(8)
        if not header:
            break
        require(len(header) == 8 and header[:4] == b'\x01\0\0\0', 'scanner-logs-invalid')
        size = struct.unpack('>I', header[4:])[0]
        require(0 < size <= 1024 * 1024 and len(result) + size <= SCANNER_LIMIT, 'scanner-logs-limit')
        result.extend(exact_read(response, size))
    require(response.length in (None, 0) and result, 'scanner-logs-incomplete')
    return decode(bytes(result))


class ScannerImage(StoppedImage):
    """Separate executed qualification; never weakens StoppedImage's fence."""
    def __init__(self, docker, target, context, verified, sources):
        require(target in FINAL_TARGETS, 'final-target-required')
        policy = target_policy(target)
        require(verified['manifest_digest'] == policy['manifest_digest'] and
                verified['config_digest'] == policy['config_digest'], 'final-image-coordinate-mismatch')
        require(set(sources) == set(SCANNER_FILES), 'scanner-source-set')
        super().__init__(docker, target, context, verified)
        self.name = 'atrinik-sdk-filesystem-' + self.owner
        self.sources = sources
        self.entrypoint = ['/usr/bin/python3', '-I', '-B', '/scan/scan-released-sdk-filesystem.py']
        self.mounts = [{'Type': 'bind', 'Source': item['path'], 'Target': '/scan/' + name,
                        'ReadOnly': True} for name, item in sources.items()]

    def create(self):
        require(not self.verified['config_object'].get('config', {}).get('Volumes'), 'image-volumes-not-allowed')
        body = {'Image': self.reference, 'Entrypoint': self.entrypoint, 'Cmd': [], 'Env': [],
                'Labels': {OWNER_LABEL: self.owner}, 'User': '65534:65534', 'WorkingDir': '/',
                'NetworkDisabled': True, 'Healthcheck': {'Test': ['NONE']},
                'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'CapDrop': ['ALL'],
                    'SecurityOpt': ['no-new-privileges'], 'RestartPolicy': {'Name': 'no'},
                    'Mounts': self.mounts, 'LogConfig': {'Type': 'local', 'Config': {'max-size': '128m', 'max-file': '1'}}}}
        self.attempted = True
        conn, response = self.docker.request('POST', '/containers/create?' + urllib.parse.urlencode({
            'name': self.name, 'platform': 'linux/amd64'}), {'Content-Type': 'application/json'},
            json.dumps(body).encode(), expected=201)
        try:
            value = decode(bounded_read(response))
        finally:
            conn.close()
        identifier = value.get('Id')
        require(isinstance(identifier, str) and re.fullmatch(r'[0-9a-f]{64}', identifier), 'invalid-created-container')
        self.identifier = identifier
        self.fence()

    def fence(self, states=('created',)):
        require(self.identifier is not None, 'container-not-created')
        value = self.docker.get('/containers/' + self.identifier + '/json')
        config, host = value.get('Config', {}), value.get('HostConfig', {})
        state = value.get('State', {})
        require(value.get('Id') == self.identifier and value.get('Name') == '/' + self.name and
                config.get('Labels', {}).get(OWNER_LABEL) == self.owner and config.get('Image') == self.reference,
                'scanner-ownership-mismatch')
        require(config.get('Entrypoint') == self.entrypoint and config.get('Cmd') in (None, [])
                and config.get('User') == '65534:65534' and config.get('WorkingDir') == '/',
                'scanner-command-mismatch')
        require(state.get('Status') in states and state.get('Running') is (state.get('Status') == 'running')
                and (state.get('Status') == 'running' or state.get('Pid') == 0), 'scanner-state-mismatch')
        require(host.get('ReadonlyRootfs') is True and host.get('NetworkMode') == 'none'
                and not host.get('Privileged') and not host.get('Binds')
                and host.get('CapDrop') == ['ALL'] and host.get('SecurityOpt') == ['no-new-privileges']
                and host.get('RestartPolicy', {}).get('Name') == 'no', 'scanner-isolation-mismatch')
        mounts = value.get('Mounts')
        require(isinstance(mounts, list) and len(mounts) == len(self.mounts), 'scanner-mount-mismatch')
        actual = {(item.get('Source'), item.get('Destination')) for item in mounts
                  if item.get('Type') == 'bind' and item.get('RW') is False}
        require(actual == {(item['Source'], item['Target']) for item in self.mounts}, 'scanner-mount-mismatch')
        image = value.get('Image')
        require(image in (self.verified['config_digest'], self.index_digest, self.verified['manifest_digest']),
                'container-image-mismatch')
        selected = value.get('ImageManifestDescriptor')
        if selected is not None or image != self.verified['config_digest']:
            require(selected_manifest_matches(selected, self.verified), 'container-manifest-mismatch')
        return value

    def execute(self):
        self.fence()
        conn, _ = self.docker.request('POST', '/containers/' + self.identifier + '/start', expected=204)
        conn.close()
        conn, response = self.docker.request('POST', '/containers/' + self.identifier + '/wait?condition=not-running',
                                             timeout=INVENTORY.MAX_SECONDS + 30)
        try:
            result = decode(bounded_read(response))
            require(type(result.get('StatusCode')) is int and result['StatusCode'] == 0 and
                    not result.get('Error'), 'scanner-process-failed')
        finally:
            conn.close()
        self.fence(('exited',))
        conn, response = self.docker.request('GET', '/containers/' + self.identifier + '/logs?stdout=1&stderr=1')
        try:
            return scanner_logs(response)
        finally:
            conn.close()

    def cleanup(self):
        if not self.attempted:
            return
        if self.identifier is None:
            # Resolve only our unique name after an ambiguous create response.
            value = self.docker.get('/containers/' + self.name + '/json')
            identifier = value.get('Id')
            require(isinstance(identifier, str) and re.fullmatch(r'[0-9a-f]{64}', identifier), 'cleanup-identity-invalid')
            self.identifier = identifier
        value = self.fence(('created', 'running', 'exited'))
        if value['State']['Status'] == 'running':
            conn, _ = self.docker.request('POST', '/containers/' + self.identifier + '/stop?t=10', expected=204)
            conn.close()
            self.fence(('exited',))
        conn, _ = self.docker.request('DELETE', '/containers/' + self.identifier, expected=204)
        conn.close()
        self.attempted = False


def qualify_filesystem(docker, target, context, verified, expected):
    policy = target_policy(target)
    require(target in FINAL_TARGETS, 'final-target-required')
    receipt = {**context, 'schema_version': 1, 'claim': 'trusted-producer-filesystem-equality',
        'image_code_executed': True, 'final_portable_cohort': False, 'target': target,
        'index_digest': TARGETS[target][2], 'manifest_digest': verified['manifest_digest'],
        'config_digest': verified['config_digest'], **policy, 'status': 'started'}
    scanner = None
    try:
        require(verified['manifest_digest'] == policy['manifest_digest'] and
                verified['config_digest'] == policy['config_digest'], 'final-image-coordinate-mismatch')
        sources = scanner_sources()
        receipt['scanner_sources'] = {name: {key: item[key] for key in ('sha256', 'size')}
                                      for name, item in sources.items()}
        scanner = ScannerImage(docker, target, context, verified, sources)
        scanner.create()
        receipt['container_id'] = scanner.identifier
        observed = scanner.execute()
        require(scanner_sources() == sources, 'scanner-source-changed')
        INVENTORY.compare_scan(observed, expected)
        receipt['scan'] = observed
        receipt['status'] = 'verified-filesystem-equality'
    except BaseException:
        receipt.update(status='stopped', reason='filesystem-qualification-failed')
    finally:
        if scanner is not None:
            try:
                signal.alarm(120)
                scanner.cleanup()
                receipt['owned_container_removed'] = True
            except BaseException:
                receipt.update(status='stopped', reason='owned-cleanup-failed', owned_container_removed=False)
    return receipt

def collect(target, context, original, folder):
    package, tag, sha = TARGETS[target]
    policy = target_policy(target)
    receipt = {**context, 'schema_version': 1, 'target': target, 'package': package,
               'display_tag': tag, 'index_digest': sha, 'producer_revision': policy['producer_revision'],
               'source': SOURCE, 'platform': 'linux/amd64', 'status': 'started',
               'claim': 'installed-identity-only', 'image_code_executed': False,
               'final_portable_cohort': False, 'artifacts': [], 'tool_bytes': {}}
    container = None
    try:
        docker = runner_docker()
        receipt.update(docker.negotiate())
        bearer = scoped_bearer(package, original, context['actor'])
        verified = verified_registry(package, sha, bearer, target=target)
        for name in ('index', 'manifest', 'config'):
            receipt['artifacts'].append(save(folder, 'registry/' + name + '.json', verified[name]))
        receipt.update({'manifest_digest': verified['manifest_digest'],
                        'config_digest': verified['config_digest']})
        receipt['pull_stream_records'] = docker.pull(package, sha, bearer)
        del bearer
        receipt.update(docker.inspect(package, sha, verified))
        container = StoppedImage(docker, target, context, verified)
        container.create()
        receipt['container_id'] = container.identifier
        data, file_records = {}, {}
        for path in COMMON_FILES + (PORTABLE_FILES if target in FINAL_TARGETS else TARGET_FILES[target]):
            observed_file, raw = container.read(path, retain=True)
            data[path] = raw
            file_records[path] = {'sha256': observed_file['sha256'], 'size': observed_file['size'],
                                  'executable': bool(int(observed_file['mode'], 8) & 0o111)}
        compiler = validate_metadata(target, data)
        for path, raw in data.items():
            receipt['artifacts'].append(save(folder, 'files' + path, raw))
        # Hash only the fixed declared LLVM roles. Alias HEAD metadata must select
        # the fixed canonical regular path; archive symlinks are always rejected.
        observed = {}
        for role, (declared, canonical) in TOOL_FILES.items():
            path, canonical_path = PREFIX + '/' + declared, PREFIX + '/' + canonical
            container.alias(path, canonical_path)
            if canonical_path not in observed:
                observed[canonical_path], _ = container.read(canonical_path, retain=False,
                    executable=role not in ('runtime', 'unwinder'))
            identity = {'path': path, 'canonical_path': canonical_path, **observed[canonical_path]}
            if compiler is not None:
                expected = compiler['tools'].get(role) or compiler.get(role)
                require(isinstance(expected, dict) and expected.get('path') == path and
                        expected.get('sha256') == identity['sha256'], 'installed-tool-bytes-mismatch')
                identity['producer_descriptor_verified'] = True
            else:
                identity['producer_descriptor_verified'] = False
            receipt['tool_bytes'][role] = identity
        container.fence()
        if target in FINAL_TARGETS:
            final_inventory = collect_final_inventory(container, data, file_records, receipt['tool_bytes'], policy)
            for name, records in final_inventory['inventories'].items():
                receipt['artifacts'].append(save(folder, 'inventories/' + name + '.json', canonical_json(records)))
            receipt['inventory_sha256'] = final_inventory['inventory_sha256']
            receipt['metadata_sha256'] = {name: item['sha256'] for name, item in final_inventory['metadata'].items()}
            receipt['build_tools'] = final_inventory['build_tools']
            # Keep acquisition and execution claims separate, including failure.
            qualification = qualify_filesystem(docker, target, context, verified, final_inventory)
            receipt['artifacts'].append(save(folder, 'filesystem-qualification.json', canonical_json(qualification)))
            require(qualification['status'] == 'verified-filesystem-equality', 'filesystem-qualification-failed')
        receipt['status'] = 'verified-installed-identity'
    except Stop as error:
        receipt.update({'status': 'stopped', 'reason': str(error)})
        if isinstance(error, BlobRedirectDenied):
            receipt['redirect_rejection'] = error.diagnostics
    except BaseException:
        receipt.update({'status': 'stopped', 'reason': 'operation-failed-no-details-retained'})
    finally:
        if container is not None:
            try:
                # Reserve cleanup time after an operation deadline. No forced stop,
                # process execution, broad container deletion or image pruning.
                signal.alarm(120)
                container.cleanup()
                receipt['owned_container_removed'] = True
            except BaseException:
                receipt.update({'status': 'stopped', 'reason': 'owned-cleanup-failed',
                                'owned_container_removed': False})
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, choices=tuple(TARGETS))
    args = parser.parse_args()
    original = os.environ.pop('GHCR_TOKEN', '')
    # Do not inherit alternate auth or debug state. The workflow supplies only
    # its ephemeral token to this process; no subprocess receives that token.
    for key in ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_CONFIG_DIR', 'XDG_CONFIG_HOME', 'GH_DEBUG'):
        os.environ.pop(key, None)
    def stop(_signum, _frame):
        raise Stop('operation-interrupted')
    try:
        require(sys.flags.isolated == 1, 'isolated-python-required')
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        signal.signal(signal.SIGALRM, stop)
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        signal.alarm(3600 if args.target in FINAL_TARGETS else 1800)
        context = runner_context(os.environ)
        root = verify_checkout(context)
        require(isinstance(original, str) and 0 < len(original) < 16384 and
                all(32 < ord(c) < 127 for c in original), 'workflow-token-unavailable')
        folder = output_directory(root, args.target)
        receipt = collect(args.target, context, original, folder)
        del original
        receipt['collector_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        receipt['inventory_helper_sha256'] = hashlib.sha256(
            Path(__file__).with_name('released_sdk_inventory.py').read_bytes()).hexdigest()
        save(folder, 'receipt.json', (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode())
        # The receipt itself is bound by a separate hash; never print raw registry,
        # archive, daemon, auth or exception content.
        receipt_raw = (folder / 'receipt.json').read_bytes()
        save(folder, 'receipt.sha256', (hashlib.sha256(receipt_raw).hexdigest() + '  receipt.json\n').encode())
        print(json.dumps({'target': args.target, 'status': receipt['status'],
                          'receipt_sha256': hashlib.sha256(receipt_raw).hexdigest()}))
        return 0 if receipt['status'] == 'verified-installed-identity' else 1
    except BaseException:
        print('{"status":"stopped","reason":"collector-preflight-or-receipt-failed"}')
        return 1
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    sys.exit(main())
