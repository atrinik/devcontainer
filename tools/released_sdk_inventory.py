# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Internal fixed-boundary inventory reader; no CLI or acquisition authority.

The caller must supply the collector's authenticated, created-state StoppedImage
and its archive protocol. This foundation is deliberately not wired to a release
target: final producer/consumer/index/platform/config pins are still required.
"""
import hashlib
import json
from pathlib import PurePosixPath
import re
import tarfile
import time
import urllib.parse

ROOT = '/opt/atrinik-portable'
DOC = '/usr/share/doc'
COMMON = '/usr/share/common-licenses'
BUILD_TOOLS = {'cmake': '/usr/bin/cmake', 'ninja': '/usr/bin/ninja',
               'pkg_config': '/usr/bin/pkgconf'}
COMMON_LICENSE_NAMES = ('Apache-2.0', 'Artistic', 'BSD', 'CC0-1.0', 'GFDL-1.2',
                        'GFDL-1.3', 'GPL-1', 'GPL-2', 'GPL-3', 'LGPL-2',
                        'LGPL-2.1', 'LGPL-3', 'MPL-1.1', 'MPL-2.0')
MAX_MEMBERS = 20000
MAX_PATH = 1024
MAX_FILE = 1024 ** 3
MAX_BUILD_TOOL = 512 * 1024 * 1024
MAX_TOTAL = 8 * 1024 ** 3
MAX_SECONDS = 900
MAX_HOPS = 16
SOURCE_MANIFESTS = ('audio-toolchain.json', 'llvm-toolchain.json')
MAX_MANIFEST = 1024 * 1024
MAX_MANIFEST_SOURCES = 128
GO_DIRECTORY = 1 << 31
GO_SYMLINK = 1 << 27


class InventoryError(Exception):
    """Only fixed failure codes; never hostile archive or daemon contents."""


class ProducerInventory(dict):
    """File identities plus bounded source manifests from the same archive.

    Payloads are private validation inputs, excluded from the serialized inventory
    and its digest. Copying only the identities cannot satisfy manifest closure.
    """
    def __init__(self):
        super().__init__()
        self.source_manifests = {}


def require(ok, code):
    if not ok:
        raise InventoryError(code)


def inventory_digest(records):
    return hashlib.sha256(json.dumps(records, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def relative_path(value):
    require(isinstance(value, str) and 0 < len(value.encode('utf-8')) <= MAX_PATH
            and all(32 < ord(c) < 127 for c in value) and '\\' not in value
            and all(part not in ('', '.', '..') for part in value.split('/')),
            'inventory-path-invalid')
    return value


def under_doc(value):
    require(isinstance(value, str) and value.startswith(DOC + '/'), 'notice-boundary')
    relative_path(value[len(DOC) + 1:])
    return value


class Budget:
    def __init__(self):
        self.deadline = time.monotonic() + MAX_SECONDS
        self.bytes = 0
        self.members = 0
        self.payload = 0

    def check(self):
        require(time.monotonic() < self.deadline, 'inventory-deadline')

    def read(self, stream, size):
        self.check()
        raw = stream.read(size)
        self.check()
        self.bytes += len(raw)
        require(self.bytes <= MAX_TOTAL + MAX_MEMBERS * (1024 + 8192) + 10240,
                'inventory-stream-limit')
        return raw

    def exact(self, stream, size):
        result = bytearray()
        while len(result) < size:
            raw = self.read(stream, min(65536, size - len(result)))
            require(bool(raw), 'inventory-truncated')
            result.extend(raw)
        return bytes(result)

    def member(self, size):
        self.members += 1
        self.payload += size
        require(self.members <= MAX_MEMBERS and 0 <= size <= MAX_FILE
                and self.payload <= MAX_TOTAL, 'inventory-size-limit')


def framing(response):
    require(response.chunked or response.length is not None, 'inventory-unframed')
    require(response.getheader('Content-Encoding') in (None, 'identity') and
            response.getheader('Content-Type', '').split(';')[0] == 'application/x-tar',
            'inventory-encoding')


def header(raw):
    try:
        info = tarfile.TarInfo.frombuf(raw, 'utf-8', 'strict')
        # TarInfo strips every directory terminator, so reject repeated raw
        # slashes before its normalization can hide a noncanonical spelling.
        require(not (info.isdir() and raw[:100].split(b'\0', 1)[0].endswith(b'//')),
                'inventory-path-invalid')
        return info
    except (tarfile.TarError, ValueError, UnicodeError):
        raise InventoryError('inventory-header-invalid') from None


def next_member(response, budget, protocol, *, symlink=False):
    raw = budget.exact(response, 512)
    if not any(raw):
        require(not any(budget.exact(response, 512)), 'inventory-end-markers')
        trailing = 0
        while True:
            raw = budget.read(response, 512)
            if not raw:
                break
            trailing += len(raw)
            require(trailing <= 10240 and not any(raw), 'inventory-tail')
        require(response.length in (None, 0), 'inventory-truncated')
        require(trailing % 512 == 0, 'inventory-tail-alignment')
        return None
    info = header(raw)
    if info.type == tarfile.XHDTYPE:
        require(0 < info.size <= 8192 and not info.linkname, 'inventory-pax-invalid')
        protocol.pax_times(budget.exact(response, info.size))
        require(not any(budget.exact(response, (-info.size) % 512)), 'inventory-padding')
        info = header(budget.exact(response, 512))
    require(not info.pax_headers and not info.sparse and
            (not info.linkname or (symlink and info.type == tarfile.SYMTYPE)),
            'inventory-extension-or-link')
    require(info.uid >= 0 and info.gid >= 0, 'inventory-owner-invalid')
    budget.member(info.size)
    return info


def tree_archive(response, protocol, expected, budget=None):
    """Hash ROOT, retaining only the bounded, fixed source-manifest payloads."""
    budget = budget or Budget()
    framing(response)
    protocol.stat_matches(expected, ROOT, directory=True)
    files, entries, directories = ProducerInventory(), set(), set()
    root_name = PurePosixPath(ROOT).name
    while True:
        info = next_member(response, budget, protocol)
        if info is None:
            break
        name = info.name
        # header() already rejects repeated raw directory terminators.
        # Absolute, dot, double slash and traversal names also fail here.
        relative_path(name)
        require(name == root_name or name.startswith(root_name + '/'), 'inventory-root-mismatch')
        require(name not in entries, 'inventory-duplicate')
        entries.add(name)
        if name == root_name:
            require(len(entries) == 1 and info.isdir() and info.mode == expected['mode'] & 0o777,
                    'inventory-root-mismatch')
        else:
            require(str(PurePosixPath(name).parent) in directories, 'inventory-parent-missing')
        if info.type == tarfile.DIRTYPE:
            require(info.size == 0 and 0 <= info.mode <= 0o777 and
                    info.mode & 0o022 == 0 and info.mode & 0o555 == 0o555,
                    'inventory-directory-mode')
            directories.add(name)
            continue
        require(info.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and name != root_name,
                'inventory-member-type')
        protocol.regular_mode(info.mode)
        path = name[len(root_name) + 1:]
        payload = bytearray() if path in SOURCE_MANIFESTS else None
        if payload is not None:
            require(0 < info.size <= MAX_MANIFEST, 'inventory-manifest-size')
        sha = hashlib.sha256()
        remaining = info.size
        while remaining:
            raw = budget.exact(response, min(65536, remaining))
            sha.update(raw)
            if payload is not None:
                payload.extend(raw)
            remaining -= len(raw)
        require(not any(budget.exact(response, (-info.size) % 512)), 'inventory-padding')
        files[path] = {'sha256': sha.hexdigest(), 'size': info.size,
                       'executable': bool(info.mode & 0o111)}
        if payload is not None:
            files.source_manifests[path] = bytes(payload)
    require(root_name in directories and bool(files), 'inventory-empty')
    return files


def notice_requests(runtime, debian):
    """Select only runtime source-package notices from authenticated documents."""
    sources = runtime.get('source_packages')
    require(isinstance(sources, dict) and 0 < len(sources) <= MAX_MEMBERS
            and isinstance(debian, list) and len(debian) <= MAX_MEMBERS, 'notice-documents-invalid')
    require(all(isinstance(name, str) and re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', name)
                and isinstance(version, str) and 0 < len(version) <= 256
                for name, version in sources.items()), 'notice-source-invalid')
    requests, found = set(), set()
    for row in debian:
        require(isinstance(row, dict), 'notice-row-invalid')
        source = row.get('source')
        require(isinstance(source, str), 'notice-row-invalid')
        if source not in sources:
            continue
        package = row.get('package')
        require(isinstance(package, str) and re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?', package)
                and row.get('source_version') == sources[source], 'notice-package-invalid')
        directory = DOC + '/' + package.split(':')[0]
        require(row.get('notice_directory') == directory, 'notice-directory-invalid')
        requests.add(directory + '/copyright')
        found.add(source)
    require(found == set(sources), 'notice-source-missing')
    return sorted(requests)


def source_manifest(records, reference, expected):
    """Parse only fixed manifests authenticated by the producer tree read."""
    require(reference == expected, 'inventory-manifest-path')
    payloads = getattr(records, 'source_manifests', {})
    raw = payloads.get(expected)
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_MANIFEST,
            'inventory-manifest-missing-or-size')
    identity = records.get(expected)
    require(isinstance(identity, dict) and identity.get('size') == len(raw)
            and identity.get('sha256') == hashlib.sha256(raw).hexdigest(),
            'inventory-manifest-bytes-mismatch')

    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'inventory-manifest-duplicate')
            value[key] = item
        return value

    def invalid_constant(_):
        raise InventoryError('inventory-manifest-json')

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                           parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise InventoryError('inventory-manifest-json') from None
    require(isinstance(value, dict) and type(value.get('schema_version')) is int
            and value['schema_version'] == 1, 'inventory-manifest-schema')
    return value


def crosscheck_archives(records, runtime, contract):
    archives, sources = runtime.get('archives'), contract.get('sources')
    require(isinstance(archives, dict) and 0 < len(archives) <= MAX_MEMBERS
            and isinstance(sources, list) and 0 < len(sources) <= MAX_MEMBERS,
            'inventory-source-documents')
    required = {}
    def add(path, sha):
        relative_path(path)
        require(isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{64}', sha), 'inventory-source-digest')
        require(path not in required or required[path] == sha, 'inventory-source-conflict')
        required[path] = sha
    for name, sha in archives.items():
        require(isinstance(name, str) and '/' not in name, 'inventory-source-name')
        add('sources/debian/' + name, sha)
    for source in sources:
        require(isinstance(source, dict), 'inventory-source-row')
        sha = source.get('sha256')
        require(isinstance(sha, str), 'inventory-source-digest')
        add('sources/' + sha + '.tar.gz', sha)
    if 'audio_manifest' in contract:
        audio = source_manifest(records, contract['audio_manifest'], 'audio-toolchain.json')
        dependencies = audio.get('dependencies')
        require(isinstance(dependencies, list) and 0 < len(dependencies) < MAX_MANIFEST_SOURCES,
                'inventory-audio-sources')
        names = set()
        for entry in [audio.get('sdl_mixer'), *dependencies]:
            require(isinstance(entry, dict), 'inventory-audio-source')
            name, source = entry.get('name'), entry.get('source')
            require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}', name)
                    and name not in names and isinstance(source, dict), 'inventory-audio-source')
            names.add(name)
            sha = source.get('sha256')
            require(isinstance(sha, str), 'inventory-source-digest')
            add('sources/' + sha + '.tar.gz', sha)
    compiler = contract.get('compiler', {})
    require(isinstance(compiler, dict), 'inventory-compiler-schema')
    if 'toolchain_manifest' in compiler:
        llvm = source_manifest(records, compiler['toolchain_manifest'], 'llvm-toolchain.json')
        version, source, metadata = llvm.get('version'), llvm.get('source'), llvm.get('metadata')
        require(isinstance(version, str) and re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}', version)
                and isinstance(source, dict) and isinstance(metadata, dict), 'inventory-llvm-source')
        # The installer writes this exact filename, and portable/Dockerfile
        # copies its source directory into sources/llvm without flattening it.
        archive = 'llvm-project-' + version + '.src.tar.xz'
        require(metadata.get('source_archive') == 'share/atrinik/sources/' + archive,
                'inventory-llvm-archive-path')
        add('sources/llvm/' + archive, source.get('sha256'))
    providers = runtime.get('custom_providers', {})
    require(isinstance(providers, dict) and len(providers) <= MAX_MEMBERS, 'inventory-custom-providers')
    for provider in providers.values():
        require(isinstance(provider, dict) and isinstance(provider.get('source_archives'), dict)
                and 0 < len(provider['source_archives']) <= MAX_MEMBERS, 'inventory-custom-provider')
        for path, sha in provider['source_archives'].items():
            require(isinstance(path, str) and path.startswith('sources/'), 'inventory-source-name')
            add(path, sha)
    for path, sha in required.items():
        require(path in records and records[path]['sha256'] == sha, 'inventory-source-bytes-mismatch')


class BudgetResponse:
    """Keep single-file protocol reads under the shared inventory deadline."""
    def __init__(self, response, budget):
        self.response, self.budget = response, budget

    def __getattr__(self, name):
        return getattr(self.response, name)

    def read(self, size):
        return self.budget.read(self.response, size)


class InstalledInventory:
    """Use only with an authenticated StoppedImage; does not grant release trust."""
    def __init__(self, image, protocol):
        self.image, self.protocol = image, protocol
        self.budget = Budget()

    def _fence(self):
        self.budget.check()
        self.image.fence()
        self.budget.check()

    def _parents(self, path):
        result = {}
        for parent in reversed(PurePosixPath(path).parents):
            if str(parent) == '/':
                continue
            self.budget.check()
            value = self.image.stat(str(parent))
            self.protocol.stat_matches(value, str(parent), directory=True)
            result[str(parent)] = value
        return result

    def _recheck(self, observations):
        for path, before in observations.items():
            self.budget.check()
            require(self.image.stat(path) == before, 'inventory-path-drift')
        self._fence()

    def _get(self, path):
        return self.image.docker.request('GET', '/containers/' + self.image.identifier + '/archive?' +
                                         urllib.parse.urlencode({'path': path}),
                                         {'Accept-Encoding': 'identity'})

    def producer(self):
        self._fence()
        observations = self._parents(ROOT)
        expected = self.image.stat(ROOT)
        self.protocol.stat_matches(expected, ROOT, directory=True)
        observations[ROOT] = expected
        conn, response = self._get(ROOT)
        try:
            require(self.protocol.path_stat(response) == expected, 'inventory-path-drift')
            result = tree_archive(response, self.protocol, expected, self.budget)
        finally:
            conn.close()
        self._recheck(observations)
        return result

    def common_licenses(self):
        return {name: self._regular(COMMON + '/' + name) for name in COMMON_LICENSE_NAMES}

    def _regular(self, path, *, executable=False):
        # Internal only: callers are the fixed licenses and verified doc resolver.
        require(path in {COMMON + '/' + name for name in COMMON_LICENSE_NAMES}
                or path in BUILD_TOOLS.values() or path.startswith(DOC + '/'),
                'inventory-file-not-allowed')
        if path.startswith(DOC + '/'):
            under_doc(path)
        self._fence()
        observations = self._parents(path)
        expected = self.image.stat(path)
        self.protocol.stat_matches(expected, path)
        self.protocol.regular_mode(expected['mode'], executable=executable)
        observations[path] = expected
        self.budget.member(expected['size'])
        conn, response = self._get(path)
        try:
            require(self.protocol.path_stat(response) == expected, 'inventory-path-drift')
            identity, _ = self.protocol.single_file_archive(
                BudgetResponse(response, self.budget), path, expected, retain=False, executable=executable)
            self.budget.check()
        finally:
            conn.close()
        self._recheck(observations)
        return {'sha256': identity['sha256'], 'size': identity['size'],
                'executable': bool(expected['mode'] & 0o111)}


    def _alias(self, path, expected):
        """Read the raw one-hop target; Docker HEAD's LinkTarget is fully resolved.

        Moby v28.5.1 daemon/archive_unix.go archives the named resource without
        dereferencing it. Never use the daemon-resolved target as traversal input.
        """
        conn, response = self._get(path)
        try:
            require(self.protocol.path_stat(response) == expected, 'notice-alias-drift')
            framing(response)
            info = next_member(response, self.budget, self.protocol, symlink=True)
            require(info is not None and info.type == tarfile.SYMTYPE and info.size == 0
                    and info.name == PurePosixPath(path).name
                    and info.mode == expected['mode'] & 0o777,
                    'notice-alias-entry')
            raw = info.linkname
            require(isinstance(raw, str) and 0 < len(raw.encode('utf-8')) <= MAX_PATH
                    and len(raw.encode('utf-8')) == expected['size']
                    and all(32 < ord(c) < 127 for c in raw) and '\\' not in raw,
                    'notice-alias-target')
            require(next_member(response, self.budget, self.protocol) is None,
                    'notice-alias-extra-member')
            return raw
        finally:
            conn.close()

    def _notice(self, requested):
        under_doc(requested)
        self._fence()
        observations = self._parents(DOC + '/copyright')
        links, visited = {}, set()

        def resolve(path):
            under_doc(path)
            parts = path[len(DOC) + 1:].split('/')
            current = DOC
            for index, part in enumerate(parts):
                current += '/' + part
                self.budget.check()
                value = self.image.stat(current)
                require(current not in observations or observations[current] == value,
                        'notice-alias-drift')
                observations[current] = value
                mode = value.get('mode')
                require(type(mode) is int, 'notice-mode-invalid')
                if mode & ~0o777 == GO_SYMLINK:
                    require(value.get('name') == part and type(value.get('size')) is int
                            and 0 < value['size'] <= MAX_PATH, 'notice-alias-stat')
                    under_doc(value.get('linkTarget'))
                    require(current not in visited and len(visited) < MAX_HOPS, 'notice-alias-cycle-or-limit')
                    visited.add(current)
                    raw = self._alias(current, value)
                    links[current] = raw
                    # Interpret raw components ourselves. Even temporary escape
                    # followed by re-entry fails; HEAD's final target is no proof.
                    if raw.startswith('/'):
                        require(raw.startswith(DOC + '/'), 'notice-boundary')
                        resolved_parts = []
                        target_parts = raw[len(DOC) + 1:].split('/')
                    else:
                        resolved_parts = current[len(DOC) + 1:].split('/')[:-1]
                        target_parts = raw.split('/')
                    descended = False
                    for component in target_parts:
                        require(component != '', 'notice-alias-target')
                        if component == '..':
                            # Only leading parent hops are safe to normalize:
                            # later components may themselves name symlinks.
                            require(not descended and bool(resolved_parts), 'notice-boundary')
                            resolved_parts.pop()
                        elif component != '.':
                            descended = True
                            resolved_parts.append(component)
                    require(bool(resolved_parts), 'notice-boundary')
                    canonical = resolve(DOC + '/' + '/'.join(resolved_parts))
                    require(canonical == value['linkTarget'], 'notice-alias-drift')
                    if index + 1 < len(parts):
                        canonical = resolve(canonical + '/' + '/'.join(parts[index + 1:]))
                    return canonical
                if index + 1 < len(parts) or mode & GO_DIRECTORY:
                    self.protocol.stat_matches(value, current, directory=True)
                else:
                    self.protocol.stat_matches(value, current)
            return current

        canonical = resolve(requested)
        result = self._regular(canonical)
        for path, raw in links.items():
            require(self._alias(path, observations[path]) == raw, 'notice-alias-drift')
        self._recheck(observations)
        return {**result, 'resolved_path': canonical}

    def debian_notices(self, runtime, debian):
        return {requested: self._notice(requested)
                for requested in notice_requests(runtime, debian)}


    def build_tools(self, installed):
        require(isinstance(installed, dict), 'build-tool-schema')
        receipt = installed.get('build_tools')
        require(isinstance(receipt, dict) and set(receipt) == {'schema_version', 'tools'}
                and type(receipt['schema_version']) is int and receipt['schema_version'] == 1
                and isinstance(receipt['tools'], dict) and set(receipt['tools']) == set(BUILD_TOOLS),
                'build-tool-schema')
        result = {}
        for role, path in BUILD_TOOLS.items():
            entry = receipt['tools'][role]
            require(isinstance(entry, dict) and set(entry) == {
                'path', 'resolved_path', 'sha256', 'size', 'executable', 'version'}, 'build-tool-fields')
            require(entry['path'] == path and entry['resolved_path'] == path,
                    'build-tool-path')
            require(isinstance(entry['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', entry['sha256'])
                    and type(entry['size']) is int and 0 < entry['size'] <= MAX_BUILD_TOOL
                    and entry['executable'] is True and isinstance(entry['version'], str)
                    and 0 < len(entry['version']) <= 65536
                    and not any((ord(char) < 32 and char != '\n') or ord(char) == 127
                                for char in entry['version'])
                    and re.fullmatch(r'cmake version [0-9]+\.[0-9]+\.[0-9]+' if role == 'cmake'
                                     else r'[0-9]+\.[0-9]+(?:\.[0-9]+)?',
                                     entry['version'].splitlines()[0]) is not None
                    and isinstance(installed.get('tools'), dict)
                    and installed['tools'].get(role) == entry['version'].splitlines()[0],
                    'build-tool-identity')
            observed = self._regular(path, executable=True)
            require(all(observed[key] == entry[key] for key in ('sha256', 'size', 'executable')),
                    'build-tool-bytes-mismatch')
            result[role] = dict(entry)
        return result
