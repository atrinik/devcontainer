# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Internal fixed-boundary inventory reader; no CLI or acquisition authority.

The fixed final-target collector supplies its authenticated, created-state
StoppedImage and archive protocol. This helper grants no acquisition or release
trust; target pins and hosted filesystem qualification belong to the caller.
"""
from abc import ABC, abstractmethod
import datetime
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
SOURCE_MANIFESTS = ('audio-toolchain.json', 'llvm-toolchain.json',
                    'curl-toolchain.json', 'classic-curl-toolchain.json')
MAX_MANIFEST = 1024 * 1024
METADATA_FILES = ('contract.json', 'installed.json', 'compiler-evidence.json',
                  'runtime-abi.json', 'runtime-sources.json', 'debian-sources.json',
                  'shader-generation.json')
LLVM_PREFIX = '/opt/llvm-23.1.3'
LLVM_TOOL_FILES = {
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
GO_DIRECTORY = 1 << 31
GO_SYMLINK = 1 << 27


class InventoryError(Exception):
    """Only fixed failure codes; never hostile archive or daemon contents."""


# Receipt diagnostics admit these exact source-defined codes only. Unknown
# exceptions, subclasses and payloads remain opaque even if they look like codes.
FAILURE_CODES = frozenset({
    'build-tool-bytes-mismatch',
    'build-tool-fields',
    'build-tool-identity',
    'build-tool-path',
    'build-tool-schema',
    'file-size-limit',
    'inventory-audio-source',
    'inventory-audio-sources',
    'inventory-cares-source',
    'inventory-compiler-schema',
    'inventory-contract-schema',
    'inventory-curl-archives',
    'inventory-curl-source',
    'inventory-custom-provider',
    'inventory-custom-providers',
    'inventory-deadline',
    'inventory-directory-entry',
    'inventory-directory-mode',
    'inventory-directory-owner',
    'inventory-duplicate',
    'inventory-empty',
    'inventory-encoding',
    'inventory-end-markers',
    'inventory-extension-or-link',
    'inventory-file-not-allowed',
    'inventory-header-invalid',
    'inventory-llvm-archive-path',
    'inventory-llvm-source',
    'inventory-manifest-bytes-mismatch',
    'inventory-manifest-duplicate',
    'inventory-manifest-json',
    'inventory-manifest-missing-or-size',
    'inventory-manifest-path',
    'inventory-manifest-payloads',
    'inventory-manifest-schema',
    'inventory-manifest-size',
    'inventory-member-type',
    'inventory-metadata-binding',
    'inventory-metadata-files',
    'inventory-metadata-size',
    'inventory-owner-invalid',
    'inventory-padding',
    'inventory-parent-missing',
    'inventory-path-drift',
    'inventory-path-invalid',
    'inventory-pax-invalid',
    'inventory-provider-bytes-mismatch',
    'inventory-provider-identity',
    'inventory-provider-reader-required',
    'inventory-report-roles',
    'inventory-root-mismatch',
    'inventory-size-limit',
    'inventory-source-bytes-mismatch',
    'inventory-source-cohort',
    'inventory-source-conflict',
    'inventory-source-digest',
    'inventory-source-documents',
    'inventory-source-name',
    'inventory-source-row',
    'inventory-stream-limit',
    'inventory-tail',
    'inventory-tail-alignment',
    'inventory-truncated',
    'inventory-unframed',
    'notice-alias-cycle-or-limit',
    'notice-alias-drift',
    'notice-alias-entry',
    'notice-alias-extra-member',
    'notice-alias-stat',
    'notice-alias-target',
    'notice-boundary',
    'notice-directory-invalid',
    'notice-documents-invalid',
    'notice-mode-invalid',
    'notice-package-invalid',
    'notice-row-invalid',
    'notice-source-invalid',
    'notice-source-missing',
    'scanner-inventory-mismatch',
    'scanner-report-shape',
})


def failure_code(error):
    if (type(error) is InventoryError and len(error.args) == 1
            and type(error.args[0]) is str and error.args[0] in FAILURE_CODES):
        return error.args[0]
    return 'inventory-operation-failed'


SCANNER_STAGES = frozenset({'startup', 'metadata', 'producer-tree', 'metadata-binding',
    'source-archives-and-providers', 'debian-notices', 'common-licenses', 'build-tools',
    'llvm-tools', 'final-fence', 'report'})
SCANNER_ERRNOS = frozenset({'EACCES', 'EPERM', 'ENOENT', 'ELOOP', 'ENOTDIR', 'EROFS',
                          'EIO', 'EMFILE', 'ENFILE', 'ENOSPC', 'other'})
SCANNER_FAILURE_CODES = frozenset({
    'scanner-alias-boundary', 'scanner-alias-cycle-or-limit', 'scanner-alias-drift',
    'scanner-alias-path', 'scanner-alias-type', 'scanner-deadline', 'scanner-depth-limit',
    'scanner-duplicate-json-key', 'scanner-empty-tree', 'scanner-execution-boundary',
    'scanner-file-drift', 'scanner-file-grew', 'scanner-file-limit', 'scanner-interrupted',
    'scanner-invalid-json', 'scanner-llvm-alias', 'scanner-manifest-bytes-mismatch',
    'scanner-member-limit', 'scanner-path', 'scanner-path-drift', 'scanner-provider-owner',
    'scanner-provider-path', 'scanner-report-limit', 'scanner-tool-not-executable',
    'scanner-total-limit', 'scanner-tree-drift', 'scanner-tree-special-or-link',
    'scanner-unsafe-directory', 'scanner-unsafe-file',
})


def scanner_failure(value):
    """Admit only bounded source-defined diagnostics from executed image stdout."""
    if type(value) is not dict or set(value) not in (
            {'status', 'reason', 'stage'}, {'status', 'reason', 'stage', 'errno_name'}):
        return None
    if (value.get('status') != 'stopped' or type(value.get('reason')) is not str
            or type(value.get('stage')) is not str or value['stage'] not in SCANNER_STAGES):
        return None
    if value['reason'] == 'scanner-os-error':
        if type(value.get('errno_name')) is not str or value['errno_name'] not in SCANNER_ERRNOS:
            return None
    elif ('errno_name' in value or value['reason'] not in
          FAILURE_CODES | SCANNER_FAILURE_CODES | {'filesystem-scan-failed'}):
        return None
    return dict(value)


class ProviderReader(ABC):
    """Authenticated byte reader supplied by the source-inventory caller.

    Implementations own admission to their stopped image or protected filesystem,
    and fence actual file/ancestor identities around every read. This interface
    is not authentication: callers must use the same source for the producer
    inventory, metadata and provider bytes, never an advisory metadata adapter.
    """
    @abstractmethod
    def read_provider(self, path):
        """Read a fixed-namespace library; return sha256, size and executable."""


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
        # Moby archives GET / with a raw '/' directory entry. TarInfo strips
        # its slash to empty; preserve only this exact canonical root spelling.
        if info.isdir() and info.name == '' and raw[:100].split(b'\0', 1)[0] == b'/':
            info.name = '/'
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
    require(isinstance(payloads, dict), 'inventory-manifest-payloads')
    raw = payloads.get(expected)
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_MANIFEST,
            'inventory-manifest-missing-or-size')
    identity = records.get(expected)
    require(isinstance(identity, dict) and type(identity.get('size')) is int
            and identity['size'] == len(raw)
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


def crosscheck_archives(records, runtime, contract, *, reader=None):
    """Validate source closure and bind provider bytes using the same image reader."""
    require(isinstance(records, dict) and isinstance(runtime, dict)
            and isinstance(contract, dict), 'inventory-source-documents')
    require(type(contract.get('schema_version')) is int and contract['schema_version'] == 2
            and contract.get('target') == 'portable-final' and contract.get('platform') == 'linux/amd64',
            'inventory-contract-schema')
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
    source_names = set()
    for source in sources:
        require(isinstance(source, dict), 'inventory-source-row')
        name = source.get('name')
        require(isinstance(name, str) and name in {'openssl', 'sdl3', 'sdl3-image', 'sdl3-ttf'}
                and name not in source_names, 'inventory-source-cohort')
        source_names.add(name)
        sha = source.get('sha256')
        require(isinstance(sha, str), 'inventory-source-digest')
        add('sources/' + sha + '.tar.gz', sha)
    require(source_names == {'openssl', 'sdl3', 'sdl3-image', 'sdl3-ttf'}, 'inventory-source-cohort')
    audio = source_manifest(records, contract.get('audio_manifest'), 'audio-toolchain.json')
    dependencies = audio.get('dependencies')
    require(isinstance(dependencies, list) and len(dependencies) == 3,
            'inventory-audio-sources')
    mixer = audio.get('sdl_mixer')
    require(isinstance(mixer, dict) and mixer.get('name') == 'SDL3_mixer', 'inventory-audio-source')
    names = set()
    for entry in [mixer, *dependencies]:
        require(isinstance(entry, dict), 'inventory-audio-source')
        name, source = entry.get('name'), entry.get('source')
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}', name)
                and name not in names and isinstance(source, dict), 'inventory-audio-source')
        names.add(name)
        sha = source.get('sha256')
        require(isinstance(sha, str), 'inventory-source-digest')
        add('sources/' + sha + '.tar.gz', sha)
    require(names == {'SDL3_mixer', 'libogg', 'libopus', 'libopusfile'}, 'inventory-audio-sources')
    compiler = contract.get('compiler')
    require(isinstance(compiler, dict), 'inventory-compiler-schema')
    llvm = source_manifest(records, compiler.get('toolchain_manifest'), 'llvm-toolchain.json')
    version, source, metadata = llvm.get('version'), llvm.get('source'), llvm.get('metadata')
    require(isinstance(version, str) and re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}', version)
            and isinstance(source, dict) and isinstance(metadata, dict), 'inventory-llvm-source')
    # The installer writes this exact filename, and portable/Dockerfile
    # copies its source directory into sources/llvm without flattening it.
    archive = 'llvm-project-' + version + '.src.tar.xz'
    require(metadata.get('source_archive') == 'share/atrinik/sources/' + archive,
            'inventory-llvm-archive-path')
    add('sources/llvm/' + archive, source.get('sha256'))

    # legal.py emits both providers. Bind their complete archive declarations
    # to the producer manifests, so dropping a provider or one archive cannot
    # shrink the corresponding-source requirements.
    curl = source_manifest(records, contract.get('curl_manifest'), 'curl-toolchain.json')
    shared = source_manifest(records, curl.get('cares_manifest'), 'classic-curl-toolchain.json')
    version, source_version, archives = curl.get('version'), curl.get('source_version'), curl.get('archives')
    require(curl.get('source_package') == 'curl' and isinstance(version, str)
            and re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}', version)
            and isinstance(source_version, str) and len(source_version) <= 128
            and re.fullmatch(re.escape(version) + r'-[0-9A-Za-z.+~]+', source_version),
            'inventory-curl-source')
    require(isinstance(archives, dict) and set(archives) == {
        'curl_' + source_version + '.debian.tar.xz', 'curl_' + source_version + '.dsc',
        'curl_' + version + '.orig.tar.gz', 'curl_' + version + '.orig.tar.gz.asc'},
        'inventory-curl-archives')
    cares = shared.get('cares')
    require(isinstance(cares, dict) and isinstance(cares.get('version'), str)
            and re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}', cares['version'])
            and isinstance(cares.get('sha256'), str), 'inventory-cares-source')
    expected_sources = {
        'libcurl': {'sources/curl/' + name: sha for name, sha in archives.items()},
        'libcares': {'sources/' + cares['sha256'] + '.tar.gz': cares['sha256']}}
    providers = runtime.get('custom_providers')
    require(isinstance(providers, dict) and set(providers) == set(expected_sources),
            'inventory-custom-providers')
    for name, sources in expected_sources.items():
        provider = providers[name]
        require(isinstance(provider, dict) and set(provider) == {
            'path', 'sha256', 'version', 'source_archives', 'build_receipt'}, 'inventory-custom-provider')
        require(isinstance(provider['path'], str) and len(provider['path']) <= MAX_PATH and re.fullmatch(
            r'/usr/local/lib/' + name + r'\.so(?:\.[0-9]+)+', provider['path'])
            and isinstance(provider['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', provider['sha256'])
            and provider['version'] == (version if name == 'libcurl' else cares['version'])
            and provider['build_receipt'] == 'curl-source-receipt.json'
            and isinstance(provider['source_archives'], dict) and provider['source_archives'] == sources,
            'inventory-custom-provider')
        for path, sha in sources.items():
            add(path, sha)
    for path, sha in required.items():
        record = records.get(path)
        require(isinstance(record, dict) and type(record.get('size')) is int
                and 0 < record['size'] <= MAX_FILE and record.get('sha256') == sha,
                'inventory-source-bytes-mismatch')
    require(isinstance(reader, ProviderReader), 'inventory-provider-reader-required')
    for provider in providers.values():
        observed = reader.read_provider(provider['path'])
        require(isinstance(observed, dict) and set(observed) == {'sha256', 'size', 'executable'}
                and isinstance(observed['sha256'], str)
                and re.fullmatch(r'[0-9a-f]{64}', observed['sha256'])
                and type(observed['size']) is int and 0 < observed['size'] <= MAX_FILE
                and type(observed['executable']) is bool, 'inventory-provider-identity')
        require(observed['sha256'] == provider['sha256'], 'inventory-provider-bytes-mismatch')


class BudgetResponse:
    """Keep single-file protocol reads under the shared inventory deadline."""
    def __init__(self, response, budget):
        self.response, self.budget = response, budget

    def __getattr__(self, name):
        return getattr(self.response, name)

    def read(self, size):
        return self.budget.read(self.response, size)


class InstalledInventory(ProviderReader):
    """Use only with an authenticated StoppedImage; does not grant release trust."""
    def __init__(self, image, protocol, *, progress=None):
        self.image, self.protocol = image, protocol
        self.budget = Budget()
        self.progress = progress

    def _same_stat(self, actual, expected, *, site, path):
        """Fence stable root fields and full nonroot stats; retain no values."""
        require(type(actual) is dict and type(expected) is dict, 'inventory-path-drift')
        matches = actual == expected
        if path == '/':
            # Moby's separate filesystem views create/remove a pivot directory
            # beneath /. Its mtime and directory storage size are view-local.
            # Only these two validated fields are excluded from root equality.
            matches = (self._valid_root_stat(actual) and self._valid_root_stat(expected)
                       and {key: value for key, value in actual.items() if key not in ('size', 'mtime')} ==
                           {key: value for key, value in expected.items() if key not in ('size', 'mtime')})
        if not matches and self.progress is not None:
            fields = ('name', 'size', 'mode', 'mtime', 'linkTarget')
            mode = expected.get('mode')
            subject = ('root-directory' if path == '/' else
                       'directory' if type(mode) is int and mode & GO_DIRECTORY else 'file')
            self.progress['path_stat_drift'] = {
                'site': site,
                'subject': subject,
                'changed_fields': [key for key in fields
                                   if (key in actual) != (key in expected)
                                   or actual.get(key) != expected.get(key)],
                'field_set_changed': actual.keys() != expected.keys(),
                'unknown_fields_changed':
                    {key: value for key, value in actual.items() if key not in fields} !=
                    {key: value for key, value in expected.items() if key not in fields},
            }
        require(matches, 'inventory-path-drift')

    @staticmethod
    def _valid_root_stat(value):
        if type(value) is not dict or set(value) != {'name', 'size', 'mode', 'mtime', 'linkTarget'}:
            return False
        mode, size, mtime = value['mode'], value['size'], value['mtime']
        if not (value['name'] == '/' and value['linkTarget'] == ''
                and type(mode) is int and mode & ~0o777 == GO_DIRECTORY
                and mode & 0o022 == 0 and mode & 0o555 == 0o555
                and type(size) is int and 0 <= size <= 2**63 - 1
                and type(mtime) is str and len(mtime) <= 35
                and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]'
                                 r'(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])', mtime)):
            return False
        try:
            datetime.datetime.fromisoformat(mtime)
        except ValueError:
            return False
        return True

    def _fence(self):
        self.budget.check()
        self.image.fence()
        self.budget.check()

    def _directory_owner(self, path, expected):
        """Read only the directory header, never its recursive archive contents.

        Docker HEAD omits UID/GID. The first member of its authenticated GET
        supplies ownership; close immediately to bound even the root archive.
        """
        conn, response = self._get(path)
        try:
            self._same_stat(self.protocol.path_stat(response), expected,
                            site='directory-header', path=path)
            framing(response)
            info = next_member(response, self.budget, self.protocol)
            names = {'/'} if path == '/' else {PurePosixPath(path).name}
            require(info is not None and info.name in names and info.isdir()
                    and info.size == 0 and info.mode == expected['mode'] & 0o777,
                    'inventory-directory-entry')
            require(info.uid == 0, 'inventory-directory-owner')
        finally:
            conn.close()

    def _parents(self, path, *, protected=False):
        result = {}
        for parent in reversed(PurePosixPath(path).parents):
            if str(parent) == '/' and not protected:
                continue
            self.budget.check()
            value = self.image.stat(str(parent))
            if str(parent) == '/':
                require(self._valid_root_stat(value), 'inventory-directory-entry')
                self.protocol.stat_matches({**value, 'name': ''}, '/', directory=True)
            else:
                self.protocol.stat_matches(value, str(parent), directory=True)
            if protected:
                self._directory_owner(str(parent), value)
            result[str(parent)] = value
        return result

    def _recheck(self, observations):
        for path, before in observations.items():
            self.budget.check()
            after = self.image.stat(path)
            self._same_stat(after, before, site='recheck', path=path)
            if path == '/':
                # HEAD cannot prove ownership. Recheck the bounded UID/mode
                # header after protected bytes as well as before them.
                self._directory_owner(path, after)
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
            self._same_stat(self.protocol.path_stat(response), expected,
                            site='producer-header', path=ROOT)
            result = tree_archive(response, self.protocol, expected, self.budget)
        finally:
            conn.close()
        self._recheck(observations)
        return result

    def read_provider(self, path):
        return self._regular(path, provider=True)

    def common_licenses(self):
        return {name: self._regular(COMMON + '/' + name) for name in COMMON_LICENSE_NAMES}

    def _regular(self, path, *, executable=False, provider=False):
        # Provider paths have already passed source-manifest validation; enforce
        # the fixed library namespace again at the actual archive request.
        provider_path = isinstance(path, str) and len(path) <= MAX_PATH and re.fullmatch(
            r'/usr/local/lib/lib(?:curl|cares)\.so(?:\.[0-9]+)+', path) is not None
        require(not provider or provider_path, 'inventory-file-not-allowed')
        require((provider and provider_path) or path in {COMMON + '/' + name for name in COMMON_LICENSE_NAMES}
                or path in BUILD_TOOLS.values() or path.startswith(DOC + '/'),
                'inventory-file-not-allowed')
        if path.startswith(DOC + '/'):
            under_doc(path)
        self._fence()
        protected = path in BUILD_TOOLS.values() or provider
        expected = self.image.stat(path)
        self.protocol.stat_matches(expected, path)
        self.protocol.regular_mode(expected['mode'], executable=executable)
        require(0 < expected['size'] <= self.protocol.BINARY_LIMIT, 'file-size-limit')
        observations = self._parents(path, protected=protected)
        observations[path] = expected
        self.budget.member(expected['size'])
        conn, response = self._get(path)
        try:
            self._same_stat(self.protocol.path_stat(response), expected,
                            site='regular-header', path=path)
            identity, _ = self.protocol.single_file_archive(
                BudgetResponse(response, self.budget), path, expected, retain=False, executable=executable, root_owned=protected)
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
        return build_tool_records(installed, lambda path: self._regular(path, executable=True))


def build_tool_records(installed, read):
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
        observed = read(path)
        require(all(observed[key] == entry[key] for key in ('sha256', 'size', 'executable')),
                'build-tool-bytes-mismatch')
        result[role] = dict(entry)
    return result


def bind_metadata(producer, raw, records):
    """Bind every retained producer file and require the seven-file handoff."""
    require(isinstance(producer, dict) and isinstance(raw, dict) and isinstance(records, dict)
            and set(METADATA_FILES) <= set(raw) and set(records) == set(raw),
            'inventory-metadata-files')
    for name, value in raw.items():
        relative_path(name)
        require(isinstance(value, bytes) and len(value) <= 4 * 1024 * 1024,
                'inventory-metadata-size')
        record = records[name]
        require(isinstance(record, dict) and set(record) == {'sha256', 'size', 'executable'}
                and type(record['size']) is int and type(record['executable']) is bool
                and record['size'] == len(value) and record['sha256'] == hashlib.sha256(value).hexdigest()
                and name in producer and producer[name] == record, 'inventory-metadata-binding')


def expected_scan(inventories, metadata, build_tools, llvm_tools):
    require(set(inventories) == {'producer', 'debian_notices', 'common_licenses'}
            and set(metadata) == set(METADATA_FILES) and set(build_tools) == set(BUILD_TOOLS)
            and set(llvm_tools) == set(LLVM_TOOL_FILES), 'inventory-report-roles')
    return {'schema_version': 1, 'claim': 'trusted-producer-filesystem-inventory',
            'image_code_executed': True, 'final_portable_cohort': False,
            'inventories': inventories,
            'inventory_sha256': {key: inventory_digest(value) for key, value in inventories.items()},
            'metadata': metadata, 'build_tools': build_tools, 'llvm_tools': llvm_tools}


def compare_scan(observed, expected):
    # Compare complete JSON structures, not a claimed digest or Python's bool/int
    # equality. This catches omitted unrelated files and every role/field change.
    require(isinstance(observed, dict) and set(observed) == set(expected), 'scanner-report-shape')
    require(json.dumps(observed, sort_keys=True, separators=(',', ':'), allow_nan=False) ==
            json.dumps(expected, sort_keys=True, separators=(',', ':'), allow_nan=False),
            'scanner-inventory-mismatch')
