#!/usr/bin/python3 -I
# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Fixed-root trusted-producer qualification; no image or path CLI overrides.

Descriptor-relative inventory/byte recording adapted from MIT-licensed
atrinik/atrinik a9661a2bd978107fe4e01e45b2e22fcd1e2d095c:
atrinik_workspace/linux_export.py (_identity, _inventory, _open_root,
_open_beneath), linux_portable.py (byte_record, verified_tree_inventory).
See RELEASED_SDK_INVENTORY.md for provenance and execution-claim boundaries.
"""
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import signal
import stat
import sys
import time

_SPEC = importlib.util.spec_from_file_location('inventory_contract',
    Path(__file__).resolve().with_name('released_sdk_inventory.py'))
I = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(I)
MAX_REPORT = 64 * 1024 * 1024
MAX_DEPTH = 128


def unique(items):
    result = {}
    for key, value in items:
        I.require(key not in result, 'scanner-duplicate-json-key')
        result[key] = value
    return result


def decode(raw):
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise I.InventoryError('scanner-invalid-json') from None


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_uid, info.st_gid,
            info.st_mtime_ns, info.st_ctime_ns)


class Filesystem(I.ProviderReader):
    """All paths are fixed by scan(); root_fd exists only for offline fixtures."""
    def __init__(self, root_fd):
        self.root_fd = root_fd
        self.deadline = time.monotonic() + I.MAX_SECONDS
        self.total = 0
        self.observed = {}
        self.links = {}

    def check(self):
        I.require(time.monotonic() < self.deadline, 'scanner-deadline')

    def remember(self, path, info):
        self.check()
        value = identity(info)
        I.require(path not in self.observed or self.observed[path] == value, 'scanner-path-drift')
        self.observed[path] = value
        I.require(len(self.observed) <= I.MAX_MEMBERS, 'scanner-member-limit')

    def directory(self, path, *, protected=False):
        I.require(path.startswith('/'), 'scanner-path')
        if path != '/':
            I.relative_path(path[1:])
        fd = os.dup(self.root_fd)
        current = ''
        try:
            root = os.fstat(fd)
            I.require(not protected or (root.st_uid == 0 and root.st_mode & 0o022 == 0),
                      'scanner-provider-owner')
            self.remember('/', root)
            for part in path.split('/')[1:]:
                if not part:
                    continue
                self.check()
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                current += '/' + part
                info = os.fstat(fd)
                I.require(stat.S_ISDIR(info.st_mode) and info.st_mode & 0o022 == 0,
                          'scanner-unsafe-directory')
                I.require(not protected or info.st_uid == 0, 'scanner-provider-owner')
                self.remember(current, info)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def record(self, path, *, retain=False, executable=False, allow_empty=False, max_size=None, protected=False):
        parent, name = path.rsplit('/', 1)
        I.relative_path(name)
        directory = self.directory(parent, protected=protected)
        fd = None
        try:
            before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            I.require(stat.S_ISREG(before.st_mode) and before.st_mode & 0o6022 == 0
                      and before.st_mode & 0o444 == 0o444, 'scanner-unsafe-file')
            I.require(not protected or before.st_uid == 0, 'scanner-provider-owner')
            if executable:
                I.require(before.st_mode & 0o111 == 0o111, 'scanner-tool-not-executable')
            limit = 4 * 1024 * 1024 if retain else I.MAX_FILE
            if max_size is not None:
                limit = min(limit, max_size)
            I.require((0 if allow_empty else 1) <= before.st_size <= limit, 'scanner-file-limit')
            self.total += before.st_size
            I.require(self.total <= I.MAX_TOTAL, 'scanner-total-limit')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            I.require(identity(os.fstat(fd)) == identity(before), 'scanner-path-drift')
            self.remember(path, before)
            digest = hashlib.sha256()
            data = bytearray() if retain else None
            count = 0
            while True:
                self.check()
                raw = os.read(fd, min(65536, before.st_size - count + 1))
                if not raw:
                    break
                count += len(raw)
                I.require(count <= before.st_size, 'scanner-file-grew')
                digest.update(raw)
                if data is not None:
                    data.extend(raw)
            I.require(count == before.st_size and identity(os.fstat(fd)) == identity(before)
                      and identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == identity(before),
                      'scanner-file-drift')
            return {'sha256': digest.hexdigest(), 'size': count,
                    'executable': bool(before.st_mode & 0o111)}, (bytes(data) if retain else None)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(directory)

    def read_provider(self, path):
        I.require(isinstance(path, str) and len(path) <= I.MAX_PATH and re.fullmatch(
            r'/usr/local/lib/lib(?:curl|cares)\.so(?:\.[0-9]+)+', path),
            'scanner-provider-path')
        self.fence()
        record, _ = self.record(path, protected=True)
        self.fence()
        return record

    def tree(self):
        # Retain only the four fixed source manifests, with bounds before reads.
        # record() and remember() fence descriptors and tree enumeration together.
        manifests = {name: self.record(I.ROOT + '/' + name, retain=True,
                                      max_size=I.MAX_MANIFEST)
                     for name in I.SOURCE_MANIFESTS}
        directory = self.directory(I.ROOT)
        def enumerate_tree(fd, prefix, depth):
            self.check()
            I.require(depth <= MAX_DEPTH, 'scanner-depth-limit')
            result = {}
            # scandir/open/stat errors propagate: no tar producer can silently
            # omit an unreadable file or directory from this traversal.
            with os.scandir(fd) as entries:
                for entry in entries:
                    self.check()
                    path = prefix + '/' + entry.name
                    I.relative_path(path[1:])
                    info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                    self.remember(path, info)
                    result[path] = identity(info)
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        try:
                            I.require(identity(os.fstat(child)) == identity(info), 'scanner-path-drift')
                            result.update(enumerate_tree(child, path, depth + 1))
                        finally:
                            os.close(child)
                    else:
                        I.require(stat.S_ISREG(info.st_mode), 'scanner-tree-special-or-link')
            return result
        try:
            before = enumerate_tree(directory, I.ROOT, 0)
            records = I.ProducerInventory()
            for path, item in sorted(before.items()):
                if stat.S_ISREG(item[2]):
                    records[path[len(I.ROOT) + 1:]], _ = self.record(path, allow_empty=True)
            I.require(enumerate_tree(directory, I.ROOT, 0) == before, 'scanner-tree-drift')
            I.require(bool(records), 'scanner-empty-tree')
            for name, (record, payload) in manifests.items():
                I.require(records.get(name) == record and len(payload) == record['size']
                          and hashlib.sha256(payload).hexdigest() == record['sha256'],
                          'scanner-manifest-bytes-mismatch')
                records.source_manifests[name] = payload
            return records
        finally:
            os.close(directory)

    def resolve(self, path, boundary):
        """Resolve every raw component, including links before parent hops."""
        I.require(path.startswith(boundary + '/'), 'scanner-alias-boundary')
        I.relative_path(path[1:])
        boundary_parts = boundary.split('/')[1:]
        current = list(boundary_parts)
        pending = path[len(boundary) + 1:].split('/')
        visited = set()
        while pending:
            self.check()
            component = pending.pop(0)
            I.require(component != '', 'scanner-alias-path')
            if component == '.':
                continue
            if component == '..':
                I.require(len(current) > len(boundary_parts), 'scanner-alias-boundary')
                current.pop()
                continue
            parent = '/' + '/'.join(current)
            fd = self.directory(parent)
            try:
                candidate = parent + '/' + component
                info = os.stat(component, dir_fd=fd, follow_symlinks=False)
                self.remember(candidate, info)
                if stat.S_ISLNK(info.st_mode):
                    I.require(candidate not in visited and len(visited) < I.MAX_HOPS,
                              'scanner-alias-cycle-or-limit')
                    visited.add(candidate)
                    raw = os.readlink(component, dir_fd=fd)
                    I.require(0 < len(raw) <= I.MAX_PATH and '\\' not in raw
                              and all(32 < ord(c) < 127 for c in raw), 'scanner-alias-path')
                    self.links[candidate] = raw
                    if raw.startswith('/'):
                        I.require(raw.startswith(boundary + '/'), 'scanner-alias-boundary')
                        current = list(boundary_parts)
                        raw = raw[len(boundary) + 1:]
                    pending = raw.split('/') + pending
                    I.require(sum(len(part) + 1 for part in current + pending) <= I.MAX_PATH,
                              'scanner-alias-path')
                else:
                    I.require(stat.S_ISDIR(info.st_mode) if pending else stat.S_ISREG(info.st_mode),
                              'scanner-alias-type')
                    current.append(component)
            finally:
                os.close(fd)
        return '/' + '/'.join(current)

    def fence(self):
        for path, expected in list(self.observed.items()):
            self.check()
            if path == '/':
                actual = os.fstat(self.root_fd)
            else:
                parent, name = path.rsplit('/', 1)
                fd = self.directory(parent or '/')
                try:
                    actual = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if path in self.links:
                        I.require(os.readlink(name, dir_fd=fd) == self.links[path], 'scanner-alias-drift')
                finally:
                    os.close(fd)
            I.require(identity(actual) == expected, 'scanner-path-drift')


def scan(root_fd):
    fs = Filesystem(root_fd)
    raw, metadata_records = {}, {}
    for name in I.METADATA_FILES:
        metadata_records[name], raw[name] = fs.record(I.ROOT + '/' + name, retain=True)
    documents = {name: decode(value) for name, value in raw.items()}
    maps = {'producer': fs.tree()}
    I.bind_metadata(maps['producer'], raw, metadata_records)
    I.crosscheck_archives(maps['producer'], documents['runtime-sources.json'], documents['contract.json'], reader=fs)
    maps['debian_notices'] = {}
    for requested in I.notice_requests(documents['runtime-sources.json'], documents['debian-sources.json']):
        resolved = fs.resolve(requested, I.DOC)
        record, _ = fs.record(resolved)
        maps['debian_notices'][requested] = {**record, 'resolved_path': resolved}
    maps['common_licenses'] = {name: fs.record(I.COMMON + '/' + name)[0] for name in I.COMMON_LICENSE_NAMES}
    build_tools = I.build_tool_records(documents['installed.json'],
                                     lambda path: fs.record(path, executable=True)[0])
    llvm_tools = {}
    for role, (declared, canonical) in I.LLVM_TOOL_FILES.items():
        path, resolved = I.LLVM_PREFIX + '/' + declared, I.LLVM_PREFIX + '/' + canonical
        I.require(fs.resolve(path, I.LLVM_PREFIX) == resolved, 'scanner-llvm-alias')
        record, _ = fs.record(resolved, executable=role not in ('runtime', 'unwinder'))
        llvm_tools[role] = {'path': path, 'canonical_path': resolved, **record}
    fs.fence()
    return {'schema_version': 1, 'claim': 'trusted-producer-filesystem-inventory',
            'image_code_executed': True, 'final_portable_cohort': False,
            'inventories': maps, 'inventory_sha256': {key: I.inventory_digest(value) for key, value in maps.items()},
            'metadata': metadata_records, 'build_tools': build_tools, 'llvm_tools': llvm_tools}


def main():
    def stop(_number, _frame):
        raise I.InventoryError('scanner-interrupted')
    try:
        I.require(sys.flags.isolated == 1 and len(sys.argv) == 1 and os.geteuid() != 0,
                  'scanner-execution-boundary')
        signal.signal(signal.SIGALRM, stop)
        signal.signal(signal.SIGTERM, stop)
        signal.alarm(I.MAX_SECONDS)
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            result = scan(fd)
        finally:
            os.close(fd)
        encoded = (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode()
        I.require(len(encoded) <= MAX_REPORT, 'scanner-report-limit')
        sys.stdout.buffer.write(encoded)
        return 0
    except BaseException:
        print('{"status":"stopped","reason":"filesystem-scan-failed"}')
        return 1
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    sys.exit(main())
