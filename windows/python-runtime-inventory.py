#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
"""Seal every file from the verified external Python runtime archive."""
from __future__ import annotations
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
import stat
from pathlib import Path


def safe_absolute(path: Path) -> Path:
    # Do not let normalization hide parent traversal or a symlink component.
    if '..' in path.parts:
        raise ValueError('Unsafe parent traversal in runtime inventory paths')
    return path.absolute()


def check_output(output: Path, runtime: Path) -> None:
    if output == runtime or runtime in output.parents:
        raise ValueError('The runtime inventory must be outside the runtime tree')
    for path in reversed((output, *output.parents)):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('Symlinks are not allowed in inventory output paths')
        if path == output:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('The inventory output must be a normal unlinked file')
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError('Inventory output parents must be normal directories')


def stamp(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def inventory(runtime: Path, output: Path) -> dict:
    runtime = safe_absolute(runtime)
    output = safe_absolute(output)
    check_output(output, runtime)
    files = {}
    normalized = set()
    # This owned build input must remain quiescent. Retained descriptors ensure
    # chmod never follows a replaced symlink; revalidate every binding and tree
    # entry before the first mutation, so malformed inputs cause no partial fix.
    with ExitStack() as stack:
        def open_entry(name, parent_fd, directory):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if directory:
                flags |= os.O_DIRECTORY
            try:
                fd = os.open(name, flags, dir_fd=parent_fd)
            except OSError as error:
                raise ValueError('Symlinks or unsafe runtime path types are not allowed') from error
            stack.callback(os.close, fd)
            return fd

        parent_fd = open_entry('/', None, True)
        bindings = []
        for component in runtime.parts[1:]:
            fd = open_entry(component, parent_fd, True)
            bindings.append((parent_fd, component, os.fstat(fd)))
            parent_fd = fd
        root_fd = parent_fd
        entries = [(root_fd, os.fstat(root_fd))]
        directories = []
        children = []

        def visit(directory_fd, relative):
            names = sorted(os.listdir(directory_fd))
            directories.append((directory_fd, names))
            for name in names:
                if (name in {'.', '..'} or any(char in name for char in '\\:')
                        or any(ord(char) < 32 for char in name) or name.endswith((' ', '.'))):
                    raise ValueError('Unsafe Python runtime path name')
                child = relative / name
                key = child.as_posix()
                if key.lower() in normalized:
                    raise ValueError('Case-insensitive Python runtime path collision')
                normalized.add(key.lower())
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    raise ValueError('Symlinks are not allowed in the Python runtime')
                directory = stat.S_ISDIR(info.st_mode)
                if not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                    raise ValueError('Special or hardlinked Python runtime entries are not allowed')
                fd = open_entry(name, directory_fd, directory)
                if stamp(info) != stamp(os.fstat(fd)):
                    raise ValueError('Python runtime entry changed during validation')
                children.append((directory_fd, name, info))
                entries.append((fd, info))
                if directory:
                    visit(fd, child)
                else:
                    digest = hashlib.sha256()
                    while data := os.read(fd, 1024 * 1024):
                        digest.update(data)
                    files[key] = {'sha256': digest.hexdigest()}

        visit(root_fd, Path())
        if 'python314.dll' not in files or not any(name.lower().startswith('vcruntime') for name in files):
            raise ValueError('The Python runtime DLL closure is incomplete')
        check_output(output, runtime)
        for parent_fd, name, info in bindings:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino, current.st_mode) != (info.st_dev, info.st_ino, info.st_mode):
                raise ValueError('Python runtime path changed during validation')
        for directory_fd, names in directories:
            if sorted(os.listdir(directory_fd)) != names:
                raise ValueError('Python runtime directory changed during validation')
        for parent_fd, name, info in children:
            if stamp(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != stamp(info):
                raise ValueError('Python runtime entry changed during validation')
        for fd, info in entries:
            if stamp(os.fstat(fd)) != stamp(info):
                raise ValueError('Python runtime entry changed during validation')
        for fd, info in entries:
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o022:
                os.fchmod(fd, mode & ~0o022)
    return {'schema_version': 1, 'files': files}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runtime', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = inventory(args.runtime, args.output)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
