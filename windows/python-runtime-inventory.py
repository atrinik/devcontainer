#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
"""Seal every file from the verified external Python runtime archive."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path


def inventory(runtime: Path, output: Path) -> dict:
    runtime = runtime.resolve(strict=True)
    if runtime == output.resolve().parent or runtime in output.resolve().parents:
        raise ValueError('The runtime inventory must be outside the runtime tree')
    files = {}
    normalized = set()
    for path in sorted(runtime.rglob('*')):
        if path.is_symlink():
            raise ValueError('Symlinks are not allowed in the Python runtime')
        if not path.is_file():
            continue
        relative = path.relative_to(runtime).as_posix()
        if relative.lower() in normalized:
            raise ValueError('Case-insensitive Python runtime path collision')
        normalized.add(relative.lower())
        files[relative] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    if 'python314.dll' not in files or not any(name.lower().startswith('vcruntime') for name in files):
        raise ValueError('The Python runtime DLL closure is incomplete')
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
