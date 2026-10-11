#!/usr/bin/env python3
"""Generate the Python import definition using LLVM PE exports, preserving DATA."""
# Copyright 2026 The Atrinik Project.
from __future__ import annotations
import argparse
from pathlib import Path
import re
import subprocess


def definition(exports: str, sections: str, dll: str) -> str:
    """Classify named exports by their RVA's executable section; reject ambiguity."""
    if 'Format: COFF-x86-64' not in exports:
        raise ValueError('Python runtime must be an x86_64 COFF DLL')
    ranges = []
    for block in re.findall(r'Section \{(.*?)\n\s*\}', sections, re.S):
        base = re.search(r'VirtualAddress: (0x[0-9A-Fa-f]+)', block)
        size = re.search(r'VirtualSize: (0x[0-9A-Fa-f]+)', block)
        if base and size:
            ranges.append((int(base[1], 16), int(base[1], 16) + int(size[1], 16), 'IMAGE_SCN_MEM_EXECUTE' in block))
    names = {}
    for block in re.findall(r'Export \{(.*?)\n\s*\}', exports, re.S):
        name = re.search(r'^\s*Name: (\S+)\s*$', block, re.M)
        rva = re.search(r'RVA: (0x[0-9A-Fa-f]+)', block)
        if not name:
            continue
        if not rva or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name[1]):
            raise ValueError('Unsupported Python export')
        matches = [execute for start, end, execute in ranges if start <= int(rva[1], 16) < end]
        if len(matches) != 1 or name[1] in names:
            raise ValueError('Unresolved or duplicate Python export: ' + name[1])
        names[name[1]] = '' if matches[0] else ' DATA'
    if not names or 'Py_Initialize' not in names or 'PyExc_RuntimeError' not in names:
        raise ValueError('Python API exports are missing')
    return 'LIBRARY ' + dll + '\nEXPORTS\n' + ''.join('  ' + name + names[name] + '\n' for name in sorted(names))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dll', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--readobj', default='llvm-readobj')
    args = parser.parse_args()
    exports = subprocess.check_output([args.readobj, '--coff-exports', str(args.dll)], text=True)
    sections = subprocess.check_output([args.readobj, '--sections', str(args.dll)], text=True)
    args.output.write_text(definition(exports, sections, args.dll.name), encoding='utf-8')


if __name__ == '__main__':
    main()
