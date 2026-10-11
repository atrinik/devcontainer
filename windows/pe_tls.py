#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
"""Inspect the actual AMD64 PE TLS callback table; never execute the DLL."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


class PE:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) > 256 * 1024 * 1024 or self.bytes(0, 2) != b'MZ':
            raise ValueError('expected bounded PE image')
        pe = self.unpack('<I', 0x3c)[0]
        if self.bytes(pe, 4) != b'PE\0\0' or self.unpack('<H', pe + 4)[0] != 0x8664:
            raise ValueError('expected AMD64 PE image')
        count = self.unpack('<H', pe + 6)[0]
        opt_size = self.unpack('<H', pe + 20)[0]
        opt = pe + 24
        if not 1 <= count <= 96 or opt_size < 192 or self.unpack('<H', opt)[0] != 0x20b:
            raise ValueError('invalid PE32+ headers')
        self.bytes(opt, opt_size)
        self.base = self.unpack('<Q', opt + 24)[0]
        self.image_size = self.unpack('<I', opt + 56)[0]
        if self.unpack('<I', opt + 108)[0] < 10:
            raise ValueError('missing TLS data directory')
        self.tls_rva, self.tls_size = self.unpack('<II', opt + 112 + 9 * 8)
        self.sections = []
        for index in range(count):
            section = opt + opt_size + index * 40
            virtual_size, rva, raw_size, raw = self.unpack('<IIII', section + 8)
            flags = self.unpack('<I', section + 36)[0]
            extent = max(virtual_size, raw_size)
            if rva + extent > self.image_size:
                raise ValueError('section outside image')
            self.bytes(raw, raw_size)
            for previous in self.sections:
                if rva < previous[0] + previous[1] and previous[0] < rva + extent:
                    raise ValueError('overlapping PE sections')
            self.sections.append((rva, extent, raw, raw_size, flags))

    def bytes(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError('truncated PE data')
        return self.data[offset:offset + size]

    def unpack(self, fmt: str, offset: int):
        return struct.unpack(fmt, self.bytes(offset, struct.calcsize(fmt)))

    def section(self, rva: int, size: int = 1):
        for entry in self.sections:
            if entry[0] <= rva and rva + size <= entry[0] + entry[1]:
                return entry
        raise ValueError('RVA outside PE sections')

    def at_rva(self, rva: int, size: int) -> bytes:
        start, _, raw, raw_size, _ = self.section(rva, size)
        if rva - start + size > raw_size:
            raise ValueError('TLS structure is not backed by file data')
        return self.bytes(raw + rva - start, size)

    def callbacks(self) -> list[int]:
        if not self.tls_rva or self.tls_size != 40:
            raise ValueError('missing or invalid PE TLS directory')
        _, _, index, callbacks, _, _ = struct.unpack('<QQQQII', self.at_rva(self.tls_rva, 40))
        if not self.section(index - self.base, 4)[4] & 0x80000000:
            raise ValueError('TLS index is not writable')
        result = []
        for offset in range(256):
            address, = struct.unpack('<Q', self.at_rva(callbacks - self.base + offset * 8, 8))
            if not address:
                if not result:
                    raise ValueError('empty PE TLS callback table')
                return result
            rva = address - self.base
            if not self.section(rva)[4] & 0x20000000:
                raise ValueError('TLS callback is not executable')
            if rva in result:
                raise ValueError('duplicate TLS callback')
            result.append(rva)
        raise ValueError('unterminated PE TLS callback table')


def inspect_glib(data: bytes, symbols: str) -> dict:
    pe = PE(data)
    callbacks = pe.callbacks()
    wanted = {'glib_priv_tls_callback', 'tls_callback_invoked', '_tls_used', '_ptr_glib_priv_tls_callback'}
    found = {}
    for line in symbols.splitlines():
        fields = line.split()
        if fields and fields[0] in wanted:
            if len(fields) < 3 or fields[0] in found:
                raise ValueError('invalid or duplicate GLib TLS symbol')
            found[fields[0]] = int(fields[2], 16) - pe.base
    if set(found) != wanted:
        raise ValueError('missing GLib TLS callback/flag symbols')
    if found['_tls_used'] != pe.tls_rva:
        raise ValueError('TLS directory does not identify _tls_used')
    callback = found['glib_priv_tls_callback']
    flag = found['tls_callback_invoked']
    pointer, = struct.unpack('<Q', pe.at_rva(found['_ptr_glib_priv_tls_callback'], 8))
    if pointer != pe.base + callback:
        raise ValueError('GLib declared callback pointer differs from its function')
    if callback not in callbacks:
        raise ValueError('GLib TLS callback is not registered')
    # GLib 2.89.3 sets this private gboolean only in DLL_PROCESS_ATTACH.
    if not pe.section(flag, 4)[4] & 0x80000000:
        raise ValueError('GLib TLS callback flag is not writable')
    return {'schema_version': 1, 'dll': 'libglib-2.0-0.dll',
            'sha256': hashlib.sha256(data).hexdigest(),
            'tls_directory_rva': pe.tls_rva, 'callback_rvas': callbacks,
            'glib_callback_rva': callback, 'glib_invoked_flag_rva': flag}


def inspect_glib_file(path: Path, llvm: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024 * 1024:
        raise ValueError('GLib DLL must be a bounded normal file')
    data = path.read_bytes()
    symbols = subprocess.run([str(llvm / 'bin/llvm-nm'), '--defined-only', '--format=posix', str(path)],
                             check=True, capture_output=True, text=True, timeout=30).stdout
    report = inspect_glib(data, symbols)
    if path.read_bytes() != data:
        raise ValueError('GLib DLL changed during TLS inspection')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dll', required=True, type=Path)
    parser.add_argument('--llvm', default=Path('/opt/llvm-mingw'), type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--header', type=Path)
    parser.add_argument('--probe', type=Path)
    args = parser.parse_args()
    report = inspect_glib_file(args.dll, args.llvm)
    if args.probe:
        if args.probe.is_symlink() or not args.probe.is_file() or args.probe.stat().st_size > 16 * 1024 * 1024:
            raise ValueError('native probe must be a bounded normal file')
        report['probe_sha256'] = hashlib.sha256(args.probe.read_bytes()).hexdigest()
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    if args.header:
        args.header.write_text('/* Generated from the inspected GLib DLL. */\n'
                              f'#define GLIB_TLS_CALLBACK_RVA {report["glib_callback_rva"]}u\n'
                              f'#define GLIB_TLS_INVOKED_FLAG_RVA {report["glib_invoked_flag_rva"]}u\n')


if __name__ == '__main__':
    main()
