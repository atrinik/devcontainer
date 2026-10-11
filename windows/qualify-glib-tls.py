#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
"""Build a focused GLib TLS native qualification bundle in an offline LLVM SDK.

This is diagnostic acceptance of GLib, not qualification of a rebuilt SDK.
The SDK remains unchanged; all build outputs use a new caller-owned directory.
"""
import argparse
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import subprocess

from pe_tls import inspect_glib_file

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('producer', ROOT / 'build-dependencies.py')
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


def run(args):
    os.umask(0o022)
    if args.work_dir.exists() or args.output.exists():
        raise ValueError('qualification requires absent work and output directories')
    lock = BUILDER.load_lock(ROOT / 'dependencies.json')
    items = {item['name']: item for item in lock['dependencies']}
    inventory = args.prefix / 'share/atrinik/windows-dependencies'
    ownership = json.loads((inventory / 'runtime-ownership.json').read_text())
    BUILDER.assert_receipt(args.prefix, ownership)
    original = args.prefix / 'bin/libglib-2.0-0.dll'
    if ownership['dlls'][original.name]['source_sha256'] != items['glib']['sha256']:
        raise ValueError('SDK GLib source does not match qualification source')
    args.work_dir.mkdir(parents=True)
    args.output.mkdir(parents=True)
    logs = args.output / 'build-evidence'
    logs.mkdir()
    sources = {}
    for name in ('glib', 'meson', 'mxe-recipes'):
        item = items[name]
        archive = args.source_archive if name == 'glib' and args.source_archive else inventory / item['archive']
        if BUILDER.file_hash(archive) != item['sha256']:
            raise ValueError(f'qualification source checksum mismatch: {name}')
        sources[name] = BUILDER.extract(archive, args.work_dir / 'sources' / name)
    source = sources['glib']
    for patch in items['glib']['patches']:
        content = (sources['mxe-recipes'] / patch['file']).read_bytes()
        import hashlib
        if hashlib.sha256(content).hexdigest() != patch['sha256']:
            raise ValueError('GLib upstream recipe patch mismatch')
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1'], cwd=source, input=content, check=True)
    (args.work_dir / 'llvm-native.ini').write_text("[binaries]\nc = 'clang'\ncpp = 'clang++'\n")
    (args.work_dir / 'llvm-cross.ini').write_text(
        "[binaries]\nc = 'x86_64-w64-mingw32-clang'\ncpp = 'x86_64-w64-mingw32-clang++'\n"
        "ar = 'llvm-ar'\nstrip = 'llvm-strip'\nwindres = 'x86_64-w64-mingw32-windres'\n"
        "pkg-config = 'x86_64-w64-mingw32-pkg-config'\n[host_machine]\nsystem = 'windows'\n"
        "cpu_family = 'x86_64'\ncpu = 'x86_64'\nendian = 'little'\n[properties]\nneeds_exe_wrapper = true\n")
    env = BUILDER.environment(args.prefix, args.work_dir / 'host', args.llvm,
                              host_llvm=args.host_llvm, build_system='meson')
    meson = ['python3', str(sources['meson'] / 'meson.py')]
    build = args.work_dir / 'build/glib'
    build.parent.mkdir()
    commands = BUILDER.commands(items['glib'], source, build, args.prefix, 2, env=env)
    def command(name, argv):
        with (logs / (name + '.log')).open('w') as output:
            result = subprocess.run(argv, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=300)
        if result.returncode:
            print((logs / (name + '.log')).read_text()[-16000:], flush=True)
            result.check_returncode()
    command('setup', meson + commands[0][1:])
    command('baseline', ['ninja', '-C', str(build), '-j2', 'glib/libglib-2.0-0.dll'])
    baseline = args.work_dir / 'baseline.dll'
    shutil.copy2(build / 'glib/libglib-2.0-0.dll', baseline)
    fixed_flags = items['glib']['environment']['LDFLAGS'].replace('{prefix}', str(args.prefix)).split()
    if '-Wl,--require-defined,_tls_used' not in fixed_flags:
        raise ValueError('target GLib recipe lacks mandatory TLS directory reference')
    fixed_flags += ['-Wl,-Map,' + str(logs / 'glib-link.map')]
    command('configure-fixed', meson + ['configure', str(build), '-Dc_link_args=' + json.dumps(fixed_flags),
                                        '-Dcpp_link_args=' + json.dumps(fixed_flags)])
    command('fixed', ['ninja', '-C', str(build), '-j2', '-v', 'glib/libglib-2.0-0.dll'])
    fixed = build / 'glib/libglib-2.0-0.dll'
    interfaces = {}
    for name, dll in (('baseline', baseline), ('fixed', fixed)):
        result = subprocess.run([str(args.llvm / 'bin/llvm-readobj'), '--coff-imports', '--coff-exports', str(dll)],
                                check=True, capture_output=True, text=True, timeout=30)
        (logs / (name + '-interfaces.txt')).write_text(result.stdout)
        interfaces[name] = re.findall(r'^  Name: (.+)$', result.stdout, re.MULTILINE)
    if interfaces['baseline'] != interfaces['fixed']:
        raise ValueError('GLib linker correction changed imported/exported interfaces')
    tls = inspect_glib_file(fixed, args.llvm)
    (logs / 'glib-tls.json').write_text(json.dumps(tls, indent=2) + '\n')
    # The map proves which CRT object supplied the previously absent directory.
    link_map = (logs / 'glib-link.map').read_text()
    if '_tls_used' not in link_map or 'tlssup' not in link_map:
        raise ValueError('link map lacks CRT TLS directory contribution')
    for name, dll in (('original', original), ('relinked', baseline)):
        try:
            inspect_glib_file(dll, args.llvm)
        except ValueError as error:
            if str(error) != 'missing or invalid PE TLS directory':
                raise
        else:
            raise ValueError(f'{name} no longer reproduces missing TLS directory')
    header = args.work_dir / 'glib-tls-rvas.h'
    header.write_text(f'#define GLIB_TLS_CALLBACK_RVA {tls["glib_callback_rva"]}u\n'
                      f'#define GLIB_TLS_INVOKED_FLAG_RVA {tls["glib_invoked_flag_rva"]}u\n')
    compiler = str(args.llvm / 'bin/x86_64-w64-mingw32-clang')
    cflags = subprocess.run(['x86_64-w64-mingw32-pkg-config', '--cflags', 'glib-2.0'],
                           env=env, check=True, text=True, capture_output=True).stdout.split()
    probe = args.work_dir / 'atrinik-glib-tls-probe.exe'
    command('probe-build', [compiler, '-std=c17', '-O2', '-Wall', '-Wextra', '-Werror',
                           '-I' + str(args.work_dir), str(ROOT / 'glib-tls-probe.c'), *cflags, '-o', str(probe)])
    readobj = str(args.llvm / 'bin/llvm-readobj')
    def imports(path):
        return BUILDER.parse_imports(subprocess.run([readobj, '--coff-imports', str(path)],
                                                    check=True, capture_output=True, text=True).stdout)
    runtime = {p.name.lower(): p for p in (args.prefix / 'bin').glob('*.dll')}
    for name, dll in (('candidate', fixed), ('original', original), ('relinked', baseline)):
        stage = args.output / name
        stage.mkdir()
        shutil.copy2(dll, stage / original.name)
        shutil.copy2(probe, stage / probe.name)
        pending = list(imports(dll) | imports(probe))
        copied = {original.name.lower()}
        while pending:
            needed = pending.pop()
            if needed in copied or needed in BUILDER.SYSTEM_DLLS or needed.startswith(('api-ms-win-', 'ext-ms-win-')):
                continue
            if needed not in runtime:
                raise ValueError(f'unresolved native probe import: {needed}')
            shutil.copy2(runtime[needed], stage / runtime[needed].name)
            copied.add(needed)
            pending.extend(imports(runtime[needed]))
    shutil.copy2(ROOT / 'run-glib-tls-qualification.ps1', args.output)
    metadata = {'schema_version': 1, 'scope': 'focused GLib TLS diagnostic, not complete SDK qualification',
                'glib_source_sha256': items['glib']['sha256'], 'tls': tls,
                'compiler': subprocess.run([compiler, '--version'], check=True, capture_output=True, text=True).stdout,
                'files': {p.relative_to(args.output).as_posix(): BUILDER.file_hash(p)
                          for p in sorted(args.output.rglob('*')) if p.is_file()}}
    (args.output / 'qualification.json').write_text(json.dumps(metadata, indent=2) + '\n')
    # No accepted SDK receipt is rewritten by this diagnostic rebuild.
    BUILDER.assert_receipt(args.prefix, ownership)
    print(json.dumps({'status': 'built', 'output': str(args.output), 'fixed_tls': tls}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, default=Path('/opt/atrinik-windows'))
    parser.add_argument('--llvm', type=Path, default=Path('/opt/llvm-mingw'))
    parser.add_argument('--host-llvm', type=Path, default=Path('/opt/llvm-23.1.3'))
    parser.add_argument('--source-archive', type=Path)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args())
