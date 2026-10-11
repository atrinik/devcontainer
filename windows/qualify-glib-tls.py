#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
"""Build a focused library TLS native qualification bundle in an offline LLVM SDK.

This is diagnostic acceptance of one library, not qualification of a rebuilt SDK.
The SDK remains unchanged; all build outputs use a new caller-owned directory.
"""
import argparse
import importlib.util
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import subprocess

from pe_tls import LIBRARIES, inspect_file

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('producer', ROOT / 'build-dependencies.py')
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


def source_provenance(items, library):
    return {
        'source_inputs': {name: items[name]['sha256'] for name in (library, 'meson', 'mxe-recipes')},
        'recipe_sha256': hashlib.sha256(json.dumps(items[library], sort_keys=True).encode()).hexdigest(),
        'tools_sha256': {name: BUILDER.file_hash(ROOT / name) for name in
                         ('qualify-glib-tls.py', 'build-dependencies.py', 'pe_tls.py', library + '-tls-probe.c')},
    }


def validated_glib_dependency(bundle, items, llvm, prefix):
    """Admit a freshly sealed repair, never the SDK's known-bad transitive DLL."""
    if bundle is None or bundle.is_symlink() or not bundle.is_dir():
        raise ValueError('Cairo requires --glib-bundle from the repaired GLib qualification')
    manifest = bundle / 'qualification.json'
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError('missing normal GLib qualification manifest')
    metadata = json.loads(manifest.read_text())
    if (metadata.get('schema_version') != 1 or metadata.get('library') != 'glib'
            or metadata.get('source_sha256') != items['glib']['sha256']
            or metadata.get('provenance') != source_provenance(items, 'glib')):
        raise ValueError('GLib dependency source/provenance does not match this qualification')
    files = metadata.get('files', {})
    required = {'candidate/libglib-2.0-0.dll', 'candidate/atrinik-glib-tls-probe.exe',
                'build-evidence/glib-tls.json'}
    if not required.issubset(files):
        raise ValueError('GLib dependency bundle lacks sealed candidate evidence')
    for relative, digest in files.items():
        path = PurePosixPath(relative)
        if path.is_absolute() or '..' in path.parts or not path.parts or '\\' in relative:
            raise ValueError('unsafe GLib dependency evidence path')
        current = bundle
        for part in path.parts:
            current /= part
            if current.is_symlink():
                raise ValueError('linked GLib dependency evidence')
        if not current.is_file() or BUILDER.file_hash(current) != digest:
            raise ValueError('changed GLib dependency evidence: ' + relative)
    candidate = bundle / 'candidate/libglib-2.0-0.dll'
    tls = inspect_file(candidate, llvm, 'glib')
    if tls != metadata.get('tls') or tls != json.loads((bundle / 'build-evidence/glib-tls.json').read_text()):
        raise ValueError('GLib dependency TLS report does not match actual PE registration')
    # Its supporting runtime must also come from the same immutable SDK.
    for path in (bundle / 'candidate').glob('*.dll'):
        if path == candidate:
            continue
        relative = 'candidate/' + path.name
        sdk = prefix / 'bin' / path.name
        if relative not in files or not sdk.is_file() or BUILDER.file_hash(sdk) != files[relative]:
            raise ValueError('GLib dependency uses a different supporting SDK runtime')
    return candidate, {'sha256': tls['sha256'], 'source_sha256': metadata['source_sha256'],
                       'qualification_sha256': BUILDER.file_hash(manifest), 'tls': tls}


def run(args):
    os.umask(0o022)
    if args.work_dir.exists() or args.output.exists():
        raise ValueError('qualification requires absent work and output directories')
    library = args.library
    dll_name = LIBRARIES[library][0]
    probe_name = f'atrinik-{library}-tls-probe.exe'
    target = 'glib/libglib-2.0-0.dll' if library == 'glib' else 'src/libcairo-2.dll'
    lock = BUILDER.load_lock(ROOT / 'dependencies.json')
    items = {item['name']: item for item in lock['dependencies']}
    dependency = None
    if library == 'cairo':
        dependency = validated_glib_dependency(args.glib_bundle, items, args.llvm, args.prefix)
    elif args.glib_bundle is not None:
        raise ValueError('--glib-bundle is only valid for Cairo')
    inventory = args.prefix / 'share/atrinik/windows-dependencies'
    ownership = json.loads((inventory / 'runtime-ownership.json').read_text())
    BUILDER.assert_receipt(args.prefix, ownership)
    original = args.prefix / 'bin' / dll_name
    if ownership['dlls'][original.name]['source_sha256'] != items[library]['sha256']:
        raise ValueError('SDK library source does not match qualification source')
    args.work_dir.mkdir(parents=True)
    args.output.mkdir(parents=True)
    logs = args.output / 'build-evidence'
    logs.mkdir()
    sources = {}
    for name in (library, 'meson', 'mxe-recipes'):
        item = items[name]
        archive = args.source_archive if name == library and args.source_archive else inventory / item['archive']
        if BUILDER.file_hash(archive) != item['sha256']:
            raise ValueError(f'qualification source checksum mismatch: {name}')
        sources[name] = BUILDER.extract(archive, args.work_dir / 'sources' / name)
    source = sources[library]
    for patch in items[library]['patches']:
        content = (sources['mxe-recipes'] / patch['file']).read_bytes()
        if hashlib.sha256(content).hexdigest() != patch['sha256']:
            raise ValueError('library upstream recipe patch mismatch')
        for old, new in patch.get('replacements', {}).items():
            content = content.replace(old.encode(), new.encode())
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p1'], cwd=source, input=content, check=True)
    (args.work_dir / 'llvm-native.ini').write_text("[binaries]\nc = 'clang'\ncpp = 'clang++'\n")
    (args.work_dir / 'llvm-cross.ini').write_text(
        "[binaries]\nc = 'x86_64-w64-mingw32-clang'\ncpp = 'x86_64-w64-mingw32-clang++'\n"
        "ar = 'llvm-ar'\nstrip = 'llvm-strip'\nwindres = 'x86_64-w64-mingw32-windres'\n"
        "pkg-config = 'x86_64-w64-mingw32-pkg-config'\n[host_machine]\nsystem = 'windows'\n"
        "cpu_family = 'x86_64'\ncpu = 'x86_64'\nendian = 'little'\n[properties]\nneeds_exe_wrapper = true\n")
    env = BUILDER.environment(args.prefix, args.work_dir / 'host', args.llvm,
                              host_llvm=args.host_llvm, build_system='meson')
    # Preserve recipe warnings/features; only omit the new linker flag in the
    # deliberately failing diagnostic build.
    for key, value in items[library].get('environment', {}).items():
        if key != 'LDFLAGS':
            env[key] = value.replace('{prefix}', str(args.prefix))
    meson = ['python3', str(sources['meson'] / 'meson.py')]
    build = args.work_dir / 'build' / library
    build.parent.mkdir()
    commands = BUILDER.commands(items[library], source, build, args.prefix, 2, env=env)
    def command(name, argv):
        with (logs / (name + '.log')).open('w') as output:
            result = subprocess.run(argv, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=300)
        if result.returncode:
            print((logs / (name + '.log')).read_text()[-16000:], flush=True)
            result.check_returncode()
    command('setup', meson + commands[0][1:])
    command('baseline', ['ninja', '-C', str(build), '-j2', target])
    baseline = args.work_dir / 'baseline.dll'
    shutil.copy2(build / target, baseline)
    fixed_flags = items[library]['environment']['LDFLAGS'].replace('{prefix}', str(args.prefix)).split()
    if '-Wl,--require-defined,_tls_used' not in fixed_flags:
        raise ValueError('target library recipe lacks mandatory TLS directory reference')
    fixed_flags += ['-Wl,-Map,' + str(logs / (library + '-link.map'))]
    command('configure-fixed', meson + ['configure', str(build), '-Dc_link_args=' + json.dumps(fixed_flags),
                                        '-Dcpp_link_args=' + json.dumps(fixed_flags)])
    command('fixed', ['ninja', '-C', str(build), '-j2', '-v', target])
    fixed = build / target
    interfaces = {}
    for name, dll in (('baseline', baseline), ('fixed', fixed)):
        result = subprocess.run([str(args.llvm / 'bin/llvm-readobj'), '--coff-imports', '--coff-exports', str(dll)],
                                check=True, capture_output=True, text=True, timeout=30)
        (logs / (name + '-interfaces.txt')).write_text(result.stdout)
        interfaces[name] = re.findall(r'^  Name: (.+)$', result.stdout, re.MULTILINE)
    if interfaces['baseline'] != interfaces['fixed']:
        raise ValueError('library linker correction changed imported/exported interfaces')
    tls = inspect_file(fixed, args.llvm, library)
    (logs / (library + '-tls.json')).write_text(json.dumps(tls, indent=2) + '\n')
    # The map proves which CRT object supplied the previously absent directory.
    link_map = (logs / (library + '-link.map')).read_text()
    if '_tls_used' not in link_map or 'tlssup' not in link_map:
        raise ValueError('link map lacks CRT TLS directory contribution')
    for name, dll in (('original', original), ('relinked', baseline)):
        try:
            inspect_file(dll, args.llvm, library)
        except ValueError as error:
            if str(error) != 'missing or invalid PE TLS directory':
                raise
        else:
            raise ValueError(f'{name} no longer reproduces missing TLS directory')
    header = args.work_dir / (library + '-tls-rvas.h')
    header.write_text(f'#define TLS_CALLBACK_RVA {tls["callback_rva"]}u\n'
                      f'#define TLS_INITIALIZED_FLAG_RVA {tls["initialized_flag_rva"]}u\n'
                      f'#define TLS_INITIALIZED_VALUE {tls["initialized_value"]}u\n')
    compiler = str(args.llvm / 'bin/x86_64-w64-mingw32-clang')
    cflags = subprocess.run(['x86_64-w64-mingw32-pkg-config', '--cflags', 'glib-2.0' if library == 'glib' else 'cairo'],
                           env=env, check=True, text=True, capture_output=True).stdout.split()
    probe = args.work_dir / probe_name
    command('probe-build', [compiler, '-std=c17', '-O2', '-Wall', '-Wextra', '-Werror',
                           '-I' + str(args.work_dir), str(ROOT / (library + '-tls-probe.c')), *cflags, '-o', str(probe)])
    readobj = str(args.llvm / 'bin/llvm-readobj')
    def imports(path):
        return BUILDER.parse_imports(subprocess.run([readobj, '--coff-imports', str(path)],
                                                    check=True, capture_output=True, text=True).stdout)
    runtime = {p.name.lower(): p for p in (args.prefix / 'bin').glob('*.dll')}
    if dependency is not None:
        runtime['libglib-2.0-0.dll'] = dependency[0]
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
    if dependency is not None:
        # Recheck after the build/copy and inspect every staged instance. All
        # controls vary Cairo only; they share exactly the repaired GLib bytes.
        if validated_glib_dependency(args.glib_bundle, items, args.llvm, args.prefix) != dependency:
            raise ValueError('GLib dependency changed during Cairo qualification')
        for lane in ('original', 'relinked', 'candidate'):
            path = args.output / lane / 'libglib-2.0-0.dll'
            if not path.is_file() or inspect_file(path, args.llvm, 'glib') != dependency[1]['tls']:
                raise ValueError('Cairo lane lacks the identical repaired GLib dependency')
    shutil.copy2(ROOT / 'run-glib-tls-qualification.ps1', args.output)
    metadata = {'schema_version': 1, 'scope': 'focused library TLS diagnostic, not complete SDK qualification', 'library': library,
                'source_sha256': items[library]['sha256'], 'tls': tls,
                'provenance': source_provenance(items, library),
                'repaired_dependencies': {'glib': dependency[1]} if dependency is not None else {},
                'compiler': subprocess.run([compiler, '--version'], check=True, capture_output=True, text=True).stdout,
                'files': {p.relative_to(args.output).as_posix(): BUILDER.file_hash(p)
                          for p in sorted(args.output.rglob('*')) if p.is_file()}}
    (args.output / 'qualification.json').write_text(json.dumps(metadata, indent=2) + '\n')
    # No accepted SDK receipt is rewritten by this diagnostic rebuild.
    BUILDER.assert_receipt(args.prefix, ownership)
    print(json.dumps({'status': 'built', 'output': str(args.output), 'fixed_tls': tls}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', choices=LIBRARIES, default='glib')
    parser.add_argument('--prefix', type=Path, default=Path('/opt/atrinik-windows'))
    parser.add_argument('--llvm', type=Path, default=Path('/opt/llvm-mingw'))
    parser.add_argument('--host-llvm', type=Path, default=Path('/opt/llvm-23.1.3'))
    parser.add_argument('--glib-bundle', type=Path)
    parser.add_argument('--source-archive', type=Path)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args())
