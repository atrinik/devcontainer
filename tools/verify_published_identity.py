#!/usr/bin/python3 -I
# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Bind Linux publisher runtime-tested image IDs to actual pushed OCI metadata.

No registry layers are downloaded and no image code is executed here. Only the
same-repository hosted publisher may capture the local daemon or acquire metadata.
The historical released-SDK collector's target/revision/admission stays unchanged.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import sys
import urllib.parse

_SPEC = importlib.util.spec_from_file_location(
    'registry_transport', Path(__file__).with_name('collect-released-sdk-metadata.py'))
R = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(R)
require = R.require
Stop = R.Stop
TARGETS = {
    'broad': ('atrinik/linux-build', 'atrinik-linux-curl:qualification'),
    'classic': ('atrinik/classic-build', 'atrinik-classic-curl:qualification'),
    'portable': ('atrinik/classic-portable-build', 'atrinik-classic-portable:release-validation'),
}
WORKFLOW = '.github/workflows/publish-linux.yml'
# Docker API 1.49–1.51 may materialize these absent fields. Never equate empty
# arrays/objects with null, nor normalize non-default values or unknown keys.
DEFAULTS = {'Cmd': None, 'Entrypoint': None, 'Env': None, 'Labels': None,
            'OnBuild': None, 'Volumes': None, 'User': '', 'WorkingDir': ''}
CONFIG_KEYS = {'architecture', 'os', 'variant', 'os.version', 'os.features',
               'config', 'rootfs', 'author', 'created', 'history', 'moby.buildkit.cache.v0'}
STRING_FIELDS = {'Hostname', 'Domainname', 'User', 'Image', 'WorkingDir', 'MacAddress', 'StopSignal'}
BOOL_FIELDS = {'AttachStdin', 'AttachStdout', 'AttachStderr', 'Tty', 'OpenStdin', 'StdinOnce',
               'ArgsEscaped', 'NetworkDisabled'}
ARRAY_FIELDS = {'Env', 'Cmd', 'Entrypoint', 'OnBuild', 'Shell'}
MAP_FIELDS = {'Labels', 'Volumes', 'ExposedPorts'}
RUNTIME_FIELDS = STRING_FIELDS | BOOL_FIELDS | ARRAY_FIELDS | MAP_FIELDS | {'Healthcheck', 'StopTimeout'}
PUBLICATION_LABELS = {'org.opencontainers.image.source', 'org.opencontainers.image.revision'}


def decode(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= R.LIMIT, 'invalid-json-size')
    value = R.decode(raw)
    # Reject non-finite numbers accepted by Python's default parser; JSON from
    # Docker/OCI cannot contain these. This also bounds hostile deep documents.
    try:
        json.dumps(value, allow_nan=False)
    except (ValueError, RecursionError):
        raise Stop('invalid-json-value') from None
    return value


def context(env):
    require(env.get('GITHUB_ACTIONS') == 'true' and
            env.get('RUNNER_ENVIRONMENT') == 'github-hosted' and sys.platform == 'linux',
            'hosted-runner-required')
    require(env.get('GITHUB_REPOSITORY') == R.REPOSITORY, 'repository-not-allowed')
    ref, event = env.get('GITHUB_REF', ''), env.get('GITHUB_EVENT_NAME')
    candidate = env.get('CANDIDATE_ONLY') == 'true'
    release = re.fullmatch(r'refs/tags/v[0-9]+\.[0-9]+\.[0-9]+', ref) is not None
    require((event == 'push' and release and not candidate) or
            (event == 'workflow_dispatch' and
             (release or (ref == 'refs/heads/main') or
              (candidate and re.fullmatch(r'refs/heads/[A-Za-z0-9._/-]+', ref)))),
            'untrusted-workflow-event')
    require(env.get('GITHUB_WORKFLOW_REF') == R.REPOSITORY + '/' + WORKFLOW + '@' + ref,
            'workflow-identity-mismatch')
    head, actor = env.get('GITHUB_SHA', ''), env.get('GITHUB_ACTOR', '')
    require(re.fullmatch(r'[0-9a-f]{40}', head) is not None, 'invalid-workflow-head')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?', actor) is not None,
            'invalid-workflow-actor')
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        require(re.fullmatch(r'[1-9][0-9]{0,19}', env.get(key, '')) is not None, 'invalid-workflow-run')
    require(not any(env.get(key) for key in ('OPENSSL_CONF', 'OPENSSL_MODULES', 'SSLKEYLOGFILE')),
            'tls-override-not-allowed')
    return {'repository': R.REPOSITORY, 'workflow': WORKFLOW, 'ref': ref, 'event': event,
            'head': head, 'actor': actor, 'candidate_only': candidate,
            'run_id': env['GITHUB_RUN_ID'], 'run_attempt': env['GITHUB_RUN_ATTEMPT']}


def loaded_identity(local):
    require(isinstance(local, dict) and R.valid_digest(local.get('Id')), 'invalid-loaded-image')
    require(local.get('Os') == 'linux' and local.get('Architecture') == 'amd64' and
            local.get('Variant', '') == '' and not local.get('OsVersion') and
            not local.get('OsFeatures'), 'loaded-platform-mismatch')
    rootfs = local.get('RootFS')
    require(isinstance(rootfs, dict) and set(rootfs) == {'Type', 'Layers'} and
            rootfs['Type'] == 'layers' and isinstance(rootfs['Layers'], list) and rootfs['Layers'] and
            all(R.valid_digest(item) for item in rootfs['Layers']), 'invalid-loaded-rootfs')
    validate_runtime(local.get('Config'))
    return local['Id']


def validate_runtime(config):
    require(isinstance(config, dict) and set(config) <= RUNTIME_FIELDS, 'unknown-runtime-config-field')
    for key, value in config.items():
        if key in STRING_FIELDS:
            require(isinstance(value, str), 'invalid-runtime-string')
        elif key in BOOL_FIELDS:
            require(type(value) is bool, 'invalid-runtime-boolean')
        elif key in ARRAY_FIELDS:
            require(value is None or (isinstance(value, list) and
                    all(isinstance(item, str) for item in value)), 'invalid-runtime-array')
        elif key in MAP_FIELDS:
            require(value is None or isinstance(value, dict), 'invalid-runtime-map')
            for item in (value or {}).values():
                require(isinstance(item, str) if key == 'Labels' else item == {}, 'invalid-runtime-map-value')
        elif key == 'StopTimeout':
            require(type(value) is int and value >= 0, 'invalid-runtime-timeout')
        elif key == 'Healthcheck':
            require(value is None or (isinstance(value, dict) and set(value) <= {
                'Test', 'Interval', 'Timeout', 'StartPeriod', 'StartInterval', 'Retries'}),
                'invalid-healthcheck')
            for field, item in (value or {}).items():
                require((isinstance(item, list) and all(isinstance(part, str) for part in item))
                        if field == 'Test' else (type(item) is int and item >= 0), 'invalid-healthcheck-value')


def same_json(left, right):
    # Python compares True == 1; use JSON equality to retain scalar types.
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def compare(local, config, revision):
    loaded_identity(local)
    require(isinstance(config, dict) and set(config) <= CONFIG_KEYS, 'unknown-image-config-field')
    require(config.get('os') == 'linux' and config.get('architecture') == 'amd64' and
            config.get('variant', '') == '' and 'os.version' not in config and
            'os.features' not in config, 'published-platform-mismatch')
    require(config.get('author', '') == local.get('Author', ''), 'image-author-mismatch')
    rootfs = config.get('rootfs')
    require(isinstance(rootfs, dict) and set(rootfs) == {'type', 'diff_ids'} and
            rootfs['type'] == 'layers' and rootfs['diff_ids'] == local['RootFS']['Layers'],
            'published-rootfs-mismatch')
    expected, actual = dict(local['Config']), config.get('config')
    validate_runtime(actual)
    actual = dict(actual)
    labels = actual.get('Labels')
    require(isinstance(labels, dict) and
            labels.get('org.opencontainers.image.source') == R.SOURCE and
            labels.get('org.opencontainers.image.revision') == revision, 'producer-label-mismatch')
    for cfg in (expected, actual):
        labels = cfg.get('Labels')
        require(labels is None or (isinstance(labels, dict) and
                all(isinstance(k, str) and isinstance(v, str) for k, v in labels.items())),
                'invalid-runtime-labels')
        # Only these exact, validated publication labels may differ.
        cfg['Labels'] = {k: v for k, v in (labels or {}).items() if k not in PUBLICATION_LABELS}
        for key, default in DEFAULTS.items():
            cfg.setdefault(key, default)
    require(same_json(expected, actual), 'published-runtime-config-mismatch')
    return {'loaded_image_id': local['Id'], 'rootfs_equal': True, 'execution_config_equal': True,
            'publication_exceptions': ['config.Labels.org.opencontainers.image.source',
                'config.Labels.org.opencontainers.image.revision', 'created', 'history',
                'moby.buildkit.cache.v0'], 'docker_absent_defaults': DEFAULTS}


def registry(package, index_digest, bearer):
    # Reuse only bounded HTTPS/auth/digest primitives, never the historical
    # collector's revision gate, pulls, containers, files, or acceptance claims.
    index_raw = R.registry_object(package, 'manifests', index_digest, bearer)
    index = decode(index_raw)
    require(isinstance(index, dict) and type(index.get('schemaVersion')) is int and
            index['schemaVersion'] == 2 and index.get('mediaType') == R.INDEX and
            isinstance(index.get('manifests'), list), 'invalid-oci-index')
    candidates = []
    for item in index['manifests']:
        R.descriptor(item, {R.MANIFEST})
        platform, annotations = item.get('platform'), item.get('annotations', {})
        require(isinstance(platform, dict) and isinstance(annotations, dict), 'invalid-index-platform')
        if platform.get('os') == 'linux' and platform.get('architecture') == 'amd64':
            require(platform == {'os': 'linux', 'architecture': 'amd64'} and
                    annotations.get('vnd.docker.reference.type') != 'attestation-manifest',
                    'unexpected-platform-metadata')
            candidates.append(item)
        else:
            require(platform == {'os': 'unknown', 'architecture': 'unknown'} and
                    annotations.get('vnd.docker.reference.type') == 'attestation-manifest',
                    'unexpected-index-platform')
    require(len(candidates) == 1, 'ambiguous-linux-amd64-manifest')
    selected = candidates[0]
    for item in index['manifests']:
        if item is not selected:
            require(item['annotations'].get('vnd.docker.reference.digest') == selected['digest'],
                    'attestation-subject-mismatch')
    manifest_raw = R.registry_object(package, 'manifests', selected['digest'], bearer)
    require(len(manifest_raw) == selected['size'], 'manifest-size-mismatch')
    manifest = decode(manifest_raw)
    require(isinstance(manifest, dict) and type(manifest.get('schemaVersion')) is int and
            manifest['schemaVersion'] == 2 and manifest.get('mediaType') == R.MANIFEST and
            not manifest.get('artifactType') and not manifest.get('subject'), 'invalid-image-manifest')
    desc = R.descriptor(manifest.get('config'), {R.CONFIG})
    require(desc['size'] <= R.LIMIT and isinstance(manifest.get('layers'), list) and
            manifest['layers'], 'invalid-image-layers')
    for layer in manifest['layers']:
        R.descriptor(layer, R.LAYERS)
    config_raw = R.registry_object(package, 'blobs', desc['digest'], bearer)
    require(len(config_raw) == desc['size'], 'config-size-mismatch')
    config = decode(config_raw)
    require(isinstance(config, dict) and isinstance(config.get('rootfs'), dict) and
            isinstance(config['rootfs'].get('diff_ids'), list) and
            len(config['rootfs']['diff_ids']) == len(manifest['layers']), 'layer-count-mismatch')
    return {'index.json': index_raw, 'manifest.json': manifest_raw, 'config.json': config_raw}, {
        'package': package, 'index_digest': index_digest, 'manifest_digest': selected['digest'],
        'config_digest': desc['digest'], 'platform': 'linux/amd64',
        'manifest_descriptor': selected, 'config_descriptor': desc}, config


def safe_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            info.st_mode & 0o077 == 0, 'unsafe-evidence-directory')


def directory(ctx, target, create):
    runner_temp = Path(os.environ['RUNNER_TEMP'])
    require(runner_temp.is_absolute() and runner_temp.resolve() == runner_temp, 'unsafe-runner-temp')
    info = runner_temp.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            not info.st_mode & 0o022, 'unsafe-runner-temp')
    root = runner_temp / 'linux-published-identity'
    if create:
        root.mkdir(mode=0o700, exist_ok=True)
    safe_directory(root)
    run = root / (ctx['run_id'] + '-' + ctx['run_attempt'])
    if create:
        run.mkdir(mode=0o700, exist_ok=True)
    safe_directory(run)
    folder = run / target
    if create:
        folder.mkdir(mode=0o700)
    safe_directory(folder)
    return folder


def save(folder, name, raw):
    require('/' not in name and name not in ('', '.', '..') and len(raw) <= R.LIMIT,
            'invalid-evidence-file')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(folder / name, flags, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)
    return {'file': name, 'digest': R.digest(raw), 'size': len(raw)}


def read(folder, name):
    require('/' not in name and name not in ('', '.', '..'), 'invalid-evidence-file')
    fd = os.open(folder / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                info.st_mode & 0o077 == 0 and 0 < info.st_size <= R.LIMIT, 'unsafe-evidence-file')
        raw = source.read(R.LIMIT + 1)
        require(len(raw) == info.st_size, 'evidence-file-changed')
    return raw


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def capture(ctx, target, folder):
    docker = R.runner_docker()
    daemon = docker.negotiate()
    query = urllib.parse.urlencode({'platform': '{"os":"linux","architecture":"amd64"}'})
    path = '/images/' + urllib.parse.quote(TARGETS[target][1], safe='') + '/json?' + query
    conn, response = docker.request('GET', path)
    try:
        raw = R.bounded_read(response)
    finally:
        conn.close()
    local = decode(raw)
    image_id = loaded_identity(local)
    artifact = save(folder, 'loaded-inspect.json', raw)
    save(folder, 'capture.json', encoded({'context': ctx, 'target': target, **daemon,
        'image_id': image_id, 'inspection': artifact}))
    # GitHub owns this output path; it may be readable but never writable by
    # other users. Only append the validated digest to the existing regular file.
    output_path = Path(os.environ['GITHUB_OUTPUT'])
    require(output_path.is_absolute() and output_path.resolve() == output_path,
            'unsafe-github-output')
    fd = os.open(output_path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        info = os.fstat(output.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                info.st_nlink == 1 and not info.st_mode & 0o022, 'unsafe-github-output')
        output.write('image_id=' + image_id + '\n')


def verify(ctx, target, folder, index_digest, original):
    require(R.valid_digest(index_digest), 'invalid-published-digest')
    require(0 < len(original) < 16384 and all(32 < ord(c) < 127 for c in original),
            'workflow-token-unavailable')
    raw = read(folder, 'loaded-inspect.json')
    captured = decode(read(folder, 'capture.json'))
    require(isinstance(captured, dict) and captured.get('context') == ctx and
            captured.get('target') == target and captured.get('inspection') == {
                'file': 'loaded-inspect.json', 'digest': R.digest(raw), 'size': len(raw)},
            'capture-context-mismatch')
    local = decode(raw)
    require(captured.get('image_id') == loaded_identity(local), 'capture-image-mismatch')
    package = TARGETS[target][0]
    bearer = R.scoped_bearer(package, original, ctx['actor'])
    blobs, relation, config = registry(package, index_digest, bearer)
    artifacts = [save(folder, name, content) for name, content in blobs.items()]
    result = compare(local, config, ctx['head'])
    report = {'schema_version': 1, 'context': ctx, 'target': target,
              'status': 'verified-published-identity', **relation, **result,
              'artifacts': [captured['inspection'], *artifacts],
              'verifier_digest': R.digest(Path(__file__).read_bytes())}
    raw_report = encoded(report)
    save(folder, 'report.json', raw_report)
    save(folder, 'report.sha256', (R.digest(raw_report).removeprefix('sha256:') + '  report.json\n').encode())
    print(json.dumps({'target': target, 'status': report['status'], 'report_digest': R.digest(raw_report)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('capture', 'verify'))
    parser.add_argument('--target', required=True, choices=tuple(TARGETS))
    parser.add_argument('--digest')
    args = parser.parse_args()
    original = os.environ.pop('GHCR_TOKEN', '')
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
        signal.alarm(300)
        ctx = context(os.environ)
        R.verify_checkout(ctx)
        folder = directory(ctx, args.target, args.operation == 'capture')
        if args.operation == 'capture':
            require(args.digest is None, 'unexpected-capture-digest')
            capture(ctx, args.target, folder)
        else:
            verify(ctx, args.target, folder, args.digest, original)
        return 0
    except BaseException:
        # No raw daemon/registry/auth/error bodies or signed redirect URLs in logs.
        print('{"status":"stopped","reason":"published-identity-fence-failed"}')
        return 1
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    sys.exit(main())
