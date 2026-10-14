# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Offline scanner failure transport and secret-free receipt regressions."""
import ast
import contextlib
import errno
import importlib.util
import io
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('scanner_diagnostic_fixtures',
    ROOT / 'tools/tests/test_released_sdk_filesystem.py')
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
C, S, I = F.C, F.S, F.I
SECRET = 'PRIVATE_TOKEN https://private.invalid/?signature=PRIVATE_SIGNATURE'


def frame(value, stream=1):
    raw = json.dumps(value).encode()
    return bytes((stream, 0, 0, 0)) + struct.pack('>I', len(raw)) + raw


class ScannerDiagnosticTests(unittest.TestCase):
    def test_scanner_code_allowlist_covers_literal_failures(self):
        codes = set()
        for node in ast.walk(ast.parse((ROOT / 'tools/scan-released-sdk-filesystem.py').read_text())):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 'I'
                    and node.func.attr in ('require', 'InventoryError')):
                code = node.args[1 if node.func.attr == 'require' else 0]
                self.assertIsInstance(code, ast.Constant)
                codes.add(code.value)
        self.assertEqual(codes, I.SCANNER_FAILURE_CODES)

    def test_scanner_main_emits_only_fixed_stage_code_and_errno(self):
        for error, reason, extra in (
            (I.InventoryError('scanner-path-drift'), 'scanner-path-drift', {}),
            (I.InventoryError('inventory-provider-bytes-mismatch'), 'inventory-provider-bytes-mismatch', {}),
            (PermissionError(errno.EACCES, SECRET, SECRET), 'scanner-os-error', {'errno_name': 'EACCES'}),
            (OSError(987654321, SECRET, SECRET), 'scanner-os-error', {'errno_name': 'other'}),
            (I.InventoryError(SECRET), 'filesystem-scan-failed', {}),
            (RuntimeError(SECRET), 'filesystem-scan-failed', {}),
        ):
            def fail(_fd, *, progress):
                progress['stage'] = 'producer-tree'
                raise error
            out = io.StringIO()
            with self.subTest(reason=reason), patch.object(S.sys, 'argv', ['scanner']), \
                    patch.object(S.sys, 'flags', SimpleNamespace(isolated=1)), \
                    patch.object(S.os, 'geteuid', return_value=65534), \
                    patch.object(S.os, 'open', return_value=55), patch.object(S.os, 'close') as close, \
                    patch.object(S.signal, 'signal'), patch.object(S.signal, 'alarm'), \
                    patch.object(S, 'scan', side_effect=fail), contextlib.redirect_stdout(out):
                self.assertEqual(S.main(), 1)
            close.assert_called_once_with(55)
            self.assertEqual(json.loads(out.getvalue()), {
                'status': 'stopped', 'reason': reason, 'stage': 'producer-tree', **extra})
            self.assertNotIn(SECRET, out.getvalue())

    def test_scanner_main_rejects_execution_boundary_before_open(self):
        for isolated, uid, argv in ((0, 65534, ['scanner']),
                                    (1, 0, ['scanner']),
                                    (1, 65534, ['scanner', SECRET])):
            out = io.StringIO()
            with self.subTest(isolated=isolated, uid=uid, argv_count=len(argv)), \
                    patch.object(S.sys, 'argv', argv), \
                    patch.object(S.sys, 'flags', SimpleNamespace(isolated=isolated)), \
                    patch.object(S.os, 'geteuid', return_value=uid), \
                    patch.object(S.os, 'open') as open_root, \
                    patch.object(S, 'scan') as scan, \
                    patch.object(S.signal, 'alarm'), contextlib.redirect_stdout(out):
                self.assertEqual(S.main(), 1)
            open_root.assert_not_called()
            scan.assert_not_called()
            self.assertEqual(json.loads(out.getvalue()), {
                'status': 'stopped', 'reason': 'scanner-execution-boundary',
                'stage': 'startup'})
            self.assertNotIn(SECRET, out.getvalue())

    def test_real_scan_retains_failed_stage(self):
        fixture = F.FilesystemTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.fixture()
        progress = {}
        with patch.object(S.Filesystem, 'tree', side_effect=I.InventoryError('scanner-tree-drift')):
            with self.assertRaisesRegex(I.InventoryError, 'scanner-tree-drift'):
                S.scan(fixture.root_fd, progress=progress)
        self.assertEqual(progress, {'stage': 'producer-tree'})

    def test_untrusted_failure_report_requires_exact_allowlisted_shape(self):
        good = {'status': 'stopped', 'reason': 'scanner-path-drift', 'stage': 'final-fence'}
        self.assertEqual(I.scanner_failure(good), good)
        for value in (None, [], SECRET, {}, {**good, 'extra': SECRET}, {**good, 'reason': SECRET},
                      {**good, 'stage': SECRET}, {**good, 'status': 'success'},
                      {**good, 'errno_name': 'EACCES'}, {**good, 'reason': 'scanner-os-error'},
                      {**good, 'reason': 'scanner-os-error', 'errno_name': SECRET}):
            with self.subTest(value=value):
                self.assertIsNone(I.scanner_failure(value))

    def qualification(self, payload, *, status=1, stream=1, drift=False, raw=None):
        fixture = F.QualificationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        scanner, state = fixture.scanner()
        scanner.create, scanner.cleanup = Mock(), Mock()
        connections = []
        def request(method, route, **kwargs):
            conn = Mock()
            connections.append(conn)
            if route.endswith('/start'):
                return conn, F.Response()
            if '/wait?' in route:
                state['State'] = {'Status': 'exited', 'Running': False, 'Pid': 0}
                if drift:
                    state['Config']['User'] = '0'
                return conn, F.Response(F.encoded({'StatusCode': status}))
            if '/logs?' in route:
                return conn, F.Response(raw if raw is not None else frame(payload, stream))
            self.fail('unexpected request')
        scanner.docker.request.side_effect = request
        with patch.object(C, 'ScannerImage', return_value=scanner):
            receipt = C.qualify_filesystem(scanner.docker, F.TARGET, fixture.context,
                                           fixture.verified, {'expected': 'inventory'})
        scanner.cleanup.assert_called_once()
        for conn in connections:
            conn.close.assert_called_once()
        self.assertTrue(receipt['owned_container_removed'])
        self.assertEqual(receipt['status'], 'stopped')
        self.assertNotIn('scan', receipt)
        self.assertNotIn(SECRET, json.dumps(receipt))
        return receipt, scanner

    def test_nonzero_process_retains_sanitized_failure_and_cleans_owned_container(self):
        failure = {'status': 'stopped', 'reason': 'scanner-provider-owner',
                   'stage': 'source-archives-and-providers'}
        receipt, scanner = self.qualification(failure)
        self.assertEqual(receipt['reason'], 'scanner-process-failed')
        self.assertEqual(receipt['failure'], {'phase': 'container-logs', 'exit_code': 1,
                                             'start_attempted': True, 'start_accepted': True, 'scan_failure': failure})
        self.assertTrue(receipt['image_code_executed'])
        self.assertEqual(scanner.docker.request.call_count, 3)

    def test_bad_failure_output_and_stderr_never_enter_receipt(self):
        for payload, stream in (({'status': 'stopped', 'reason': SECRET, 'stage': SECRET}, 1),
                                (SECRET, 2), ({'expected': 'inventory'}, 1)):
            with self.subTest(stream=stream, payload=payload):
                receipt, _ = self.qualification(payload, stream=stream)
                self.assertEqual(receipt['reason'], 'scanner-process-failed')
                self.assertNotIn('scan_failure', receipt['failure'])
                self.assertIn(receipt['failure']['log_reason'],
                              ('scanner-logs-invalid', 'scanner-failure-report-invalid'))
        receipt, _ = self.qualification(None, raw=b'\x01\0\0\0' + struct.pack('>I', 4097))
        self.assertEqual(receipt['failure']['log_reason'], 'scanner-logs-limit')

    def test_exit_status_and_postexit_identity_cannot_be_bypassed_by_failure_report(self):
        failure = {'status': 'stopped', 'reason': 'scanner-path-drift', 'stage': 'final-fence'}
        for status in (True, -1, 256, SECRET):
            with self.subTest(status=status):
                receipt, scanner = self.qualification(failure, status=status)
                self.assertNotIn('exit_code', receipt['failure'])
                self.assertEqual(scanner.docker.request.call_count, 2)
        receipt, scanner = self.qualification(failure, drift=True)
        self.assertEqual(receipt['reason'], 'scanner-command-mismatch')
        self.assertEqual(scanner.docker.request.call_count, 2)
        receipt, _ = self.qualification(failure, status=0)
        self.assertEqual(receipt['failure']['phase'], 'inventory-comparison')
        self.assertNotIn('scan_failure', receipt['failure'])

    def test_host_errors_are_exact_type_and_code_allowlisted(self):
        class ForeignStop(C.Stop):
            pass
        for error in (C.Stop(SECRET), C.Stop('unknown-code'), C.Stop('scanner-process-failed', SECRET),
                      ForeignStop('scanner-process-failed'), RuntimeError(SECRET)):
            self.assertEqual(C.scanner_host_failure(error), 'filesystem-qualification-failed')

    def test_single_log_file_disables_compression_and_fences_config_drift(self):
        fixture = F.QualificationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        scanner, state = fixture.scanner()
        scanner.docker.request.return_value = (Mock(), F.Response(F.encoded({'Id': scanner.identifier})))
        scanner.create()
        body = json.loads(scanner.docker.request.call_args.args[3])
        log = body['HostConfig']['LogConfig']
        # Source-derived local-driver validation: compression defaults to true
        # and cannot be combined with one file. The explicit option is needed.
        self.assertEqual(log['Type'], 'local')
        self.assertEqual(log['Config']['max-file'], '1')
        self.assertEqual(log['Config']['max-size'], '128m')
        self.assertEqual(log['Config'].get('compress', 'true'), 'false')
        for config in ({'Type': 'json-file', 'Config': log['Config']},
                       {'Type': 'local', 'Config': {'max-size': '128m', 'max-file': '1'}},
                       {'Type': 'local', 'Config': {**log['Config'], 'compress': 'true'}},
                       {'Type': 'local', 'Config': {**log['Config'], 'max-file': '2'}},
                       {'Type': 'local', 'Config': {**log['Config'], 'max-size': '256m'}}):
            state['HostConfig']['LogConfig'] = config
            with self.subTest(config=config), self.assertRaisesRegex(C.Stop, 'scanner-log-config-mismatch'):
                scanner.fence()

    def test_start_http_failure_retains_only_fixed_phase_and_code(self):
        fixture = F.QualificationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        scanner, _ = fixture.scanner()
        scanner.create, scanner.cleanup = Mock(), Mock()
        scanner.docker.request.side_effect = C.Stop('docker-http-status')
        with patch.object(C, 'ScannerImage', return_value=scanner):
            receipt = C.qualify_filesystem(scanner.docker, F.TARGET, fixture.context,
                                           fixture.verified, {'expected': 'inventory'})
        self.assertEqual(receipt['status'], 'stopped')
        self.assertEqual(receipt['reason'], 'docker-http-status')
        self.assertEqual(receipt['failure'], {'phase': 'container-start', 'start_attempted': True})
        self.assertIsNone(receipt['image_code_executed'])
        self.assertNotIn('scan', receipt)
        self.assertNotIn('exit_code', receipt['failure'])
        scanner.cleanup.assert_called_once()
        scanner.docker.request.assert_called_once()


    def lost_start_receipt(self, status='running', *, drift=None, inspect_failure=False,
                           stop_failure=False, prestart_failure=False):
        fixture = F.QualificationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        scanner, value = fixture.scanner()
        scanner.create = Mock()
        zero = '0001-01-01T00:00:00Z'
        started = '2026-10-13T12:34:56.123456789Z'
        value['State'].update(StartedAt=zero, Paused=False, Restarting=False, Dead=False)
        scanner.docker = C.Docker('/fixture-only', (1, 2, 3))
        calls, connections = [], []
        dispatched = False

        def connection(*args, **kwargs):
            conn = Mock()
            connections.append(conn)
            current = {}
            def request(method, path, **kwargs):
                current.update(method=method, path=path)
                calls.append((method, path))
            def getresponse():
                nonlocal dispatched
                response_status, raw = 200, b''
                if current['method'] == 'GET':
                    if (dispatched and inspect_failure) or prestart_failure:
                        raise ConnectionResetError(SECRET)
                    raw = json.dumps(value).encode()
                elif current['path'].endswith('/start'):
                    dispatched = True
                    value['State'].update(Status=status, Running=status == 'running',
                                          Pid=123 if status == 'running' else 0,
                                          StartedAt=zero if status == 'created' else started)
                    if drift:
                        drift(value)
                    # The daemon started the exact container, but no 204 reaches
                    # the collector's real Docker.request/LocalConnection path.
                    raise ConnectionResetError(SECRET)
                elif '/stop?' in current['path']:
                    if stop_failure:
                        raise ConnectionResetError(SECRET)
                    value['State'].update(Status='exited', Running=False, Pid=0)
                    response_status = 204
                elif current['method'] == 'DELETE':
                    response_status = 204
                else:
                    self.fail('unexpected request')
                response = F.Response(raw)
                response.status = response_status
                return response
            conn.request.side_effect = request
            conn.getresponse.side_effect = getresponse
            return conn

        with patch.object(C, 'ScannerImage', return_value=scanner), \
                patch.object(C, 'LocalConnection', side_effect=connection):
            receipt = C.qualify_filesystem(scanner.docker, F.TARGET, fixture.context,
                                           fixture.verified, {'expected': 'inventory'})
        self.assertEqual(receipt['status'], 'stopped')
        self.assertNotIn('scan', receipt)
        self.assertNotIn(SECRET, json.dumps(receipt))
        for conn in connections:
            conn.close.assert_called_once()
        return receipt, calls

    def test_lost_start_response_reconciles_owned_running_and_fast_exit(self):
        for status in ('running', 'exited'):
            with self.subTest(status=status):
                receipt, calls = self.lost_start_receipt(status)
                self.assertIs(receipt['image_code_executed'], True)
                self.assertEqual(receipt['schema_version'], 2)
                self.assertTrue(receipt['owned_container_removed'])
                self.assertEqual([m for m, _ in calls],
                                 ['GET', 'POST', 'GET', 'POST', 'GET', 'DELETE']
                                 if status == 'running' else ['GET', 'POST', 'GET', 'DELETE'])

    def test_lost_start_created_snapshot_is_unknown_even_after_removal(self):
        receipt, calls = self.lost_start_receipt('created')
        self.assertIsNone(receipt['image_code_executed'])
        self.assertTrue(receipt['owned_container_removed'])
        self.assertEqual([m for m, _ in calls], ['GET', 'POST', 'GET', 'DELETE'])

    def test_no_dispatched_start_is_definitively_unexecuted(self):
        receipt, calls = self.lost_start_receipt(prestart_failure=True)
        self.assertIs(receipt['image_code_executed'], False)
        self.assertFalse(receipt['owned_container_removed'])
        self.assertTrue(all(m == 'GET' for m, _ in calls))

    def test_lost_start_inspection_failure_or_fence_drift_stays_unknown(self):
        edits = (
            lambda v: v.update(Id='a' * 64),
            lambda v: v.update(Name='/foreign'),
            lambda v: v['Config']['Labels'].update({C.OWNER_LABEL: 'foreign'}),
            lambda v: v.update(Image='sha256:' + '0' * 64),
            lambda v: v.update(ImageManifestDescriptor={'digest': 'sha256:' + '0' * 64}),
            lambda v: v['Config'].update(User='0'),
            lambda v: v['HostConfig'].update(NetworkMode='host'),
            lambda v: v['Mounts'][0].update(RW=True),
            lambda v: v['HostConfig']['LogConfig']['Config'].update(compress='true'),
        )
        for drift in edits:
            receipt, calls = self.lost_start_receipt(drift=drift)
            self.assertIsNone(receipt['image_code_executed'])
            self.assertFalse(receipt['owned_container_removed'])
            self.assertEqual([m for m, _ in calls], ['GET', 'POST', 'GET'])
        receipt, _ = self.lost_start_receipt(inspect_failure=True)
        self.assertIsNone(receipt['image_code_executed'])
        self.assertFalse(receipt['owned_container_removed'])

    def test_malformed_or_inconsistent_start_evidence_cannot_prove_execution(self):
        for status, field, invalid in (
            ('running', 'StartedAt', '0001-01-01T00:00:00Z'),
            ('exited', 'StartedAt', '0001-01-01T00:00:00Z'),
            ('exited', 'StartedAt', '0001-01-01T00:00:00.000000000Z'),
            ('exited', 'StartedAt', SECRET),
            ('exited', 'StartedAt', '2026-02-30T00:00:00Z'),
            ('exited', 'StartedAt', '2026-01-01T00:00:00.1234567890Z'),
            ('exited', 'StartedAt', None),
            ('exited', 'StartedAt', ''),
            ('exited', 'StartedAt', '0000-01-01T00:00:00Z'),
            ('exited', 'StartedAt', '2026-10-13T12:34:56+00:00'),
            ('running', 'Pid', True),
            ('running', 'Pid', 0),
            ('running', 'Pid', -1),
            ('running', 'Pid', 2**31),
            ('running', 'Pid', 123.0),
            ('running', 'Running', 1),
            ('exited', 'Pid', False),
            ('exited', 'Pid', 1),
            ('exited', 'Paused', True),
            ('exited', 'Restarting', True),
            ('exited', 'Dead', True),
            ('exited', 'Dead', 0),
            ('exited', 'Paused', None),
        ):
            with self.subTest(status=status, field=field, invalid=invalid):
                receipt, _ = self.lost_start_receipt(status,
                    drift=lambda v: v['State'].update({field: invalid}),
                    stop_failure=True)
                self.assertIsNone(receipt['image_code_executed'])

    def test_proven_start_is_retained_when_owned_cleanup_later_fails(self):
        receipt, calls = self.lost_start_receipt(stop_failure=True)
        self.assertIs(receipt['image_code_executed'], True)
        self.assertFalse(receipt['owned_container_removed'])
        self.assertEqual(receipt['reason'], 'owned-cleanup-failed')
        self.assertEqual([m for m, _ in calls], ['GET', 'POST', 'GET', 'POST'])


if __name__ == '__main__':
    unittest.main()
