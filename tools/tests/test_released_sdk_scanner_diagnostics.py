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
                                             'start_accepted': True, 'scan_failure': failure})
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
        self.assertEqual(receipt['failure'], {'phase': 'container-start'})
        self.assertFalse(receipt['image_code_executed'])
        self.assertNotIn('scan', receipt)
        self.assertNotIn('exit_code', receipt['failure'])
        scanner.cleanup.assert_called_once()
        scanner.docker.request.assert_called_once()


if __name__ == '__main__':
    unittest.main()
