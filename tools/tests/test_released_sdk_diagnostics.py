# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Offline failure receipts retain only fixed inventory codes and stages."""
import ast
import contextlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'collector_diagnostic_fixtures', ROOT / 'tools/tests/test_collect_released_sdk_metadata.py')
FIXTURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURES)
C = FIXTURES.M
I = C.INVENTORY
SECRET = 'PRIVATE_TOKEN https://private.invalid/archive?signature=PRIVATE_SIGNATURE'


class DiagnosticTests(unittest.TestCase):
    def test_code_allowlist_covers_only_literal_inventory_failures(self):
        codes = set()
        for node in ast.walk(ast.parse((ROOT / 'tools/released_sdk_inventory.py').read_text())):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in ('require', 'InventoryError')):
                continue
            value = node.args[1 if node.func.id == 'require' else 0]
            if isinstance(value, ast.Constant):
                self.assertIs(type(value.value), str)
                codes.add(value.value)
            else:
                # require() alone forwards its already-selected code.
                self.assertEqual(node.func.id, 'InventoryError')
                self.assertEqual(ast.dump(value), "Name(id='code', ctx=Load())")
        self.assertEqual(codes, I.FAILURE_CODES)
        for code in codes:
            self.assertEqual(I.failure_code(I.InventoryError(code)), code)

    def test_unknown_payload_types_and_exception_subclasses_never_render(self):
        class Hostile:
            def __str__(self):
                raise AssertionError('must not stringify')

        class HostileError(I.InventoryError):
            def __str__(self):
                raise AssertionError('must not stringify')

        class HostileString(str):
            def __hash__(self):
                raise AssertionError('must not hash')

        for error in (I.InventoryError(SECRET), I.InventoryError('unknown-valid-looking-code'),
                      I.InventoryError(), I.InventoryError('inventory-tail', SECRET),
                      I.InventoryError(Hostile()), I.InventoryError(['inventory-tail']),
                      I.InventoryError(HostileString('inventory-tail')),
                      HostileError('inventory-tail'), RuntimeError(SECRET)):
            with self.subTest(kind=type(error).__name__):
                self.assertEqual(I.failure_code(error), 'inventory-operation-failed')

    def collect_failure(self, stage, error):
        fixture = FIXTURES.OfflineTests()
        data, binary = fixture.portable_fixture()
        shader_path = I.ROOT + '/shader-generation.json'
        shader = json.loads(data[shader_path])
        shader.update(source_commit=C.FINAL_TARGETS['portable-final']['consumer_commit'],
                      source_inputs={'fixture-input': '1' * 64})
        data[shader_path] = FIXTURES.encoded(shader)
        operations = (
            ('producer-tree', I.InstalledInventory, 'producer',
             {'sources/classic-shaders/fixture-input': {'sha256': '1' * 64}}),
            ('metadata-binding', I, 'bind_metadata', None),
            ('source-archives-and-providers', I, 'crosscheck_archives', None),
            ('debian-notices', I.InstalledInventory, 'debian_notices', {}),
            ('common-licenses', I.InstalledInventory, 'common_licenses', {}),
            ('build-tools', I.InstalledInventory, 'build_tools', {}),
            ('inventory-report', I, 'expected_scan', None),
        )
        with contextlib.ExitStack() as stack:
            mocked = []
            for name, owner, method, result in operations:
                mocked.append(stack.enter_context(patch.object(
                    owner, method, return_value=result, side_effect=error if name == stage else None)))
            scanner = stack.enter_context(patch.object(C, 'qualify_filesystem'))
            result, _ = fixture.collect_portable_fixture(data, binary, target='portable-final')
            scanner.assert_not_called()
            index = next(i for i, operation in enumerate(operations) if operation[0] == stage)
            mocked[index].assert_called_once()
            for operation in mocked[index + 1:]:
                operation.assert_not_called()
        self.assertEqual(result['status'], 'stopped')
        self.assertEqual(result['inventory_failure'], {'stage': stage})
        self.assertTrue(result['owned_container_removed'])
        self.assertFalse(result['image_code_executed'])
        self.assertFalse(result['final_portable_cohort'])
        self.assertNotIn('inventory_sha256', result)
        self.assertNotIn('metadata_sha256', result)
        self.assertEqual(len(result['tool_bytes']), 12)
        for secret in ('PRIVATE_TOKEN', 'private.invalid', 'PRIVATE_SIGNATURE'):
            self.assertNotIn(secret, json.dumps(result))
        return result

    def test_each_inventory_stage_retains_fixed_code_and_stops_before_scanner(self):
        for stage, code in (
            ('producer-tree', 'inventory-extension-or-link'),
            ('metadata-binding', 'inventory-metadata-binding'),
            ('source-archives-and-providers', 'inventory-provider-bytes-mismatch'),
            ('debian-notices', 'notice-alias-target'),
            ('common-licenses', 'file-size-limit'),
            ('build-tools', 'build-tool-bytes-mismatch'),
            ('inventory-report', 'inventory-report-roles'),
        ):
            with self.subTest(stage=stage):
                receipt = self.collect_failure(stage, I.InventoryError(code))
                self.assertEqual(receipt['reason'], code)

    def test_hostile_unknown_and_noninventory_failures_remain_opaque(self):
        for error, reason in (
            (I.InventoryError(SECRET), 'inventory-operation-failed'),
            (I.InventoryError('unknown-code'), 'inventory-operation-failed'),
            (RuntimeError(SECRET), 'operation-failed-no-details-retained'),
            (KeyboardInterrupt(SECRET), 'operation-failed-no-details-retained'),
        ):
            with self.subTest(kind=type(error).__name__):
                receipt = self.collect_failure('producer-tree', error)
                self.assertEqual(receipt['reason'], reason)


if __name__ == '__main__':
    unittest.main()
