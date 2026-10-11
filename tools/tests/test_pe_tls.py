# SPDX-License-Identifier: MIT
# Copyright 2026 The Atrinik Project
import importlib.util
from pathlib import Path
import struct
import unittest

SPEC = importlib.util.spec_from_file_location('pe_tls', Path(__file__).resolve().parents[2] / 'windows/pe_tls.py')
TLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TLS)
BASE = 0x180000000


def fixture():
    data = bytearray(0x1400)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', data, 0x84, 0x8664, 2)
    struct.pack_into('<H', data, 0x94, 240)
    opt = 0x98
    struct.pack_into('<H', data, opt, 0x20b)
    struct.pack_into('<Q', data, opt + 24, BASE)
    struct.pack_into('<I', data, opt + 56, 0x4000)
    struct.pack_into('<I', data, opt + 108, 16)
    struct.pack_into('<II', data, opt + 184, 0x2000, 40)
    for i, (rva, raw, flags) in enumerate(((0x1000, 0x400, 0x60000020), (0x2000, 0xc00, 0xc0000040))):
        section = opt + 240 + i * 40
        struct.pack_into('<IIII', data, section + 8, 0x800, rva, 0x800, raw)
        struct.pack_into('<I', data, section + 36, flags)
    struct.pack_into('<QQQQII', data, 0xc00, BASE + 0x2080, BASE + 0x2088, BASE + 0x2070, BASE + 0x2040, 0, 0)
    struct.pack_into('<QQ', data, 0xc40, BASE + 0x1010, 0)
    symbols = f'glib_priv_tls_callback t {BASE+0x1010:x} 0\ntls_callback_invoked b {BASE+0x2090:x} 0\n'
    symbols += f'_tls_used R {BASE+0x2000:x} 0\n_ptr_glib_priv_tls_callback R {BASE+0x2040:x} 0\n'
    return data, symbols


class PETLSTests(unittest.TestCase):
    def test_resolves_callback_and_source_flag(self):
        data, symbols = fixture()
        result = TLS.inspect_glib(data, symbols)
        self.assertEqual(result['callback_rvas'], [0x1010])
        self.assertEqual(result['initialized_flag_rva'], 0x2090)

    def test_resolves_cairo_callback_and_pre_api_initialization_flag(self):
        data, symbols = fixture()
        symbols = symbols.replace('glib_priv_tls_callback', 'cairo_win32_tls_callback').replace(
            'tls_callback_invoked', '_cairo_mutex_initialized')
        result = TLS.inspect_callback(data, symbols, 'cairo')
        self.assertEqual(result['dll'], 'libcairo-2.dll')
        self.assertEqual(result['initialized_value'], 2)
        self.assertEqual(result['callback_rva'], 0x1010)
        with self.assertRaisesRegex(ValueError, 'missing'):
            TLS.inspect_callback(data, symbols.replace('_cairo_mutex_initialized', 'unrelated'), 'cairo')

    def test_rejects_retained_callback_without_tls_directory(self):
        data, symbols = fixture()
        struct.pack_into('<II', data, 0x98 + 184, 0, 0)
        with self.assertRaisesRegex(ValueError, 'TLS directory'):
            TLS.inspect_glib(data, symbols)

    def test_rejects_registered_other_callback(self):
        data, symbols = fixture()
        struct.pack_into('<Q', data, 0xc40, BASE + 0x1020)
        with self.assertRaisesRegex(ValueError, 'callback pointer|not registered'):
            TLS.inspect_glib(data, symbols)

    def test_rejects_nonexecutable_callback(self):
        data, symbols = fixture()
        struct.pack_into('<Q', data, 0xc40, BASE + 0x2020)
        with self.assertRaisesRegex(ValueError, 'not executable'):
            TLS.inspect_glib(data, symbols)

    def test_rejects_outside_callback_array(self):
        data, symbols = fixture()
        struct.pack_into('<Q', data, 0xc18, BASE + 0x5000)
        with self.assertRaisesRegex(ValueError, 'outside PE sections'):
            TLS.inspect_glib(data, symbols)

    def test_rejects_unterminated_array(self):
        data, symbols = fixture()
        for i in range(248):
            struct.pack_into('<Q', data, 0xc40 + i*8, BASE + 0x1000 + i)
        with self.assertRaises(ValueError):
            TLS.inspect_glib(data, symbols)

    def test_rejects_missing_and_duplicate_symbols(self):
        data, symbols = fixture()
        for bad in ('', symbols + symbols):
            with self.subTest(symbols=bad), self.assertRaisesRegex(ValueError, 'library TLS'):
                TLS.inspect_glib(data, bad)

    def test_rejects_truncated_and_overlapping_sections(self):
        data, symbols = fixture()
        with self.assertRaisesRegex(ValueError, 'truncated'):
            TLS.inspect_glib(data[:200], symbols)
        struct.pack_into('<I', data, 0x98+240+40+12, 0x1100)
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            TLS.inspect_glib(data, symbols)


if __name__ == '__main__':
    unittest.main()
