"""Preserve authenticated source hashes and Debian's exact OpenSSL patch preparation."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('build_curl', Path(__file__).with_name('build-curl.py'))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class CurlSourceTests(unittest.TestCase):
    def test_source_checksum_table_is_complete_and_unique(self):
        checksum = 'a' * 64
        text = 'Checksums-Sha256:\n ' + checksum + ' 12 curl.dsc\nOther: stop\n'
        self.assertEqual(builder.checksum_table(text, 'Checksums-Sha256'), {'curl.dsc': checksum})
        for extra in (' malformed\n', ' ' + checksum + ' 12 curl.dsc\n'):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                builder.checksum_table(text.replace('Other: stop\n', extra), 'Checksums-Sha256')

    def test_matching_version_rejects_changed_authenticated_archives(self):
        text = 'Package: curl\nVersion: 7.88.1-10+deb12u15\nChecksums-Sha256:\n ' + 'a' * 64 + ' 12 curl.dsc\n'
        manifest = {'source_version': '7.88.1-10+deb12u15', 'archives': {'curl.dsc': 'a' * 64}}
        self.assertEqual(builder.matching_source(text, manifest), text)
        manifest['archives']['curl.dsc'] = 'b' * 64
        with self.assertRaises(ValueError):
            builder.matching_source(text, manifest)

    def test_pop_only_terminal_variant_patches_and_keep_all_security_patches(self):
        series = '# packaging\n11_paths.patch\nCVE-2026-security.patch\n90_gnutls.patch\n99_nss.patch\n'
        applied = ['11_paths.patch', 'CVE-2026-security.patch', '90_gnutls.patch', '99_nss.patch']
        self.assertEqual(builder.openssl_series(series, applied, ['99_nss.patch', '90_gnutls.patch']), applied[:-2])
        for bad_applied, bad_pop in ((applied[1:], ['99_nss.patch', '90_gnutls.patch']),
                                     (applied, ['90_gnutls.patch', '99_nss.patch']),
                                     (applied, ['99_nss.patch'])):
            with self.subTest(applied=bad_applied, pop=bad_pop), self.assertRaises(ValueError):
                builder.openssl_series(series, bad_applied, bad_pop)


if __name__ == '__main__':
    unittest.main()
