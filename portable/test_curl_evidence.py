"""Reject a threaded or missing resolver in the portable curl producer record."""
import unittest
import copy
import json
from pathlib import Path
from curl_evidence import configuration, require_features


class CurlConfigurationTests(unittest.TestCase):
    def test_cares_only_configuration(self):
        configuration('#define USE_ARES 1\n/* #undef USE_THREADS_POSIX */\n')

    def test_missing_or_hybrid_configuration_rejected(self):
        for config in ('/* #undef USE_ARES */\n', '#define USE_ARES 0\n',
                       '#define USE_ARES 1\n#define USE_THREADS_POSIX 1\n',
                       '#define USE_ARES 1\n#define USE_THREADS_WIN32 1\n'):
            with self.subTest(config=config), self.assertRaises(ValueError):
                configuration(config)

    def test_original_matrix_and_loaded_provider_identity_are_required(self):
        manifest = json.loads(Path(__file__).with_name("curl-toolchain.json").read_text())
        cares = {"version": "1.34.6"}
        value = {"features": manifest["required_features"], "protocols": manifest["required_protocols"],
                 "header_version": "7.88.1", "cares_header_version": "1.34.6", "cares_version": "1.34.6",
                 "runtime_version": "libcurl/7.88.1 OpenSSL/3.5.5 c-ares/1.34.6",
                 "curl_path": "/usr/local/lib/libcurl.so.4", "cares_path": "/usr/local/lib/libcares.so.2"}
        require_features(value, manifest, cares)
        for key, changed in (("features", [name for name in value["features"] if name != "NTLM_WB"]),
                             ("protocols", [name for name in value["protocols"] if name != "LDAP"]),
                             ("curl_path", "/usr/lib/x86_64-linux-gnu/libcurl.so.4"),
                             ("cares_header_version", "1.18.1"),
                             ("runtime_version", "libcurl/7.88.1 OpenSSL/3.5.5")):
            altered = copy.deepcopy(value)
            altered[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError):
                require_features(altered, manifest, cares)


if __name__ == '__main__':
    unittest.main()
