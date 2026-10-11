"""Reject a threaded or missing resolver in the portable curl producer record."""
import unittest
import copy
import json
import tempfile
import hashlib
from pathlib import Path
from curl_evidence import configuration, require_features, pinned_public_ca, tls_results


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

    def test_public_ca_bundle_and_origin_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            bundle.write_bytes(b"qualification certificate bytes")
            manifest = {"public_ca": {"endpoint": "https://curl.se/", "sha256": hashlib.sha256(bundle.read_bytes()).hexdigest()}}
            pinned_public_ca(bundle, manifest)
            bundle.write_bytes(b"changed")
            with self.assertRaises(ValueError): pinned_public_ca(bundle, manifest)
            manifest["public_ca"]["endpoint"] = "https://foreign.example/"
            with self.assertRaises(ValueError): pinned_public_ca(bundle, manifest)

    def test_tls_requires_verified_positive_and_actual_untrusted_failure(self):
        positive = {"origin": "curl.se", "passed": True, "expected_untrusted": False, "result": 0, "verification": 0, "status": 200}
        negative = {"origin": "curl.se", "passed": True, "expected_untrusted": True, "result": 60, "verification": 18, "status": 0}
        tls_results(positive, negative)
        for target, key, changed in ((positive, "verification", 18), (positive, "status", 500),
                                     (negative, "result", 6), (negative, "result", 0),
                                     (negative, "verification", 0), (negative, "passed", False)):
            altered_positive, altered_negative = dict(positive), dict(negative)
            (altered_positive if target is positive else altered_negative)[key] = changed
            with self.subTest(key=key, value=changed), self.assertRaises(ValueError):
                tls_results(altered_positive, altered_negative)


if __name__ == '__main__':
    unittest.main()
