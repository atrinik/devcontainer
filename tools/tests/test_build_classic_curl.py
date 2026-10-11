from __future__ import annotations

import os
import hashlib
import io
import json
import tarfile
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ClassicCurlToolSelectionTests(unittest.TestCase):
    def test_missing_archive_tool_stops_before_configure_or_download(self) -> None:
        for missing in ("AR", "RANLIB"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                marker = root / "pkg-config-called"
                for name, output in (("clang", "clang version 23.1.3"),
                                     ("clang++", "clang version 23.1.3"),
                                     ("ld.lld", "LLD 23.1.3"),
                                     ("llvm-ar", ""), ("llvm-ranlib", "")):
                    path = root / name
                    path.write_text("#!/bin/sh\nprintf '%s\\n' '" + output + "'\n")
                    path.chmod(0o755)
                pkg = root / "pkg-config"
                pkg.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\nexit 1\n")
                pkg.chmod(0o755)
                manifest = root / "manifest.json"
                manifest.write_text("{}\n")
                env = {**os.environ, "PATH": str(root) + os.pathsep + os.defpath,
                       "CC": "clang", "CXX": "clang++", "LD": "ld.lld",
                       "AR": "llvm-ar", "RANLIB": "llvm-ranlib"}
                env[missing] = "atrinik-nonexistent-llvm-tool"
                result = subprocess.run(["bash", str(ROOT / "tools/build-classic-curl.sh"), str(manifest)],
                                        env=env, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists(), result.stderr)

    def test_release_overrides_are_optional_and_preserve_argument_boundaries(self) -> None:
        for overrides in ({}, {"ATRINIK_RELEASE_C_FLAGS": "-O2 -DNDEBUG",
                               "ATRINIK_RELEASE_CXX_FLAGS": "-O2 -DNDEBUG"}):
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                def script(name, content):
                    path = root / name
                    path.write_text(content)
                    path.chmod(0o755)
                for name, output in (("clang", "clang version 23.1.3"),
                                     ("clang++", "clang version 23.1.3"),
                                     ("ld.lld", "LLD 23.1.3"), ("llvm-ar", ""), ("llvm-ranlib", "")):
                    script(name, "#!/bin/sh\nprintf '%s\\n' '" + output + "'\n")
                archive = root / "fixture.tar"
                with tarfile.open(archive, "w") as tar:
                    entry = tarfile.TarInfo("c-ares-1.34.6/LICENSE.md")
                    data = b"fixture\n"
                    entry.size = len(data)
                    tar.addfile(entry, io.BytesIO(data))
                checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
                manifest = root / "manifest.json"
                manifest.write_text(json.dumps({"cares": {"version": "1.34.6", "url": "https://fixture/cares", "sha256": checksum},
                                                "linux": {"openssl_version": "3.5.5", "curl_version": "8.18.0",
                                                          "curl_url": "https://fixture/curl", "curl_sha256": checksum}}))
                script("pkg-config", "#!/bin/sh\nprintf '%s\\n' 3.5.5\n")
                script("jq", "#!/usr/bin/env python3\nimport json,sys\nv=json.load(open(sys.argv[-1]))\nfor key in sys.argv[-2].lstrip('.').split('.'):v=v[key]\nprint(v)\n")
                script("curl", "#!/usr/bin/env python3\nimport shutil,sys\nshutil.copyfile(" + repr(str(archive)) + ",sys.argv[sys.argv.index('--output')+1])\n")
                arguments = root / "cmake-arguments.json"
                script("cmake", "#!/usr/bin/env python3\nimport json,sys\njson.dump(sys.argv[1:],open(" + repr(str(arguments)) + ",'w'))\nsys.exit(73)\n")
                env = {**os.environ, "PATH": str(root) + os.pathsep + os.defpath,
                       "CC": "clang", "CXX": "clang++", "LD": "ld.lld", "AR": "llvm-ar", "RANLIB": "llvm-ranlib"}
                env.pop("ATRINIK_RELEASE_C_FLAGS", None)
                env.pop("ATRINIK_RELEASE_CXX_FLAGS", None)
                env.update(overrides)
                result = subprocess.run(["bash", str(ROOT / "tools/build-classic-curl.sh"), str(manifest)],
                                        env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode, 73, result.stderr)
                args = json.loads(arguments.read_text())
                for variable, option in (("ATRINIK_RELEASE_C_FLAGS", "-DCMAKE_C_FLAGS_RELEASE="),
                                         ("ATRINIK_RELEASE_CXX_FLAGS", "-DCMAKE_CXX_FLAGS_RELEASE=")):
                    selected = [arg for arg in args if arg.startswith(option)]
                    self.assertEqual(selected, [option + overrides[variable]] if variable in overrides else [])


if __name__ == "__main__":
    unittest.main()
