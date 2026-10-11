from __future__ import annotations

import os
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


if __name__ == "__main__":
    unittest.main()
