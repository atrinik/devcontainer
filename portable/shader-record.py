#!/usr/bin/env python3
"""Bind the generated shader data to the exact higher-ABI build-only inputs."""
import hashlib
import json
import shutil
from pathlib import Path
import subprocess

source = Path("/cohort/source")
shader = Path("/cohort/shaders")
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

paths = subprocess.check_output(["git", "-C", str(source), "ls-files", "-z", "client/shaders", "client/tools/generate_gpu_shaders.sh", "client/tools/write_gpu_shader_manifest.py", "client/tools/embed_gpu_shaders.py", "LICENSE.md", "ATTRIBUTIONS.md", "PROVENANCE.md"]).decode().split("\0")
inputs = {name: digest(source / name) for name in sorted(filter(None, paths))}
for name in inputs:
    target = Path("/cohort/corresponding-source") / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source / name, target)
Path("/cohort/input-sha256.txt").write_text("".join(f"{value}  {source / name}\n" for name, value in inputs.items()))
record = {"schema_version": 1,
          "source_commit": subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip(),
          "source_inputs": inputs,
          "output_manifest_sha256": digest(shader / "SHA256SUMS"),
          "expected_manifest_sha256": digest(source / "client/shaders/SHA256SUMS"),
          "tool_manifest_sha256": digest(Path("/opt/shader-toolchain.json")),
          "installer_sha256": digest(Path("/opt/install-shaders.py")),
          "builder": {"base": "ubuntu:26.04@sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03", "snapshot": "20260810T000000Z", "package_lock_sha256": digest(Path("/tmp/classic-packages.lock"))},
          "tools": {name: digest(Path("/usr/local") / name) for name in ["bin/dxc", "lib/libdxcompiler.so", "lib/libdxil.so", "bin/spirv-cross"]}}
assert record["output_manifest_sha256"] == record["expected_manifest_sha256"]
Path("/cohort/generation.json").write_text(json.dumps(record, indent=2) + "\n")

# The canonical manifest writer uses a private temporary file. Consumers may
# run with a different non-root UID, so seal verified data with public reads.
for path in [shader, *shader.rglob("*")]:
    path.chmod(0o555 if path.is_dir() else 0o444)
