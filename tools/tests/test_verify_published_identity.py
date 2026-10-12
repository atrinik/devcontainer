# Copyright (c) 2026 Atrinik contributors
# SPDX-License-Identifier: MIT
"""Offline tests for the Linux publisher's loaded-to-published identity fence."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "published_identity", ROOT / "tools/verify_published_identity.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
REVISION = "1" * 40
INDEX_DIGEST = "sha256:" + "9" * 64
BEARER = "FAKE_SCOPED_PULL_BEARER"


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def descriptor(raw, media_type):
    return {"digest": M.R.digest(raw), "size": len(raw), "mediaType": media_type}


def runtime(labels=None):
    return {
        "Hostname": "",
        "Domainname": "",
        "User": "1000:1000",
        "AttachStdin": False,
        "AttachStdout": False,
        "AttachStderr": False,
        "Tty": False,
        "OpenStdin": False,
        "StdinOnce": False,
        "Env": ["PATH=/usr/bin", "LANG=C.UTF-8"],
        "Cmd": ["/bin/true"],
        "Entrypoint": None,
        "Image": "",
        "Labels": labels,
        "Volumes": None,
        "WorkingDir": "/work",
        "NetworkDisabled": False,
        "MacAddress": "",
        "OnBuild": None,
        "StopSignal": "SIGTERM",
        "StopTimeout": 10,
        "Shell": ["/bin/sh", "-c"],
        "ArgsEscaped": False,
        "ExposedPorts": {"443/tcp": {}},
        "Healthcheck": {"Test": ["CMD", "/bin/true"], "Interval": 1,
                        "Timeout": 2, "StartPeriod": 3, "StartInterval": 4,
                        "Retries": 5},
    }


def fixture():
    layers = ["sha256:" + "a" * 64, "sha256:" + "b" * 64]
    local = {
        "Id": "sha256:" + "c" * 64,
        "Os": "linux",
        "Architecture": "amd64",
        "Variant": "",
        "Author": "Atrinik",
        "RootFS": {"Type": "layers", "Layers": list(layers)},
        "Config": runtime({"fixture": "same"}),
    }
    published = {
        "architecture": "amd64",
        "os": "linux",
        "author": "Atrinik",
        "created": "2026-10-12T00:00:00Z",
        "history": [],
        "moby.buildkit.cache.v0": None,
        "rootfs": {"type": "layers", "diff_ids": list(layers)},
        "config": runtime({
            "fixture": "same",
            "org.opencontainers.image.source": M.R.SOURCE,
            "org.opencontainers.image.revision": REVISION,
        }),
    }
    return local, published


def context_env(**changes):
    ref = changes.pop("GITHUB_REF", "refs/tags/v1.2.3")
    env = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_REPOSITORY": M.R.REPOSITORY,
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": ref,
        "GITHUB_WORKFLOW_REF": M.R.REPOSITORY + "/" + M.WORKFLOW + "@" + ref,
        "GITHUB_SHA": REVISION,
        "GITHUB_ACTOR": "trusted-actor",
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "2",
    }
    env.update(changes)
    return env


def registry_fixture(config=None):
    if config is None:
        _, config = fixture()
    raw_config = encoded(config)
    layers = [
        {"digest": "sha256:" + "d" * 64, "size": 101,
         "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"},
        {"digest": "sha256:" + "e" * 64, "size": 102,
         "mediaType": "application/vnd.oci.image.layer.v1.tar+zstd"},
    ]
    manifest = {"schemaVersion": 2, "mediaType": M.R.MANIFEST,
                "config": descriptor(raw_config, M.R.CONFIG), "layers": layers}
    raw_manifest = encoded(manifest)
    selected = dict(descriptor(raw_manifest, M.R.MANIFEST),
                    platform={"os": "linux", "architecture": "amd64"})
    attestation = dict(
        descriptor(encoded({"attestation": True}), M.R.MANIFEST),
        platform={"os": "unknown", "architecture": "unknown"},
        annotations={"vnd.docker.reference.type": "attestation-manifest",
                     "vnd.docker.reference.digest": selected["digest"]})
    index = {"schemaVersion": 2, "mediaType": M.R.INDEX,
             "manifests": [selected, attestation]}
    raw_index = encoded(index)
    objects = {INDEX_DIGEST: raw_index, selected["digest"]: raw_manifest,
               manifest["config"]["digest"]: raw_config}
    return objects, config, manifest, index


class Response(io.BytesIO):
    def __init__(self, raw):
        super().__init__(raw)
        self.status = 200
        self.length = len(raw)


class OfflineTests(unittest.TestCase):
    def setUp(self):
        blockers = (
            patch.object(M.R, "https_get", side_effect=AssertionError("network forbidden")),
            patch.object(M.R.LocalConnection, "connect",
                         side_effect=AssertionError("Docker socket forbidden")),
            patch.object(M.R.subprocess, "run",
                         side_effect=AssertionError("subprocess forbidden")),
        )
        for blocker in blockers:
            blocker.start()
            self.addCleanup(blocker.stop)

    def assert_stop(self, code, call, *args):
        with self.assertRaisesRegex(M.Stop, code):
            call(*args)

    def test_exact_runtime_config_rootfs_and_publication_labels_match(self):
        local, published = fixture()
        result = M.compare(local, published, REVISION)
        self.assertEqual(result["loaded_image_id"], local["Id"])
        self.assertTrue(result["rootfs_equal"])
        self.assertTrue(result["execution_config_equal"])
        self.assertEqual(result["docker_absent_defaults"], M.DEFAULTS)

    def test_docker_absent_defaults_are_exact_but_null_is_not_empty_array(self):
        local, published = fixture()
        for key in M.DEFAULTS:
            for direction in ("loaded-materialized", "published-materialized"):
                left, right = copy.deepcopy(local), copy.deepcopy(published)
                if key == "Labels":
                    if direction == "loaded-materialized":
                        left["Config"][key] = None
                    else:
                        left["Config"].pop(key, None)
                    right["config"]["Labels"] = {
                        "org.opencontainers.image.source": M.R.SOURCE,
                        "org.opencontainers.image.revision": REVISION,
                    }
                elif direction == "loaded-materialized":
                    left["Config"][key] = copy.deepcopy(M.DEFAULTS[key])
                    right["config"].pop(key, None)
                else:
                    left["Config"].pop(key, None)
                    right["config"][key] = copy.deepcopy(M.DEFAULTS[key])
                with self.subTest(key=key, direction=direction):
                    M.compare(left, right, REVISION)
        for key in ("Cmd", "Entrypoint", "Env", "OnBuild"):
            with self.subTest(null_vs_array=key):
                left, right = copy.deepcopy(local), copy.deepcopy(published)
                left["Config"][key] = None
                right["config"][key] = []
                self.assert_stop("published-runtime-config-mismatch", M.compare,
                                 left, right, REVISION)

    def test_environment_order_scalar_types_and_rootfs_order_are_bound(self):
        local, published = fixture()
        published["config"]["Env"].reverse()
        self.assert_stop("published-runtime-config-mismatch", M.compare,
                         local, published, REVISION)
        local, published = fixture()
        local["Config"]["StopTimeout"] = True
        published["config"]["StopTimeout"] = True
        self.assert_stop("invalid-runtime-timeout", M.compare, local, published, REVISION)
        local, published = fixture()
        published["rootfs"]["diff_ids"].reverse()
        self.assert_stop("published-rootfs-mismatch", M.compare, local, published, REVISION)

    def test_unknown_runtime_and_top_level_config_fields_are_rejected(self):
        for location, code in (("runtime", "unknown-runtime-config-field"),
                               ("top", "unknown-image-config-field")):
            local, published = fixture()
            if location == "runtime":
                local["Config"]["Unknown"] = "same"
                published["config"]["Unknown"] = "same"
            else:
                published["unknown"] = "value"
            with self.subTest(location=location):
                self.assert_stop(code, M.compare, local, published, REVISION)

    def test_runtime_field_types_maps_and_healthcheck_are_strict(self):
        cases = [
            ("AttachStdin", 0, "invalid-runtime-boolean"),
            ("User", None, "invalid-runtime-string"),
            ("Env", [True], "invalid-runtime-array"),
            ("Labels", {"x": 1}, "invalid-runtime-map-value"),
            ("Volumes", {"/data": None}, "invalid-runtime-map-value"),
            ("ExposedPorts", {"80/tcp": []}, "invalid-runtime-map-value"),
            ("StopTimeout", -1, "invalid-runtime-timeout"),
            ("Healthcheck", {"Unknown": 1}, "invalid-healthcheck"),
            ("Healthcheck", {"Test": [1]}, "invalid-healthcheck-value"),
            ("Healthcheck", {"Retries": True}, "invalid-healthcheck-value"),
        ]
        for key, value, code in cases:
            local, published = fixture()
            local["Config"][key] = value
            published["config"][key] = copy.deepcopy(value)
            with self.subTest(key=key, value=value):
                self.assert_stop(code, M.compare, local, published, REVISION)

    def test_loaded_and_published_platform_fields_are_exact(self):
        for key, value in (("OsVersion", "6.8"), ("OsFeatures", ["feature"])):
            local, published = fixture()
            local[key] = value
            with self.subTest(loaded=key):
                self.assert_stop("loaded-platform-mismatch", M.compare,
                                 local, published, REVISION)
        for key, value in (("os.version", "6.8"), ("os.features", []),
                           ("variant", "v8")):
            local, published = fixture()
            published[key] = value
            with self.subTest(published=key):
                self.assert_stop("published-platform-mismatch", M.compare,
                                 local, published, REVISION)

    def test_author_revision_and_source_are_exact(self):
        for mutation, code in (
                (lambda local, published: published.update(author="other"),
                 "image-author-mismatch"),
                (lambda local, published: published["config"]["Labels"].update(
                    {"org.opencontainers.image.revision": "2" * 40}),
                 "producer-label-mismatch"),
                (lambda local, published: published["config"]["Labels"].update(
                    {"org.opencontainers.image.source": "https://example.invalid"}),
                 "producer-label-mismatch")):
            local, published = fixture()
            mutation(local, published)
            self.assert_stop(code, M.compare, local, published, REVISION)

    def test_only_declared_top_level_build_metadata_is_exempt_from_comparison(self):
        local, published = fixture()
        published.update(created={"opaque": "builder value"}, history=[{"created_by": "x"}],
                         **{"moby.buildkit.cache.v0": {"arbitrary": [1, True, None]}})
        self.assertTrue(M.compare(local, published, REVISION)["execution_config_equal"])

    def test_decode_rejects_empty_oversized_duplicate_and_nonfinite_json(self):
        self.assert_stop("invalid-json-size", M.decode, b"")
        self.assert_stop("invalid-json-size", M.decode, b" " * (M.R.LIMIT + 1))
        self.assert_stop("duplicate-json-key", M.decode, b'{"x":1,"x":2}')
        for raw in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.subTest(raw=raw):
                self.assert_stop("invalid-json-value", M.decode, raw)

    def test_registry_binds_complete_descriptor_chain_and_platform(self):
        objects, config, manifest, index = registry_fixture()
        calls = []
        def get(package, kind, digest, bearer):
            calls.append((package, kind, digest, bearer))
            return objects[digest]
        with patch.object(M.R, "registry_object", side_effect=get):
            blobs, relation, actual = M.registry("atrinik/linux-build", INDEX_DIGEST, BEARER)
        self.assertEqual(actual, config)
        self.assertEqual(set(blobs), {"index.json", "manifest.json", "config.json"})
        self.assertEqual(relation["platform"], "linux/amd64")
        self.assertEqual(relation["manifest_descriptor"], index["manifests"][0])
        self.assertEqual(relation["config_descriptor"], manifest["config"])
        self.assertEqual([item[1] for item in calls], ["manifests", "manifests", "blobs"])

    def test_registry_rejects_descriptor_size_digest_platform_and_type_confusion(self):
        mutations = [
            ("manifest-size", "manifest-size-mismatch",
             lambda o, c, m, i: i["manifests"][0].update(size=1)),
            ("config-size", "config-size-mismatch",
             lambda o, c, m, i: m["config"].update(size=1)),
            ("manifest-digest", "invalid-oci-descriptor",
             lambda o, c, m, i: i["manifests"][0].update(digest="bad")),
            ("descriptor-type", "invalid-oci-descriptor",
             lambda o, c, m, i: i["manifests"][0].update(size=True)),
            ("platform-extra", "unexpected-platform-metadata",
             lambda o, c, m, i: i["manifests"][0]["platform"].update(variant="v8")),
            ("schema-bool", "invalid-oci-index",
             lambda o, c, m, i: i.update(schemaVersion=True)),
            ("manifest-media", "invalid-image-manifest",
             lambda o, c, m, i: m.update(mediaType=M.R.INDEX)),
            ("config-media", "invalid-oci-descriptor",
             lambda o, c, m, i: m["config"].update(mediaType=M.R.MANIFEST)),
            ("layer-media", "invalid-oci-descriptor",
             lambda o, c, m, i: m["layers"][0].update(mediaType=M.R.CONFIG)),
        ]
        for name, code, mutate in mutations:
            objects, config, manifest, index = registry_fixture()
            mutate(objects, config, manifest, index)
            raw_config = encoded(config)
            if name not in ("config-size", "config-media"):
                manifest["config"] = descriptor(raw_config, M.R.CONFIG)
            raw_manifest = encoded(manifest)
            if name not in ("manifest-size", "manifest-digest", "descriptor-type"):
                index["manifests"][0].update(descriptor(raw_manifest, M.R.MANIFEST))
            index["manifests"][1]["annotations"]["vnd.docker.reference.digest"] = \
                index["manifests"][0]["digest"]
            raw_index = encoded(index)
            objects = {INDEX_DIGEST: raw_index,
                       index["manifests"][0]["digest"]: raw_manifest,
                       manifest["config"]["digest"]: raw_config}
            with self.subTest(name=name), patch.object(
                    M.R, "registry_object", side_effect=lambda p, k, d, b, data=objects: data[d]), \
                    self.assertRaisesRegex(M.Stop, code):
                M.registry("atrinik/linux-build", INDEX_DIGEST, BEARER)

    def test_registry_rejects_ambiguous_platform_attestation_and_layer_count(self):
        for name, code in (("ambiguous", "ambiguous-linux-amd64-manifest"),
                           ("attestation-subject", "attestation-subject-mismatch"),
                           ("layer-count", "layer-count-mismatch")):
            objects, config, manifest, index = registry_fixture()
            if name == "ambiguous":
                index["manifests"].append(copy.deepcopy(index["manifests"][0]))
            elif name == "attestation-subject":
                index["manifests"][1]["annotations"]["vnd.docker.reference.digest"] = "sha256:" + "f" * 64
            else:
                config["rootfs"]["diff_ids"].pop()
            raw_config = encoded(config)
            manifest["config"] = descriptor(raw_config, M.R.CONFIG)
            raw_manifest = encoded(manifest)
            for item in index["manifests"]:
                if item["platform"]["os"] == "linux":
                    item.update(descriptor(raw_manifest, M.R.MANIFEST))
            if name != "attestation-subject":
                index["manifests"][1]["annotations"]["vnd.docker.reference.digest"] = \
                    index["manifests"][0]["digest"]
            raw_index = encoded(index)
            data = {INDEX_DIGEST: raw_index, M.R.digest(raw_manifest): raw_manifest,
                    M.R.digest(raw_config): raw_config}
            with self.subTest(name=name), patch.object(
                    M.R, "registry_object", side_effect=lambda p, k, d, b, data=data: data[d]), \
                    self.assertRaisesRegex(M.Stop, code):
                M.registry("atrinik/linux-build", INDEX_DIGEST, BEARER)

    def test_context_binds_host_repository_event_ref_workflow_and_source(self):
        ctx = M.context(context_env())
        self.assertEqual(ctx["head"], REVISION)
        self.assertFalse(ctx["candidate_only"])
        dispatch = context_env(
            GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REF="refs/heads/feature/safe",
            GITHUB_WORKFLOW_REF=M.R.REPOSITORY + "/" + M.WORKFLOW + "@refs/heads/feature/safe",
            CANDIDATE_ONLY="true")
        self.assertTrue(M.context(dispatch)["candidate_only"])
        bad = (
            {"RUNNER_ENVIRONMENT": "self-hosted"},
            {"GITHUB_REPOSITORY": "other/repo"},
            {"GITHUB_EVENT_NAME": "pull_request"},
            {"GITHUB_REF": "refs/heads/main"},
            {"GITHUB_WORKFLOW_REF": "other/workflow@refs/tags/v1.2.3"},
            {"GITHUB_SHA": "not-a-revision"},
            {"GITHUB_ACTOR": "bad actor"},
            {"OPENSSL_CONF": "/tmp/hostile"},
        )
        for changes in bad:
            with self.subTest(changes=changes), self.assertRaises(M.Stop):
                M.context(context_env(**changes))

    def test_evidence_files_reject_names_links_modes_and_oversize(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            os.chmod(folder, 0o700)
            for name in ("", ".", "..", "sub/file"):
                with self.subTest(save=name), self.assertRaises(M.Stop):
                    M.save(folder, name, b"x")
                with self.subTest(read=name), self.assertRaises(M.Stop):
                    M.read(folder, name)
            path = folder / "evidence"
            path.write_bytes(b"x")
            os.chmod(path, 0o644)
            self.assert_stop("unsafe-evidence-file", M.read, folder, "evidence")
            os.chmod(path, 0o600)
            hardlink = folder / "hardlink"
            os.link(path, hardlink)
            self.assert_stop("unsafe-evidence-file", M.read, folder, "evidence")
            hardlink.unlink()
            path.unlink()
            path.symlink_to("missing")
            with self.assertRaises(OSError):
                M.read(folder, "evidence")
            self.assert_stop("invalid-evidence-file", M.save, folder, "large", b"x" * (M.R.LIMIT + 1))

    def test_directory_requires_absolute_owned_private_nonsymlink_path(self):
        ctx = M.context(context_env())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            with patch.dict(os.environ, {"RUNNER_TEMP": str(root)}):
                folder = M.directory(ctx, "broad", True)
                self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
            os.chmod(root, 0o777)
            with patch.dict(os.environ, {"RUNNER_TEMP": str(root)}):
                self.assert_stop("unsafe-runner-temp", M.directory, ctx, "broad", False)
        with patch.dict(os.environ, {"RUNNER_TEMP": "relative"}):
            self.assert_stop("unsafe-runner-temp", M.directory, ctx, "broad", False)

    def capture_fixture(self, folder, output):
        local, _ = fixture()
        raw = encoded(local)
        response = Response(raw)
        connection = Mock()
        docker = Mock()
        docker.negotiate.return_value = {"docker_api": "1.51", "docker_version": "28.5.1"}
        docker.request.return_value = (connection, response)
        with patch.object(M.R, "runner_docker", return_value=docker), \
                patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
            M.capture(M.context(context_env()), "broad", folder)
        connection.close.assert_called_once_with()
        requested = docker.request.call_args.args[1]
        self.assertIn("platform=%7B%22os%22%3A%22linux%22%2C%22architecture%22%3A%22amd64%22%7D", requested)
        return local

    def test_capture_writes_bound_evidence_and_only_validated_digest_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder, output = root / "evidence", root / "output"
            folder.mkdir(mode=0o700)
            output.touch(mode=0o600)
            local = self.capture_fixture(folder, output)
            capture = M.decode((folder / "capture.json").read_bytes())
            self.assertEqual(capture["image_id"], local["Id"])
            self.assertEqual(capture["target"], "broad")
            self.assertEqual(output.read_text(), "image_id=" + local["Id"] + "\n")

    def test_capture_rejects_output_symlink_hardlink_writable_mode_and_relative_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.touch(mode=0o600)
            hardlink = root / "hardlink"
            os.link(target, hardlink)
            symlink = root / "symlink"
            symlink.symlink_to(target)
            writable = root / "writable"
            writable.touch(mode=0o666)
            os.chmod(writable, 0o666)
            for output in (symlink, hardlink, writable, Path("relative-output")):
                folder = root / ("case-" + str(len(list(root.iterdir()))))
                folder.mkdir(mode=0o700)
                with self.subTest(output=output), self.assertRaises((M.Stop, OSError)):
                    self.capture_fixture(folder, output)

    def test_verify_binds_capture_context_image_and_registry_relation(self):
        ctx = M.context(context_env())
        local, published = fixture()
        raw = encoded(local)
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            os.chmod(folder, 0o700)
            inspection = M.save(folder, "loaded-inspect.json", raw)
            M.save(folder, "capture.json", M.encoded({
                "context": ctx, "target": "broad", "docker_api": "1.51",
                "docker_version": "28.5.1", "image_id": local["Id"],
                "inspection": inspection,
            }))
            relation = {"package": M.TARGETS["broad"][0], "index_digest": INDEX_DIGEST,
                        "manifest_digest": "sha256:" + "d" * 64,
                        "config_digest": "sha256:" + "e" * 64, "platform": "linux/amd64",
                        "manifest_descriptor": {}, "config_descriptor": {}}
            blobs = {"index.json": b"index", "manifest.json": b"manifest", "config.json": b"config"}
            with patch.object(M.R, "scoped_bearer", return_value=BEARER) as bearer, \
                    patch.object(M, "registry", return_value=(blobs, relation, published)) as registry, \
                    patch("builtins.print"):
                M.verify(ctx, "broad", folder, INDEX_DIGEST, "ORIGINAL_TOKEN")
            bearer.assert_called_once_with(M.TARGETS["broad"][0], "ORIGINAL_TOKEN", ctx["actor"])
            registry.assert_called_once_with(M.TARGETS["broad"][0], INDEX_DIGEST, BEARER)
            report = M.decode((folder / "report.json").read_bytes())
            self.assertEqual(report["status"], "verified-published-identity")
            self.assertEqual(report["loaded_image_id"], local["Id"])
            self.assertEqual(report["context"], ctx)

    def test_verify_rejects_capture_context_and_image_drift_before_registry(self):
        ctx = M.context(context_env())
        local, _ = fixture()
        raw = encoded(local)
        for change, code in (("context", "capture-context-mismatch"),
                             ("image", "capture-image-mismatch")):
            with tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                os.chmod(folder, 0o700)
                inspection = M.save(folder, "loaded-inspect.json", raw)
                captured = {"context": ctx, "target": "broad", "image_id": local["Id"],
                            "inspection": inspection}
                if change == "context":
                    captured["context"] = dict(ctx, run_attempt="3")
                else:
                    captured["image_id"] = "sha256:" + "f" * 64
                M.save(folder, "capture.json", M.encoded(captured))
                with self.subTest(change=change), patch.object(
                        M.R, "scoped_bearer") as bearer, self.assertRaisesRegex(M.Stop, code):
                    M.verify(ctx, "broad", folder, INDEX_DIGEST, "ORIGINAL_TOKEN")
                bearer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
