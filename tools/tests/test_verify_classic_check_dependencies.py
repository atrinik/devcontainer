from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "verify_classic_check_dependencies",
    ROOT / "tools" / "verify_classic_check_dependencies.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeAPI:
    def __init__(self, dependencies: list[dict[str, object]]) -> None:
        self.releases: dict[tuple[str, str], dict[str, object]] = {}
        self.tags: dict[tuple[str, str], str] = {}
        for dependency in dependencies:
            repository = str(dependency["repository"])
            tag = str(dependency["tag"])
            self.releases[(repository, tag)] = {
                "tag_name": tag,
                "draft": False,
                "prerelease": False,
                "published_at": "2026-08-24T00:00:00Z",
                "assets": [
                    {
                        "name": str(dependency["url"]).rsplit("/", 1)[1],
                        "browser_download_url": dependency["url"],
                        "size": 123,
                        "state": "uploaded",
                        "digest": f"sha256:{dependency['sha256']}",
                    }
                ],
            }
            self.tags[(repository, tag)] = str(dependency["commit"])

    def release(self, repository: str, tag: str) -> dict[str, object]:
        return self.releases[(repository, tag)]

    def tag_commit(self, repository: str, tag: str) -> str:
        return self.tags[(repository, tag)]


def dependency(
    name: str, repository: str, tag: str, commit: str, digest: str
) -> dict[str, object]:
    return {
        "name": name,
        "repository": repository,
        "tag": tag,
        "commit": commit,
        "url": f"https://github.com/{repository}/releases/download/{tag}/{name}.tar.gz",
        "sha256": digest,
        "destination": name,
        "strip_components": 1,
    }


class ClassicDependencyVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "classic"
        (self.root / ".github/workflows").mkdir(parents=True)
        (self.root / "client/tools").mkdir(parents=True)
        (self.root / "server").mkdir(parents=True)
        (self.root / ".github/workflows/check.yml").write_text(
            "jobs:\n  windows:\n    name: Build native Windows tests\n"
            "  security:\n    name: Native Windows security tests\n",
            encoding="utf-8",
        )
        (self.root / "client/tools/dependencies.py").write_text("# fixture\n", encoding="utf-8")
        self.manifest = Path(self.tempdir.name) / "classic-check-toolchain.json"
        self.client_dependency = dependency(
            "sound",
            "atrinik/sound",
            "v1.0.3",
            "a" * 40,
            "b" * 64,
        )
        self.server_dependency = dependency(
            "content",
            "atrinik/content",
            "v1.0.0",
            "c" * 40,
            "d" * 64,
        )
        self.dependencies = [self.client_dependency, self.server_dependency]
        self.write_fixture()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write_fixture(self) -> None:
        manifest = {
            "consumer": {
                "repository": "atrinik/classic",
                "validation_commit": "e" * 40,
                "workflow": ".github/workflows/check.yml",
                "jobs": [
                    "Build native Windows tests",
                    "Native Windows security tests",
                ],
                "lock_files": [
                    "client/dependencies.lock.json",
                    "server/dependencies.lock.json",
                ],
            }
        }
        self.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        for relative, item in zip(
            ("client/dependencies.lock.json", "server/dependencies.lock.json"),
            self.dependencies,
        ):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps({"schema_version": 1, "dependencies": [item]}, indent=2) + "\n",
                encoding="utf-8",
            )

    def verify(self, api: FakeAPI | None = None) -> int:
        with mock.patch.object(MODULE, "git_head", return_value="e" * 40):
            return MODULE.verify_consumer(self.root, self.manifest, api or FakeAPI(self.dependencies))

    def test_validates_every_declared_lock_entry(self) -> None:
        self.assertEqual(self.verify(), 2)

    def test_rejects_missing_asset(self) -> None:
        api = FakeAPI(self.dependencies)
        api.releases[("atrinik/content", "v1.0.0")]["assets"] = []
        with self.assertRaisesRegex(MODULE.VerificationError, "asset is missing"):
            self.verify(api)

    def test_rejects_mismatched_asset_digest(self) -> None:
        api = FakeAPI(self.dependencies)
        api.releases[("atrinik/sound", "v1.0.3")]["assets"][0]["digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(MODULE.VerificationError, "digest"):
            self.verify(api)

    def test_rejects_tag_pointing_at_a_different_commit(self) -> None:
        api = FakeAPI(self.dependencies)
        api.tags[("atrinik/sound", "v1.0.3")] = "f" * 40
        with self.assertRaisesRegex(MODULE.VerificationError, "unexpected commit"):
            self.verify(api)

    def test_rejects_missing_declared_workflow_job(self) -> None:
        workflow = self.root / ".github/workflows/check.yml"
        workflow.write_text("name: Check\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.VerificationError, "workflow job is missing"):
            self.verify()

    def test_rejects_duplicate_lock_keys(self) -> None:
        path = self.root / "client/dependencies.lock.json"
        path.write_text(
            '{"schema_version": 1, "dependencies": [], "dependencies": []}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MODULE.VerificationError, "duplicate JSON key"):
            self.verify()

    def test_rejects_lock_url_for_a_different_tag(self) -> None:
        path = self.root / "server/dependencies.lock.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["dependencies"][0]["url"] = value["dependencies"][0]["url"].replace(
            "/v1.0.0/", "/v0.9.0/"
        )
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.VerificationError, "repository and tag"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
