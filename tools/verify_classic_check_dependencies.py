#!/usr/bin/env python3
"""Verify every release asset declared by the pinned Classic consumer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Iterable
import urllib.parse


MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_DEPENDENCIES = 32
MAX_TAG_DEPTH = 8
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
TAG_RE = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
LOCK_KEYS = {
    "schema_version",
    "dependencies",
}
DEPENDENCY_KEYS = {
    "name",
    "repository",
    "tag",
    "commit",
    "url",
    "sha256",
    "destination",
    "strip_components",
}


class VerificationError(RuntimeError):
    """A Classic consumer coordinate failed closed verification."""


def reject_duplicate_keys(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path, context: str) -> object:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise VerificationError(f"cannot read {context}: {error}") from error
    if len(data) > MAX_JSON_BYTES:
        raise VerificationError(f"{context} exceeds the JSON size limit")
    try:
        return json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{context} is not valid UTF-8 JSON: {error}") from error


def require_keys(value: dict[str, object], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        raise VerificationError(f"{context}: {'; '.join(details)}")


def load_manifest(path: Path) -> dict[str, object]:
    value = load_json(path, "Classic Check toolchain manifest")
    if not isinstance(value, dict):
        raise VerificationError("Classic Check toolchain manifest must be an object")
    consumer = value.get("consumer")
    if not isinstance(consumer, dict):
        raise VerificationError("Classic Check toolchain manifest has no consumer object")
    require_keys(
        consumer,
        {"repository", "validation_commit", "workflow", "jobs", "lock_files"},
        "consumer",
    )
    if consumer["repository"] != "atrinik/classic":
        raise VerificationError("consumer.repository must be atrinik/classic")
    if not isinstance(consumer["validation_commit"], str) or not COMMIT_RE.fullmatch(
        consumer["validation_commit"]
    ):
        raise VerificationError("consumer.validation_commit must be a full lowercase commit")
    workflow = consumer["workflow"]
    if not isinstance(workflow, str) or not safe_relative_path(workflow):
        raise VerificationError("consumer.workflow must be a safe relative path")
    jobs = consumer["jobs"]
    if (
        not isinstance(jobs, list)
        or not jobs
        or any(
            not isinstance(job, str)
            or job != job.strip()
            or not job
            or "\r" in job
            or "\n" in job
            for job in jobs
        )
        or len(set(jobs)) != len(jobs)
    ):
        raise VerificationError("consumer.jobs must be a non-empty unique string list")
    lock_files = consumer["lock_files"]
    if (
        not isinstance(lock_files, list)
        or lock_files != [
            "client/dependencies.lock.json",
            "server/dependencies.lock.json",
        ]
        or any(not isinstance(path, str) or not safe_relative_path(path) for path in lock_files)
    ):
        raise VerificationError(
            "consumer.lock_files must name the client and server dependency locks"
        )
    return consumer


def safe_relative_path(value: str) -> bool:
    if not value or "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return (
        value == path.as_posix()
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def resolved_child(root: Path, relative: str, context: str) -> Path:
    if not safe_relative_path(relative):
        raise VerificationError(f"{context} is not a safe relative path")
    try:
        root = root.resolve(strict=True)
        candidate = (root / PurePosixPath(relative)).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise VerificationError(f"{context} cannot be resolved: {error}") from error
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise VerificationError(f"{context} escapes the Classic checkout") from error
    if not candidate.is_file():
        raise VerificationError(f"{context} is not a regular file")
    return candidate


def load_lock(path: Path) -> list[dict[str, object]]:
    value = load_json(path, str(path))
    if not isinstance(value, dict):
        raise VerificationError(f"{path}: lock root must be an object")
    require_keys(value, LOCK_KEYS, f"{path}: lock root")
    if value["schema_version"] != 1:
        raise VerificationError(f"{path}: unsupported lock schema version")
    dependencies = value["dependencies"]
    if not isinstance(dependencies, list) or not dependencies:
        raise VerificationError(f"{path}: dependencies must be a non-empty array")
    if len(dependencies) > MAX_DEPENDENCIES:
        raise VerificationError(f"{path}: dependency count exceeds the bounded limit")

    names: set[str] = set()
    result: list[dict[str, object]] = []
    for index, item in enumerate(dependencies):
        context = f"{path}: dependency {index}"
        if not isinstance(item, dict):
            raise VerificationError(f"{context} must be an object")
        require_keys(item, DEPENDENCY_KEYS, context)
        name = item["name"]
        repository = item["repository"]
        tag = item["tag"]
        commit = item["commit"]
        url = item["url"]
        digest = item["sha256"]
        destination = item["destination"]
        strip_components = item["strip_components"]
        if not isinstance(name, str) or not NAME_RE.fullmatch(name) or name in names:
            raise VerificationError(f"{context}.name is malformed or duplicated")
        names.add(name)
        if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
            raise VerificationError(f"{context}.repository is malformed")
        if any(part in {".", ".."} for part in repository.split("/")):
            raise VerificationError(f"{context}.repository is malformed")
        if not isinstance(tag, str) or not TAG_RE.fullmatch(tag):
            raise VerificationError(f"{context}.tag is not a canonical release tag")
        if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
            raise VerificationError(f"{context}.commit is not a full lowercase commit")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise VerificationError(f"{context}.sha256 is not a lowercase SHA-256")
        if not isinstance(destination, str) or not safe_relative_path(destination):
            raise VerificationError(f"{context}.destination is unsafe")
        if (
            not isinstance(strip_components, int)
            or isinstance(strip_components, bool)
            or not 1 <= strip_components <= 8
        ):
            raise VerificationError(f"{context}.strip_components is outside the supported range")
        if not isinstance(url, str):
            raise VerificationError(f"{context}.url must be a string")
        try:
            parsed = urllib.parse.urlsplit(url)
            parsed_port = parsed.port
        except ValueError as error:
            raise VerificationError(f"{context}.url is not a canonical GitHub HTTPS URL") from error
        if (
            parsed.scheme != "https"
            or parsed.netloc != "github.com"
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
            or parsed_port is not None
        ):
            raise VerificationError(f"{context}.url must be a canonical GitHub HTTPS URL")
        prefix = f"/{repository}/releases/download/{tag}/"
        if not parsed.path.startswith(prefix):
            raise VerificationError(f"{context}.url does not match its repository and tag")
        asset_name = parsed.path[len(prefix) :]
        if (
            not asset_name
            or "/" in asset_name
            or not asset_name.endswith(".tar.gz")
            or urllib.parse.unquote(asset_name) != asset_name
            or asset_name != urllib.parse.quote(asset_name, safe="-._~")
        ):
            raise VerificationError(f"{context}.url has a non-canonical asset name")
        result.append(item)
    return result


def run_json(arguments: list[str]) -> object:
    result = subprocess.run(
        arguments,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if len(result.stdout) > MAX_JSON_BYTES or len(result.stderr) > MAX_JSON_BYTES:
        raise VerificationError("GitHub API response exceeds the bounded output limit")
    if result.returncode:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        endpoint = arguments[-1] if arguments else "unknown endpoint"
        raise VerificationError(
            f"GitHub API request failed for {endpoint}: {message or 'unknown error'}"
        )
    try:
        return json.loads(result.stdout, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"GitHub API returned invalid JSON: {error}") from error


class GitHubAPI:
    """Use the runner's authenticated gh CLI without a shell."""

    def __init__(self) -> None:
        self._releases: dict[tuple[str, str], dict[str, object]] = {}
        self._tag_commits: dict[tuple[str, str], str] = {}

    def get(self, endpoint: str) -> object:
        return run_json(["gh", "api", "--method", "GET", endpoint])

    def release(self, repository: str, tag: str) -> dict[str, object]:
        key = (repository, tag)
        if key not in self._releases:
            value = self.get(f"repos/{repository}/releases/tags/{tag}")
            if not isinstance(value, dict):
                raise VerificationError(f"{repository}@{tag}: release response is not an object")
            self._releases[key] = value
        return self._releases[key]

    def tag_commit(self, repository: str, tag: str) -> str:
        key = (repository, tag)
        if key in self._tag_commits:
            return self._tag_commits[key]
        value = self.get(f"repos/{repository}/git/ref/tags/{tag}")
        seen: set[str] = set()
        for _ in range(MAX_TAG_DEPTH):
            if not isinstance(value, dict) or not isinstance(value.get("object"), dict):
                raise VerificationError(f"{repository}@{tag}: malformed tag response")
            target = value["object"]
            target_type = target.get("type")
            sha = target.get("sha")
            if not isinstance(sha, str) or not COMMIT_RE.fullmatch(sha):
                raise VerificationError(f"{repository}@{tag}: malformed tag target")
            if target_type == "commit":
                self._tag_commits[key] = sha
                return sha
            if target_type != "tag" or sha in seen:
                raise VerificationError(f"{repository}@{tag}: unsupported or cyclic tag")
            seen.add(sha)
            value = self.get(f"repos/{repository}/git/tags/{sha}")
        raise VerificationError(f"{repository}@{tag}: annotated tag chain is too deep")


def git_head(classic_root: Path) -> str:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(classic_root),
            "rev-parse",
            "--verify",
            "--end-of-options",
            "HEAD^{commit}",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode or not COMMIT_RE.fullmatch(result.stdout.strip()):
        raise VerificationError("Classic checkout HEAD is unavailable")
    return result.stdout.strip()


def verify_layout(classic_root: Path, consumer: dict[str, object]) -> None:
    actual = git_head(classic_root)
    expected = consumer["validation_commit"]
    if actual != expected:
        raise VerificationError(f"Classic checkout is at {actual}, expected {expected}")
    workflow = resolved_child(classic_root, str(consumer["workflow"]), "consumer.workflow")
    try:
        workflow_text = workflow.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise VerificationError(f"consumer.workflow cannot be read: {error}") from error
    workflow_names = {
        line.strip()[len("name: ") :]
        for line in workflow_text.splitlines()
        if line.strip().startswith("name: ")
    }
    for job in consumer["jobs"]:  # type: ignore[union-attr]
        if job not in workflow_names:
            raise VerificationError(f"declared Classic workflow job is missing: {job}")
    for required in ("client/tools/dependencies.py",):
        resolved_child(classic_root, required, required)


def verify_release(
    dependency: dict[str, object], api: GitHubAPI, context: str
) -> None:
    repository = str(dependency["repository"])
    tag = str(dependency["tag"])
    try:
        release = api.release(repository, tag)
    except VerificationError as error:
        raise VerificationError(f"{context}: release lookup failed: {error}") from error
    if (
        release.get("tag_name") != tag
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or not isinstance(release.get("published_at"), str)
        or not release["published_at"]
    ):
        raise VerificationError(f"{context}: release is not published and immutable")
    assets = release.get("assets")
    if not isinstance(assets, list) or len(assets) > 1024:
        raise VerificationError(f"{context}: release assets are malformed or unbounded")
    asset_name = str(urllib.parse.urlsplit(str(dependency["url"])).path.rsplit("/", 1)[1])
    matches = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == asset_name]
    if len(matches) != 1 or not isinstance(matches[0], dict):
        raise VerificationError(f"{context}: declared release asset is missing or duplicated")
    asset = matches[0]
    if (
        asset.get("browser_download_url") != dependency["url"]
        or asset.get("state") != "uploaded"
        or not isinstance(asset.get("size"), int)
        or isinstance(asset["size"], bool)
        or asset["size"] < 1
        or asset.get("digest") != f"sha256:{dependency['sha256']}"
    ):
        raise VerificationError(f"{context}: release asset URL, state, size, or digest mismatches lock")
    try:
        actual_commit = api.tag_commit(repository, tag)
    except VerificationError as error:
        raise VerificationError(f"{context}: tag lookup failed: {error}") from error
    if actual_commit != dependency["commit"]:
        raise VerificationError(f"{context}: release tag resolves to an unexpected commit")


def verify_consumer(classic_root: Path, manifest_path: Path, api: GitHubAPI) -> int:
    classic_root = classic_root.resolve(strict=True)
    consumer = load_manifest(manifest_path)
    verify_layout(classic_root, consumer)
    dependencies: list[dict[str, object]] = []
    for relative in consumer["lock_files"]:  # type: ignore[union-attr]
        lock_path = resolved_child(classic_root, str(relative), f"consumer.lock_files entry {relative}")
        dependencies.extend(load_lock(lock_path))
    if not dependencies or len(dependencies) > MAX_DEPENDENCIES:
        raise VerificationError("combined Classic dependency count is outside the bounded limit")
    seen: set[tuple[str, str, str, str, str]] = set()
    for dependency in dependencies:
        coordinate = (
            str(dependency["repository"]),
            str(dependency["tag"]),
            str(dependency["commit"]),
            str(dependency["url"]),
            str(dependency["sha256"]),
        )
        if coordinate in seen:
            continue
        seen.add(coordinate)
        verify_release(dependency, api, f"{dependency['repository']}@{dependency['tag']}")
    return len(dependencies)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify pinned Classic dependency tags, assets, commits, and digests."
    )
    parser.add_argument("classic_checkout", type=Path)
    parser.add_argument("toolchain_manifest", type=Path)
    args = parser.parse_args(argv)
    try:
        count = verify_consumer(args.classic_checkout, args.toolchain_manifest, GitHubAPI())
    except (OSError, UnicodeError, VerificationError) as error:
        print(f"Classic dependency verification failed: {error}", file=sys.stderr)
        return 1
    print(f"Verified {count} Classic dependency lock entries before image publication.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
