"""Check retained candidate bytes and run binding without granting release authority."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path

from sentinel_core.release_evidence import (
    build_tracked_file_records,
    sha256_file,
    tracked_paths_from_git,
)

_FILES = {
    "sentinel",
    "sentinel.sha256",
    "tracked-files.sha256.json",
    "release-evidence.json",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)


def verify_candidate_bundle(
    bundle: Path,
    *,
    expected_sha: str,
    expected_repository: str,
    expected_run_id: str,
    expected_run_attempt: str,
    repo_root: Path | None = None,
) -> None:
    """Verify consistency against caller-supplied trusted run metadata, never execute files."""

    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise ValueError("expected commit must be a full Git SHA")
    if not re.fullmatch(r"[^/\s]+/[^/\s]+", expected_repository):
        raise ValueError("expected repository must be owner/name")
    if not all(
        re.fullmatch(r"[1-9][0-9]*", value)
        for value in (expected_run_id, expected_run_attempt)
    ):
        raise ValueError("expected run identifiers must be positive integers")
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("bundle must be a regular directory")
    entries = list(bundle.iterdir())
    if {entry.name for entry in entries} != _FILES:
        raise ValueError("bundle must contain exactly the four candidate files")
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise ValueError("bundle members must be regular files without symlinks")

    manifest = _read_json(bundle / "release-evidence.json")
    if not isinstance(manifest, dict):
        raise ValueError("release evidence must be an object")
    expected = {
        "schema_version": "sentinel-release-evidence-v1",
        "repository": expected_repository,
        "commit_sha": expected_sha,
        "run_id": expected_run_id,
        "run_attempt": expected_run_attempt,
        "release_authority": "NONE_VALIDATION_ONLY",
        "result": "CANDIDATE_VALIDATED",
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise ValueError(f"release evidence mismatch: {key}")
    if manifest.get("canonical_write_allowed") is not False:
        raise ValueError("candidate must not permit canonical writes")

    for name, field in (
        ("tracked-files.sha256.json", "tracked_files_manifest_sha256"),
        ("sentinel.sha256", "binary_manifest_sha256"),
    ):
        if manifest.get(field) != sha256_file(bundle / name):
            raise ValueError(f"manifest hash mismatch: {name}")

    checksum = (bundle / "sentinel.sha256").read_text(encoding="ascii")
    match = re.fullmatch(r"([0-9a-f]{64})  sentinel\n", checksum)
    if match is None:
        raise ValueError("binary checksum must name exactly sentinel with a relative path")
    if match.group(1) != sha256_file(bundle / "sentinel"):
        raise ValueError("binary hash mismatch")

    records = _read_json(bundle / "tracked-files.sha256.json")
    if not isinstance(records, list) or not records:
        raise ValueError("tracked file records must be a nonempty list")
    names: list[str] = []
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
            raise ValueError("invalid tracked file record")
        name, digest = record["path"], record["sha256"]
        if not isinstance(name, str) or not name:
            raise ValueError("invalid tracked file path")
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or name != path.as_posix():
            raise ValueError("tracked file path must be canonical and relative")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ValueError("invalid tracked file digest")
        names.append(name)
    if names != sorted(set(names)):
        raise ValueError("tracked file paths must be sorted and unique")

    if repo_root is not None:
        actual_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo_root, text=True
        ).strip()
        if actual_sha != expected_sha:
            raise ValueError("source checkout does not match expected commit")
        if subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"], cwd=repo_root
        ):
            raise ValueError("tracked source bytes or coverage differ from expected commit")
        actual_records = build_tracked_file_records(
            repo_root, tracked_paths_from_git(repo_root)
        )
        if records != actual_records:
            raise ValueError("tracked source bytes or coverage differ")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--expected-run-attempt", required=True)
    parser.add_argument("--repo-root", type=Path)
    args = parser.parse_args(argv)
    try:
        verify_candidate_bundle(
            args.bundle,
            expected_sha=args.expected_sha,
            expected_repository=args.expected_repository,
            expected_run_id=args.expected_run_id,
            expected_run_attempt=args.expected_run_attempt,
            repo_root=args.repo_root,
        )
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Candidate bundle verification failed: {exc}\n")
    print("CANDIDATE_BUNDLE_CONSISTENT (unsigned; no release authority)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
