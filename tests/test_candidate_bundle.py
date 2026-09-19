import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from sentinel_core.candidate_bundle import verify_candidate_bundle
from sentinel_core.release_evidence import sha256_file, write_tracked_file_manifest

_CONTEXT = {
    "expected_sha": "a" * 40,
    "expected_repository": "example/sentinel",
    "expected_run_id": "123",
    "expected_run_attempt": "1",
}


def _manifest(bundle: Path, **changes: object) -> None:
    value = {
        "schema_version": "sentinel-release-evidence-v1",
        "repository": _CONTEXT["expected_repository"],
        "commit_sha": _CONTEXT["expected_sha"],
        "run_id": _CONTEXT["expected_run_id"],
        "run_attempt": _CONTEXT["expected_run_attempt"],
        "release_authority": "NONE_VALIDATION_ONLY",
        "canonical_write_allowed": False,
        "result": "CANDIDATE_VALIDATED",
        "tracked_files_manifest_sha256": sha256_file(bundle / "tracked-files.sha256.json"),
        "binary_manifest_sha256": sha256_file(bundle / "sentinel.sha256"),
    }
    value.update(changes)
    (bundle / "release-evidence.json").write_text(json.dumps(value), encoding="utf-8")


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "sentinel").write_bytes(b"synthetic candidate, never executed")
    (root / "sentinel.sha256").write_text(
        f"{sha256_file(root / 'sentinel')}  sentinel\n", encoding="ascii"
    )
    (root / "tracked-files.sha256.json").write_text(
        json.dumps([{"path": "README.md", "sha256": hashlib.sha256(b"source").hexdigest()}]),
        encoding="utf-8",
    )
    _manifest(root)
    return root


def test_accepts_intact_candidate_in_a_different_directory(bundle: Path, tmp_path: Path) -> None:
    moved = tmp_path / "downloaded"
    bundle.rename(moved)
    verify_candidate_bundle(moved, **_CONTEXT)


@pytest.mark.parametrize(
    "filename",
    ["sentinel", "sentinel.sha256", "tracked-files.sha256.json"],
)
def test_rejects_tampered_candidate_bytes(bundle: Path, filename: str) -> None:
    with (bundle / filename).open("ab") as handle:
        handle.write(b"tampered")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_candidate_bundle(bundle, **_CONTEXT)


@pytest.mark.parametrize(
    "field,value",
    [
        ("commit_sha", "b" * 40),
        ("repository", "other/repo"),
        ("run_id", "456"),
        ("run_attempt", "2"),
        ("release_authority", "PRODUCTION"),
        ("canonical_write_allowed", True),
        ("canonical_write_allowed", 0),
        ("result", "RC_VERIFIED"),
    ],
)
def test_rejects_wrong_run_binding_or_authority(bundle: Path, field: str, value: object) -> None:
    _manifest(bundle, **{field: value})
    with pytest.raises(ValueError):
        verify_candidate_bundle(bundle, **_CONTEXT)


def test_rejects_extra_file_before_upload(bundle: Path) -> None:
    (bundle / ".env").write_text("synthetic", encoding="utf-8")
    with pytest.raises(ValueError, match="exactly the four"):
        verify_candidate_bundle(bundle, **_CONTEXT)


def test_rejects_symlink_member(bundle: Path, tmp_path: Path) -> None:
    target = tmp_path / "outside"
    (bundle / "sentinel").rename(target)
    (bundle / "sentinel").symlink_to(target)
    with pytest.raises(ValueError, match="without symlinks"):
        verify_candidate_bundle(bundle, **_CONTEXT)


def test_rejects_missing_binary(bundle: Path) -> None:
    (bundle / "sentinel").unlink()
    with pytest.raises(ValueError, match="exactly the four"):
        verify_candidate_bundle(bundle, **_CONTEXT)


def test_rejects_nonportable_checksum_even_when_manifest_matches(bundle: Path) -> None:
    checksum = bundle / "sentinel.sha256"
    checksum.write_text(f"{sha256_file(bundle / 'sentinel')}  /tmp/sentinel\n", encoding="ascii")
    _manifest(bundle)
    with pytest.raises(ValueError, match="relative path"):
        verify_candidate_bundle(bundle, **_CONTEXT)


def test_rejects_tracked_path_escape_even_when_manifest_matches(bundle: Path) -> None:
    (bundle / "tracked-files.sha256.json").write_text(
        json.dumps([{"path": "../outside", "sha256": "a" * 64}]), encoding="utf-8"
    )
    _manifest(bundle)
    with pytest.raises(ValueError, match="canonical and relative"):
        verify_candidate_bundle(bundle, **_CONTEXT)


def test_rejects_duplicate_json_members(bundle: Path) -> None:
    path = bundle / "release-evidence.json"
    text = path.read_text(encoding="utf-8")
    path.write_text(text[:-1] + ', "run_id": "123"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON"):
        verify_candidate_bundle(bundle, **_CONTEXT)


def test_compares_full_source_coverage_and_bytes(bundle: Path, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    (source / "README.md").write_text("source", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "commit", "-qm", "synthetic source"],
        cwd=source, check=True,
    )
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    write_tracked_file_manifest(source, bundle / "tracked-files.sha256.json")
    _manifest(bundle, commit_sha=commit)
    context = {**_CONTEXT, "expected_sha": commit}
    verify_candidate_bundle(bundle, **context, repo_root=source)
    (source / "README.md").write_text("tampered source", encoding="utf-8")
    with pytest.raises(ValueError, match="source bytes or coverage"):
        verify_candidate_bundle(bundle, **context, repo_root=source)
