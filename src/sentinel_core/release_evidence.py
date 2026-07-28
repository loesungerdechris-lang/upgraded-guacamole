"""Deterministic hashing of every Git-tracked release-candidate file."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path

_CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path) -> str:
    """Return the lowercase SHA-256 digest of one file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validated_relative_path(value: str) -> Path:
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"tracked path must stay inside the repository: {value!r}")
    return path


def build_tracked_file_records(
    repo_root: Path,
    tracked_paths: Iterable[str],
) -> list[dict[str, str]]:
    """Build deterministic hash records for supplied Git-relative paths."""

    root = repo_root.resolve()
    records: list[dict[str, str]] = []
    for raw_path in sorted(set(tracked_paths)):
        relative = _validated_relative_path(raw_path)
        full_path = root / relative
        if not full_path.is_file():
            raise ValueError(f"tracked path is not a regular file: {raw_path!r}")
        records.append(
            {
                "path": raw_path,
                "sha256": sha256_file(full_path),
            }
        )
    return records


def tracked_paths_from_git(repo_root: Path) -> list[str]:
    """Read the exact tracked path set from Git using NUL delimiters."""

    raw = subprocess.check_output(
        ["git", "ls-files", "-z"],
        cwd=repo_root,
    )
    return [os.fsdecode(item) for item in raw.split(b"\0") if item]


def write_tracked_file_manifest(repo_root: Path, output: Path) -> None:
    """Write a canonical JSON manifest for every tracked file."""

    records = build_tracked_file_records(repo_root, tracked_paths_from_git(repo_root))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(records, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Generate the tracked-file evidence manifest."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    write_tracked_file_manifest(args.repo_root, args.output)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
