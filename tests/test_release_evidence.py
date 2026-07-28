import hashlib
import json
from pathlib import Path

import pytest

from sentinel_core.release_evidence import build_tracked_file_records


def test_hashes_option_like_filename_as_data(tmp_path: Path) -> None:
    candidate = tmp_path / "--help"
    candidate.write_bytes(b"sentinel")

    records = build_tracked_file_records(tmp_path, ["--help"])

    assert records == [
        {
            "path": "--help",
            "sha256": hashlib.sha256(b"sentinel").hexdigest(),
        }
    ]
    json.dumps(records)


def test_rejects_path_escape(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="inside the repository"):
        build_tracked_file_records(tmp_path, ["../outside"])


def test_rejects_missing_tracked_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a regular file"):
        build_tracked_file_records(tmp_path, ["missing.txt"])
