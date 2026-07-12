from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

import sentinel_core.evidence_artifact as evidence_artifact


def test_filesystem_identity_unavailable_blocks_bytes():
    stat_result = SimpleNamespace(st_ino=0, st_dev=0)
    with pytest.raises(
        evidence_artifact.EvidenceArtifactValidationError,
        match="Stable filesystem object identity is unavailable; BYTES is blocked",
    ):
        evidence_artifact._filesystem_identity(stat_result)


@pytest.mark.parametrize(
    "bad_path",
    [
        "/raw/a",
        "raw/a/",
        "raw//a",
        "raw/./a",
        "raw/../a",
        "raw\\a",
        "raw/a\x00",
        "raw/a\x1f",
        "raw/a\x7f",
    ],
)
def test_safe_path_schema_matches_semantic_rejection(bad_path: str):
    safe_path_schema = evidence_artifact.load_evidence_artifact_schema()["$defs"][
        "safePath"
    ]
    validator = Draft202012Validator(safe_path_schema)
    assert list(validator.iter_errors(bad_path))
    with pytest.raises(evidence_artifact.EvidenceArtifactValidationError):
        evidence_artifact._validate_safe_path(bad_path)


def test_safe_path_schema_accepts_exact_posix_relative_path():
    safe_path_schema = evidence_artifact.load_evidence_artifact_schema()["$defs"][
        "safePath"
    ]
    validator = Draft202012Validator(safe_path_schema)
    assert not list(validator.iter_errors("raw/alpha.html"))
    assert evidence_artifact._validate_safe_path("raw/alpha.html") == "raw/alpha.html"
