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
        "C:/raw/a",
        "raw/C:foo",
        "raw/file.txt:stream",
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


@pytest.mark.parametrize(
    "payload",
    [
        {"value": "high-\ud800"},
        {"value": "low-\udc00"},
        {"value": "inverted-\udc00\ud800"},
        {"hidden-\ud800-key": "value"},
    ],
)
def test_in_memory_surrogates_fail_before_hash(monkeypatch, payload):
    hash_called = False

    def forbidden_hash(*args, **kwargs):
        nonlocal hash_called
        hash_called = True
        raise AssertionError("SHA-256 must not run for invalid Unicode")

    monkeypatch.setattr(evidence_artifact.hashlib, "sha256", forbidden_hash)

    with pytest.raises(
        evidence_artifact.EvidenceArtifactValidationError,
        match="isolated Unicode surrogate",
    ):
        evidence_artifact.compute_artifact_hash(payload)

    assert hash_called is False


@pytest.mark.parametrize(
    "raw_json",
    [
        b'{"value":"\\ud800"}',
        b'{"value":"text-\\udc00"}',
        b'{"value":"\\udc00\\ud800"}',
        b'{"hidden-\\ud800-key":"value"}',
    ],
)
def test_json_escaped_surrogates_are_rejected_after_strict_parse(tmp_path, raw_json):
    artifact_path = tmp_path / "artifact.json"
    artifact_path.write_bytes(raw_json)

    with pytest.raises(
        evidence_artifact.EvidenceArtifactValidationError,
        match="isolated Unicode surrogate",
    ):
        evidence_artifact.load_evidence_artifact_json(artifact_path)


def test_invalid_raw_utf8_is_rejected_at_io_boundary(tmp_path):
    artifact_path = tmp_path / "artifact.json"
    artifact_path.write_bytes(b'{"value":"\xff"}')

    with pytest.raises(
        evidence_artifact.EvidenceArtifactValidationError,
        match="Unable to load evidence artifact JSON",
    ):
        evidence_artifact.load_evidence_artifact_json(artifact_path)


def test_valid_supplementary_unicode_scalar_is_canonicalizable():
    canonical = evidence_artifact.canonicalize_artifact_json({"value": "\U0001f600"})
    assert canonical == '{"value":"\U0001f600"}'
