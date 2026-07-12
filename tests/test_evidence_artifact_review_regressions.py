import os
import runpy
from pathlib import Path
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
        "raw/file.",
        "raw/file ",
        "raw/CON",
        "raw/con.txt",
        "raw/PRN",
        "raw/AUX.log",
        "raw/NUL",
        "raw/COM1",
        "raw/com9.bin",
        "raw/LPT1",
        "raw/lpt9.txt",
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


def test_duplicate_descriptor_path_is_rejected_for_bindings():
    helpers = runpy.run_path(str(Path(__file__).with_name("test_evidence_artifact.py")))
    value = helpers["make_artifact"]()
    value["members"][1]["path"] = "raw/alpha.html"
    helpers["rebind_members"](value)

    result = evidence_artifact.verify_evidence_artifact(value)

    assert result.integrity_valid is False
    assert result.level == "NONE"
    assert "Duplicate evidence bundle descriptor path" in result.issues[0].message


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


def test_json_size_limit_is_enforced_during_read(tmp_path):
    artifact_path = tmp_path / "artifact.json"
    artifact_path.write_bytes(b'{"value":"0123456789"}')

    with pytest.raises(
        evidence_artifact.EvidenceArtifactValidationError,
        match="Evidence artifact JSON exceeds size limit",
    ):
        evidence_artifact.load_evidence_artifact_json(artifact_path, max_bytes=8)


@pytest.mark.parametrize("invalid_limit", [0, -1, True])
def test_json_size_limit_must_be_positive_integer(tmp_path, invalid_limit):
    artifact_path = tmp_path / "artifact.json"
    artifact_path.write_bytes(b"{}")

    with pytest.raises(
        evidence_artifact.EvidenceArtifactValidationError,
        match="size limit must be a positive integer",
    ):
        evidence_artifact.load_evidence_artifact_json(
            artifact_path,
            max_bytes=invalid_limit,
        )


def test_json_loader_rejects_non_regular_input():
    device = Path("/dev/null")
    if not device.exists():
        pytest.skip("No safe non-regular test input is available")

    with pytest.raises(
        evidence_artifact.EvidenceArtifactValidationError,
        match="Evidence artifact JSON input must be a regular file",
    ):
        evidence_artifact.load_evidence_artifact_json(device)


def test_json_loader_rejects_fifo_without_blocking(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable")
    fifo = tmp_path / "artifact.fifo"
    os.mkfifo(fifo)

    with pytest.raises(
        evidence_artifact.EvidenceArtifactValidationError,
        match="Evidence artifact JSON input must be a regular file",
    ):
        evidence_artifact.load_evidence_artifact_json(fifo)


def test_json_loader_does_not_follow_final_symlink(tmp_path):
    target = tmp_path / "target.json"
    target.write_bytes(b"{}")
    link = tmp_path / "artifact.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(
        evidence_artifact.EvidenceArtifactValidationError,
        match="Unable to open evidence input safely",
    ):
        evidence_artifact.load_evidence_artifact_json(link)


def test_bundle_open_does_not_follow_final_symlink(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    target = tmp_path / "target.bin"
    target.write_bytes(b"alpha")
    link = raw / "alpha.html"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(
        evidence_artifact.EvidenceArtifactValidationError,
        match="Unable to open bundle member safely",
    ):
        evidence_artifact._open_bundle_member_nofollow(
            tmp_path,
            "raw/alpha.html",
        )


def test_valid_supplementary_unicode_scalar_is_canonicalizable():
    canonical = evidence_artifact.canonicalize_artifact_json({"value": "\U0001f600"})
    assert canonical == '{"value":"\U0001f600"}'
