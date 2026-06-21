import json
from pathlib import Path

import pytest

from sentinel_core.hashchain import ZERO_HASH, compute_chain_link
from sentinel_core.schema import SchemaValidationError, validate_evidence_schema
from sentinel_core.verifier import verify_evidence_record

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    with (FIXTURE_DIR / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_valid_fixture_matches_schema() -> None:
    record = load_fixture("valid_evidence.json")
    validate_evidence_schema(record)


def test_schema_violation_is_rejected() -> None:
    record = load_fixture("evidence_schema_violation.json")
    with pytest.raises(SchemaValidationError):
        validate_evidence_schema(record)


def test_verifier_accepts_valid_record() -> None:
    record = load_fixture("valid_evidence.json")
    result = verify_evidence_record(record, expected_previous_hash=ZERO_HASH)

    assert result.ok
    assert result.digest == compute_chain_link(record).digest
    assert not result.errors
    assert result.warnings


def test_verifier_rejects_wrong_previous_hash() -> None:
    record = load_fixture("evidence_wrong_previous_hash.json")
    result = verify_evidence_record(record, expected_previous_hash=ZERO_HASH)

    assert not result.ok
    assert any("previous_hash mismatch" in error for error in result.errors)


def test_verifier_rejects_schema_violation() -> None:
    record = load_fixture("evidence_schema_violation.json")
    result = verify_evidence_record(record, expected_previous_hash=ZERO_HASH)

    assert not result.ok
    assert any("Schema validation failed" in error for error in result.errors)


def test_verifier_rejects_digest_mismatch() -> None:
    record = load_fixture("valid_evidence.json")
    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        expected_digest="sha256:" + "f" * 64,
    )

    assert not result.ok
    assert any("digest mismatch" in error for error in result.errors)
