from __future__ import annotations

from typing import Any

from sentinel_core.receipt import receipt_hash, verify_receipt

ZERO_HASH = "sha256:" + "0" * 64


def _receipt(*, sequence: Any = 1, previous_hash: str = ZERO_HASH) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "schema_version": "sentinel.receipt.v1",
        "receipt_id": "REC-CANONICAL-CHAIN-0001",
        "receipt_type": "release_receipt",
        "subject": {
            "entity_type": "release_artifact",
            "entity_id": "canonical-chain-hardening",
        },
        "created_at": "2026-07-10T08:00:00.000Z",
        "release_class": "B",
        "policy": {
            "policy_id": "sentinel.release-control",
            "policy_version": "1.0.0",
            "required_roles": [],
            "min_signatures": 1,
        },
        "evidence": {
            "artifact_hash": "sha256:" + "1" * 64,
            "source_commit": "canonical-chain-hardening",
            "pipeline_run_id": "test-canonical-chain",
            "artifact_path": "dist/release.pdf",
        },
        "chain": {
            "sequence": sequence,
            "previous_hash": previous_hash,
            "receipt_hash": "",
        },
        "signatures": [],
    }
    receipt["chain"]["receipt_hash"] = receipt_hash(receipt)
    return receipt


def _codes(result: Any) -> set[str]:
    return {issue.code for issue in result.issues}


def test_rejects_boolean_chain_sequence() -> None:
    result = verify_receipt(
        _receipt(sequence=True),
        trust_registry={"unused-key": {"status": "active"}},
    )

    assert result.status == "NOT_VERIFIED"
    assert "CHAIN_SEQUENCE_INVALID" in _codes(result)


def test_rejects_uppercase_previous_hash_digest() -> None:
    result = verify_receipt(
        _receipt(previous_hash="sha256:" + "A" * 64),
        trust_registry={"unused-key": {"status": "active"}},
    )

    assert result.status == "NOT_VERIFIED"
    assert "PREVIOUS_HASH_INVALID" in _codes(result)
