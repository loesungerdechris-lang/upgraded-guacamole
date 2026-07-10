from __future__ import annotations

import base64
from typing import Any

from sentinel_core.external_signing import (
    ExternalSignatureResult,
    finalize_receipt_signature,
    prepare_receipt_signature,
)

ZERO_HASH = "sha256:" + "0" * 64
KEY_ID = (
    "https://sentinel-test.vault.azure.net/keys/"
    "sentinel-receipt-es256/0123456789abcdef0123456789abcdef"
)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unicode_receipt() -> dict[str, Any]:
    return {
        "schema_version": "sentinel.receipt.v1",
        "receipt_id": "REC-UNICODE-0001",
        "receipt_type": "release_receipt",
        "subject": {
            "entity_type": "release_artifact",
            "entity_id": "café-東京",
        },
        "created_at": "2026-07-10T08:00:00.000Z",
        "release_class": "B",
        "policy": {
            "policy_id": "sentinel.external-signing",
            "policy_version": "1.0.0",
            "required_roles": ["release_signer"],
            "min_signatures": 1,
        },
        "evidence": {
            "artifact_hash": "sha256:" + "1" * 64,
            "source_commit": "05aa7df1bae9934ce2ad052fc3d08e43e081b023",
            "pipeline_run_id": "run-unicode-001",
            "artifact_path": "dist/überblick.json",
        },
        "chain": {
            "sequence": 1,
            "previous_hash": ZERO_HASH,
            "receipt_hash": "",
        },
        "signatures": [],
    }


def test_finalizes_valid_unicode_receipt_without_type_error() -> None:
    receipt = _unicode_receipt()
    prepared = prepare_receipt_signature(
        receipt,
        key_id=KEY_ID,
        signer_role="release_signer",
    )
    result = ExternalSignatureResult(
        algorithm="ES256",
        key_id=KEY_ID,
        signature_b64url=_b64url_encode(b"\x01" * 64),
    )

    signed = finalize_receipt_signature(receipt, prepared=prepared, result=result)

    assert signed["subject"]["entity_id"] == "café-東京"
    assert signed["evidence"]["artifact_path"] == "dist/überblick.json"
    assert len(signed["signatures"]) == 1
