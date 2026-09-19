from __future__ import annotations

import base64
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from sentinel_core.live_evidence import LiveEvidenceError, PublicKeyMetadata

KEY_ID = (
    "https://sentinel-evidence.vault.azure.net/keys/"
    "sentinel-receipt-es256/0123456789abcdef0123456789abcdef"
)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _valid_mapping() -> dict[str, Any]:
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    return {
        "kid": KEY_ID,
        "kty": "EC",
        "crv": "P-256",
        "key_ops": ["sign", "verify"],
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }


@pytest.mark.parametrize(
    "mutation",
    [
        {"d": _b64url(b"\x01" * 32)},
        {"private_key": "must-not-be-accepted"},
        {"unexpected": {"nested": "value"}},
    ],
)
def test_rejects_private_or_unknown_metadata_fields(mutation: dict[str, Any]) -> None:
    metadata = _valid_mapping()
    metadata.update(mutation)

    with pytest.raises(
        LiveEvidenceError,
        match="exactly the approved public fields",
    ):
        PublicKeyMetadata.from_mapping(metadata)


@pytest.mark.parametrize("missing_field", ["kid", "kty", "crv", "key_ops", "x", "y"])
def test_rejects_missing_public_metadata_fields(missing_field: str) -> None:
    metadata = _valid_mapping()
    metadata.pop(missing_field)

    with pytest.raises(
        LiveEvidenceError,
        match="exactly the approved public fields",
    ):
        PublicKeyMetadata.from_mapping(metadata)
