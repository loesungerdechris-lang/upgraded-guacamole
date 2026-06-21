"""Minimal public-key verification helpers for SENTINEL.

This module contains verification code only. It must never contain private keys,
seed values, production trust anchors, or real evidence material.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sentinel_core.hashchain import compute_chain_link


class CryptoVerificationError(ValueError):
    """Raised when public-key verification fails."""


def decode_urlsafe(value: str) -> bytes:
    """Decode unpadded URL-safe base64 text."""

    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def verify_eddsa_record(record: dict[str, Any], public_key: str) -> None:
    """Verify an EdDSA/Ed25519 evidence record signature."""

    sig = record.get("signature")
    if not isinstance(sig, dict):
        raise CryptoVerificationError("missing signature object")
    if sig.get("alg") != "EdDSA":
        raise CryptoVerificationError("unsupported signature algorithm")

    value = sig.get("value")
    if not isinstance(value, str) or not value:
        raise CryptoVerificationError("missing signature value")

    try:
        key = Ed25519PublicKey.from_public_bytes(decode_urlsafe(public_key))
        payload = compute_chain_link(record).canonical_json.encode("utf-8")
        key.verify(decode_urlsafe(value), payload)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise CryptoVerificationError("signature verification failed") from exc
