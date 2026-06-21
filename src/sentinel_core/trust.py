"""Trust registry primitives for SENTINEL verifier stages 2 and 4."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

KeyStatus = Literal["active", "revoked", "expired"]
TrustRole = Literal["sensor", "auditor", "authority", "admin"]


@dataclass(frozen=True)
class TrustKey:
    """Public trust-key metadata.

    The registry stores public material and authorization metadata only. Private
    signing material must never be committed to the repository.
    """

    key_id: str
    alg: str
    public_key: str
    role: TrustRole
    status: KeyStatus = "active"
    not_before: str | None = None
    not_after: str | None = None


class TrustRegistryError(ValueError):
    """Raised when a key cannot be trusted for verification."""


class TrustRegistry:
    """Small in-memory trust registry for deterministic tests and local verification."""

    def __init__(self, keys: list[TrustKey] | None = None) -> None:
        self._keys = {key.key_id: key for key in keys or []}

    def add(self, key: TrustKey) -> None:
        """Add or replace one public trust key."""

        self._keys[key.key_id] = key

    def resolve_active_key(self, key_id: str, alg: str) -> TrustKey:
        """Resolve a key and require matching algorithm plus active status."""

        key = self._keys.get(key_id)
        if key is None:
            raise TrustRegistryError(f"unknown key_id: {key_id}")
        if key.alg != alg:
            raise TrustRegistryError(f"algorithm mismatch for {key_id}: expected {key.alg}, got {alg}")
        if key.status != "active":
            raise TrustRegistryError(f"key_id {key_id} is not active: {key.status}")
        return key
