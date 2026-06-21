"""Trust registry primitives for SENTINEL verifier stages 2, 4 and 5."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
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


def parse_rfc3339_utc(value: str) -> datetime:
    """Parse an RFC3339 timestamp and normalize it to UTC."""

    normalized = value.replace("Z", "+00:00") if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise TrustRegistryError(f"invalid RFC3339 timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise TrustRegistryError(f"timestamp must include timezone: {value}")
    return parsed.astimezone(timezone.utc)


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

    def resolve_active_key_at(self, key_id: str, alg: str, issued_at: str) -> TrustKey:
        """Resolve an active key and require that it was valid at issued_at."""

        key = self.resolve_active_key(key_id, alg)
        issued = parse_rfc3339_utc(issued_at)

        if key.not_before is not None:
            not_before = parse_rfc3339_utc(key.not_before)
            if issued < not_before:
                raise TrustRegistryError(
                    f"key_id {key_id} is not valid before {key.not_before}: issued_at {issued_at}"
                )

        if key.not_after is not None:
            not_after = parse_rfc3339_utc(key.not_after)
            if issued > not_after:
                raise TrustRegistryError(
                    f"key_id {key_id} is not valid after {key.not_after}: issued_at {issued_at}"
                )

        return key
