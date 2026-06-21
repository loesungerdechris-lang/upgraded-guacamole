"""Deterministic hash-chain helpers for SENTINEL evidence records."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

ZERO_HASH = "sha256:" + "0" * 64


@dataclass(frozen=True)
class ChainLink:
    """Minimal immutable chain-link result."""

    canonical_json: str
    digest: str


def canonicalize_json(value: dict[str, Any]) -> str:
    """Return deterministic JSON for hashing.

    This is intentionally minimal for the bootstrap stage. A later production version
    should implement or depend on a full RFC 8785 JSON Canonicalization Scheme.
    """

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_prefixed(data: str | bytes) -> str:
    """Return a sha256 digest in SENTINEL's prefixed format."""

    if isinstance(data, str):
        data = data.encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def compute_chain_link(record: dict[str, Any]) -> ChainLink:
    """Compute the deterministic hash for an evidence record.

    The signature value is excluded from the hash input so records can be signed
    after the canonical evidence body is computed.
    """

    unsigned = dict(record)
    signature = unsigned.get("signature")
    if isinstance(signature, dict):
        unsigned["signature"] = {**signature, "value": ""}

    canonical = canonicalize_json(unsigned)
    return ChainLink(canonical_json=canonical, digest=sha256_prefixed(canonical))


def verify_previous_hash(record: dict[str, Any], expected_previous_hash: str) -> bool:
    """Check whether a record points to the expected previous chain hash."""

    return record.get("previous_hash") == expected_previous_hash
