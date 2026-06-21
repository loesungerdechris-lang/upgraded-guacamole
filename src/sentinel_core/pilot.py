"""Synthetic end-to-end pilot flow for SENTINEL Core.

The pilot uses only synthetic records and runtime-generated keys. It does not
persist private keys and must not be used as a production trust-registry format.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_core.hashchain import ZERO_HASH, compute_chain_link, sha256_prefixed
from sentinel_core.policy import PolicyRegistry, default_bootstrap_policy
from sentinel_core.trust import TrustKey, TrustRegistry
from sentinel_core.verifier import VerificationResult, verify_evidence_record


@dataclass(frozen=True)
class PilotResult:
    """Result of one synthetic evidence pilot run."""

    record: dict[str, Any]
    verification: VerificationResult


def _encode_urlsafe(data: bytes) -> str:
    """Encode bytes as unpadded URL-safe base64 text."""

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def build_signed_synthetic_record(*, role: str = "auditor", decision: str = "allow") -> tuple[dict[str, Any], TrustRegistry]:
    """Build one signed synthetic evidence record and matching trust registry."""

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()

    record: dict[str, Any] = {
        "schema_version": "0.1.0",
        "evidence_id": "evid-pilot-0001",
        "issued_at": "2026-06-21T00:00:00Z",
        "source": "synthetic-pilot",
        "artifact_hash": sha256_prefixed("synthetic-pilot-artifact-v1"),
        "previous_hash": ZERO_HASH,
        "policy_id": "policy.bootstrap",
        "decision": decision,
        "signature": {
            "alg": "EdDSA",
            "key_id": "synthetic-pilot-key",
            "value": "",
        },
    }

    payload = compute_chain_link(record).canonical_json.encode("utf-8")
    record["signature"]["value"] = _encode_urlsafe(private_key.sign(payload))

    trust_registry = TrustRegistry(
        [
            TrustKey(
                key_id="synthetic-pilot-key",
                alg="EdDSA",
                public_key=_encode_urlsafe(public_key),
                role=role,
                status="active",
            )
        ]
    )
    return record, trust_registry


def run_synthetic_pilot(*, role: str = "auditor", decision: str = "allow") -> PilotResult:
    """Run the full synthetic SENTINEL verification pipeline."""

    record, trust_registry = build_signed_synthetic_record(role=role, decision=decision)
    verification = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        trust_registry=trust_registry,
        require_trusted_signature=True,
        policy_registry=PolicyRegistry([default_bootstrap_policy()]),
        require_policy_authorization=True,
    )
    return PilotResult(record=record, verification=verification)
