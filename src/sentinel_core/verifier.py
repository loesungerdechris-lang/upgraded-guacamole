"""Verifier for SENTINEL evidence records.

Stage 1 verifies structure and hash-chain integrity. Stage 2 can additionally
verify public-key signatures through an explicit trust registry. Stage 3 adds
policy authorization. Stage 4 binds authorization to the verified TrustKey role.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel_core.crypto import CryptoVerificationError, verify_eddsa_record
from sentinel_core.hashchain import ZERO_HASH, compute_chain_link
from sentinel_core.policy import PolicyError, PolicyRegistry, authorize_record
from sentinel_core.schema import SchemaValidationError, validate_evidence_schema
from sentinel_core.trust import TrustKey, TrustRegistry, TrustRegistryError


@dataclass(frozen=True)
class VerificationResult:
    """Machine-readable verifier outcome."""

    ok: bool
    digest: str | None = None
    errors: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    actor_role: str | None = None
    key_id: str | None = None


def verify_evidence_record(
    record: dict[str, Any],
    *,
    expected_previous_hash: str = ZERO_HASH,
    expected_digest: str | None = None,
    require_signature_value: bool = True,
    trust_registry: TrustRegistry | None = None,
    require_trusted_signature: bool = False,
    policy_registry: PolicyRegistry | None = None,
    actor_role: str | None = None,
    require_policy_authorization: bool = False,
) -> VerificationResult:
    """Verify one evidence record.

    Checks:
    - JSON Schema conformance
    - previous_hash chain continuity
    - deterministic digest computation
    - optional expected digest match
    - signature value presence
    - optional trusted EdDSA/Ed25519 signature verification
    - optional policy authorization derived from the verified TrustKey role

    `actor_role` is retained only for legacy Stage-3 compatibility when no
    TrustRegistry is supplied. When a TrustKey is resolved, its embedded role is
    authoritative and overrides any manual role input.
    """

    errors: list[str] = []
    warnings: list[str] = []
    digest: str | None = None
    resolved_trust_key: TrustKey | None = None
    resolved_key_id: str | None = None
    resolved_actor_role: str | None = None

    try:
        validate_evidence_schema(record)
    except SchemaValidationError as exc:
        errors.append(str(exc))

    previous_hash = record.get("previous_hash")
    if previous_hash != expected_previous_hash:
        errors.append(
            f"previous_hash mismatch: expected {expected_previous_hash}, got {previous_hash}"
        )

    try:
        digest = compute_chain_link(record).digest
    except Exception as exc:  # pragma: no cover - defensive boundary
        errors.append(f"digest computation failed: {exc}")

    if expected_digest is not None and digest != expected_digest:
        errors.append(f"digest mismatch: expected {expected_digest}, got {digest}")

    signature = record.get("signature")
    signature_value = signature.get("value") if isinstance(signature, dict) else None
    if require_signature_value and not signature_value:
        errors.append("signature.value is required")

    if trust_registry is None:
        if require_trusted_signature:
            errors.append("trusted signature verification requested without trust registry")
        else:
            warnings.append("cryptographic signature verification not requested")
    elif not isinstance(signature, dict):
        errors.append("signature object is required for trusted verification")
    else:
        key_id = signature.get("key_id")
        alg = signature.get("alg")
        if not isinstance(key_id, str) or not isinstance(alg, str):
            errors.append("signature.key_id and signature.alg are required")
        else:
            try:
                trust_key = trust_registry.resolve_active_key(key_id, alg)
                resolved_trust_key = trust_key
                resolved_key_id = trust_key.key_id
                resolved_actor_role = trust_key.role
                if trust_key.alg == "EdDSA":
                    verify_eddsa_record(record, trust_key.public_key)
                else:
                    errors.append(f"unsupported trusted signature algorithm: {trust_key.alg}")
            except (TrustRegistryError, CryptoVerificationError) as exc:
                errors.append(str(exc))

    if policy_registry is None:
        if require_policy_authorization:
            errors.append("policy authorization requested without policy registry")
        else:
            warnings.append("policy authorization not requested")
    else:
        policy_role = resolved_trust_key.role if resolved_trust_key is not None else actor_role
        if policy_role is None:
            errors.append("trusted key role or actor_role is required for policy authorization")
        else:
            try:
                authorize_record(record, role=policy_role, registry=policy_registry)
                resolved_actor_role = policy_role
            except PolicyError as exc:
                errors.append(str(exc))

    return VerificationResult(
        ok=not errors,
        digest=digest,
        errors=tuple(errors),
        warnings=tuple(warnings),
        actor_role=resolved_actor_role,
        key_id=resolved_key_id,
    )
