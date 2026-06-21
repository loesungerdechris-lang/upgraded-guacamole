"""Bootstrap verifier for SENTINEL evidence records.

Stage 1 verifies structure and hash-chain integrity. Cryptographic signature
verification is intentionally represented as an explicit pending check so the
trust-anchor model can be added without weakening the current verifier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel_core.hashchain import ZERO_HASH, compute_chain_link
from sentinel_core.schema import SchemaValidationError, validate_evidence_schema


@dataclass(frozen=True)
class VerificationResult:
    """Machine-readable verifier outcome."""

    ok: bool
    digest: str | None = None
    errors: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)


def verify_evidence_record(
    record: dict[str, Any],
    *,
    expected_previous_hash: str = ZERO_HASH,
    expected_digest: str | None = None,
    require_signature_value: bool = True,
) -> VerificationResult:
    """Verify one evidence record.

    This stage checks:
    - JSON Schema conformance
    - previous_hash chain continuity
    - deterministic digest computation
    - optional expected digest match
    - presence of a signature value, without cryptographic verification yet
    """

    errors: list[str] = []
    warnings: list[str] = []
    digest: str | None = None

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

    warnings.append(
        "cryptographic signature verification is not enabled in verifier stage 1"
    )

    return VerificationResult(
        ok=not errors,
        digest=digest,
        errors=tuple(errors),
        warnings=tuple(warnings),
    )
