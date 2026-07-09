"""Production-oriented SENTINEL receipt verification.

This module verifies signed SENTINEL release receipts. It is verifier-only:
no private keys, signing helpers, or browser/demo key generation belong here.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from sentinel_core.hashchain import canonicalize_json, sha256_prefixed

ReceiptStatus = Literal["RC_VERIFIED", "NOT_VERIFIED", "CONFIG_ERROR"]
IssueSeverity = Literal["error", "warning", "info"]


@dataclass(frozen=True)
class ReceiptVerificationIssue:
    """One machine-readable verification issue."""

    severity: IssueSeverity
    code: str
    message: str


@dataclass(frozen=True)
class ReceiptVerificationResult:
    """Machine-readable receipt verification outcome."""

    status: ReceiptStatus
    verified: bool
    valid_signatures: int
    required_signatures: int
    matched_roles: tuple[str, ...] = field(default_factory=tuple)
    receipt_hash: str | None = None
    issues: tuple[ReceiptVerificationIssue, ...] = field(default_factory=tuple)


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _issue(
    issues: list[ReceiptVerificationIssue],
    severity: IssueSeverity,
    code: str,
    message: str,
) -> None:
    issues.append(ReceiptVerificationIssue(severity=severity, code=code, message=message))


def parse_rfc3339_utc(value: str) -> datetime:
    """Parse an RFC3339 timestamp and normalize it to UTC."""

    normalized = value.replace("Z", "+00:00") if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp must include timezone: {value}")
    return parsed.astimezone(timezone.utc)


def build_unsigned_receipt_payload(receipt: dict[str, Any]) -> str:
    """Canonicalize the signed receipt body.

    The receipt hash and signatures are intentionally excluded. The chain still
    binds sequence and previous_hash, so reordering or replay changes the signed
    payload.
    """

    chain = receipt.get("chain") if isinstance(receipt.get("chain"), dict) else {}
    unsigned_receipt = {
        "schema_version": receipt.get("schema_version"),
        "receipt_id": receipt.get("receipt_id"),
        "receipt_type": receipt.get("receipt_type"),
        "subject": receipt.get("subject"),
        "created_at": receipt.get("created_at"),
        "release_class": receipt.get("release_class"),
        "policy": receipt.get("policy"),
        "evidence": receipt.get("evidence"),
        "chain": {
            "sequence": chain.get("sequence"),
            "previous_hash": chain.get("previous_hash"),
        },
    }
    return canonicalize_json(unsigned_receipt)


def receipt_hash(receipt: dict[str, Any]) -> str:
    """Return the sha256: hash of the canonical unsigned receipt payload."""

    return sha256_prefixed(build_unsigned_receipt_payload(receipt))


def _payload_b64(receipt: dict[str, Any]) -> str:
    return _b64url_encode(build_unsigned_receipt_payload(receipt).encode("utf-8"))


def _load_es256_public_key(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("ES256 trust key must be an EC P-256 JWK")

    x = int.from_bytes(_b64url_decode(str(jwk["x"])), "big")
    y = int.from_bytes(_b64url_decode(str(jwk["y"])), "big")
    numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
    return numbers.public_key()


def _raw_es256_to_der(raw_signature: bytes) -> bytes:
    if len(raw_signature) != 64:
        raise ValueError("ES256 JWS signatures must be 64 raw bytes")
    r = int.from_bytes(raw_signature[:32], "big")
    s = int.from_bytes(raw_signature[32:], "big")
    return encode_dss_signature(r, s)


def verify_es256_jws_signature(
    *,
    public_jwk: dict[str, Any],
    signing_input: str,
    signature_b64: str,
) -> bool:
    """Verify an ES256 JWS-style raw R||S signature."""

    public_key = _load_es256_public_key(public_jwk)
    raw_signature = _b64url_decode(signature_b64)
    der_signature = _raw_es256_to_der(raw_signature)

    try:
        public_key.verify(
            der_signature,
            signing_input.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except InvalidSignature:
        return False


def verify_receipt(
    receipt: dict[str, Any],
    *,
    trust_registry: dict[str, dict[str, Any]],
) -> ReceiptVerificationResult:
    """Verify one SENTINEL receipt against a public trust registry."""

    issues: list[ReceiptVerificationIssue] = []
    matched_roles: set[str] = set()
    valid_signatures = 0

    policy = receipt.get("policy") if isinstance(receipt.get("policy"), dict) else {}
    chain = receipt.get("chain") if isinstance(receipt.get("chain"), dict) else {}
    required_roles = policy.get("required_roles", [])
    min_signatures = policy.get("min_signatures", 0)

    if not trust_registry:
        _issue(
            issues,
            "error",
            "TRUST_REGISTRY_EMPTY",
            "Trust registry is empty. Production verification is impossible.",
        )
        return ReceiptVerificationResult(
            status="CONFIG_ERROR",
            verified=False,
            valid_signatures=0,
            required_signatures=int(min_signatures or 0),
            issues=tuple(issues),
        )

    if receipt.get("schema_version") != "sentinel.receipt.v1":
        _issue(issues, "error", "SCHEMA_VERSION_INVALID", "Unsupported receipt schema version.")

    created_at = receipt.get("created_at")
    created_at_dt: datetime | None = None
    if not isinstance(created_at, str) or not created_at.endswith("Z"):
        _issue(issues, "error", "CREATED_AT_INVALID", "created_at must be RFC3339 UTC ending Z.")
    else:
        try:
            created_at_dt = parse_rfc3339_utc(created_at)
        except ValueError as exc:
            _issue(issues, "error", "CREATED_AT_INVALID", str(exc))

    if receipt.get("release_class") not in {"A", "B", "C"}:
        _issue(issues, "error", "RELEASE_CLASS_INVALID", "release_class must be A, B or C.")

    if not isinstance(chain.get("sequence"), int):
        _issue(issues, "error", "CHAIN_SEQUENCE_INVALID", "chain.sequence must be an integer.")

    previous_hash = chain.get("previous_hash")
    if not isinstance(previous_hash, str) or not previous_hash.startswith("sha256:"):
        _issue(issues, "error", "PREVIOUS_HASH_INVALID", "chain.previous_hash must be a sha256: URN.")

    expected_hash = receipt_hash(receipt)
    if chain.get("receipt_hash") != expected_hash:
        _issue(
            issues,
            "error",
            "RECEIPT_HASH_MISMATCH",
            "chain.receipt_hash does not match the canonical unsigned receipt payload.",
        )

    expected_payload_b64 = _payload_b64(receipt)
    signatures = receipt.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        _issue(issues, "error", "SIGNATURES_MISSING", "Receipt contains no signatures.")
        signatures = []

    if not isinstance(required_roles, list) or not all(isinstance(role, str) for role in required_roles):
        _issue(
            issues,
            "error",
            "REQUIRED_ROLES_INVALID",
            "policy.required_roles must be a list of role strings.",
        )
        required_roles = []

    if not isinstance(min_signatures, int) or min_signatures < 0:
        _issue(
            issues,
            "error",
            "MIN_SIGNATURES_INVALID",
            "policy.min_signatures must be a non-negative integer.",
        )
        min_signatures = 0

    for signature in signatures:
        if not isinstance(signature, dict):
            _issue(issues, "error", "SIGNATURE_INVALID", "Signature entry must be an object.")
            continue

        kid = signature.get("kid")
        signer_role = signature.get("signer_role")
        alg = signature.get("alg")
        if not isinstance(kid, str) or not isinstance(signer_role, str) or alg != "ES256":
            _issue(issues, "error", "SIGNATURE_METADATA_INVALID", "Invalid signature metadata.")
            continue

        trust_key = trust_registry.get(kid)
        if trust_key is None:
            _issue(issues, "error", "UNKNOWN_KID", f"Unknown signing key: {kid}")
            continue

        if trust_key.get("status") != "active":
            _issue(issues, "error", "KEY_NOT_ACTIVE", f"Signing key is not active: {kid}")
            continue

        if trust_key.get("alg") != "ES256":
            _issue(issues, "error", "ALG_INVALID", f"Unsupported algorithm for key: {kid}")
            continue

        if trust_key.get("role") != signer_role:
            _issue(issues, "error", "ROLE_MISMATCH", f"Signer role does not match trust key: {kid}")
            continue

        if created_at_dt is not None:
            not_before = trust_key.get("not_before")
            not_after = trust_key.get("not_after")
            try:
                if isinstance(not_before, str) and created_at_dt < parse_rfc3339_utc(not_before):
                    _issue(issues, "error", "KEY_NOT_YET_VALID", f"Key was not valid yet: {kid}")
                    continue
                if isinstance(not_after, str) and created_at_dt > parse_rfc3339_utc(not_after):
                    _issue(issues, "error", "KEY_EXPIRED", f"Key was expired: {kid}")
                    continue
            except ValueError as exc:
                _issue(issues, "error", "KEY_WINDOW_INVALID", str(exc))
                continue

        protected = signature.get("protected")
        payload = signature.get("payload")
        value = signature.get("signature")
        if not all(isinstance(part, str) and part for part in (protected, payload, value)):
            _issue(issues, "error", "SIGNATURE_PARTS_MISSING", f"Signature parts missing: {kid}")
            continue

        try:
            protected_header = json.loads(_b64url_decode(protected).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            _issue(issues, "error", "PROTECTED_HEADER_INVALID", f"Invalid protected header: {exc}")
            continue

        if protected_header.get("alg") != "ES256":
            _issue(issues, "error", "PROTECTED_HEADER_ALG_INVALID", f"Invalid header alg: {kid}")
            continue

        if protected_header.get("kid") != kid:
            _issue(issues, "error", "PROTECTED_HEADER_KID_MISMATCH", f"Header kid mismatch: {kid}")
            continue

        if payload != expected_payload_b64:
            _issue(
                issues,
                "error",
                "SIGNATURE_PAYLOAD_MISMATCH",
                f"Signature payload does not match canonical receipt payload: {kid}",
            )
            continue

        try:
            if not verify_es256_jws_signature(
                public_jwk=trust_key["jwk"],
                signing_input=f"{protected}.{payload}",
                signature_b64=value,
            ):
                _issue(issues, "error", "SIGNATURE_INVALID", f"Invalid ES256 signature: {kid}")
                continue
        except (KeyError, ValueError, TypeError) as exc:
            _issue(issues, "error", "SIGNATURE_PARSE_ERROR", f"Could not verify {kid}: {exc}")
            continue

        valid_signatures += 1
        matched_roles.add(signer_role)

    for role in required_roles:
        if role not in matched_roles:
            _issue(issues, "error", "REQUIRED_ROLE_MISSING", f"Missing required role: {role}")

    if valid_signatures < int(min_signatures):
        _issue(
            issues,
            "error",
            "MIN_SIGNATURES_NOT_MET",
            f"Only {valid_signatures} valid signatures, required {min_signatures}.",
        )

    if receipt.get("release_class") == "A" and int(min_signatures) < 2:
        _issue(
            issues,
            "error",
            "CLASS_A_POLICY_TOO_WEAK",
            "Release class A requires at least two valid signatures.",
        )

    has_errors = any(issue.severity == "error" for issue in issues)
    return ReceiptVerificationResult(
        status="NOT_VERIFIED" if has_errors else "RC_VERIFIED",
        verified=not has_errors,
        valid_signatures=valid_signatures,
        required_signatures=int(min_signatures),
        matched_roles=tuple(sorted(matched_roles)),
        receipt_hash=expected_hash,
        issues=tuple(issues),
    )
