"""External digest-signing contract for SENTINEL receipts.

This module prepares and finalizes receipt signatures without owning private key
material. The only object passed to an external signer contains the algorithm,
versioned key identifier and SHA-256 digest of the JWS signing input.

The verifier remains independent and must be invoked separately by the caller.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Literal, Protocol
from urllib.parse import urlparse

from sentinel_core.hashchain import canonicalize_json, sha256_prefixed
from sentinel_core.receipt import build_unsigned_receipt_payload

SigningAlgorithm = Literal["ES256"]

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_SIGNER_ROLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_P256_ORDER = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)


class SigningContractError(ValueError):
    """Raised when the external signing boundary would not fail closed."""


@dataclass(frozen=True)
class DigestSigningRequest:
    """Narrow request that may cross the external signer boundary."""

    algorithm: SigningAlgorithm
    key_id: str
    digest_b64url: str


@dataclass(frozen=True)
class ExternalSignatureResult:
    """Result returned by an external digest signer."""

    algorithm: SigningAlgorithm
    key_id: str
    signature_b64url: str


@dataclass(frozen=True)
class PreparedReceiptSignature:
    """Immutable local context used to finalize one receipt signature."""

    request: DigestSigningRequest
    signer_role: str
    receipt_hash: str
    canonical_payload: str
    protected_b64url: str
    payload_b64url: str
    signing_input: str


class ExternalDigestSigner(Protocol):
    """Minimal external signer interface; implementations receive only a digest."""

    def sign_digest(self, request: DigestSigningRequest) -> ExternalSignatureResult:
        """Sign the supplied digest without exposing private key material."""


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode_strict(value: str, *, field_name: str) -> bytes:
    if not isinstance(value, str) or not value or not _BASE64URL_RE.fullmatch(value):
        raise SigningContractError(f"{field_name} must be unpadded base64url text")

    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(
            (value + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError) as exc:
        raise SigningContractError(f"{field_name} is not valid base64url") from exc

    if _b64url_encode(decoded) != value:
        raise SigningContractError(f"{field_name} is not canonical base64url")
    return decoded


def _validate_versioned_key_id(key_id: str) -> None:
    if not isinstance(key_id, str) or not key_id:
        raise SigningContractError("key_id must be a non-empty versioned HTTPS key identifier")

    parsed = urlparse(key_id)
    path_parts = [part for part in parsed.path.split("/") if part]
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.params
        or parsed.query
        or parsed.fragment
        or len(path_parts) != 3
        or path_parts[0] != "keys"
        or not path_parts[1]
        or not path_parts[2]
    ):
        raise SigningContractError(
            "key_id must be a versioned HTTPS identifier ending in /keys/<name>/<version>"
        )


def _validate_signer_role(signer_role: str) -> None:
    if not isinstance(signer_role, str) or not _SIGNER_ROLE_RE.fullmatch(signer_role):
        raise SigningContractError("signer_role contains unsupported characters")


def _validate_receipt_shape(receipt: dict[str, Any]) -> None:
    if not isinstance(receipt, dict):
        raise SigningContractError("receipt must be an object")
    if not isinstance(receipt.get("chain"), dict):
        raise SigningContractError("receipt.chain must be an object")
    signatures = receipt.get("signatures")
    if not isinstance(signatures, list):
        raise SigningContractError("receipt.signatures must be a list")


def _validate_prepared(prepared: PreparedReceiptSignature) -> None:
    if not isinstance(prepared, PreparedReceiptSignature):
        raise SigningContractError("prepared signature context is invalid")
    if prepared.request.algorithm != "ES256":
        raise SigningContractError("prepared signing algorithm must be ES256")
    _validate_versioned_key_id(prepared.request.key_id)
    _validate_signer_role(prepared.signer_role)

    expected_receipt_hash = sha256_prefixed(prepared.canonical_payload)
    if not hmac.compare_digest(expected_receipt_hash, prepared.receipt_hash):
        raise SigningContractError("prepared receipt hash is inconsistent")

    protected_bytes = _b64url_decode_strict(
        prepared.protected_b64url,
        field_name="prepared protected header",
    )
    payload_bytes = _b64url_decode_strict(
        prepared.payload_b64url,
        field_name="prepared payload",
    )

    try:
        protected_header = json.loads(protected_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise SigningContractError("prepared protected header is not valid JSON") from exc

    try:
        payload_text = payload_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SigningContractError("prepared payload is not valid UTF-8") from exc

    expected_header = {
        "alg": "ES256",
        "kid": prepared.request.key_id,
        "typ": "SENTINEL-JWS",
    }
    if protected_header != expected_header:
        raise SigningContractError("prepared protected header does not match the frozen profile")
    if canonicalize_json(protected_header).encode("utf-8") != protected_bytes:
        raise SigningContractError("prepared protected header is not canonical")
    if payload_text != prepared.canonical_payload:
        raise SigningContractError("prepared payload does not match the canonical receipt")

    expected_signing_input = f"{prepared.protected_b64url}.{prepared.payload_b64url}"
    if not hmac.compare_digest(expected_signing_input, prepared.signing_input):
        raise SigningContractError("prepared signing input is inconsistent")

    expected_digest = _b64url_encode(hashlib.sha256(prepared.signing_input.encode("ascii")).digest())
    if not hmac.compare_digest(expected_digest, prepared.request.digest_b64url):
        raise SigningContractError("prepared signing digest is inconsistent")


def prepare_receipt_signature(
    receipt: dict[str, Any],
    *,
    key_id: str,
    signer_role: str,
) -> PreparedReceiptSignature:
    """Prepare a deterministic digest request for an external ES256 signer.

    No signer is called here. The caller may send only ``prepared.request`` to
    the external boundary.
    """

    _validate_receipt_shape(receipt)
    _validate_versioned_key_id(key_id)
    _validate_signer_role(signer_role)

    signatures = receipt["signatures"]
    if any(isinstance(item, dict) and item.get("kid") == key_id for item in signatures):
        raise SigningContractError(f"receipt already contains a signature for key_id: {key_id}")

    canonical_payload = build_unsigned_receipt_payload(receipt)
    computed_receipt_hash = sha256_prefixed(canonical_payload)
    existing_receipt_hash = receipt["chain"].get("receipt_hash")
    if existing_receipt_hash not in (None, "", computed_receipt_hash):
        raise SigningContractError("receipt.chain.receipt_hash conflicts with the canonical payload")

    protected_header = {
        "alg": "ES256",
        "kid": key_id,
        "typ": "SENTINEL-JWS",
    }
    protected_json = canonicalize_json(protected_header)
    protected_b64url = _b64url_encode(protected_json.encode("utf-8"))
    payload_b64url = _b64url_encode(canonical_payload.encode("utf-8"))
    signing_input = f"{protected_b64url}.{payload_b64url}"
    digest_b64url = _b64url_encode(hashlib.sha256(signing_input.encode("ascii")).digest())

    prepared = PreparedReceiptSignature(
        request=DigestSigningRequest(
            algorithm="ES256",
            key_id=key_id,
            digest_b64url=digest_b64url,
        ),
        signer_role=signer_role,
        receipt_hash=computed_receipt_hash,
        canonical_payload=canonical_payload,
        protected_b64url=protected_b64url,
        payload_b64url=payload_b64url,
        signing_input=signing_input,
    )
    _validate_prepared(prepared)
    return prepared


def finalize_receipt_signature(
    receipt: dict[str, Any],
    *,
    prepared: PreparedReceiptSignature,
    result: ExternalSignatureResult,
) -> dict[str, Any]:
    """Attach one structurally valid external signature to a copied receipt.

    This function does not declare the signature verified. The returned receipt
    must still pass ``verify_receipt`` against an independent public registry.
    """

    _validate_receipt_shape(receipt)
    _validate_prepared(prepared)
    if not isinstance(result, ExternalSignatureResult):
        raise SigningContractError("external signature result is invalid")
    if result.algorithm != "ES256":
        raise SigningContractError("external signature algorithm must be ES256")
    if result.key_id != prepared.request.key_id:
        raise SigningContractError("external signature key_id does not match the prepared request")

    current_payload = build_unsigned_receipt_payload(receipt)
    if not hmac.compare_digest(
        current_payload.encode("utf-8"),
        prepared.canonical_payload.encode("utf-8"),
    ):
        raise SigningContractError("receipt changed after signing preparation")

    current_receipt_hash = sha256_prefixed(current_payload)
    if not hmac.compare_digest(current_receipt_hash, prepared.receipt_hash):
        raise SigningContractError("receipt hash changed after signing preparation")

    existing_receipt_hash = receipt["chain"].get("receipt_hash")
    if existing_receipt_hash not in (None, "", prepared.receipt_hash):
        raise SigningContractError("receipt.chain.receipt_hash changed after preparation")

    if any(
        isinstance(item, dict) and item.get("kid") == prepared.request.key_id
        for item in receipt["signatures"]
    ):
        raise SigningContractError(
            f"receipt already contains a signature for key_id: {prepared.request.key_id}"
        )

    raw_signature = _b64url_decode_strict(
        result.signature_b64url,
        field_name="external signature",
    )
    if len(raw_signature) != 64:
        raise SigningContractError("ES256 external signature must be exactly 64 raw bytes")

    r = int.from_bytes(raw_signature[:32], "big")
    s = int.from_bytes(raw_signature[32:], "big")
    if not (1 <= r < _P256_ORDER and 1 <= s < _P256_ORDER):
        raise SigningContractError("ES256 signature scalars must be in the P-256 group range")

    signed_receipt = deepcopy(receipt)
    signed_receipt["chain"]["receipt_hash"] = prepared.receipt_hash
    signed_receipt["signatures"].append(
        {
            "kid": prepared.request.key_id,
            "alg": "ES256",
            "signer_role": prepared.signer_role,
            "protected": prepared.protected_b64url,
            "payload": prepared.payload_b64url,
            "signature": result.signature_b64url,
        }
    )
    return signed_receipt


def sign_receipt_with_external_digest_signer(
    receipt: dict[str, Any],
    *,
    key_id: str,
    signer_role: str,
    signer: ExternalDigestSigner,
) -> dict[str, Any]:
    """Prepare, externally sign and structurally finalize a copied receipt."""

    prepared = prepare_receipt_signature(
        receipt,
        key_id=key_id,
        signer_role=signer_role,
    )
    result = signer.sign_digest(prepared.request)
    return finalize_receipt_signature(receipt, prepared=prepared, result=result)
