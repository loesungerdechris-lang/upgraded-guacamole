from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import asdict
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
)

from sentinel_core.external_signing import (
    DigestSigningRequest,
    ExternalSignatureResult,
    SigningContractError,
    finalize_receipt_signature,
    prepare_receipt_signature,
    sign_receipt_with_external_digest_signer,
)
from sentinel_core.receipt import verify_receipt

ZERO_HASH = "sha256:" + "0" * 64
KEY_ID = (
    "https://sentinel-test.vault.azure.net/keys/"
    "sentinel-receipt-es256/0123456789abcdef0123456789abcdef"
)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))


def _public_jwk(public_key: ec.EllipticCurvePublicKey) -> dict[str, str | bool]:
    numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_encode(numbers.x.to_bytes(32, "big")),
        "y": _b64url_encode(numbers.y.to_bytes(32, "big")),
        "ext": True,
    }


def _unsigned_receipt() -> dict[str, Any]:
    return {
        "schema_version": "sentinel.receipt.v1",
        "receipt_id": "REC-EXTERNAL-SIGNER-0001",
        "receipt_type": "release_receipt",
        "subject": {
            "entity_type": "release_artifact",
            "entity_id": "SENTINEL-EXTERNAL-SIGNER",
        },
        "created_at": "2026-07-10T08:00:00.000Z",
        "release_class": "B",
        "policy": {
            "policy_id": "sentinel.external-signing",
            "policy_version": "1.0.0",
            "required_roles": ["release_signer"],
            "min_signatures": 1,
        },
        "evidence": {
            "artifact_hash": "sha256:" + "1" * 64,
            "source_commit": "05aa7df1bae9934ce2ad052fc3d08e43e081b023",
            "pipeline_run_id": "run-external-signer-001",
            "artifact_path": "dist/release.json",
        },
        "chain": {
            "sequence": 1,
            "previous_hash": ZERO_HASH,
            "receipt_hash": "",
        },
        "signatures": [],
    }


class IsolatedDigestSigner:
    """Test-only signer that proves the digest boundary and verifier parity."""

    def __init__(self, key_id: str) -> None:
        self.key_id = key_id
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.requests: list[DigestSigningRequest] = []

    @property
    def public_jwk(self) -> dict[str, str | bool]:
        return _public_jwk(self.signing_key.public_key())

    def sign_digest(self, request: DigestSigningRequest) -> ExternalSignatureResult:
        self.requests.append(request)
        digest = _b64url_decode(request.digest_b64url)
        der_signature = self.signing_key.sign(
            digest,
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
        r, s = decode_dss_signature(der_signature)
        raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return ExternalSignatureResult(
            algorithm="ES256",
            key_id=self.key_id,
            signature_b64url=_b64url_encode(raw_signature),
        )


def _result(*, key_id: str = KEY_ID, algorithm: str = "ES256", size: int = 64) -> Any:
    return ExternalSignatureResult(
        algorithm=algorithm,  # type: ignore[arg-type]
        key_id=key_id,
        signature_b64url=_b64url_encode(b"\x01" * size),
    )


def test_preparation_is_deterministic_and_does_not_mutate_input() -> None:
    receipt = _unsigned_receipt()
    original = deepcopy(receipt)

    first = prepare_receipt_signature(receipt, key_id=KEY_ID, signer_role="release_signer")
    second = prepare_receipt_signature(receipt, key_id=KEY_ID, signer_role="release_signer")

    assert first == second
    assert receipt == original
    assert len(_b64url_decode(first.request.digest_b64url)) == 32
    assert set(asdict(first.request)) == {"algorithm", "key_id", "digest_b64url"}
    assert "subject" not in asdict(first.request)
    assert "payload" not in asdict(first.request)


def test_external_digest_signature_passes_independent_verifier() -> None:
    receipt = _unsigned_receipt()
    original = deepcopy(receipt)
    signer = IsolatedDigestSigner(KEY_ID)

    signed = sign_receipt_with_external_digest_signer(
        receipt,
        key_id=KEY_ID,
        signer_role="release_signer",
        signer=signer,
    )

    assert receipt == original
    assert len(signer.requests) == 1
    assert set(asdict(signer.requests[0])) == {"algorithm", "key_id", "digest_b64url"}
    assert signed["chain"]["receipt_hash"].startswith("sha256:")
    assert len(signed["signatures"]) == 1

    trust_registry = {
        KEY_ID: {
            "kid": KEY_ID,
            "role": "release_signer",
            "alg": "ES256",
            "status": "active",
            "not_before": "2026-01-01T00:00:00.000Z",
            "not_after": "2027-01-01T00:00:00.000Z",
            "jwk": signer.public_jwk,
        }
    }
    verification = verify_receipt(signed, trust_registry=trust_registry)

    assert verification.status == "RC_VERIFIED"
    assert verification.verified is True
    assert verification.valid_signatures == 1


def test_rejects_wrong_returned_key_id() -> None:
    receipt = _unsigned_receipt()
    prepared = prepare_receipt_signature(receipt, key_id=KEY_ID, signer_role="release_signer")

    with pytest.raises(SigningContractError, match="key_id does not match"):
        finalize_receipt_signature(
            receipt,
            prepared=prepared,
            result=_result(key_id=KEY_ID + "-other"),
        )


def test_rejects_wrong_returned_algorithm() -> None:
    receipt = _unsigned_receipt()
    prepared = prepare_receipt_signature(receipt, key_id=KEY_ID, signer_role="release_signer")

    with pytest.raises(SigningContractError, match="algorithm must be ES256"):
        finalize_receipt_signature(
            receipt,
            prepared=prepared,
            result=_result(algorithm="RS256"),
        )


def test_rejects_non_base64url_signature() -> None:
    receipt = _unsigned_receipt()
    prepared = prepare_receipt_signature(receipt, key_id=KEY_ID, signer_role="release_signer")

    result = ExternalSignatureResult(
        algorithm="ES256",
        key_id=KEY_ID,
        signature_b64url="not+base64url",
    )
    with pytest.raises(SigningContractError, match="unpadded base64url"):
        finalize_receipt_signature(receipt, prepared=prepared, result=result)


def test_rejects_wrong_es256_signature_length() -> None:
    receipt = _unsigned_receipt()
    prepared = prepare_receipt_signature(receipt, key_id=KEY_ID, signer_role="release_signer")

    with pytest.raises(SigningContractError, match="exactly 64 raw bytes"):
        finalize_receipt_signature(receipt, prepared=prepared, result=_result(size=63))


def test_rejects_signed_field_mutation_after_preparation() -> None:
    receipt = _unsigned_receipt()
    prepared = prepare_receipt_signature(receipt, key_id=KEY_ID, signer_role="release_signer")
    changed = deepcopy(receipt)
    changed["subject"]["entity_id"] = "CHANGED-AFTER-PREPARATION"

    with pytest.raises(SigningContractError, match="changed after signing preparation"):
        finalize_receipt_signature(changed, prepared=prepared, result=_result())


def test_rejects_duplicate_key_before_external_call() -> None:
    receipt = _unsigned_receipt()
    receipt["signatures"].append({"kid": KEY_ID})

    with pytest.raises(SigningContractError, match="already contains a signature"):
        prepare_receipt_signature(receipt, key_id=KEY_ID, signer_role="release_signer")


def test_rejects_duplicate_key_added_during_external_call() -> None:
    receipt = _unsigned_receipt()
    prepared = prepare_receipt_signature(receipt, key_id=KEY_ID, signer_role="release_signer")
    changed = deepcopy(receipt)
    changed["signatures"].append({"kid": KEY_ID})

    with pytest.raises(SigningContractError, match="already contains a signature"):
        finalize_receipt_signature(changed, prepared=prepared, result=_result())


def test_rejects_conflicting_existing_receipt_hash() -> None:
    receipt = _unsigned_receipt()
    receipt["chain"]["receipt_hash"] = "sha256:" + "f" * 64

    with pytest.raises(SigningContractError, match="conflicts with the canonical payload"):
        prepare_receipt_signature(receipt, key_id=KEY_ID, signer_role="release_signer")


def test_structural_finalization_does_not_claim_verification() -> None:
    receipt = _unsigned_receipt()
    prepared = prepare_receipt_signature(receipt, key_id=KEY_ID, signer_role="release_signer")
    signed = finalize_receipt_signature(receipt, prepared=prepared, result=_result())

    assert "verified" not in signed
    assert "verification" not in signed

    unrelated_signer = IsolatedDigestSigner(KEY_ID)
    trust_registry = {
        KEY_ID: {
            "kid": KEY_ID,
            "role": "release_signer",
            "alg": "ES256",
            "status": "active",
            "not_before": "2026-01-01T00:00:00.000Z",
            "not_after": "2027-01-01T00:00:00.000Z",
            "jwk": unrelated_signer.public_jwk,
        }
    }
    verification = verify_receipt(signed, trust_registry=trust_registry)

    assert verification.status == "NOT_VERIFIED"
    assert verification.verified is False
