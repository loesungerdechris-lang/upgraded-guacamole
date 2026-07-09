from __future__ import annotations

from copy import deepcopy
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from sentinel_core.receipt import (
    _b64url_encode,
    build_unsigned_receipt_payload,
    receipt_hash,
    verify_receipt,
)

ZERO_HASH = "sha256:" + "0" * 64


def _public_jwk(public_key: ec.EllipticCurvePublicKey) -> dict[str, str | bool]:
    numbers = public_key.public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_encode(x),
        "y": _b64url_encode(y),
        "ext": True,
    }


def _new_key(kid: str, role: str, status: str = "active") -> dict[str, Any]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    return {
        "kid": kid,
        "role": role,
        "alg": "ES256",
        "status": status,
        "not_before": "2026-01-01T00:00:00.000Z",
        "private_key": private_key,
        "jwk": _public_jwk(private_key.public_key()),
    }


def _unsigned_receipt() -> dict[str, Any]:
    return {
        "schema_version": "sentinel.receipt.v1",
        "receipt_id": "REC-TEST-0001",
        "receipt_type": "release_receipt",
        "subject": {
            "entity_type": "strategic_campaign",
            "entity_id": "NIS2_Q3_ULTIMATE",
        },
        "created_at": "2026-07-09T08:00:00.000Z",
        "release_class": "A",
        "policy": {
            "policy_id": "sentinel.release-control",
            "policy_version": "1.0.0",
            "required_roles": ["marketing_lead", "legal_officer"],
            "min_signatures": 2,
        },
        "evidence": {
            "artifact_hash": "sha256:" + "1" * 64,
            "source_commit": "abc123",
            "pipeline_run_id": "run-001",
            "artifact_path": "dist/release.pdf",
        },
        "chain": {
            "sequence": 1,
            "previous_hash": ZERO_HASH,
            "receipt_hash": "",
        },
        "signatures": [],
    }


def _registry(*keys: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        key["kid"]: {
            "kid": key["kid"],
            "role": key["role"],
            "alg": key["alg"],
            "status": key["status"],
            "not_before": key["not_before"],
            "jwk": key["jwk"],
        }
        for key in keys
    }


def _sign(receipt: dict[str, Any], key: dict[str, Any], role: str | None = None) -> None:
    receipt["chain"]["receipt_hash"] = receipt_hash(receipt)
    payload = build_unsigned_receipt_payload(receipt).encode("utf-8")
    payload_b64 = _b64url_encode(payload)
    protected_header = {
        "alg": "ES256",
        "kid": key["kid"],
        "typ": "SENTINEL-JWS",
    }
    protected_b64 = _b64url_encode(
        __import__("json").dumps(protected_header, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{protected_b64}.{payload_b64}".encode("utf-8")
    der_signature = key["private_key"].sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    receipt["signatures"] = [
        signature for signature in receipt["signatures"] if signature.get("kid") != key["kid"]
    ]
    receipt["signatures"].append(
        {
            "kid": key["kid"],
            "alg": "ES256",
            "signer_role": role or key["role"],
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _b64url_encode(raw_signature),
        }
    )


def _signed_fixture() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    marketing = _new_key("key-mkt-lead-01", "marketing_lead")
    legal = _new_key("key-legal-ciso-02", "legal_officer")
    receipt = _unsigned_receipt()
    _sign(receipt, marketing)
    _sign(receipt, legal)
    return receipt, _registry(marketing, legal)


def _codes(result: Any) -> set[str]:
    return {issue.code for issue in result.issues}


def test_accepts_fully_valid_receipt_with_required_roles() -> None:
    receipt, trust_registry = _signed_fixture()

    result = verify_receipt(receipt, trust_registry=trust_registry)

    assert result.status == "RC_VERIFIED"
    assert result.verified is True
    assert result.valid_signatures == 2
    assert result.required_signatures == 2
    assert set(result.matched_roles) == {"marketing_lead", "legal_officer"}
    assert result.issues == ()


def test_rejects_subject_tampering_after_signing() -> None:
    receipt, trust_registry = _signed_fixture()
    tampered = deepcopy(receipt)
    tampered["subject"]["entity_id"] = "NIS2_Q3_TAMPERED"

    result = verify_receipt(tampered, trust_registry=trust_registry)

    assert result.status == "NOT_VERIFIED"
    assert {"RECEIPT_HASH_MISMATCH", "SIGNATURE_PAYLOAD_MISMATCH"} <= _codes(result)


def test_rejects_evidence_artifact_tampering_after_signing() -> None:
    receipt, trust_registry = _signed_fixture()
    tampered = deepcopy(receipt)
    tampered["evidence"]["artifact_hash"] = "sha256:" + "9" * 64

    result = verify_receipt(tampered, trust_registry=trust_registry)

    assert result.status == "NOT_VERIFIED"
    assert {"RECEIPT_HASH_MISMATCH", "SIGNATURE_PAYLOAD_MISMATCH"} <= _codes(result)


def test_rejects_missing_required_legal_signature() -> None:
    marketing = _new_key("key-mkt-lead-01", "marketing_lead")
    legal = _new_key("key-legal-ciso-02", "legal_officer")
    receipt = _unsigned_receipt()
    _sign(receipt, marketing)

    result = verify_receipt(receipt, trust_registry=_registry(marketing, legal))

    assert result.status == "NOT_VERIFIED"
    assert result.valid_signatures == 1
    assert {"REQUIRED_ROLE_MISSING", "MIN_SIGNATURES_NOT_MET"} <= _codes(result)


def test_rejects_revoked_key() -> None:
    marketing = _new_key("key-mkt-lead-01", "marketing_lead")
    legal = _new_key("key-legal-ciso-02", "legal_officer", status="revoked")
    receipt = _unsigned_receipt()
    _sign(receipt, marketing)
    _sign(receipt, legal)

    result = verify_receipt(receipt, trust_registry=_registry(marketing, legal))

    assert result.status == "NOT_VERIFIED"
    assert {"KEY_NOT_ACTIVE", "REQUIRED_ROLE_MISSING", "MIN_SIGNATURES_NOT_MET"} <= _codes(result)


def test_rejects_role_spoofing() -> None:
    marketing = _new_key("key-mkt-lead-01", "marketing_lead")
    legal = _new_key("key-legal-ciso-02", "legal_officer")
    receipt = _unsigned_receipt()
    _sign(receipt, marketing, role="legal_officer")
    _sign(receipt, legal)

    result = verify_receipt(receipt, trust_registry=_registry(marketing, legal))

    assert result.status == "NOT_VERIFIED"
    assert {"ROLE_MISMATCH", "REQUIRED_ROLE_MISSING"} <= _codes(result)


def test_rejects_corrupted_signature_bytes() -> None:
    receipt, trust_registry = _signed_fixture()
    corrupted = deepcopy(receipt)
    corrupted["signatures"][0]["signature"] = "AAAA"

    result = verify_receipt(corrupted, trust_registry=trust_registry)

    assert result.status == "NOT_VERIFIED"
    assert "SIGNATURE_PARSE_ERROR" in _codes(result)


def test_rejects_malformed_previous_hash() -> None:
    receipt, trust_registry = _signed_fixture()
    tampered = deepcopy(receipt)
    tampered["chain"]["previous_hash"] = "not-a-sha256-urn"

    result = verify_receipt(tampered, trust_registry=trust_registry)

    assert result.status == "NOT_VERIFIED"
    assert {"PREVIOUS_HASH_INVALID", "RECEIPT_HASH_MISMATCH"} <= _codes(result)


def test_rejects_class_a_policy_with_fewer_than_two_required_signatures() -> None:
    marketing = _new_key("key-mkt-lead-01", "marketing_lead")
    receipt = _unsigned_receipt()
    receipt["policy"]["required_roles"] = ["marketing_lead"]
    receipt["policy"]["min_signatures"] = 1
    _sign(receipt, marketing)

    result = verify_receipt(receipt, trust_registry=_registry(marketing))

    assert result.status == "NOT_VERIFIED"
    assert "CLASS_A_POLICY_TOO_WEAK" in _codes(result)


def test_empty_trust_registry_is_configuration_error() -> None:
    receipt, _ = _signed_fixture()

    result = verify_receipt(receipt, trust_registry={})

    assert result.status == "CONFIG_ERROR"
    assert result.verified is False
    assert "TRUST_REGISTRY_EMPTY" in _codes(result)
