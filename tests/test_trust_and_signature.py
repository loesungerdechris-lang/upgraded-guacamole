import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_core.hashchain import ZERO_HASH, compute_chain_link
from sentinel_core.trust import TrustKey, TrustRegistry
from sentinel_core.verifier import verify_evidence_record

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def encode_urlsafe(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def load_fixture(name: str) -> dict:
    with (FIXTURE_DIR / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def signed_record() -> tuple[dict, TrustRegistry]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()

    record = load_fixture("valid_evidence.json")
    record["signature"] = {
        "alg": "EdDSA",
        "key_id": "synthetic-test-key",
        "value": "",
    }
    payload = compute_chain_link(record).canonical_json.encode("utf-8")
    record["signature"]["value"] = encode_urlsafe(private_key.sign(payload))

    registry = TrustRegistry(
        [
            TrustKey(
                key_id="synthetic-test-key",
                alg="EdDSA",
                public_key=encode_urlsafe(public_key),
                status="active",
            )
        ]
    )
    return record, registry


def test_verifier_accepts_trusted_eddsa_signature() -> None:
    record, registry = signed_record()

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        trust_registry=registry,
        require_trusted_signature=True,
    )

    assert result.ok
    assert not result.errors


def test_verifier_rejects_unknown_key() -> None:
    record, _registry = signed_record()
    empty_registry = TrustRegistry()

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        trust_registry=empty_registry,
        require_trusted_signature=True,
    )

    assert not result.ok
    assert any("unknown key_id" in error for error in result.errors)


def test_verifier_rejects_revoked_key() -> None:
    record, registry = signed_record()
    registry.add(
        TrustKey(
            key_id="synthetic-test-key",
            alg="EdDSA",
            public_key=registry.resolve_active_key("synthetic-test-key", "EdDSA").public_key,
            status="revoked",
        )
    )

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        trust_registry=registry,
        require_trusted_signature=True,
    )

    assert not result.ok
    assert any("not active" in error for error in result.errors)


def test_verifier_rejects_tampered_signed_record() -> None:
    record, registry = signed_record()
    record["decision"] = "allow"

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        trust_registry=registry,
        require_trusted_signature=True,
    )

    assert not result.ok
    assert any("signature verification failed" in error for error in result.errors)
