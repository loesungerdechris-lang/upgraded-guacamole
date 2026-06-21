import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_core.hashchain import ZERO_HASH, compute_chain_link
from sentinel_core.policy import PolicyRegistry, default_bootstrap_policy
from sentinel_core.trust import TrustKey, TrustRegistry
from sentinel_core.verifier import verify_evidence_record

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def encode_urlsafe(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def load_fixture(name: str) -> dict:
    with (FIXTURE_DIR / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def signed_record_with_role(role: str, decision: str) -> tuple[dict, TrustRegistry]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()

    record = load_fixture("valid_evidence.json")
    record["decision"] = decision
    record["signature"] = {
        "alg": "EdDSA",
        "key_id": "synthetic-bound-key",
        "value": "",
    }
    payload = compute_chain_link(record).canonical_json.encode("utf-8")
    record["signature"]["value"] = encode_urlsafe(private_key.sign(payload))

    registry = TrustRegistry(
        [
            TrustKey(
                key_id="synthetic-bound-key",
                alg="EdDSA",
                public_key=encode_urlsafe(public_key),
                role=role,
                status="active",
            )
        ]
    )
    return record, registry


def policy_registry() -> PolicyRegistry:
    return PolicyRegistry([default_bootstrap_policy()])


def test_policy_role_is_derived_from_trust_key() -> None:
    record, trust_registry = signed_record_with_role(role="auditor", decision="allow")

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        trust_registry=trust_registry,
        require_trusted_signature=True,
        policy_registry=policy_registry(),
        require_policy_authorization=True,
    )

    assert result.ok
    assert result.actor_role == "auditor"
    assert result.key_id == "synthetic-bound-key"


def test_manual_actor_role_cannot_override_trust_key_role() -> None:
    record, trust_registry = signed_record_with_role(role="sensor", decision="allow")

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        trust_registry=trust_registry,
        require_trusted_signature=True,
        policy_registry=policy_registry(),
        actor_role="auditor",
        require_policy_authorization=True,
    )

    assert not result.ok
    assert result.actor_role == "sensor"
    assert any("role sensor is not allowed" in error for error in result.errors)


def test_sensor_key_can_only_use_sensor_permissions() -> None:
    record, trust_registry = signed_record_with_role(role="sensor", decision="review")

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        trust_registry=trust_registry,
        require_trusted_signature=True,
        policy_registry=policy_registry(),
        actor_role="admin",
        require_policy_authorization=True,
    )

    assert result.ok
    assert result.actor_role == "sensor"
