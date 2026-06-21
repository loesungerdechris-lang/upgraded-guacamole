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


def signed_record_with_window(
    *,
    issued_at: str,
    not_before: str | None,
    not_after: str | None,
) -> tuple[dict, TrustRegistry]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()

    record = load_fixture("valid_evidence.json")
    record["issued_at"] = issued_at
    record["decision"] = "allow"
    record["signature"] = {
        "alg": "EdDSA",
        "key_id": "synthetic-window-key",
        "value": "",
    }
    payload = compute_chain_link(record).canonical_json.encode("utf-8")
    record["signature"]["value"] = encode_urlsafe(private_key.sign(payload))

    registry = TrustRegistry(
        [
            TrustKey(
                key_id="synthetic-window-key",
                alg="EdDSA",
                public_key=encode_urlsafe(public_key),
                role="auditor",
                status="active",
                not_before=not_before,
                not_after=not_after,
            )
        ]
    )
    return record, registry


def policy_registry() -> PolicyRegistry:
    return PolicyRegistry([default_bootstrap_policy()])


def test_key_validity_window_accepts_matching_issued_at() -> None:
    record, trust_registry = signed_record_with_window(
        issued_at="2026-06-21T00:00:00Z",
        not_before="2026-01-01T00:00:00Z",
        not_after="2026-12-31T23:59:59Z",
    )

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        trust_registry=trust_registry,
        require_trusted_signature=True,
        policy_registry=policy_registry(),
        require_policy_authorization=True,
    )

    assert result.ok
    assert not result.errors


def test_key_validity_window_rejects_record_before_not_before() -> None:
    record, trust_registry = signed_record_with_window(
        issued_at="2025-12-31T23:59:59Z",
        not_before="2026-01-01T00:00:00Z",
        not_after=None,
    )

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        trust_registry=trust_registry,
        require_trusted_signature=True,
        policy_registry=policy_registry(),
        require_policy_authorization=True,
    )

    assert not result.ok
    assert any("not valid before" in error for error in result.errors)


def test_key_validity_window_rejects_record_after_not_after() -> None:
    record, trust_registry = signed_record_with_window(
        issued_at="2027-01-01T00:00:00Z",
        not_before="2026-01-01T00:00:00Z",
        not_after="2026-12-31T23:59:59Z",
    )

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        trust_registry=trust_registry,
        require_trusted_signature=True,
        policy_registry=policy_registry(),
        require_policy_authorization=True,
    )

    assert not result.ok
    assert any("not valid after" in error for error in result.errors)
