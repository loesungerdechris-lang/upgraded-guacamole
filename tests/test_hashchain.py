from sentinel_core.hashchain import ZERO_HASH, compute_chain_link, sha256_prefixed, verify_previous_hash


def test_sha256_prefixed_is_stable() -> None:
    assert sha256_prefixed("sentinel") == (
        "sha256:2eec8466e3938ac713b33d9f6fe808f84b16efbfd3c28d36109e7e5bf7d0db79"
    )


def test_chain_link_is_independent_of_key_order() -> None:
    first = {
        "schema_version": "0.1.0",
        "evidence_id": "ev-0001",
        "issued_at": "2026-06-21T00:00:00Z",
        "source": "synthetic-test",
        "artifact_hash": "sha256:" + "a" * 64,
        "previous_hash": ZERO_HASH,
        "policy_id": "policy.bootstrap",
        "decision": "review",
        "signature": {"alg": "ES256", "key_id": "test", "value": "signature-a"},
    }
    second = {
        "decision": "review",
        "policy_id": "policy.bootstrap",
        "previous_hash": ZERO_HASH,
        "artifact_hash": "sha256:" + "a" * 64,
        "source": "synthetic-test",
        "issued_at": "2026-06-21T00:00:00Z",
        "evidence_id": "ev-0001",
        "schema_version": "0.1.0",
        "signature": {"value": "signature-b", "key_id": "test", "alg": "ES256"},
    }

    assert compute_chain_link(first).digest == compute_chain_link(second).digest


def test_previous_hash_check() -> None:
    record = {"previous_hash": ZERO_HASH}
    assert verify_previous_hash(record, ZERO_HASH)
    assert not verify_previous_hash(record, "sha256:" + "1" * 64)
