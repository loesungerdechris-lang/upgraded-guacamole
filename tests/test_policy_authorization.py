import json
from pathlib import Path

from sentinel_core.hashchain import ZERO_HASH
from sentinel_core.policy import PolicyRegistry, default_bootstrap_policy
from sentinel_core.verifier import verify_evidence_record

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    with (FIXTURE_DIR / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def bootstrap_registry() -> PolicyRegistry:
    return PolicyRegistry([default_bootstrap_policy()])


def test_sensor_can_request_review() -> None:
    record = load_fixture("valid_evidence.json")
    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        policy_registry=bootstrap_registry(),
        actor_role="sensor",
        require_policy_authorization=True,
    )

    assert result.ok
    assert not result.errors


def test_sensor_cannot_allow() -> None:
    record = load_fixture("valid_evidence.json")
    record["decision"] = "allow"

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        policy_registry=bootstrap_registry(),
        actor_role="sensor",
        require_policy_authorization=True,
    )

    assert not result.ok
    assert any("not allowed" in error for error in result.errors)


def test_auditor_can_allow() -> None:
    record = load_fixture("valid_evidence.json")
    record["decision"] = "allow"

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        policy_registry=bootstrap_registry(),
        actor_role="auditor",
        require_policy_authorization=True,
    )

    assert result.ok
    assert not result.errors


def test_unknown_policy_is_rejected() -> None:
    record = load_fixture("valid_evidence.json")
    record["policy_id"] = "policy.unknown"

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        policy_registry=bootstrap_registry(),
        actor_role="auditor",
        require_policy_authorization=True,
    )

    assert not result.ok
    assert any("unknown policy_id" in error for error in result.errors)


def test_unknown_role_is_rejected() -> None:
    record = load_fixture("valid_evidence.json")

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        policy_registry=bootstrap_registry(),
        actor_role="guest",
        require_policy_authorization=True,
    )

    assert not result.ok
    assert any("role is not authorized" in error for error in result.errors)


def test_policy_registry_required_when_policy_is_required() -> None:
    record = load_fixture("valid_evidence.json")

    result = verify_evidence_record(
        record,
        expected_previous_hash=ZERO_HASH,
        actor_role="auditor",
        require_policy_authorization=True,
    )

    assert not result.ok
    assert any("without policy registry" in error for error in result.errors)
