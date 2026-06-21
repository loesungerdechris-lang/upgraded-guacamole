from sentinel_core.pilot import run_synthetic_pilot


def test_synthetic_pilot_accepts_auditor_allow() -> None:
    result = run_synthetic_pilot(role="auditor", decision="allow")

    assert result.verification.ok
    assert result.verification.actor_role == "auditor"
    assert result.verification.key_id == "synthetic-pilot-key"
    assert result.record["decision"] == "allow"
    assert result.record["signature"]["value"]


def test_synthetic_pilot_rejects_sensor_allow() -> None:
    result = run_synthetic_pilot(role="sensor", decision="allow")

    assert not result.verification.ok
    assert result.verification.actor_role == "sensor"
    assert any("role sensor is not allowed" in error for error in result.verification.errors)


def test_synthetic_pilot_accepts_sensor_review() -> None:
    result = run_synthetic_pilot(role="sensor", decision="review")

    assert result.verification.ok
    assert result.verification.actor_role == "sensor"
