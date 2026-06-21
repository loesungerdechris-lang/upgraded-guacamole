import json
from pathlib import Path

import pytest

from sentinel_core.policy import authorize_record
from sentinel_core.registry_loader import (
    RegistryLoaderError,
    load_policy_registry,
    load_trust_registry,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_DIR = REPO_ROOT / "registries"


def test_load_bootstrap_trust_registry() -> None:
    registry = load_trust_registry(REGISTRY_DIR / "trust-registry.bootstrap.json")
    key = registry.resolve_active_key_at(
        "synthetic-bootstrap-auditor",
        "EdDSA",
        "2026-06-21T00:00:00Z",
    )

    assert key.role == "auditor"
    assert key.status == "active"


def test_load_bootstrap_policy_registry_allows_auditor_allow() -> None:
    registry = load_policy_registry(REGISTRY_DIR / "policy-registry.bootstrap.json")
    record = {
        "policy_id": "policy.bootstrap",
        "decision": "allow",
        "source": "synthetic-pilot",
    }

    authorize_record(record, role="auditor", registry=registry)


def test_loaded_policy_registry_rejects_sensor_allow() -> None:
    registry = load_policy_registry(REGISTRY_DIR / "policy-registry.bootstrap.json")
    record = {
        "policy_id": "policy.bootstrap",
        "decision": "allow",
        "source": "synthetic-pilot",
    }

    with pytest.raises(ValueError, match="not allowed"):
        authorize_record(record, role="sensor", registry=registry)


def test_trust_registry_rejects_unknown_role(tmp_path: Path) -> None:
    path = tmp_path / "bad-trust.json"
    path.write_text(
        json.dumps(
            {
                "registry_id": "trust.bad",
                "version": "0.1.0",
                "keys": [
                    {
                        "key_id": "bad-key",
                        "alg": "EdDSA",
                        "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "role": "guest",
                        "status": "active",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RegistryLoaderError, match="unsupported trust key role"):
        load_trust_registry(path)


def test_policy_registry_rejects_unknown_decision(tmp_path: Path) -> None:
    path = tmp_path / "bad-policy.json"
    path.write_text(
        json.dumps(
            {
                "registry_id": "policy.bad",
                "version": "0.1.0",
                "policies": [
                    {
                        "policy_id": "policy.bad",
                        "version": "0.1.0",
                        "rules": [
                            {
                                "role": "auditor",
                                "allowed_decisions": ["publish"],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RegistryLoaderError, match="unsupported policy decisions"):
        load_policy_registry(path)
