"""Load persistent SENTINEL trust and policy registries from JSON files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel_core.policy import PolicyRegistry, PolicyRule, PolicyVersion
from sentinel_core.trust import TrustKey, TrustRegistry, parse_rfc3339_utc

ALLOWED_ROLES = {"sensor", "auditor", "authority", "admin"}
ALLOWED_DECISIONS = {"allow", "deny", "review", "quarantine"}
ALLOWED_KEY_STATUS = {"active", "revoked", "expired"}
ALLOWED_TRUST_ALGORITHMS = {"EdDSA"}


class RegistryLoaderError(ValueError):
    """Raised when a persistent registry file is malformed."""


def _load_json_object(path: Path) -> dict[str, Any]:
    """Load a JSON object from disk."""

    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise RegistryLoaderError(f"registry root must be an object: {path}")
    return data


def _required_str(value: object, field: str) -> str:
    """Return a required string field."""

    if not isinstance(value, str) or not value:
        raise RegistryLoaderError(f"{field} must be a non-empty string")
    return value


def _optional_time(value: object, field: str) -> str | None:
    """Validate an optional RFC3339 timestamp."""

    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise RegistryLoaderError(f"{field} must be null or a non-empty RFC3339 string")
    try:
        parse_rfc3339_utc(value)
    except ValueError as exc:
        raise RegistryLoaderError(str(exc)) from exc
    return value


def load_trust_registry(path: str | Path) -> TrustRegistry:
    """Load a persistent trust registry JSON file."""

    registry_path = Path(path)
    data = _load_json_object(registry_path)
    keys_data = data.get("keys")
    if not isinstance(keys_data, list):
        raise RegistryLoaderError("trust registry requires a keys array")

    keys: list[TrustKey] = []
    for index, raw_key in enumerate(keys_data):
        if not isinstance(raw_key, dict):
            raise RegistryLoaderError(f"keys[{index}] must be an object")

        key_id = _required_str(raw_key.get("key_id"), f"keys[{index}].key_id")
        alg = _required_str(raw_key.get("alg"), f"keys[{index}].alg")
        public_key = _required_str(raw_key.get("public_key"), f"keys[{index}].public_key")
        role = _required_str(raw_key.get("role"), f"keys[{index}].role")
        status = _required_str(raw_key.get("status", "active"), f"keys[{index}].status")

        if alg not in ALLOWED_TRUST_ALGORITHMS:
            raise RegistryLoaderError(f"unsupported trust key algorithm: {alg}")
        if role not in ALLOWED_ROLES:
            raise RegistryLoaderError(f"unsupported trust key role: {role}")
        if status not in ALLOWED_KEY_STATUS:
            raise RegistryLoaderError(f"unsupported trust key status: {status}")

        keys.append(
            TrustKey(
                key_id=key_id,
                alg=alg,
                public_key=public_key,
                role=role,  # type: ignore[arg-type]
                status=status,  # type: ignore[arg-type]
                not_before=_optional_time(raw_key.get("not_before"), "not_before"),
                not_after=_optional_time(raw_key.get("not_after"), "not_after"),
            )
        )

    return TrustRegistry(keys)


def load_policy_registry(path: str | Path) -> PolicyRegistry:
    """Load a persistent policy registry JSON file."""

    registry_path = Path(path)
    data = _load_json_object(registry_path)
    policies_data = data.get("policies")
    if not isinstance(policies_data, list):
        raise RegistryLoaderError("policy registry requires a policies array")

    policies: list[PolicyVersion] = []
    for policy_index, raw_policy in enumerate(policies_data):
        if not isinstance(raw_policy, dict):
            raise RegistryLoaderError(f"policies[{policy_index}] must be an object")

        policy_id = _required_str(raw_policy.get("policy_id"), "policy_id")
        version = _required_str(raw_policy.get("version"), "version")
        rules_data = raw_policy.get("rules")
        if not isinstance(rules_data, list):
            raise RegistryLoaderError(f"policy {policy_id} requires a rules array")

        rules: list[PolicyRule] = []
        for rule_index, raw_rule in enumerate(rules_data):
            if not isinstance(raw_rule, dict):
                raise RegistryLoaderError(f"rules[{rule_index}] must be an object")

            role = _required_str(raw_rule.get("role"), f"rules[{rule_index}].role")
            if role not in ALLOWED_ROLES:
                raise RegistryLoaderError(f"unsupported policy role: {role}")

            decisions = raw_rule.get("allowed_decisions")
            if not isinstance(decisions, list) or not decisions:
                raise RegistryLoaderError("allowed_decisions must be a non-empty array")
            if not all(isinstance(decision, str) for decision in decisions):
                raise RegistryLoaderError("allowed_decisions must contain only strings")
            invalid = set(decisions) - ALLOWED_DECISIONS
            if invalid:
                raise RegistryLoaderError(f"unsupported policy decisions: {sorted(invalid)}")

            sources = raw_rule.get("allowed_sources", [])
            if not isinstance(sources, list):
                raise RegistryLoaderError("allowed_sources must be an array when provided")
            if not all(isinstance(source, str) for source in sources):
                raise RegistryLoaderError("allowed_sources must contain only strings")

            rules.append(
                PolicyRule(
                    role=role,  # type: ignore[arg-type]
                    allowed_decisions=frozenset(decisions),
                    allowed_sources=frozenset(sources),
                )
            )

        policies.append(PolicyVersion(policy_id=policy_id, version=version, rules=tuple(rules)))

    return PolicyRegistry(policies)
