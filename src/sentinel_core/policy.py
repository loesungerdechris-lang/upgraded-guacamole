"""Policy authorization layer for SENTINEL verifier stage 3."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Role = Literal["sensor", "auditor", "authority", "admin"]
Decision = Literal["allow", "deny", "review", "quarantine"]


class PolicyError(ValueError):
    """Raised when a record is not authorized by policy."""


@dataclass(frozen=True)
class PolicyRule:
    """One role-to-decision authorization rule."""

    role: Role
    allowed_decisions: frozenset[Decision]
    allowed_sources: frozenset[str] = field(default_factory=frozenset)

    def allows(self, *, decision: str, source: str) -> bool:
        """Return whether this rule allows a decision from a source."""

        if decision not in self.allowed_decisions:
            return False
        if self.allowed_sources and source not in self.allowed_sources:
            return False
        return True


@dataclass(frozen=True)
class PolicyVersion:
    """Immutable policy version used for historical verification."""

    policy_id: str
    version: str
    rules: tuple[PolicyRule, ...]

    def rule_for_role(self, role: str) -> PolicyRule:
        """Return the policy rule for a role."""

        for rule in self.rules:
            if rule.role == role:
                return rule
        raise PolicyError(f"role is not authorized by policy {self.policy_id}: {role}")


class PolicyRegistry:
    """In-memory policy registry keyed by policy_id.

    The record's own `policy_id` determines the exact policy used for verification.
    This preserves historical verification: old records can continue to be checked
    against the policy version they declared at signing time.
    """

    def __init__(self, policies: list[PolicyVersion] | None = None) -> None:
        self._policies = {policy.policy_id: policy for policy in policies or []}

    def add(self, policy: PolicyVersion) -> None:
        """Add or replace one policy version."""

        self._policies[policy.policy_id] = policy

    def resolve(self, policy_id: str) -> PolicyVersion:
        """Resolve a declared policy version."""

        policy = self._policies.get(policy_id)
        if policy is None:
            raise PolicyError(f"unknown policy_id: {policy_id}")
        return policy


def default_bootstrap_policy() -> PolicyVersion:
    """Return the deterministic bootstrap policy used by tests and local runs."""

    return PolicyVersion(
        policy_id="policy.bootstrap",
        version="0.1.0",
        rules=(
            PolicyRule(role="sensor", allowed_decisions=frozenset({"review", "quarantine"})),
            PolicyRule(role="auditor", allowed_decisions=frozenset({"review", "allow", "deny"})),
            PolicyRule(role="authority", allowed_decisions=frozenset({"review", "allow", "deny", "quarantine"})),
            PolicyRule(role="admin", allowed_decisions=frozenset({"review", "allow", "deny", "quarantine"})),
        ),
    )


def authorize_record(record: dict[str, Any], *, role: str, registry: PolicyRegistry) -> None:
    """Authorize an evidence record against its declared policy_id.

    Raises:
        PolicyError: if the policy, role, source or decision is not authorized.
    """

    policy_id = record.get("policy_id")
    decision = record.get("decision")
    source = record.get("source")

    if not isinstance(policy_id, str) or not policy_id:
        raise PolicyError("record.policy_id is required")
    if not isinstance(decision, str) or not decision:
        raise PolicyError("record.decision is required")
    if not isinstance(source, str) or not source:
        raise PolicyError("record.source is required")

    policy = registry.resolve(policy_id)
    rule = policy.rule_for_role(role)
    if not rule.allows(decision=decision, source=source):
        raise PolicyError(
            f"role {role} is not allowed to issue decision {decision} under {policy_id}"
        )
