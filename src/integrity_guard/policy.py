"""Immutable finding policy and a reproducible local policy fingerprint.

The digest uses this module's explicit JSON serialization. It is not a JCS
implementation, a signature, or evidence that an executing guard is trusted.
"""

import hashlib
import json
from types import MappingProxyType


SCHEMA_VERSION = "1.0"
REQUIRED_CHECK_IDS = ("diff", "guard", "secrets", "workflows")
INCOMPLETE_EXIT_CODES = frozenset({20, 21, 22, 30, 50, 99})
EXIT_CODES = frozenset({0, 10, 40}) | INCOMPLETE_EXIT_CODES
MAX_FINDINGS = 1000


def _blocking(priority: str, kind: str, severity: str = "high") -> MappingProxyType:
    return MappingProxyType(
        {
            "priority": priority,
            "kind": kind,
            "may_block": True,
            "must_block": True,
            "min_confidence": "high",
            "min_blocking_confidence": "high",
            "min_severity": severity,
        }
    )


def _advisory(priority: str) -> MappingProxyType:
    return MappingProxyType(
        {
            "priority": priority,
            "kind": "advisory",
            "may_block": False,
            "must_block": False,
        }
    )


# INT-000 describes the overall decision, not a finding. A mandatory finding
# cannot become harmless by changing its scanner-controlled `blocking` flag.
RULES = MappingProxyType(
    {
        "INT-001": _blocking("P0", "policy"),
        "INT-002": _blocking("P0", "policy"),
        "INT-010": _blocking("P0", "guard"),
        "INT-011": _blocking("P0", "guard"),
        "INT-012": _blocking("P0", "technical"),
        "INT-013": _blocking("P0", "technical"),
        "INT-014": _blocking("P0", "technical"),
        "INT-020": _blocking("P1", "policy"),
        "INT-021": _blocking("P1", "policy"),
        "INT-030": _blocking("P1", "policy"),
        "INT-040": _blocking("P2", "policy", "critical"),
        "INT-041": _advisory("P2"),
        "INT-050": _advisory("P3"),
        "INT-060": _advisory("P3"),
        "INT-061": _advisory("P3"),
    }
)


def policy_digest() -> str:
    """Return SHA-256 over the locally canonicalized registry and check set."""
    payload = {
        "schema_version": SCHEMA_VERSION,
        "required_check_ids": sorted(REQUIRED_CHECK_IDS),
        "rules": {rule_id: dict(policy) for rule_id, policy in RULES.items()},
    }
    serialized = json.dumps(
        payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")
    return hashlib.sha256(serialized).hexdigest()
