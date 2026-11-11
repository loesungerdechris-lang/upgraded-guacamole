"""Fail-closed structure, policy and provenance checks for guard results.

Successful validation proves internal consistency only. It does not prove that
the scanners ran, or authenticate a report supplied by untrusted PR code. The
trusted orchestrator supplies the expected context and observed process exit.
"""

import json
from collections import Counter
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, validators

from .policy import EXIT_CODES, INCOMPLETE_EXIT_CODES, REQUIRED_CHECK_IDS, RULES, policy_digest


class SemanticValidationError(ValueError):
    """Invalid result; messages deliberately omit input values and source text."""


_CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SCHEMA = json.loads(Path(__file__).with_name("result.schema.json").read_text(encoding="utf-8"))

# JSON Schema normally accepts 0.0 as an integer. The process/report boundary
# requires actual integers, excluding both floats and bool (an int subclass).
_INTEGER_CHECKER = Draft202012Validator.TYPE_CHECKER.redefine(
    "integer", lambda _checker, value: type(value) is int
)
_VALIDATOR_CLASS = validators.extend(Draft202012Validator, type_checker=_INTEGER_CHECKER)
_VALIDATOR_CLASS.check_schema(_SCHEMA)
_RESULT_VALIDATOR = _VALIDATOR_CLASS(_SCHEMA)
# Preserve semantic error identifiers for callers of validate_semantics while
# still checking all nested types before indexing scanner-controlled objects.
_SHAPE_VALIDATOR = _VALIDATOR_CLASS({k: v for k, v in _SCHEMA.items() if k != "allOf"})
_CONTEXT_VALIDATOR = _VALIDATOR_CLASS(_SCHEMA["$defs"]["context"])


def _require_shape(result: Any) -> None:
    if not _SHAPE_VALIDATOR.is_valid(result):
        raise SemanticValidationError("SCHEMA-001: Invalid result structure.") from None


def _safe_path(path: str) -> bool:
    return (
        not path.startswith("/")
        and "\\" not in path
        and all(part not in {"", ".", ".."} for part in path.split("/"))
        and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in path)
    )


def validate_semantics(result: Any) -> None:
    """Validate structure and the deterministic v1 decision contract."""
    _require_shape(result)
    errors: list[str] = []
    status = result["status"]
    exit_code = result["exit_code"]
    complete = result["complete"]
    findings = result["findings"]
    checks = result["checks"]
    blockers = [finding for finding in findings if finding["blocking"]]
    guard_findings = [finding for finding in findings if finding["rule_id"] in {"INT-010", "INT-011"}]

    if status == "PASS" and (exit_code != 0 or complete is not True):
        errors.append("SEM-001: PASS requires exit zero and a complete run.")
    if exit_code == 0:
        if status != "PASS" or complete is not True:
            errors.append("SEM-001: Exit zero requires a complete PASS.")
        if blockers:
            errors.append("SEM-002: Exit zero cannot contain a blocking finding.")
    elif status != "FAIL":
        errors.append("SEM-001: A nonzero exit requires FAIL.")

    if exit_code == 10:
        if not blockers:
            errors.append("SEM-003: A policy violation requires a blocking finding.")
        if complete is not True:
            errors.append("SEM-004: A policy violation requires completed checks.")
        if guard_findings:
            errors.append("SEM-006: Guard violations require the dedicated exit code.")
    if exit_code in INCOMPLETE_EXIT_CODES and complete is not False:
        errors.append("SEM-005: A technical failure cannot be a complete run.")
    if exit_code == 40 and not any(finding["blocking"] for finding in guard_findings):
        errors.append("SEM-006: A guard failure requires a blocking guard finding.")
    if guard_findings and exit_code != 40:
        errors.append("SEM-006: Guard violations require the dedicated exit code.")

    identities: set[tuple[Any, ...]] = set()
    for finding in findings:
        rule_id = finding["rule_id"]
        blocking = finding["blocking"]
        severity = finding["severity"]
        confidence = finding["confidence"]
        policy = RULES.get(rule_id)

        if blocking and severity in {"low", "info"}:
            errors.append("SEM-007: Low-severity findings cannot block.")
        if policy is None:
            errors.append("SEM-011: Finding rule is not registered.")
        else:
            if blocking and not policy["may_block"]:
                errors.append("SEM-012: Advisory rules cannot block.")
            if policy["must_block"] and not blocking:
                errors.append("SEM-014: Mandatory findings cannot be downgraded.")
            minimum = policy.get("min_confidence")
            if minimum is not None and _CONFIDENCE_RANK[confidence] < _CONFIDENCE_RANK[minimum]:
                errors.append("SEM-013: Mandatory confidence threshold is not satisfied.")
            minimum_severity = policy.get("min_severity")
            if (
                minimum_severity is not None
                and _SEVERITY_RANK[severity] < _SEVERITY_RANK[minimum_severity]
            ):
                errors.append("SEM-015: Mandatory severity threshold is not satisfied.")
            if policy["kind"] == "technical" and exit_code not in INCOMPLETE_EXIT_CODES | {40}:
                errors.append("SEM-016: Technical findings cannot be a completed policy decision.")

        if "path" in finding and not _safe_path(finding["path"]):
            errors.append("SEM-017: Finding path is not a safe repository-relative path.")
        if "end_line" in finding and finding["end_line"] < finding["line"]:
            errors.append("SEM-009: Finding line range is reversed.")
        identity = (rule_id, finding.get("path"), finding.get("line"), finding["message"])
        if identity in identities:
            errors.append("SEM-010: Duplicate finding identity.")
        identities.add(identity)

    check_counts = Counter(check["check_id"] for check in checks)
    if set(check_counts) != set(REQUIRED_CHECK_IDS) or any(count != 1 for count in check_counts.values()):
        errors.append("SEM-018: Exactly one result for every required check is mandatory.")
    if complete and any(not check["complete"] or check["status"] == "ERROR" for check in checks):
        errors.append("SEM-019: Complete runs require completed non-error checks.")
    if status == "PASS" and any(check["status"] != "PASS" for check in checks):
        errors.append("SEM-020: PASS requires every required check to pass.")
    if any(check["status"] == "PASS" and not check["complete"] for check in checks):
        errors.append("SEM-021: An incomplete check cannot claim PASS.")
    if any(check["status"] == "ERROR" and check["complete"] for check in checks):
        errors.append("SEM-021: A check error cannot claim completion.")

    if errors:
        raise SemanticValidationError("\n".join(dict.fromkeys(errors))) from None


def validate_result(
    result: Any,
    *,
    expected_context: dict[str, str] | None = None,
    process_exit_code: int | None = None,
) -> None:
    """Validate a report, optionally binding it to trusted run observations.

    Callers making a release decision must provide both expected_context and
    process_exit_code. Omitting them is useful only for standalone validation.
    """
    validate_semantics(result)
    if not _RESULT_VALIDATOR.is_valid(result):
        raise SemanticValidationError("SCHEMA-002: Result decision violates its schema.") from None
    if expected_context is not None:
        if not _CONTEXT_VALIDATOR.is_valid(expected_context):
            raise SemanticValidationError("CTX-001: Invalid expected context.") from None
        if result["context"] != expected_context:
            raise SemanticValidationError("CTX-002: Result does not match the expected context.") from None
    if process_exit_code is not None:
        if type(process_exit_code) is not int or process_exit_code not in EXIT_CODES:
            raise SemanticValidationError("EXIT-001: Invalid observed process exit.") from None
        if process_exit_code != result["exit_code"]:
            raise SemanticValidationError("EXIT-002: Report and observed process exit disagree.") from None


__all__ = ["RULES", "SemanticValidationError", "policy_digest", "validate_result", "validate_semantics"]
