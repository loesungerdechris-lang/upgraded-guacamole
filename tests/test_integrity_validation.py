"""Adversarial contract tests: scanner-controlled metadata cannot grant PASS."""

import copy
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from integrity_guard.policy import REQUIRED_CHECK_IDS, RULES, policy_digest
from integrity_guard.semantic_validation import (
    SemanticValidationError,
    validate_result,
    validate_semantics,
)


def finding(rule_id="INT-001", **updates):
    value = {
        "rule_id": rule_id,
        "severity": "critical",
        "confidence": "high",
        "blocking": True,
        "message": "Synthetic finding; no real credential.",
        "path": "src/example.py",
        "line": 10,
    }
    value.update(updates)
    return value


def result(**updates):
    value = {
        "schema_version": "1.0",
        "status": "PASS",
        "exit_code": 0,
        "complete": True,
        "findings": [],
        "context": {
            "repository": "example/project",
            "base_sha": "1" * 40,
            "head_sha": "2" * 40,
            "policy_digest": policy_digest(),
        },
        "checks": [
            {"check_id": check_id, "status": "PASS", "complete": True}
            for check_id in REQUIRED_CHECK_IDS
        ],
    }
    value.update(updates)
    return value


def failed(rule_id="INT-001", *, code=10, complete=True):
    data = result(
        status="FAIL", exit_code=code, complete=complete, findings=[finding(rule_id)]
    )
    data["checks"][1 if code == 40 else 2]["status"] = "FAIL"
    if not complete:
        data["checks"][3].update(status="ERROR", complete=False)
    return data


def test_pass_with_exact_trusted_observations():
    data = result()
    validate_result(data, expected_context=copy.deepcopy(data["context"]), process_exit_code=0)


@pytest.mark.parametrize("rule_id", ["INT-041", "INT-050", "INT-060", "INT-061"])
def test_advisory_findings_do_not_block_clean_run(rule_id):
    data = result(findings=[finding(rule_id, severity="info", blocking=False)])
    validate_result(data, process_exit_code=0)


@pytest.mark.parametrize("rule_id", ["INT-001", "INT-002", "INT-020", "INT-021", "INT-030", "INT-040"])
def test_actual_policy_findings_are_valid_failed_results(rule_id):
    validate_result(failed(rule_id), process_exit_code=10)


@pytest.mark.parametrize("rule_id", ["INT-010", "INT-011"])
@pytest.mark.parametrize("complete", [True, False])
def test_guard_detection_can_stop_before_all_scans_finish(rule_id, complete):
    validate_result(failed(rule_id, code=40, complete=complete), process_exit_code=40)


@pytest.mark.parametrize("code", [20, 21, 22, 30, 50, 99])
def test_technical_errors_preserve_failed_state(code):
    data = result(status="FAIL", exit_code=code, complete=False)
    data["checks"][2].update(status="ERROR", complete=False)
    validate_result(data, process_exit_code=code)


@pytest.mark.parametrize("rule_id,code", [("INT-012", 20), ("INT-013", 21), ("INT-014", 22)])
def test_registered_technical_findings_are_valid_in_incomplete_runs(rule_id, code):
    validate_result(failed(rule_id, code=code, complete=False))


@pytest.mark.parametrize(
    "rule_id",
    ["INT-001", "INT-002", "INT-010", "INT-011", "INT-012", "INT-013", "INT-014",
     "INT-020", "INT-021", "INT-030", "INT-040"],
)
def test_scanner_cannot_downgrade_mandatory_finding_to_obtain_pass(rule_id):
    data = result(findings=[finding(rule_id, blocking=False)])
    with pytest.raises(SemanticValidationError, match="SEM-014"):
        validate_result(data, process_exit_code=0)


@pytest.mark.parametrize("severity,confidence", [("info", "high"), ("medium", "high"), ("high", "low")])
def test_scanner_cannot_hide_secret_by_lowering_severity_or_confidence(severity, confidence):
    data = result(findings=[finding(severity=severity, confidence=confidence, blocking=False)])
    with pytest.raises(SemanticValidationError):
        validate_result(data)


@pytest.mark.parametrize("confidence", ["medium", "low"])
def test_p2_uncertain_finding_must_use_advisory_rule(confidence):
    data = failed("INT-040")
    data["findings"][0]["confidence"] = confidence
    with pytest.raises(SemanticValidationError, match="SEM-013"):
        validate_result(data)


def test_p2_noncritical_finding_cannot_masquerade_as_critical_rule():
    data = failed("INT-040")
    data["findings"][0]["severity"] = "high"
    with pytest.raises(SemanticValidationError, match="SEM-015"):
        validate_result(data)


@pytest.mark.parametrize("rule_id", ["INT-041", "INT-050", "INT-060", "INT-061"])
def test_advisory_rules_cannot_become_mandatory(rule_id):
    with pytest.raises(SemanticValidationError, match="SEM-012"):
        validate_result(failed(rule_id))


@pytest.mark.parametrize("rule_id", ["INT-999", "INT-000"])
def test_unknown_and_summary_rule_ids_cannot_claim_pass(rule_id):
    with pytest.raises(SemanticValidationError, match="SEM-011"):
        validate_result(result(findings=[finding(rule_id, blocking=False)]))


@pytest.mark.parametrize("code", [20, 21, 22, 30, 50, 99])
def test_technical_failure_cannot_claim_completion(code):
    with pytest.raises(SemanticValidationError, match="SEM-005"):
        validate_result(result(status="FAIL", exit_code=code))


def test_fail_with_exit_zero_is_rejected():
    with pytest.raises(SemanticValidationError, match="SEM-001"):
        validate_semantics(result(status="FAIL"))


def test_pass_with_blocker_is_rejected():
    with pytest.raises(SemanticValidationError, match="SEM-002"):
        validate_semantics(result(findings=[finding()]))


def test_policy_failure_requires_blocking_finding():
    with pytest.raises(SemanticValidationError, match="SEM-003"):
        validate_result(result(status="FAIL", exit_code=10))


def test_incomplete_policy_failure_requires_technical_exit():
    with pytest.raises(SemanticValidationError, match="SEM-004"):
        validate_result(failed(complete=False))


@pytest.mark.parametrize("rule_id", ["INT-010", "INT-011"])
def test_guard_failure_is_not_reported_as_ordinary_policy_failure(rule_id):
    with pytest.raises(SemanticValidationError, match="SEM-006"):
        validate_result(failed(rule_id))


def test_guard_failure_requires_a_guard_finding():
    with pytest.raises(SemanticValidationError, match="SEM-006"):
        validate_result(failed(code=40))


@pytest.mark.parametrize("rule_id", ["INT-012", "INT-013", "INT-014"])
def test_technical_findings_cannot_claim_completed_policy_analysis(rule_id):
    with pytest.raises(SemanticValidationError, match="SEM-016"):
        validate_result(failed(rule_id))


@pytest.mark.parametrize("status,complete", [("FAIL", True), ("ERROR", False), ("PASS", False)])
def test_single_nonpassing_required_check_prevents_pass(status, complete):
    data = result()
    data["checks"][2].update(status=status, complete=complete)
    with pytest.raises(SemanticValidationError):
        validate_result(data)


def test_duplicate_check_cannot_fill_a_missing_check_slot():
    data = result()
    data["checks"][3] = copy.deepcopy(data["checks"][2])
    with pytest.raises(SemanticValidationError, match="SEM-018"):
        validate_result(data)


@pytest.mark.parametrize("change", ["missing", "extra", "unknown"])
def test_required_check_inventory_is_exact(change):
    data = result()
    if change == "missing":
        data["checks"].pop()
    elif change == "extra":
        data["checks"].append(copy.deepcopy(data["checks"][0]))
    else:
        data["checks"][0]["check_id"] = "forged"
    with pytest.raises(SemanticValidationError):
        validate_result(data)


@pytest.mark.parametrize(
    "path",
    ["/etc/passwd", "../secret", "src/../secret", "./file", "src/./file", "src//file",
     "src/", "src\\file", ".", "..", "src/line\nfile", "src/line\x00file", "file\x85"],
)
def test_annotations_cannot_escape_repository_or_contain_controls(path):
    data = failed()
    data["findings"][0]["path"] = path
    with pytest.raises(SemanticValidationError):
        validate_result(data)


def test_repo_relative_unicode_path_is_valid():
    data = failed()
    data["findings"][0].update(path="src/überprüfung.py", line=20, end_line=22)
    validate_result(data)


@pytest.mark.parametrize("line", [0, -1, 2147483648, True, False, 1.0, "1"])
def test_line_requires_bounded_real_integer(line):
    data = failed()
    data["findings"][0]["line"] = line
    with pytest.raises(SemanticValidationError):
        validate_result(data)


def test_reversed_line_range_is_rejected():
    data = failed()
    data["findings"][0]["end_line"] = 9
    with pytest.raises(SemanticValidationError, match="SEM-009"):
        validate_result(data)


@pytest.mark.parametrize("remove", ["path", "line"])
def test_line_range_requires_its_context(remove):
    data = failed()
    data["findings"][0]["end_line"] = 12
    data["findings"][0].pop(remove)
    with pytest.raises(SemanticValidationError):
        validate_result(data)


def test_duplicate_finding_is_rejected_even_with_different_end_line():
    data = failed()
    data["findings"].append(dict(data["findings"][0], end_line=12))
    with pytest.raises(SemanticValidationError, match="SEM-010"):
        validate_result(data)


def test_same_rule_at_different_lines_is_not_a_duplicate():
    data = failed()
    data["findings"].append(dict(data["findings"][0], line=11))
    validate_result(data)


@pytest.mark.parametrize("data", [None, [], "", 1, True, {}, {"findings": [None]}])
def test_malformed_input_raises_controlled_error_without_key_errors(data):
    with pytest.raises(SemanticValidationError, match="SCHEMA"):
        validate_semantics(data)


@pytest.mark.parametrize("value", [True, False, 0.0, "0", None, 255])
def test_report_exit_is_a_supported_integer(value):
    with pytest.raises(SemanticValidationError):
        validate_result(result(exit_code=value))


@pytest.mark.parametrize("field,value", [("complete", 1), ("status", True), ("findings", {}), ("checks", {})])
def test_result_types_are_not_coerced(field, value):
    with pytest.raises(SemanticValidationError):
        validate_result(result(**{field: value}))


@pytest.mark.parametrize("target", ["root", "context", "check", "finding"])
def test_unknown_fields_are_rejected_without_echoing_secret_values(target):
    marker = "SYNTHETIC_PRIVATE_MARKER_NOT_A_REAL_SECRET"
    data = failed()
    obj = {"root": data, "context": data["context"], "check": data["checks"][0], "finding": data["findings"][0]}[target]
    obj[marker] = marker
    with pytest.raises(SemanticValidationError) as caught:
        validate_result(data)
    assert marker not in str(caught.value)


def test_error_messages_do_not_echo_finding_text_or_untrusted_ids():
    marker = "SYNTHETIC_PRIVATE_MARKER_NOT_A_REAL_SECRET"
    data = result(findings=[finding(rule_id=marker, message=marker)])
    with pytest.raises(SemanticValidationError) as caught:
        validate_result(data)
    assert marker not in str(caught.value)


@pytest.mark.parametrize("field", ["message", "action"])
def test_finding_strings_are_bounded(field):
    data = failed()
    data["findings"][0][field] = "x" * 4097
    with pytest.raises(SemanticValidationError):
        validate_result(data)


def test_finding_inventory_is_bounded():
    with pytest.raises(SemanticValidationError):
        validate_result(result(findings=[finding(line=index + 1) for index in range(1001)]))


@pytest.mark.parametrize("field,value", [("repository", "other/project"), ("base_sha", "3" * 40), ("head_sha", "3" * 40), ("policy_digest", "3" * 64)])
def test_report_is_bound_to_every_expected_context_field(field, value):
    data = result()
    expected = copy.deepcopy(data["context"])
    data["context"][field] = value
    with pytest.raises(SemanticValidationError, match="CTX-002"):
        validate_result(data, expected_context=expected, process_exit_code=0)


@pytest.mark.parametrize("expected", [{}, None, "invalid"])
def test_expected_context_validation_and_optional_mode(expected):
    if expected is None:
        validate_result(result(), expected_context=None)
    else:
        with pytest.raises(SemanticValidationError, match="CTX-001"):
            validate_result(result(), expected_context=expected)


@pytest.mark.parametrize("code", [True, False, 0.0, "0", -9, 1, 255])
def test_observed_process_exit_is_not_coerced(code):
    with pytest.raises(SemanticValidationError, match="EXIT-001"):
        validate_result(result(), process_exit_code=code)


def test_process_failure_cannot_be_hidden_by_pass_report():
    with pytest.raises(SemanticValidationError, match="EXIT-002"):
        validate_result(result(), process_exit_code=21)


def test_failed_report_cannot_be_hidden_by_successful_process_exit():
    with pytest.raises(SemanticValidationError, match="EXIT-002"):
        validate_result(failed(), process_exit_code=0)


def test_registry_contains_every_matrix_finding_rule():
    assert set(RULES) == {
        "INT-001", "INT-002", "INT-010", "INT-011", "INT-012", "INT-013", "INT-014",
        "INT-020", "INT-021", "INT-030", "INT-040", "INT-041", "INT-050", "INT-060", "INT-061",
    }


def test_registry_and_each_nested_policy_are_immutable():
    with pytest.raises(TypeError):
        RULES["INT-999"] = {}
    with pytest.raises(TypeError):
        RULES["INT-001"]["must_block"] = False


def test_policy_fingerprint_reproduces_documented_local_json_serialization():
    payload = {
        "schema_version": "1.0",
        "required_check_ids": sorted(REQUIRED_CHECK_IDS),
        "rules": {rule_id: dict(policy) for rule_id, policy in RULES.items()},
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    assert policy_digest() == hashlib.sha256(raw.encode("ascii")).hexdigest()
    assert len(policy_digest()) == 64


def test_schema_independently_rejects_pass_with_blocking_finding():
    schema = json.loads(
        (Path(__file__).parents[1] / "src/integrity_guard/result.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    assert not Draft202012Validator(schema).is_valid(result(findings=[finding()]))


def test_validation_does_not_mutate_scanner_result():
    data = failed()
    before = copy.deepcopy(data)
    validate_result(data)
    assert data == before
