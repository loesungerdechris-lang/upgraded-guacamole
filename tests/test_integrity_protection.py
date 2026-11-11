"""Protection planning must preserve live constraints and reject optimistic activation."""

import copy
import hashlib
import json

import pytest

from integrity_guard.protection import (
    CI_CONTEXT,
    GUARD_CONTEXT,
    ProtectionValidationError,
    build_ruleset_payload,
    evaluate_readiness,
    fingerprint_ruleset,
)


APP = 15368
REPO = "example/project"
HEAD = "a" * 40
LEGACY_CONTEXTS = [
    "codeql", "gitleaks", "govulncheck", "python-tests",
    "receipt-verifier", "repository-hygiene", "test",
]


def ruleset():
    return {
        "id": 27074079,
        "name": "Pre-Merge Integrity Protection (main)",
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {"ref_name": {"include": ["refs/heads/main", "~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [
            {"type": "deletion"},
            {"type": "pull_request", "parameters": {
                "required_approving_review_count": 1,
                "dismiss_stale_reviews_on_push": True,
                "require_code_owner_review": False,
                "require_last_push_approval": False,
                "required_review_thread_resolution": True,
                "require_extra_approval_for_unattributed_changes": True,
                "required_reviewers": [],
                "allowed_merge_methods": ["merge", "squash", "rebase"],
            }},
            {"type": "non_fast_forward"},
        ],
        "updated_at": "2026-11-11T23:21:50Z",
        "source": REPO,
        "source_type": "Repository",
    }


def protection():
    return {"required_status_checks": {
        "strict": False,
        "contexts": list(LEGACY_CONTEXTS),
        "checks": [{"context": name, "app_id": APP} for name in LEGACY_CONTEXTS],
    }}


def indexed(payload):
    return {rule["type"]: rule for rule in payload["rules"]}


def checks(payload):
    return {
        check["context"]: check.get("integration_id")
        for check in indexed(payload)["required_status_checks"]["parameters"]["required_status_checks"]
    }


def ready_inputs():
    return {
        "repository": REPO,
        "bootstrap_pr": {
            "merged": True, "state": "closed", "draft": False,
            "base": {"ref": "main", "repo": {"full_name": REPO}},
            "head": {"sha": "b" * 40, "repo": {"full_name": REPO}},
            "merge_commit_sha": "c" * 40,
        },
        "deployed_files_match": True,
        "guard_check": {
            "name": GUARD_CONTEXT, "head_sha": HEAD, "app": {"id": APP},
            "status": "completed", "conclusion": "success",
        },
        "ci_check": {
            "name": CI_CONTEXT, "head_sha": HEAD, "app": {"id": APP},
            "status": "completed", "conclusion": "success",
        },
        "current_head_sha": HEAD,
        "source_app_id": APP,
        "independent_codeowner_verified": True,
    }


def test_real_snapshot_shape_preserves_seven_legacy_checks_and_adds_two_bound_gates():
    current, classic = ruleset(), protection()
    before = copy.deepcopy((current, classic))
    payload = build_ruleset_payload(current, classic, source_app_id=APP)
    assert checks(payload) == {name: APP for name in LEGACY_CONTEXTS + [GUARD_CONTEXT, CI_CONTEXT]}
    assert (current, classic) == before
    assert payload["conditions"] == current["conditions"]
    assert payload["name"] == current["name"]
    assert "id" not in payload and "source" not in payload and "updated_at" not in payload
    status = indexed(payload)["required_status_checks"]["parameters"]
    assert status["strict_required_status_checks_policy"] is True
    assert status["do_not_enforce_on_create"] is False
    pr = indexed(payload)["pull_request"]["parameters"]
    assert pr["require_code_owner_review"] is True
    assert pr["require_last_push_approval"] is True
    assert pr["dismiss_stale_reviews_on_push"] is True
    assert pr["required_review_thread_resolution"] is True
    assert "require_review_thread_resolution" not in pr
    assert pr["require_extra_approval_for_unattributed_changes"] is True
    assert pr["allowed_merge_methods"] == ["merge", "squash", "rebase"]
    assert payload["enforcement"] == "active" and payload["bypass_actors"] == []


def test_planning_is_idempotent_without_duplicate_rules_or_checks():
    first = build_ruleset_payload(ruleset(), protection(), source_app_id=APP)
    assert build_ruleset_payload(first, protection(), source_app_id=APP) == first


def test_preserves_stronger_approvals_unrelated_rules_and_other_publishers():
    current = ruleset()
    current["rules"][1]["parameters"]["required_approving_review_count"] = 3
    extra = {"type": "required_signatures"}
    current["rules"].extend([extra, {
        "type": "required_status_checks", "parameters": {"required_status_checks": [
            {"context": "External verifier", "integration_id": 9001},
            {"context": "legacy-any-source"},
        ]},
    }])
    payload = build_ruleset_payload(current, protection(), source_app_id=APP)
    assert indexed(payload)["required_signatures"] == extra
    assert indexed(payload)["pull_request"]["parameters"]["required_approving_review_count"] == 3
    assert checks(payload)["External verifier"] == 9001
    assert checks(payload)["legacy-any-source"] is None


def test_known_classic_source_strengthens_same_unbound_ruleset_context():
    current = ruleset()
    current["rules"].append({"type": "required_status_checks", "parameters": {
        "required_status_checks": [{"context": "python-tests"}],
    }})
    assert checks(build_ruleset_payload(current, protection(), source_app_id=APP))["python-tests"] == APP


def test_different_known_sources_are_not_silently_rebound():
    current = ruleset()
    current["rules"].append({"type": "required_status_checks", "parameters": {
        "required_status_checks": [{"context": "python-tests", "integration_id": 777}],
    }})
    with pytest.raises(ProtectionValidationError, match="sources conflict"):
        build_ruleset_payload(current, protection(), source_app_id=APP)


def test_new_gate_cannot_silently_replace_an_existing_dedicated_app():
    classic = protection()
    classic["required_status_checks"]["checks"].append({"context": GUARD_CONTEXT, "app_id": 777})
    with pytest.raises(ProtectionValidationError):
        build_ruleset_payload(ruleset(), classic, source_app_id=APP)


def test_classic_unbound_contexts_are_preserved_and_minus_one_is_not_an_app():
    classic = {"required_status_checks": {
        "contexts": ["legacy"], "checks": [{"context": "other", "app_id": -1}],
    }}
    output = checks(build_ruleset_payload(ruleset(), classic, source_app_id=APP))
    assert output["legacy"] is None and output["other"] is None


def test_missing_baseline_rules_are_added_without_relaxing_other_rules():
    current = ruleset()
    current["rules"] = [{"type": "required_linear_history"}]
    payload = build_ruleset_payload(current, {"required_status_checks": None}, source_app_id=APP)
    assert set(indexed(payload)) == {
        "deletion", "non_fast_forward", "pull_request", "required_status_checks", "required_linear_history",
    }


@pytest.mark.parametrize("source", [True, False, None, 0, -1, 15368.0, "15368", 2**63])
def test_invalid_expected_source_cannot_generate_payload(source):
    with pytest.raises(ProtectionValidationError):
        build_ruleset_payload(ruleset(), protection(), source_app_id=source)


def test_user_payload_typo_is_rejected_instead_of_silently_ignored():
    current = ruleset()
    params = current["rules"][1]["parameters"]
    params["require_review_thread_resolution"] = params.pop("required_review_thread_resolution")
    with pytest.raises(ProtectionValidationError):
        build_ruleset_payload(current, protection(), source_app_id=APP)


def test_duplicate_rule_types_are_ambiguous_and_rejected():
    current = ruleset()
    current["rules"].append({"type": "non_fast_forward"})
    with pytest.raises(ProtectionValidationError):
        build_ruleset_payload(current, protection(), source_app_id=APP)


@pytest.mark.parametrize("location", ["contexts", "checks"])
def test_duplicate_classic_contexts_are_rejected(location):
    classic = protection()
    classic["required_status_checks"][location].append(classic["required_status_checks"][location][0])
    with pytest.raises(ProtectionValidationError):
        build_ruleset_payload(ruleset(), classic, source_app_id=APP)


def test_duplicate_ruleset_contexts_are_rejected_even_when_sources_agree():
    current = ruleset()
    current["rules"].append({"type": "required_status_checks", "parameters": {
        "required_status_checks": [{"context": "same", "integration_id": APP}] * 2,
    }})
    with pytest.raises(ProtectionValidationError):
        build_ruleset_payload(current, protection(), source_app_id=APP)


@pytest.mark.parametrize("classic", [{}, {"required_status_checks": {}}, [], None])
def test_unknown_classic_protection_is_not_treated_as_absence(classic):
    with pytest.raises(ProtectionValidationError):
        build_ruleset_payload(ruleset(), classic, source_app_id=APP)


@pytest.mark.parametrize("field,value", [
    ("target", "tag"), ("bypass_actors", None), ("name", ""), ("rules", None),
    ("enforcement", []), ("enforcement", {}), ("enforcement", True),
])
def test_invalid_ruleset_shape_cannot_be_fingerprinted(field, value):
    current = ruleset()
    current[field] = value
    with pytest.raises(ProtectionValidationError):
        fingerprint_ruleset(current)


@pytest.mark.parametrize("selector", ["refs/heads/main", "refs/heads/*", "*", "~ALL", "~DEFAULT_BRANCH"])
def test_excluding_main_cannot_generate_an_apparently_active_lockdown(selector):
    current = ruleset()
    current["conditions"]["ref_name"]["exclude"] = [selector]
    with pytest.raises(ProtectionValidationError):
        build_ruleset_payload(current, protection(), source_app_id=APP)


def test_unrelated_ref_exclusion_is_preserved_without_widening_scope():
    current = ruleset()
    current["conditions"]["ref_name"]["exclude"] = ["refs/heads/release/*"]
    result = build_ruleset_payload(current, protection(), source_app_id=APP)
    assert result["conditions"] == current["conditions"]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), b"not-json", object(), {1: "key"}])
def test_non_json_values_cannot_hide_in_ruleset_metadata(value):
    current = ruleset()
    current["metadata"] = value
    with pytest.raises(ProtectionValidationError) as error:
        fingerprint_ruleset(current)
    assert "not-json" not in str(error.value)


def test_fingerprint_excludes_readonly_metadata_but_detects_control_drift():
    current = ruleset()
    before = fingerprint_ruleset(current)
    assert len(before) == 64
    current["updated_at"] = "later"
    current["node_id"] = "opaque"
    assert fingerprint_ruleset(current) == before
    current["rules"][1]["parameters"]["require_last_push_approval"] = True
    assert fingerprint_ruleset(current) != before
    expected = {key: ruleset()[key] for key in (
        "name", "target", "enforcement", "bypass_actors", "conditions", "rules",
    )}
    encoded = json.dumps(expected, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    assert before == hashlib.sha256(encoded).hexdigest()


def test_exact_success_evidence_allows_readiness_without_claiming_application():
    assert evaluate_readiness(**ready_inputs()) == []


def test_actual_unmerged_bootstrap_conditions_hold_even_with_two_green_checks():
    data = ready_inputs()
    data["bootstrap_pr"].update(merged=False, state="open", draft=True, merge_commit_sha=None)
    data["deployed_files_match"] = False
    data["independent_codeowner_verified"] = False
    codes = {reason["code"] for reason in evaluate_readiness(**data)}
    assert {"BOOTSTRAP_NOT_MERGED", "DEPLOYMENT_NOT_VERIFIED", "INDEPENDENT_CODEOWNER_REQUIRED"} <= codes


@pytest.mark.parametrize("field", ["guard_check", "ci_check"])
@pytest.mark.parametrize("conclusion", [None, "neutral", "skipped", "failure", "cancelled", "timed_out"])
def test_neutral_skipped_and_other_non_successes_cannot_activate(field, conclusion):
    data = ready_inputs()
    data[field]["conclusion"] = conclusion
    assert evaluate_readiness(**data)


@pytest.mark.parametrize("field", ["guard_check", "ci_check"])
def test_success_text_without_completed_run_cannot_activate(field):
    data = ready_inputs()
    data[field]["status"] = "in_progress"
    assert evaluate_readiness(**data)


@pytest.mark.parametrize("field", ["guard_check", "ci_check"])
@pytest.mark.parametrize("mutation", ["missing", "wrong_sha", "wrong_app", "boolean_app", "wrong_name"])
def test_missing_or_misattributed_checks_cannot_activate(field, mutation):
    data = ready_inputs()
    if mutation == "missing":
        data[field] = None
    elif mutation == "wrong_sha":
        data[field]["head_sha"] = "d" * 40
    elif mutation == "wrong_app":
        data[field]["app"]["id"] = 777
    elif mutation == "boolean_app":
        data[field]["app"]["id"] = True
    else:
        data[field]["name"] = "other"
    assert evaluate_readiness(**data)


@pytest.mark.parametrize("field", ["deployed_files_match", "independent_codeowner_verified"])
@pytest.mark.parametrize("value", [False, None, 1, "true"])
def test_readiness_requires_positive_typed_deployment_and_owner_evidence(field, value):
    data = ready_inputs()
    data[field] = value
    assert evaluate_readiness(**data)


@pytest.mark.parametrize("part", ["base", "head"])
def test_wrong_bootstrap_repository_cannot_be_used(part):
    data = ready_inputs()
    data["bootstrap_pr"][part]["repo"]["full_name"] = "other/repository"
    assert evaluate_readiness(**data)


def test_bootstrap_must_target_main():
    data = ready_inputs()
    data["bootstrap_pr"]["base"]["ref"] = "other"
    assert evaluate_readiness(**data)


@pytest.mark.parametrize("revision", ["b" * 40, "c" * 40])
def test_bootstrap_or_merge_commit_cannot_replace_separate_activation_test(revision):
    data = ready_inputs()
    data["current_head_sha"] = revision
    data["guard_check"]["head_sha"] = revision
    data["ci_check"]["head_sha"] = revision
    assert any(reason["code"] == "BOOTSTRAP_REVISION_REUSED" for reason in evaluate_readiness(**data))


def test_connector_summary_is_not_mistaken_for_raw_pr_evidence():
    data = ready_inputs()
    data["bootstrap_pr"] = {
        "merged": True, "state": "closed", "draft": False,
        "base": "main", "head": "feature", "base_sha": "b" * 40, "head_sha": HEAD,
    }
    assert evaluate_readiness(**data)


@pytest.mark.parametrize("field,value", [
    ("repository", "../repository"), ("repository", None),
    ("source_app_id", True), ("source_app_id", -1),
    ("current_head_sha", "main"), ("current_head_sha", None),
])
def test_invalid_expected_identity_is_a_fixed_hold(field, value):
    data = ready_inputs()
    data[field] = value
    assert evaluate_readiness(**data) == [{
        "code": "INPUT_INVALID", "message": "Expected repository, revision or source identity is invalid.",
    }]


def test_invalid_evidence_never_echoes_untrusted_secrets():
    data = ready_inputs()
    data["bootstrap_pr"] = {"unexpected": "UNTRUSTED_SECRET_MARKER"}
    data["guard_check"]["name"] = "UNTRUSTED_SECRET_MARKER"
    result = evaluate_readiness(**data)
    assert result and "UNTRUSTED_SECRET_MARKER" not in json.dumps(result)
