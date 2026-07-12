from pathlib import Path


ADDENDUM_PATH = Path("docs/phase3-pilot-threat-model-addendum.md")


def read_addendum() -> str:
    return ADDENDUM_PATH.read_text(encoding="utf-8")


def normalized_addendum() -> str:
    return " ".join(read_addendum().split())


def test_addendum_is_hold_and_grants_no_authority():
    text = read_addendum()
    normalized = normalized_addendum()
    assert "**Status:** DRAFT / HOLD" in text
    assert "**Activation authority:** none" in text
    assert (
        "Every modeled pilot state and every resulting evidence record remains `HOLD`."
        in normalized
    )


def test_issue_30_remains_publication_only():
    normalized = normalized_addendum()
    assert "Issue #30 remains the separate publication dependency." in normalized
    assert (
        "It does not grant pilot, network, adapter, acquisition, or environment authority."
        in normalized
    )
    assert "Publication remains outside the pilot" in normalized


def test_memento_authority_laundering_is_explicitly_blocked():
    text = read_addendum()
    normalized = normalized_addendum()
    assert "### P-23 — Memento authority laundering" in text
    assert "Memento remains discovery-only" in normalized
    assert "no candidate-content acquisition" in normalized
    assert "no automatic routing" in normalized
    assert "source_archive_verified: false" in text
    assert "datetime_verified: false" in text


def test_authorization_is_bound_and_expires():
    text = read_addendum()
    normalized = normalized_addendum()
    assert "### P-01 — Stale authorization replay" in text
    assert "bind `start_not_before` and `expires_at`" in normalized
    assert "Any binding mismatch or expired authorization" in normalized
    assert (
        "Approval must not be inferred from team membership, prior approval, CI success"
        in normalized
    )


def test_review_to_run_drift_is_fail_closed():
    text = read_addendum()
    normalized = normalized_addendum()
    assert "### P-05 — Review-to-run TOCTOU" in text
    assert "use exact commit SHA, not a mutable branch name" in normalized
    assert "regenerate authorization after any change" in normalized
    assert "bind parent PR head SHAs and base branches" in normalized


def test_untrusted_workflow_cannot_receive_pilot_secrets():
    text = read_addendum()
    normalized = normalized_addendum()
    assert "### P-13 — Fork or pull-request secret exposure" in text
    assert "no pilot secrets on untrusted pull-request events" in normalized
    assert "no `pull_request_target` execution of untrusted code" in normalized
    assert "pilot credentials have no production or signing privileges" in normalized


def test_egress_and_transport_are_exactly_bound():
    text = read_addendum()
    normalized = normalized_addendum()
    assert "### P-17 — Egress allowlist bypass" in text
    assert "no implicit redirects" in normalized
    assert "actual destination monitoring" in normalized
    assert "transport ID and implementation hash bound to authorization" in normalized
    assert "Any unapproved destination attempt" in normalized


def test_retry_and_pagination_cannot_expand_unboundedly():
    text = read_addendum()
    normalized = normalized_addendum()
    assert "### P-19 — Retry storm" in text
    assert "finite nonnegative retry delays only" in normalized
    assert "### P-20 — Pagination or candidate explosion" in text
    assert "no recursive Memento traversal" in normalized
    assert "`PAGINATION_REQUIRED` remains terminal" in normalized


def test_sensitive_data_is_excluded_from_actions_artifacts():
    text = read_addendum()
    normalized = normalized_addendum()
    assert "### P-27 — GitHub Actions artifact leakage" in text
    assert "raw sensitive evidence prohibited from Actions artifacts by default" in normalized
    assert "Actions artifacts are never authoritative evidence storage" in normalized
    assert "### P-26 — Sensitive logging" in text


def test_abort_does_not_delete_required_evidence():
    text = read_addendum()
    normalized = normalized_addendum()
    assert "### P-37 — Automatic evidence deletion" in text
    assert "no automatic deletion merely because a run aborted" in normalized
    assert "separate authorized destruction record" in normalized
    assert "### P-38 — Indefinite over-retention" in text


def test_result_classes_cannot_be_laundered():
    text = read_addendum()
    normalized = normalized_addendum()
    assert "### P-30 — Partial-result laundering" in text
    for marker in (
        "QUERY_FAILED",
        "POLICY_BLOCKED",
        "NOT_QUERIED",
        "PAGINATION_REQUIRED",
        "NOT_FOUND",
        "PARTIAL_HOLD",
    ):
        assert marker in text
    assert "no adapter failure interpreted as absence" in normalized


def test_stop_conditions_cover_critical_boundary_failures():
    text = read_addendum()
    normalized = normalized_addendum()
    assert "## 18. Mandatory stop conditions" in text
    for marker in (
        "an unapproved destination is contacted or attempted",
        "active content executes or live fallback occurs",
        "an archive write is attempted",
        "Memento attempts candidate-content acquisition or automatic routing",
        "stop switch, circuit breaker, redaction, or evidence-store control fails",
    ):
        assert marker in normalized


def test_negative_tests_cover_pilot_specific_failures():
    text = read_addendum()
    normalized = normalized_addendum()
    assert "## 20. Required negative tests" in text
    for marker in (
        "expired authorization is rejected",
        "CI success cannot substitute for pilot approval",
        "unapproved target or wildcard target is blocked",
        "workflow from untrusted code receives no pilot secret",
        "raw evidence cannot be uploaded as an Actions artifact by default",
        "deletion requires a separate authorized disposition record",
        "no pilot state becomes `VERIFIED` or `PUBLISHED`",
    ):
        assert marker in normalized


def test_explicit_non_goals_block_all_activation_paths():
    text = read_addendum()
    for marker in (
        "pilot approval",
        "environment activation",
        "endpoint or source activation",
        "transport approval",
        "external network execution",
        "Memento content acquisition",
        "archive writes",
        "background monitoring",
        "automatic status elevation",
        "receipt signing",
        "production use",
        "publication",
    ):
        assert f"- {marker};" in text or f"- {marker}." in text
