from pathlib import Path


FRAMEWORK_PATH = Path("docs/phase3-pilot-activation-framework.md")


def read_framework() -> str:
    return FRAMEWORK_PATH.read_text(encoding="utf-8")


def test_framework_exists_and_grants_no_authority():
    text = read_framework()
    assert "**Status:** DRAFT / HOLD" in text
    assert "**Activation authority:** none" in text
    assert "Every run and\nevery output remains `HOLD`." in text


def test_issue_30_is_only_the_publication_dependency():
    text = read_framework()
    assert "Issue #30 is not a prerequisite for a strictly internal HOLD-only pilot." in text
    assert "It is\nthe separate prerequisite for any future publication transition." in text
    assert "There is no transition to `VERIFIED` or `PUBLISHED`." in text


def test_memento_remains_discovery_only():
    text = read_framework()
    assert "Memento remains discovery-only and never acquires candidate content." in text
    assert "There is no pilot phase in which the Memento adapter itself retrieves archived\ncontent." in text
    assert "no Memento content acquisition" in text


def test_first_profile_is_manual_bounded_and_sequential():
    text = read_framework()
    for marker in (
        "maximum_sources: 3",
        "maximum_targets: 50",
        "maximum_runs_per_day: 1",
        "manual_trigger_only: true",
        "global_concurrency: 1",
        "per_source_concurrency: 1",
        "publication: false",
    ):
        assert marker in text
    assert "The first Wayback live phase is limited to five approved URLs." in text
    assert "The first Wayback plus Memento discovery phase is limited to ten approved URLs." in text


def test_rate_limit_is_conservative_and_source_specific():
    text = read_framework()
    assert "The effective request rate is always the stricter of:" in text
    assert "one request every five seconds per\nsource" in text
    assert "No pilot source may exceed one request per second." in text
    assert "Invalid,\nnegative, or non-finite values use bounded fallback." in text


def test_raw_evidence_is_not_a_github_actions_artifact_by_default():
    text = read_framework()
    assert "must not be uploaded to GitHub\nActions artifacts by default" in text
    assert "An Actions artifact is not the authoritative evidence store." in text
    assert "approved encrypted restricted pilot store" in text


def test_abort_preserves_minimum_audit_and_incident_evidence():
    text = read_framework()
    assert "Raw data is not automatically deleted on abort." in text
    assert "preserve the immutable minimum audit record" in text
    assert "RETAIN_UNDER_INCIDENT_HOLD" in text
    assert "DESTROY_AFTER_APPROVED_REVIEW" in text


def test_wayback_and_secondary_provenance_are_not_mixed():
    text = read_framework()
    assert "Wayback artifacts use the reviewed Wayback schema." in text
    assert "They must not be forced into Wayback provenance fields." in text
    assert "Source identity, policy, transport, timestamps, and provenance remain\n   isolated." in text


def test_archive_writes_and_active_content_remain_disabled():
    text = read_framework()
    for marker in (
        "archive_writes: false",
        "active_content_execution: false",
        "live_fallback: false",
        "recursive_memento_traversal: false",
    ):
        assert marker in text
    assert "- Save Page Now;" in text
    assert "- archived JavaScript execution;" in text
    assert "- Perma.cc link creation;" in text


def test_phase_progression_requires_separate_manual_decisions():
    text = read_framework()
    assert "Each phase requires a separate manual GO/HOLD decision." in text
    assert "Approval for one phase\ndoes not authorize the next." in text
    assert "P4 is not granted by this framework document." in text


def test_pilot_environment_is_not_activation_authority():
    text = read_framework()
    assert "Creating the environment does not activate it." in text
    assert "manual trigger only" in text
    assert "no cron, background monitor, or automatic retry schedule" in text
    assert "no access to production credentials, production data, or signing keys" in text


def test_non_goals_block_activation_and_publication_paths():
    text = read_framework()
    for marker in (
        "source activation",
        "endpoint activation",
        "transport approval",
        "credential use",
        "whole-domain crawling",
        "background monitoring",
        "Memento content acquisition",
        "archive.today challenge bypass",
        "automatic status elevation",
        "receipt signing",
        "publication",
        "production use",
    ):
        assert f"- {marker};" in text or f"- {marker}." in text
