from pathlib import Path


SPEC_PATH = Path("docs/phase3-operational-orchestration-spec.md")


def read_spec() -> str:
    return SPEC_PATH.read_text(encoding="utf-8")


def test_operational_spec_exists_and_is_hold():
    text = read_spec()
    assert "**Status:** DRAFT / HOLD" in text
    assert "**Activation authority:** none" in text
    assert "Every run and every output remains `HOLD`." in text


def test_no_release_state_transition_is_defined():
    text = read_spec()
    assert "There is no transition to `VERIFIED` or `PUBLISHED`." in text
    assert "No run changes `HOLD` to `VERIFIED` or `PUBLISHED`." in text
    assert "Publication is outside Phase 3 and remains blocked by Issue #30." in text


def test_first_profile_is_sequential_and_fail_closed():
    text = read_spec()
    assert "global_concurrency: 1" in text
    assert "per_source_concurrency: 1" in text
    assert "no automatic all-source fan-out" in text
    assert "The first operational profile is sequential." in text


def test_wayback_boundary_is_preserved():
    text = read_spec()
    assert "fixed official Internet Archive hosts" in text
    assert "no Save Page Now" in text
    assert "no live-resource fallback" in text


def test_memento_remains_discovery_only():
    text = read_spec()
    assert "Memento is discovery provenance only and never acquires candidate content." in text
    assert "no candidate-content acquisition" in text
    assert "no recursive TimeMap traversal" in text
    assert "Memento discovery metadata alone is not eligible for byte-level agreement." in text


def test_secondary_sources_remain_disabled():
    text = read_spec()
    assert "### 9.3 archive.today-family services" in text
    assert "Status: planned and disabled." in text
    assert "The adapter must not bypass CAPTCHAs" in text
    assert "No Perma.cc creation path is part of the initial Phase 3 operational profile." in text


def test_cross_verification_has_no_network_authority():
    text = read_spec()
    assert "It has no adapter registry and no transport." in text
    assert "Source count is not truth." in text
    assert "majority votes" in text
    assert "automatic representative-version selection" in text


def test_failure_classes_are_not_collapsed():
    text = read_spec()
    for marker in (
        "NOT_FOUND",
        "QUERY_FAILED",
        "POLICY_BLOCKED",
        "NOT_QUERIED",
        "PAGINATION_REQUIRED",
        "PARTIAL_HOLD",
    ):
        assert marker in text
    assert "a failed query is not `NOT_FOUND`" in text


def test_unsafe_capabilities_are_explicit_non_goals():
    text = read_spec()
    for marker in (
        "endpoint activation",
        "credential use",
        "archive writes",
        "whole-domain crawling",
        "background monitoring",
        "aggressive parallelism",
        "recursive Memento traversal",
        "archive.today challenge bypass",
        "Perma.cc link creation",
        "active rendering",
        "receipt signing",
        "publication",
    ):
        assert f"- {marker};" in text or f"- {marker}." in text
