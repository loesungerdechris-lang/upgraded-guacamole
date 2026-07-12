from __future__ import annotations

import copy

import pytest

from sentinel_core.hashchain import canonicalize_json, sha256_prefixed
from sentinel_core.wayback import (
    WaybackSnapshot,
    build_artifact_record,
    build_evidence_manifest,
    materialize_offline_restore,
)
from sentinel_core.wayback_manifest import (
    WaybackManifestValidationError,
    validate_wayback_manifest,
)


def _manifest_and_bytes() -> tuple[dict, bytes]:
    snapshot = WaybackSnapshot(
        timestamp="20240102030405",
        original_url="https://example.com/",
        status_code=200,
        replay_url="https://web.archive.org/web/20240102030405/https://example.com/",
        mime_type="text/html",
        archive_digest="ABC123",
        length=20,
    )
    content = b"<html>archive</html>"
    artifact = build_artifact_record(
        snapshot=snapshot,
        content=content,
        content_type="text/html",
        relative_path="site/index.html",
        retrieved_at="2026-07-12T08:00:00Z",
    )
    manifest = build_evidence_manifest(
        target_url="https://example.com/",
        snapshot=snapshot,
        artifacts=[artifact],
        observed_at="2026-07-12T08:00:00Z",
    )
    return manifest, content


def _rehash(manifest: dict) -> None:
    unsigned = copy.deepcopy(manifest)
    unsigned.pop("manifest_hash", None)
    manifest["manifest_hash"] = sha256_prefixed(canonicalize_json(unsigned))


def test_valid_hold_manifest_and_bundle_pass(tmp_path) -> None:
    manifest, content = _manifest_and_bytes()
    materialize_offline_restore({"site/index.html": content}, tmp_path)

    validate_wayback_manifest(manifest, bundle_root=tmp_path)
    assert manifest["status"] == "HOLD"
    assert manifest["release_gate"]["publish_restored_content"] is False


def test_manifest_requires_all_interpretation_limits() -> None:
    manifest, _ = _manifest_and_bytes()
    manifest["interpretation_limits"].pop()
    _rehash(manifest)

    with pytest.raises(WaybackManifestValidationError, match="Schema validation"):
        validate_wayback_manifest(manifest)


def test_manifest_hash_tampering_fails() -> None:
    manifest, _ = _manifest_and_bytes()
    manifest["artifacts"][0]["byte_length"] = 1

    with pytest.raises(WaybackManifestValidationError, match="hash verification"):
        validate_wayback_manifest(manifest)


def test_bundle_hash_mismatch_fails(tmp_path) -> None:
    manifest, _ = _manifest_and_bytes()
    materialize_offline_restore({"site/index.html": b"tampered"}, tmp_path)

    with pytest.raises(WaybackManifestValidationError, match="byte length|SHA-256"):
        validate_wayback_manifest(manifest, bundle_root=tmp_path)


def test_non_hold_requires_explicit_release_aware_validation() -> None:
    manifest, _ = _manifest_and_bytes()
    manifest["status"] = "VERIFIED"
    manifest["release_gate"].update(
        {
            "mode": "offline_reviewed",
            "rights_review_status": "approved",
            "privacy_review_status": "approved",
            "provenance_review_status": "approved",
        }
    )
    _rehash(manifest)

    with pytest.raises(WaybackManifestValidationError, match="Non-HOLD"):
        validate_wayback_manifest(manifest)
    validate_wayback_manifest(manifest, allow_non_hold=True)


def test_cross_source_record_does_not_expand_wayback_network_trust() -> None:
    manifest, _ = _manifest_and_bytes()
    manifest["cross_verification_sources"] = [
        {
            "source_id": "perma-cc",
            "source_class": "external_archive",
            "source_origin": "Perma.cc",
            "original_url": "https://example.com/",
            "archive_url": "https://perma.cc/ABCD-1234",
            "archive_timestamp": None,
            "retrieval_timestamp": "2026-07-12T08:30:00Z",
            "sha256": "sha256:" + "0" * 64,
            "acquisition_authority": "separate_policy_required",
            "provenance_notes": "Recorded for later cross-verification only.",
            "limitations": ["Separate source policy and capture semantics apply."],
        }
    ]
    _rehash(manifest)

    validate_wayback_manifest(manifest)


def test_cross_source_must_target_same_original_url() -> None:
    manifest, _ = _manifest_and_bytes()
    manifest["cross_verification_sources"] = [
        {
            "source_id": "local-singlefile",
            "source_class": "local_capture",
            "source_origin": "SingleFile",
            "original_url": "https://example.net/",
            "archive_url": "https://example.net/local-record",
            "archive_timestamp": None,
            "retrieval_timestamp": "2026-07-12T08:30:00Z",
            "sha256": "sha256:" + "1" * 64,
            "acquisition_authority": "separate_policy_required",
            "provenance_notes": "Local record.",
            "limitations": ["Not an Internet Archive capture."],
        }
    ]
    _rehash(manifest)

    with pytest.raises(WaybackManifestValidationError, match="different original URL"):
        validate_wayback_manifest(manifest)
