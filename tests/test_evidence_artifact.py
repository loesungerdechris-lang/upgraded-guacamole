from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from sentinel_core.evidence_artifact import (
    ZERO_HASH,
    build_merkle_proof,
    compute_artifact_hash,
    compute_conflict_hash,
    compute_event_hash,
    compute_governance_root,
    compute_member_hash,
    load_evidence_artifact_json,
    merkle_root,
    sha256_prefixed,
    validate_evidence_artifact,
    verify_evidence_artifact,
    verify_evidence_artifact_file,
    verify_merkle_proof,
)


def digest(label: str) -> str:
    return sha256_prefixed(label)


def member(
    member_id: str,
    payload: bytes,
    path: str | None,
    *,
    source_id: str = "internet-archive-wayback",
    source_origin: str = "wayback-phase1",
    identity_status: str = "VERIFIED",
    datetime_status: str = "VERIFIED",
    acquisition_authority: str = "phase1_wayback_read_only",
) -> dict:
    value = {
        "member_id": member_id,
        "kind": "RAW_PAYLOAD",
        "source_id": source_id,
        "path": path,
        "media_type": "text/html",
        "byte_length": len(payload),
        "sha256": sha256_prefixed(payload),
        "observed_at": "2026-07-12T10:00:00Z",
        "provenance": {
            "source_origin": source_origin,
            "source_record_hash": digest(f"record:{member_id}"),
            "identity_status": identity_status,
            "datetime_status": datetime_status,
            "acquisition_authority": acquisition_authority,
        },
        "member_hash": ZERO_HASH,
    }
    value["member_hash"] = compute_member_hash(value)
    return value


def event(
    sequence: int,
    event_type: str,
    occurred_at: str,
    previous_event_hash: str,
    *,
    inputs: list[str],
    outputs: list[str],
    policies: list[str],
    decision: str = "HOLD",
    actor_type: str = "SYSTEM",
    actor_id_hash: str | None = None,
) -> dict:
    value = {
        "sequence": sequence,
        "event_type": event_type,
        "occurred_at": occurred_at,
        "actor": {
            "actor_type": actor_type,
            "actor_id_hash": actor_id_hash,
            "role": "artifact_builder",
        },
        "input_hashes": sorted(inputs),
        "output_hashes": sorted(outputs),
        "policy_hashes": sorted(policies),
        "decision": decision,
        "previous_event_hash": previous_event_hash,
        "event_hash": ZERO_HASH,
    }
    value["event_hash"] = compute_event_hash(value)
    return value


def artifact_fixture(payloads: tuple[bytes, bytes] = (b"alpha", b"beta")) -> dict:
    members = [
        member("member-001", payloads[0], "raw/alpha.html"),
        member(
            "member-002",
            payloads[1],
            "raw/beta.html",
            source_id="memento-discovery",
            source_origin="memento-protocol-discovery",
            identity_status="DECLARED",
            datetime_status="DECLARED",
            acquisition_authority="separate_policy_required",
        ),
    ]
    policy_hash = digest("policy:v1")
    governance = {
        "policies": [
            {"policy_id": "evidence-policy", "version": "1.0", "sha256": policy_hash}
        ],
        "registries": [
            {"registry_id": "source-registry", "version": "1.0", "sha256": digest("registry:v1")}
        ],
        "operation_plan_hash": digest("operation-plan"),
        "source_commit": "a" * 40,
        "parent_stack_hash": digest("parent-stack"),
        "ci_evidence": {
            "workflow_hash": digest("workflow"),
            "run_id": "run-123",
            "result": "SUCCESS",
        },
        "environment_descriptor_hash": None,
        "privacy_review_hash": digest("privacy-review"),
        "terms_review_hash": digest("terms-review"),
        "threat_model_hash": digest("threat-model"),
        "retention_decision_hash": digest("retention"),
    }
    evidence_root = merkle_root([item["member_hash"] for item in members])
    conflict_root = ZERO_HASH
    governance_root = compute_governance_root(governance)
    discovered = event(
        0,
        "DISCOVERED",
        "2026-07-12T10:05:00Z",
        ZERO_HASH,
        inputs=[],
        outputs=[item["member_hash"] for item in members],
        policies=[policy_hash],
    )
    sealed = event(
        1,
        "INTEGRITY_SEAL",
        "2026-07-12T10:10:00Z",
        discovered["event_hash"],
        inputs=[evidence_root, conflict_root, governance_root],
        outputs=[],
        policies=[policy_hash],
    )
    value = {
        "schema_version": "sentinel.evidence.artifact.v1",
        "profile": "sentinel-e2e-evidence-v1",
        "canonicalization_profile": "sentinel-canonical-json-v1",
        "artifact_id": "artifact:test-001",
        "status": "HOLD",
        "created_at": "2026-07-12T10:15:00Z",
        "subject": {
            "subject_id": "subject-001",
            "case_id_hash": None,
            "description_hash": digest("subject description"),
        },
        "roots": {
            "member_count": 2,
            "conflict_count": 0,
            "evidence_root": evidence_root,
            "conflict_root": conflict_root,
            "governance_root": governance_root,
            "lifecycle_root": sealed["event_hash"],
        },
        "members": members,
        "governance_bindings": governance,
        "conflicts": [],
        "lifecycle": [discovered, sealed],
        "temporal_binding": {
            "claimed_created_at": "2026-07-12T10:15:00Z",
            "anchor_status": "UNANCHORED_HOLD",
            "anchor_hashes": [],
        },
        "release_binding": {
            "publication": False,
            "verified_envelope_hash": None,
            "release_receipt_hash": None,
        },
        "interpretation_limits": [
            "archive timestamp is not automatically publication time",
            "archive gaps do not prove non-existence",
            "integrity verification is not a truth judgment",
        ],
        "artifact_hash": ZERO_HASH,
    }
    value["artifact_hash"] = compute_artifact_hash(value)
    return value


def rehash(value: dict) -> dict:
    value["artifact_hash"] = compute_artifact_hash(value)
    return value


def rebuild_lifecycle(value: dict) -> None:
    previous = ZERO_HASH
    for index, item in enumerate(value["lifecycle"]):
        item["sequence"] = index
        item["previous_event_hash"] = previous
        item["event_hash"] = compute_event_hash(item)
        previous = item["event_hash"]
    value["roots"]["lifecycle_root"] = previous
    rehash(value)


def test_valid_hold_artifact_verifies_bindings():
    result = verify_evidence_artifact(artifact_fixture())
    assert result.status == "SEA_INTEGRITY_OK"
    assert result.integrity_valid is True
    assert result.level == "BINDINGS"
    assert result.release_authorized is False
    assert result.temporal_anchor_verified is False


def test_local_bundle_verifies_exact_bytes(tmp_path: Path):
    value = artifact_fixture()
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "alpha.html").write_bytes(b"alpha")
    (tmp_path / "raw" / "beta.html").write_bytes(b"beta")
    result = verify_evidence_artifact(value, bundle_root=tmp_path)
    assert result.integrity_valid is True
    assert result.level == "BYTES"


def test_payload_tamper_is_detected(tmp_path: Path):
    value = artifact_fixture()
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "alpha.html").write_bytes(b"tampered")
    (tmp_path / "raw" / "beta.html").write_bytes(b"beta")
    result = verify_evidence_artifact(value, bundle_root=tmp_path)
    assert result.integrity_valid is False
    assert "payload hash mismatch" in result.issues[0].message


def test_member_metadata_tamper_is_detected():
    value = artifact_fixture()
    value["members"][0]["media_type"] = "text/plain"
    result = verify_evidence_artifact(value)
    assert result.integrity_valid is False
    assert "descriptor hash mismatch" in result.issues[0].message


def test_artifact_hash_tamper_is_detected():
    value = artifact_fixture()
    value["artifact_hash"] = digest("wrong")
    assert verify_evidence_artifact(value).integrity_valid is False


def test_governance_tamper_is_detected_even_after_artifact_rehash():
    value = artifact_fixture()
    value["governance_bindings"]["source_commit"] = "b" * 40
    rehash(value)
    result = verify_evidence_artifact(value)
    assert result.integrity_valid is False
    assert "Governance root mismatch" in result.issues[0].message


def test_lifecycle_previous_hash_tamper_is_detected():
    value = artifact_fixture()
    value["lifecycle"][1]["previous_event_hash"] = digest("wrong")
    value["lifecycle"][1]["event_hash"] = compute_event_hash(value["lifecycle"][1])
    value["roots"]["lifecycle_root"] = value["lifecycle"][1]["event_hash"]
    rehash(value)
    result = verify_evidence_artifact(value)
    assert result.integrity_valid is False
    assert "previous hash mismatch" in result.issues[0].message


def test_lifecycle_unknown_hash_is_rejected():
    value = artifact_fixture()
    value["lifecycle"][0]["input_hashes"] = [digest("unknown")]
    rebuild_lifecycle(value)
    result = verify_evidence_artifact(value)
    assert result.integrity_valid is False
    assert "unknown hash" in result.issues[0].message


def test_non_hold_status_is_rejected():
    value = artifact_fixture()
    value["status"] = "VERIFIED"
    rehash(value)
    assert verify_evidence_artifact(value).integrity_valid is False


def test_release_receipt_binding_is_rejected():
    value = artifact_fixture()
    value["release_binding"]["release_receipt_hash"] = digest("receipt")
    rehash(value)
    assert verify_evidence_artifact(value).integrity_valid is False


def test_temporal_anchor_is_rejected():
    value = artifact_fixture()
    value["temporal_binding"]["anchor_hashes"] = [digest("timestamp")]
    rehash(value)
    assert verify_evidence_artifact(value).integrity_valid is False


def test_temporal_claim_must_match_created_at():
    value = artifact_fixture()
    value["temporal_binding"]["claimed_created_at"] = "2026-07-12T09:00:00Z"
    rehash(value)
    result = verify_evidence_artifact(value)
    assert result.integrity_valid is False
    assert "Temporal claim" in result.issues[0].message


def test_member_observation_after_creation_is_rejected():
    value = artifact_fixture()
    value["members"][0]["observed_at"] = "2026-07-12T11:00:00Z"
    value["members"][0]["member_hash"] = compute_member_hash(value["members"][0])
    value["roots"]["evidence_root"] = merkle_root(
        [item["member_hash"] for item in value["members"]]
    )
    rehash(value)
    result = verify_evidence_artifact(value)
    assert result.integrity_valid is False
    assert "after artifact creation" in result.issues[0].message


def test_unsafe_bundle_path_is_rejected():
    value = artifact_fixture()
    value["members"][0]["path"] = "../escape"
    value["members"][0]["member_hash"] = compute_member_hash(value["members"][0])
    rehash(value)
    assert verify_evidence_artifact(value).integrity_valid is False


def test_symlink_member_is_rejected(tmp_path: Path):
    value = artifact_fixture()
    outside = tmp_path / "outside"
    outside.write_bytes(b"alpha")
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "alpha.html").symlink_to(outside)
    (tmp_path / "raw" / "beta.html").write_bytes(b"beta")
    result = verify_evidence_artifact(value, bundle_root=tmp_path)
    assert result.integrity_valid is False
    assert "symbolic link" in result.issues[0].message


def test_members_must_be_sorted():
    value = artifact_fixture()
    value["members"].reverse()
    rehash(value)
    result = verify_evidence_artifact(value)
    assert result.integrity_valid is False
    assert "sorted by member_id" in result.issues[0].message


def test_conflict_binds_existing_member_hashes():
    value = artifact_fixture()
    conflict = {
        "conflict_id": "conflict-001",
        "type": "HASH_MISMATCH",
        "severity": "HIGH",
        "member_hashes": sorted([item["member_hash"] for item in value["members"]]),
        "description_hash": digest("different payloads"),
        "resolution_status": "OPEN_HOLD",
        "resolution_record_hash": None,
        "conflict_hash": ZERO_HASH,
    }
    conflict["conflict_hash"] = compute_conflict_hash(conflict)
    value["conflicts"] = [conflict]
    value["roots"]["conflict_count"] = 1
    value["roots"]["conflict_root"] = merkle_root([conflict["conflict_hash"]])
    value["lifecycle"][1]["input_hashes"] = sorted(
        [
            value["roots"]["evidence_root"],
            value["roots"]["conflict_root"],
            value["roots"]["governance_root"],
        ]
    )
    rebuild_lifecycle(value)
    assert verify_evidence_artifact(value).integrity_valid is True


def test_conflict_unknown_member_is_rejected():
    value = artifact_fixture()
    conflict = {
        "conflict_id": "conflict-001",
        "type": "HASH_MISMATCH",
        "severity": "HIGH",
        "member_hashes": [digest("unknown-member")],
        "description_hash": digest("different payloads"),
        "resolution_status": "OPEN_HOLD",
        "resolution_record_hash": None,
        "conflict_hash": ZERO_HASH,
    }
    conflict["conflict_hash"] = compute_conflict_hash(conflict)
    value["conflicts"] = [conflict]
    value["roots"]["conflict_count"] = 1
    value["roots"]["conflict_root"] = merkle_root([conflict["conflict_hash"]])
    rehash(value)
    assert verify_evidence_artifact(value).integrity_valid is False


def test_merkle_inclusion_proof_verifies():
    value = artifact_fixture()
    hashes = [item["member_hash"] for item in value["members"]]
    proof = build_merkle_proof(hashes, 1)
    assert verify_merkle_proof(
        hashes[1],
        index=1,
        leaf_count=len(hashes),
        proof=proof,
        expected_root=value["roots"]["evidence_root"],
    )


def test_merkle_proof_is_bound_to_index():
    value = artifact_fixture()
    hashes = [item["member_hash"] for item in value["members"]]
    proof = build_merkle_proof(hashes, 1)
    assert not verify_merkle_proof(
        hashes[1],
        index=0,
        leaf_count=len(hashes),
        proof=proof,
        expected_root=value["roots"]["evidence_root"],
    )


def test_floating_point_values_are_rejected():
    value = artifact_fixture()
    value["roots"]["member_count"] = 2.0
    result = verify_evidence_artifact(value)
    assert result.integrity_valid is False
    assert "Floating-point" in result.issues[0].message


def test_unsafe_integer_is_rejected():
    value = artifact_fixture()
    value["roots"]["member_count"] = 2**53
    assert verify_evidence_artifact(value).integrity_valid is False


def test_human_actor_requires_hashed_identifier():
    value = artifact_fixture()
    value["lifecycle"][0]["actor"]["actor_type"] = "HUMAN"
    rebuild_lifecycle(value)
    result = verify_evidence_artifact(value)
    assert result.integrity_valid is False
    assert "hashed identifier" in result.issues[0].message


def test_lifecycle_timestamps_must_be_ordered():
    value = artifact_fixture()
    value["lifecycle"][1]["occurred_at"] = "2026-07-12T09:00:00Z"
    rebuild_lifecycle(value)
    assert verify_evidence_artifact(value).integrity_valid is False


def test_hash_arrays_must_be_sorted():
    value = artifact_fixture()
    value["lifecycle"][1]["input_hashes"].reverse()
    rebuild_lifecycle(value)
    result = verify_evidence_artifact(value)
    assert result.integrity_valid is False
    assert "sorted unique hashes" in result.issues[0].message


def test_duplicate_json_keys_are_rejected(tmp_path: Path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":"a","schema_version":"b"}', encoding="utf-8")
    result = verify_evidence_artifact_file(path)
    assert result.integrity_valid is False
    assert result.issues[0].code == "ARTIFACT_JSON_INVALID"


def test_oversized_json_is_rejected(tmp_path: Path):
    path = tmp_path / "large.json"
    path.write_text("{}" * 20, encoding="utf-8")
    with pytest.raises(Exception, match="size limit"):
        load_evidence_artifact_json(path, max_bytes=8)


def test_invalid_json_returns_machine_readable_failure(tmp_path: Path):
    path = tmp_path / "invalid.json"
    path.write_text("{", encoding="utf-8")
    result = verify_evidence_artifact_file(path)
    assert result.status == "SEA_NOT_VERIFIED"
    assert result.level == "NONE"


def test_zero_conflict_root_is_explicit():
    value = artifact_fixture()
    assert value["conflicts"] == []
    assert value["roots"]["conflict_root"] == ZERO_HASH
    assert validate_evidence_artifact(value) == "BINDINGS"
