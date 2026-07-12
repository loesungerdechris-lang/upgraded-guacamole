from __future__ import annotations

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


def h(label: str | bytes) -> str:
    return sha256_prefixed(label)


def make_member(member_id: str, payload: bytes, path: str | None) -> dict:
    source_id = (
        "internet-archive-wayback"
        if member_id.endswith("1")
        else "memento-discovery"
    )
    declared = source_id == "memento-discovery"
    value = {
        "member_id": member_id,
        "kind": "DISCOVERY_RECORD" if declared else "RAW_PAYLOAD",
        "source_id": source_id,
        "path": path,
        "media_type": "application/json" if declared else "text/html",
        "byte_length": len(payload),
        "sha256": h(payload),
        "observed_at": "2026-07-12T10:00:00Z",
        "provenance": {
            "source_origin": (
                "memento-protocol-discovery" if declared else "wayback-phase1"
            ),
            "source_record_hash": h(f"record:{member_id}"),
            "identity_status": "DECLARED" if declared else "VERIFIED",
            "datetime_status": "DECLARED" if declared else "VERIFIED",
            "acquisition_authority": (
                "separate_policy_required"
                if declared
                else "phase1_wayback_read_only"
            ),
        },
        "member_hash": ZERO_HASH,
    }
    value["member_hash"] = compute_member_hash(value)
    return value


def make_event(
    sequence: int,
    event_type: str,
    occurred_at: str,
    previous: str,
    inputs: list[str],
    outputs: list[str],
    policy_hash: str,
) -> dict:
    value = {
        "sequence": sequence,
        "event_type": event_type,
        "occurred_at": occurred_at,
        "actor": {
            "actor_type": "SYSTEM",
            "actor_id_hash": None,
            "role": "builder",
        },
        "input_hashes": sorted(inputs),
        "output_hashes": sorted(outputs),
        "policy_hashes": [policy_hash],
        "decision": "HOLD",
        "previous_event_hash": previous,
        "event_hash": ZERO_HASH,
    }
    value["event_hash"] = compute_event_hash(value)
    return value


def make_artifact() -> dict:
    members = [
        make_member("member-001", b"alpha", "raw/alpha.html"),
        make_member("member-002", b"beta", "raw/beta.json"),
    ]
    policy_hash = h("policy:v1")
    governance = {
        "policies": [
            {
                "policy_id": "evidence-policy",
                "version": "1.0",
                "sha256": policy_hash,
            }
        ],
        "registries": [
            {
                "registry_id": "source-registry",
                "version": "1.0",
                "sha256": h("registry"),
            }
        ],
        "operation_plan_hash": h("operation-plan"),
        "source_commit": "a" * 40,
        "parent_stack_hash": h("parent-stack"),
        "ci_evidence": {
            "workflow_hash": h("workflow"),
            "run_id": "run-123",
            "result": "SUCCESS",
        },
        "environment_descriptor_hash": None,
        "privacy_review_hash": h("privacy"),
        "terms_review_hash": h("terms"),
        "threat_model_hash": h("threat-model"),
        "retention_decision_hash": h("retention"),
    }
    evidence_root = merkle_root([item["member_hash"] for item in members])
    governance_root = compute_governance_root(governance)
    first = make_event(
        0,
        "DISCOVERED",
        "2026-07-12T10:05:00Z",
        ZERO_HASH,
        [],
        [item["member_hash"] for item in members],
        policy_hash,
    )
    terminal = make_event(
        1,
        "INTEGRITY_SEAL",
        "2026-07-12T10:10:00Z",
        first["event_hash"],
        [evidence_root, ZERO_HASH, governance_root],
        [],
        policy_hash,
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
            "description_hash": h("description"),
        },
        "roots": {
            "member_count": 2,
            "conflict_count": 0,
            "evidence_root": evidence_root,
            "conflict_root": ZERO_HASH,
            "governance_root": governance_root,
            "lifecycle_root": terminal["event_hash"],
        },
        "members": members,
        "governance_bindings": governance,
        "conflicts": [],
        "lifecycle": [first, terminal],
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
            "archive time is not publication time",
            "archive gaps do not prove non-existence",
            "integrity is not a truth judgment",
        ],
        "artifact_hash": ZERO_HASH,
    }
    value["artifact_hash"] = compute_artifact_hash(value)
    return value


def seal(value: dict) -> None:
    previous = ZERO_HASH
    for sequence, item in enumerate(value["lifecycle"]):
        item["sequence"] = sequence
        item["previous_event_hash"] = previous
        item["event_hash"] = compute_event_hash(item)
        previous = item["event_hash"]
    value["roots"]["lifecycle_root"] = previous
    value["artifact_hash"] = compute_artifact_hash(value)


def rebind_members(value: dict) -> None:
    for item in value["members"]:
        item["member_hash"] = compute_member_hash(item)
    evidence_root = merkle_root([item["member_hash"] for item in value["members"]])
    value["roots"]["evidence_root"] = evidence_root
    value["lifecycle"][0]["output_hashes"] = sorted(
        item["member_hash"] for item in value["members"]
    )
    value["lifecycle"][1]["input_hashes"] = sorted(
        [
            evidence_root,
            value["roots"]["conflict_root"],
            value["roots"]["governance_root"],
        ]
    )
    seal(value)


def test_valid_artifact_is_integrity_ok_but_not_released():
    result = verify_evidence_artifact(make_artifact())
    assert result.status == "SEA_INTEGRITY_OK"
    assert result.level == "BINDINGS"
    assert result.release_authorized is False
    assert result.temporal_anchor_verified is False


def test_exact_local_bytes_raise_verification_to_bytes(tmp_path: Path):
    value = make_artifact()
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "alpha.html").write_bytes(b"alpha")
    (tmp_path / "raw" / "beta.json").write_bytes(b"beta")
    assert verify_evidence_artifact(value, bundle_root=tmp_path).level == "BYTES"


def test_pathless_member_cannot_receive_bytes_level(tmp_path: Path):
    value = make_artifact()
    value["members"][1]["path"] = None
    rebind_members(value)
    result = verify_evidence_artifact(value, bundle_root=tmp_path)
    assert result.integrity_valid is False
    assert "requires every member to be path-bound" in result.issues[0].message


def test_payload_tamper_fails(tmp_path: Path):
    value = make_artifact()
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw" / "alpha.html").write_bytes(b"ALPHA")
    (tmp_path / "raw" / "beta.json").write_bytes(b"beta")
    result = verify_evidence_artifact(value, bundle_root=tmp_path)
    assert result.integrity_valid is False
    assert "payload hash mismatch" in result.issues[0].message


@pytest.mark.parametrize(
    ("field", "new_value"),
    [("media_type", "text/plain"), ("byte_length", 999)],
)
def test_member_descriptor_tamper_fails(field: str, new_value: object):
    value = make_artifact()
    value["members"][0][field] = new_value
    assert verify_evidence_artifact(value).integrity_valid is False


def test_memento_cannot_claim_verified_identity_or_time():
    value = make_artifact()
    value["members"][1]["provenance"]["identity_status"] = "VERIFIED"
    value["members"][1]["provenance"]["datetime_status"] = "VERIFIED"
    rebind_members(value)
    result = verify_evidence_artifact(value)
    assert result.integrity_valid is False
    assert (
        "fixed Memento discovery provenance profile" in result.issues[0].message
        or "Schema validation failed" in result.issues[0].message
    )


def test_memento_origin_and_source_id_cannot_diverge():
    value = make_artifact()
    value["members"][1]["source_id"] = "other-source"
    rebind_members(value)
    assert verify_evidence_artifact(value).integrity_valid is False


def test_governance_tamper_fails_even_when_outer_hash_is_recomputed():
    value = make_artifact()
    value["governance_bindings"]["source_commit"] = "b" * 40
    value["artifact_hash"] = compute_artifact_hash(value)
    result = verify_evidence_artifact(value)
    assert result.integrity_valid is False
    assert "Governance root mismatch" in result.issues[0].message


def test_previous_event_hash_tamper_fails():
    value = make_artifact()
    value["lifecycle"][1]["previous_event_hash"] = h("wrong")
    value["lifecycle"][1]["event_hash"] = compute_event_hash(value["lifecycle"][1])
    value["roots"]["lifecycle_root"] = value["lifecycle"][1]["event_hash"]
    value["artifact_hash"] = compute_artifact_hash(value)
    assert verify_evidence_artifact(value).integrity_valid is False


def test_unknown_lifecycle_reference_fails():
    value = make_artifact()
    value["lifecycle"][0]["input_hashes"] = [h("unknown")]
    seal(value)
    assert verify_evidence_artifact(value).integrity_valid is False


@pytest.mark.parametrize("status", ["VERIFIED", "PUBLISHED"])
def test_non_hold_status_fails(status: str):
    value = make_artifact()
    value["status"] = status
    value["artifact_hash"] = compute_artifact_hash(value)
    assert verify_evidence_artifact(value).integrity_valid is False


def test_release_receipt_and_temporal_anchor_are_blocked():
    release = make_artifact()
    release["release_binding"]["release_receipt_hash"] = h("receipt")
    release["artifact_hash"] = compute_artifact_hash(release)
    assert verify_evidence_artifact(release).integrity_valid is False

    temporal = make_artifact()
    temporal["temporal_binding"]["anchor_hashes"] = [h("timestamp")]
    temporal["artifact_hash"] = compute_artifact_hash(temporal)
    assert verify_evidence_artifact(temporal).integrity_valid is False


def test_temporal_claim_must_equal_created_at():
    value = make_artifact()
    value["temporal_binding"]["claimed_created_at"] = "2026-07-12T09:00:00Z"
    value["artifact_hash"] = compute_artifact_hash(value)
    assert verify_evidence_artifact(value).integrity_valid is False


def test_overprecision_timestamp_is_rejected_before_ordering():
    value = make_artifact()
    value["lifecycle"][0]["occurred_at"] = "2026-07-12T10:05:00.1234569Z"
    seal(value)
    result = verify_evidence_artifact(value)
    assert result.integrity_valid is False
    assert (
        "at most six fractional-second digits" in result.issues[0].message
        or "Schema validation failed" in result.issues[0].message
    )


def test_paths_are_traversal_and_final_symlink_safe(tmp_path: Path):
    traversal = make_artifact()
    traversal["members"][0]["path"] = "../escape"
    rebind_members(traversal)
    assert verify_evidence_artifact(traversal).integrity_valid is False

    symlink = make_artifact()
    outside = tmp_path / "outside"
    outside.write_bytes(b"alpha")
    (tmp_path / "raw").mkdir()
    try:
        (tmp_path / "raw" / "alpha.html").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    (tmp_path / "raw" / "beta.json").write_bytes(b"beta")
    assert (
        verify_evidence_artifact(symlink, bundle_root=tmp_path).integrity_valid
        is False
    )


def test_intermediate_symlink_component_is_rejected(tmp_path: Path):
    value = make_artifact()
    real = tmp_path / "real"
    real.mkdir()
    (real / "alpha.html").write_bytes(b"alpha")
    (real / "beta.json").write_bytes(b"beta")
    try:
        (tmp_path / "raw").symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    result = verify_evidence_artifact(value, bundle_root=tmp_path)
    assert result.integrity_valid is False
    assert "symbolic-link component" in result.issues[0].message


def test_member_order_is_bound():
    value = make_artifact()
    value["members"].reverse()
    value["artifact_hash"] = compute_artifact_hash(value)
    assert verify_evidence_artifact(value).integrity_valid is False


def test_conflict_must_reference_existing_member():
    value = make_artifact()
    conflict = {
        "conflict_id": "conflict-001",
        "type": "HASH_MISMATCH",
        "severity": "HIGH",
        "member_hashes": [h("unknown-member")],
        "description_hash": h("description"),
        "resolution_status": "OPEN_HOLD",
        "resolution_record_hash": None,
        "conflict_hash": ZERO_HASH,
    }
    conflict["conflict_hash"] = compute_conflict_hash(conflict)
    value["conflicts"] = [conflict]
    value["roots"]["conflict_count"] = 1
    value["roots"]["conflict_root"] = merkle_root([conflict["conflict_hash"]])
    value["artifact_hash"] = compute_artifact_hash(value)
    assert verify_evidence_artifact(value).integrity_valid is False


def test_merkle_proof_binds_hash_index_and_count():
    value = make_artifact()
    hashes = [item["member_hash"] for item in value["members"]]
    proof = build_merkle_proof(hashes, 1)
    assert verify_merkle_proof(
        hashes[1],
        index=1,
        leaf_count=2,
        proof=proof,
        expected_root=value["roots"]["evidence_root"],
    )
    assert not verify_merkle_proof(
        hashes[1],
        index=0,
        leaf_count=2,
        proof=proof,
        expected_root=value["roots"]["evidence_root"],
    )


@pytest.mark.parametrize("bad_count", [2.0, 2**53])
def test_unsafe_canonical_numbers_fail(bad_count: object):
    value = make_artifact()
    value["roots"]["member_count"] = bad_count
    assert verify_evidence_artifact(value).integrity_valid is False


def test_human_actor_requires_hashed_identifier():
    value = make_artifact()
    value["lifecycle"][0]["actor"]["actor_type"] = "HUMAN"
    seal(value)
    assert verify_evidence_artifact(value).integrity_valid is False


def test_duplicate_json_keys_and_oversize_are_rejected(tmp_path: Path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"a","schema_version":"b"}',
        encoding="utf-8",
    )
    assert verify_evidence_artifact_file(duplicate).integrity_valid is False

    large = tmp_path / "large.json"
    large.write_text("{}" * 20, encoding="utf-8")
    with pytest.raises(Exception, match="size limit"):
        load_evidence_artifact_json(large, max_bytes=8)


def test_invalid_json_returns_machine_readable_failure(tmp_path: Path):
    path = tmp_path / "invalid.json"
    path.write_text("{", encoding="utf-8")
    result = verify_evidence_artifact_file(path)
    assert result.status == "SEA_NOT_VERIFIED"
    assert result.level == "NONE"


def test_zero_conflict_root_is_explicit():
    value = make_artifact()
    assert value["roots"]["conflict_root"] == ZERO_HASH
    assert validate_evidence_artifact(value) == "BINDINGS"
