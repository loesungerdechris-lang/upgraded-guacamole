"""Verifier-only SENTINEL end-to-end evidence artifact prototype.

This module performs deterministic offline integrity verification. It contains no
network transport, private keys, signing helpers, release transition, or
publication function.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Literal, Mapping, Sequence

from jsonschema import Draft202012Validator, FormatChecker

from sentinel_core.schema import repository_root

ZERO_HASH = "sha256:" + "0" * 64
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]")
_SAFE_INTEGER = 2**53 - 1
_MAX_JSON_BYTES = 16 * 1024 * 1024

VerificationStatus = Literal["SEA_INTEGRITY_OK", "SEA_NOT_VERIFIED"]
VerificationLevel = Literal["NONE", "BINDINGS", "BYTES"]


class EvidenceArtifactValidationError(ValueError):
    """Raised when an evidence artifact fails closed."""


@dataclass(frozen=True)
class EvidenceArtifactIssue:
    """One machine-readable verification issue."""

    code: str
    message: str


@dataclass(frozen=True)
class EvidenceArtifactVerificationResult:
    """Offline evidence-artifact verification result."""

    status: VerificationStatus
    integrity_valid: bool
    level: VerificationLevel
    artifact_hash: str | None = None
    evidence_root: str | None = None
    conflict_root: str | None = None
    governance_root: str | None = None
    lifecycle_root: str | None = None
    release_authorized: bool = False
    temporal_anchor_verified: bool = False
    issues: tuple[EvidenceArtifactIssue, ...] = field(default_factory=tuple)


def _fail(message: str) -> None:
    raise EvidenceArtifactValidationError(message)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_evidence_artifact_json(
    path: str | Path,
    *,
    max_bytes: int = _MAX_JSON_BYTES,
) -> dict[str, Any]:
    """Load bounded UTF-8 JSON while rejecting duplicate object keys."""

    source = Path(path)
    try:
        if source.stat().st_size > max_bytes:
            _fail("Evidence artifact JSON exceeds size limit")
        with source.open("r", encoding="utf-8") as handle:
            value = json.load(handle, object_pairs_hook=_reject_duplicate_pairs)
    except EvidenceArtifactValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"Unable to load evidence artifact JSON: {exc}")
    if not isinstance(value, dict):
        _fail("Evidence artifact JSON root must be an object")
    return value


@lru_cache(maxsize=1)
def load_evidence_artifact_schema() -> dict[str, Any]:
    """Load and validate the versioned artifact schema."""

    path = repository_root() / "schemas" / "sentinel.evidence.artifact.v1.json"
    try:
        with path.open("r", encoding="utf-8") as handle:
            schema = json.load(handle)
    except (OSError, ValueError) as exc:
        _fail(f"Unable to load evidence artifact schema: {exc}")
    if not isinstance(schema, dict):
        _fail("Evidence artifact schema must be an object")
    Draft202012Validator.check_schema(schema)
    return schema


@lru_cache(maxsize=1)
def evidence_artifact_validator() -> Draft202012Validator:
    """Return a cached strict schema validator."""

    return Draft202012Validator(
        load_evidence_artifact_schema(),
        format_checker=FormatChecker(),
    )


def _validate_canonical_domain(value: Any, path: str = "<root>") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if abs(value) > _SAFE_INTEGER:
            _fail(f"Integer exceeds safe canonical range at {path}")
        return
    if isinstance(value, float):
        _fail(f"Floating-point values are forbidden at {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_canonical_domain(item, f"{path}/{index}")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                _fail(f"Object keys must be ASCII strings at {path}")
            _validate_canonical_domain(item, f"{path}/{key}")
        return
    _fail(f"Unsupported canonical JSON type at {path}: {type(value).__name__}")


def canonicalize_artifact_json(value: Any) -> str:
    """Return deterministic JSON under the restricted v1 profile."""

    _validate_canonical_domain(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256_prefixed(data: str | bytes) -> str:
    """Return a lowercase prefixed SHA-256 identifier."""

    raw = data.encode("utf-8") if isinstance(data, str) else data
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest(identifier: str) -> bytes:
    if not _SHA256_RE.fullmatch(identifier):
        _fail("Invalid SHA-256 identifier")
    return bytes.fromhex(identifier[7:])


def descriptor_hash(record: Mapping[str, Any], hash_field: str) -> str:
    """Hash a descriptor while excluding only its self-hash field."""

    unsigned = copy.deepcopy(dict(record))
    unsigned.pop(hash_field, None)
    return sha256_prefixed(canonicalize_artifact_json(unsigned))


def compute_member_hash(member: Mapping[str, Any]) -> str:
    return descriptor_hash(member, "member_hash")


def compute_conflict_hash(conflict: Mapping[str, Any]) -> str:
    return descriptor_hash(conflict, "conflict_hash")


def compute_event_hash(event: Mapping[str, Any]) -> str:
    return descriptor_hash(event, "event_hash")


def compute_governance_root(governance: Mapping[str, Any]) -> str:
    return sha256_prefixed(canonicalize_artifact_json(dict(governance)))


def compute_artifact_hash(artifact: Mapping[str, Any]) -> str:
    unsigned = copy.deepcopy(dict(artifact))
    unsigned.pop("artifact_hash", None)
    return sha256_prefixed(canonicalize_artifact_json(unsigned))


def merkle_root(hashes: Sequence[str]) -> str:
    """Compute the domain-separated ordered Merkle root."""

    if not hashes:
        return ZERO_HASH
    level = [
        hashlib.sha256(b"SENTINEL-EVIDENCE-LEAF-v1\0" + _digest(value)).digest()
        for value in hashes
    ]
    while len(level) > 1:
        next_level: list[bytes] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(
                hashlib.sha256(
                    b"SENTINEL-EVIDENCE-NODE-v1\0" + left + right
                ).digest()
            )
        level = next_level
    return "sha256:" + level[0].hex()


def build_merkle_proof(
    hashes: Sequence[str],
    index: int,
) -> tuple[dict[str, str], ...]:
    """Build a deterministic inclusion proof for one ordered leaf."""

    if index < 0 or index >= len(hashes):
        _fail("Merkle proof index is out of range")
    level = [
        hashlib.sha256(b"SENTINEL-EVIDENCE-LEAF-v1\0" + _digest(value)).digest()
        for value in hashes
    ]
    current_index = index
    proof: list[dict[str, str]] = []
    while len(level) > 1:
        sibling_index = current_index - 1 if current_index % 2 else current_index + 1
        if sibling_index >= len(level):
            sibling_index = current_index
        proof.append(
            {
                "position": "left" if sibling_index < current_index else "right",
                "hash": "sha256:" + level[sibling_index].hex(),
            }
        )
        next_level: list[bytes] = []
        for offset in range(0, len(level), 2):
            left = level[offset]
            right = level[offset + 1] if offset + 1 < len(level) else left
            next_level.append(
                hashlib.sha256(
                    b"SENTINEL-EVIDENCE-NODE-v1\0" + left + right
                ).digest()
            )
        level = next_level
        current_index //= 2
    return tuple(proof)


def verify_merkle_proof(
    member_hash: str,
    *,
    index: int,
    leaf_count: int,
    proof: Sequence[Mapping[str, str]],
    expected_root: str,
) -> bool:
    """Verify an inclusion proof while binding index and leaf count."""

    if leaf_count < 1 or index < 0 or index >= leaf_count:
        return False
    try:
        current = hashlib.sha256(
            b"SENTINEL-EVIDENCE-LEAF-v1\0" + _digest(member_hash)
        ).digest()
        width = leaf_count
        current_index = index
        for step in proof:
            if width <= 1:
                return False
            sibling = _digest(str(step.get("hash")))
            expected_position = "left" if current_index % 2 else "right"
            if step.get("position") != expected_position:
                return False
            left, right = (
                (sibling, current)
                if expected_position == "left"
                else (current, sibling)
            )
            current = hashlib.sha256(
                b"SENTINEL-EVIDENCE-NODE-v1\0" + left + right
            ).digest()
            current_index //= 2
            width = (width + 1) // 2
        return width == 1 and "sha256:" + current.hex() == expected_root
    except (EvidenceArtifactValidationError, TypeError, ValueError):
        return False


def _parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not _UTC_TIMESTAMP_RE.fullmatch(value):
        _fail(
            "Timestamp must be RFC3339 UTC ending Z with at most six "
            "fractional-second digits"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        _fail(f"Invalid RFC3339 timestamp: {exc}")
    return parsed.astimezone(timezone.utc)


def _validate_schema(artifact: Mapping[str, Any]) -> None:
    errors = sorted(
        evidence_artifact_validator().iter_errors(dict(artifact)),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path) or "<root>"
        _fail(f"Schema validation failed at {location}: {first.message}")


def _require_sorted_unique(
    records: Sequence[Mapping[str, Any]],
    field_name: str,
    label: str,
) -> None:
    values = [record[field_name] for record in records]
    if values != sorted(values):
        _fail(f"{label} must be sorted by {field_name}")
    if len(values) != len(set(values)):
        _fail(f"{label} contain duplicate {field_name} values")


def _require_sorted_hashes(values: Sequence[str], label: str) -> None:
    if list(values) != sorted(values) or len(values) != len(set(values)):
        _fail(f"{label} must contain sorted unique hashes")


def _validate_safe_path(value: str) -> str:
    """Validate an exact, portable POSIX-relative bundle path."""

    if not isinstance(value, str) or not value:
        _fail("Unsafe evidence bundle path")
    if "\\" in value or _CONTROL_CHARACTER_RE.search(value):
        _fail("Unsafe evidence bundle path")
    if value.startswith("/") or value.endswith("/"):
        _fail("Non-canonical evidence bundle path")
    segments = value.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        _fail("Non-canonical evidence bundle path")
    if "/".join(segments) != value or PurePosixPath(value).as_posix() != value:
        _fail("Non-canonical evidence bundle path")
    return value


def _validate_source_profile(member: Mapping[str, Any], index: int) -> None:
    provenance = member["provenance"]
    memento_by_id = member["source_id"] == "memento-discovery"
    memento_by_origin = provenance["source_origin"] == "memento-protocol-discovery"
    if not (memento_by_id or memento_by_origin):
        return
    expected = {
        "source_id": "memento-discovery",
        "kind": "DISCOVERY_RECORD",
        "source_origin": "memento-protocol-discovery",
        "identity_status": "DECLARED",
        "datetime_status": "DECLARED",
        "acquisition_authority": "separate_policy_required",
    }
    actual = {
        "source_id": member["source_id"],
        "kind": member["kind"],
        "source_origin": provenance["source_origin"],
        "identity_status": provenance["identity_status"],
        "datetime_status": provenance["datetime_status"],
        "acquisition_authority": provenance["acquisition_authority"],
    }
    if actual != expected:
        _fail(
            f"Member {index} violates the fixed Memento discovery provenance profile"
        )


def _validate_lifecycle(
    events: Sequence[Mapping[str, Any]],
    known_hashes: set[str],
    created_at: datetime,
) -> str:
    previous_hash = ZERO_HASH
    previous_time: datetime | None = None
    for index, event in enumerate(events):
        if event["sequence"] != index:
            _fail(f"Lifecycle event {index} has non-consecutive sequence")
        if event["previous_event_hash"] != previous_hash:
            _fail(f"Lifecycle event {index} previous hash mismatch")
        occurred_at = _parse_utc(event["occurred_at"])
        if previous_time is not None and occurred_at < previous_time:
            _fail("Lifecycle timestamps must be non-decreasing")
        if occurred_at > created_at:
            _fail("Lifecycle event occurs after artifact creation")
        actor = event["actor"]
        if actor["actor_type"] == "HUMAN" and actor["actor_id_hash"] is None:
            _fail("Human lifecycle actors require a hashed identifier")
        for field_name in ("input_hashes", "output_hashes", "policy_hashes"):
            _require_sorted_hashes(event[field_name], f"event {index} {field_name}")
            if any(value not in known_hashes for value in event[field_name]):
                _fail(f"Lifecycle event {index} references unknown hash")
        expected_hash = compute_event_hash(event)
        if event["event_hash"] != expected_hash:
            _fail(f"Lifecycle event {index} hash mismatch")
        previous_hash = expected_hash
        previous_time = occurred_at
        known_hashes.add(expected_hash)
    terminal = events[-1]
    if terminal["event_type"] not in {"INTEGRITY_SEAL", "BLOCKED"}:
        _fail("Lifecycle must terminate with INTEGRITY_SEAL or BLOCKED")
    if terminal["decision"] not in {"HOLD", "BLOCKED"}:
        _fail("Lifecycle terminal decision must remain HOLD or BLOCKED")
    return previous_hash


def _stream_sha256(handle: BinaryIO) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _reject_symlink_components(root: Path, relative: str, index: int) -> Path:
    current = root
    for part in relative.split("/"):
        current = current / part
        if current.is_symlink():
            _fail(f"Member {index} path contains a symbolic-link component")
    return current


def _filesystem_identity(stat_result: os.stat_result) -> tuple[int, int]:
    """Return a stable filesystem object identity or fail closed."""

    inode = int(getattr(stat_result, "st_ino", 0))
    device = int(getattr(stat_result, "st_dev", 0))
    if inode <= 0:
        _fail("Stable filesystem object identity is unavailable; BYTES is blocked")
    return device, inode


def _verify_bundle(
    members: Sequence[Mapping[str, Any]],
    bundle_root: str | Path,
) -> None:
    supplied_root = Path(bundle_root)
    if supplied_root.is_symlink():
        _fail("Evidence bundle root must not be a symbolic link")
    try:
        root = supplied_root.resolve(strict=True)
    except OSError as exc:
        _fail(f"Evidence bundle root is unavailable: {exc}")
    if not root.is_dir():
        _fail("Evidence bundle root must be a directory")

    for index, member in enumerate(members):
        if member["path"] is None:
            _fail(
                f"Member {index} has no bundle path; BYTES verification "
                "requires every member to be path-bound"
            )

    seen_descriptor_paths: set[str] = set()
    seen_resolved_paths: set[str] = set()
    seen_identities: set[tuple[int, int]] = set()

    for index, member in enumerate(members):
        relative = _validate_safe_path(member["path"])
        if relative in seen_descriptor_paths:
            _fail(f"Duplicate evidence bundle descriptor path: {relative}")
        seen_descriptor_paths.add(relative)

        candidate = _reject_symlink_components(root, relative, index)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError):
            _fail(f"Member {index} is missing or escapes the bundle root")
        if not resolved.is_file():
            _fail(f"Member {index} is not a regular file")

        normalized_resolved = os.path.normcase(str(resolved))
        if normalized_resolved in seen_resolved_paths:
            _fail(f"Member {index} resolves to an already-bound filesystem path")
        seen_resolved_paths.add(normalized_resolved)

        try:
            with resolved.open("rb") as handle:
                stat_result = os.fstat(handle.fileno())
                identity = _filesystem_identity(stat_result)
                if identity in seen_identities:
                    _fail(
                        f"Member {index} resolves to an already-bound filesystem object"
                    )
                seen_identities.add(identity)
                if stat_result.st_size != member["byte_length"]:
                    _fail(f"Member {index} byte length mismatch")
                if _stream_sha256(handle) != member["sha256"]:
                    _fail(f"Member {index} payload hash mismatch")
        except EvidenceArtifactValidationError:
            raise
        except OSError as exc:
            _fail(f"Member {index} could not be read safely: {exc}")


def validate_evidence_artifact(
    artifact: Mapping[str, Any],
    *,
    bundle_root: str | Path | None = None,
) -> VerificationLevel:
    """Validate the HOLD artifact and optionally verify local member bytes."""

    if not isinstance(artifact, Mapping):
        _fail("Evidence artifact must be an object")
    _validate_canonical_domain(dict(artifact))
    _validate_schema(artifact)

    if artifact["status"] != "HOLD":
        _fail("Prototype accepts only HOLD core artifacts")
    if artifact["release_binding"] != {
        "publication": False,
        "verified_envelope_hash": None,
        "release_receipt_hash": None,
    }:
        _fail("Release authority is unavailable in the HOLD prototype")
    temporal = artifact["temporal_binding"]
    if temporal["claimed_created_at"] != artifact["created_at"]:
        _fail("Temporal claim must match artifact created_at")
    if temporal["anchor_status"] != "UNANCHORED_HOLD" or temporal["anchor_hashes"]:
        _fail("Trusted temporal anchoring is unavailable in v1")

    created_at = _parse_utc(artifact["created_at"])
    members = artifact["members"]
    conflicts = artifact["conflicts"]
    governance = artifact["governance_bindings"]
    roots = artifact["roots"]

    _require_sorted_unique(members, "member_id", "members")
    _require_sorted_unique(conflicts, "conflict_id", "conflicts")
    _require_sorted_unique(governance["policies"], "policy_id", "policies")
    _require_sorted_unique(governance["registries"], "registry_id", "registries")

    member_hashes: list[str] = []
    payload_hashes: set[str] = set()
    for index, member in enumerate(members):
        _validate_source_profile(member, index)
        if member["member_hash"] != compute_member_hash(member):
            _fail(f"Member {index} descriptor hash mismatch")
        if member["path"] is not None:
            _validate_safe_path(member["path"])
        if (
            member["observed_at"] is not None
            and _parse_utc(member["observed_at"]) > created_at
        ):
            _fail(f"Member {index} observation occurs after artifact creation")
        member_hashes.append(member["member_hash"])
        payload_hashes.add(member["sha256"])

    conflict_hashes: list[str] = []
    member_hash_set = set(member_hashes)
    for index, conflict in enumerate(conflicts):
        _require_sorted_hashes(
            conflict["member_hashes"], f"conflict {index} member_hashes"
        )
        if any(value not in member_hash_set for value in conflict["member_hashes"]):
            _fail(f"Conflict {index} references unknown member hash")
        if conflict["conflict_hash"] != compute_conflict_hash(conflict):
            _fail(f"Conflict {index} descriptor hash mismatch")
        conflict_hashes.append(conflict["conflict_hash"])

    expected_evidence_root = merkle_root(member_hashes)
    expected_conflict_root = merkle_root(conflict_hashes)
    expected_governance_root = compute_governance_root(governance)
    if roots["member_count"] != len(members):
        _fail("Member count mismatch")
    if roots["conflict_count"] != len(conflicts):
        _fail("Conflict count mismatch")
    if roots["evidence_root"] != expected_evidence_root:
        _fail("Evidence Merkle root mismatch")
    if roots["conflict_root"] != expected_conflict_root:
        _fail("Conflict Merkle root mismatch")
    if roots["governance_root"] != expected_governance_root:
        _fail("Governance root mismatch")

    known_hashes = payload_hashes | member_hash_set | set(conflict_hashes)
    known_hashes |= {
        governance["operation_plan_hash"],
        governance["parent_stack_hash"],
        governance["ci_evidence"]["workflow_hash"],
        governance["threat_model_hash"],
        expected_evidence_root,
        expected_conflict_root,
        expected_governance_root,
    }
    known_hashes |= {item["sha256"] for item in governance["policies"]}
    known_hashes |= {item["sha256"] for item in governance["registries"]}
    for optional_name in (
        "environment_descriptor_hash",
        "privacy_review_hash",
        "terms_review_hash",
        "retention_decision_hash",
    ):
        if governance[optional_name] is not None:
            known_hashes.add(governance[optional_name])

    expected_lifecycle_root = _validate_lifecycle(
        artifact["lifecycle"],
        known_hashes,
        created_at,
    )
    if roots["lifecycle_root"] != expected_lifecycle_root:
        _fail("Lifecycle root mismatch")
    if artifact["artifact_hash"] != compute_artifact_hash(artifact):
        _fail("Artifact root hash mismatch")

    if bundle_root is not None:
        _verify_bundle(members, bundle_root)
        return "BYTES"
    return "BINDINGS"


def verify_evidence_artifact(
    artifact: Mapping[str, Any],
    *,
    bundle_root: str | Path | None = None,
) -> EvidenceArtifactVerificationResult:
    """Return a non-throwing, machine-readable offline verification result."""

    try:
        level = validate_evidence_artifact(artifact, bundle_root=bundle_root)
    except (EvidenceArtifactValidationError, OSError, TypeError, ValueError) as exc:
        return EvidenceArtifactVerificationResult(
            status="SEA_NOT_VERIFIED",
            integrity_valid=False,
            level="NONE",
            issues=(EvidenceArtifactIssue("ARTIFACT_INVALID", str(exc)),),
        )
    roots = artifact["roots"]
    return EvidenceArtifactVerificationResult(
        status="SEA_INTEGRITY_OK",
        integrity_valid=True,
        level=level,
        artifact_hash=artifact["artifact_hash"],
        evidence_root=roots["evidence_root"],
        conflict_root=roots["conflict_root"],
        governance_root=roots["governance_root"],
        lifecycle_root=roots["lifecycle_root"],
        release_authorized=False,
        temporal_anchor_verified=False,
    )


def verify_evidence_artifact_file(
    path: str | Path,
    *,
    bundle_root: str | Path | None = None,
    max_json_bytes: int = _MAX_JSON_BYTES,
) -> EvidenceArtifactVerificationResult:
    """Load and verify one bounded artifact file without network access."""

    try:
        artifact = load_evidence_artifact_json(path, max_bytes=max_json_bytes)
    except EvidenceArtifactValidationError as exc:
        return EvidenceArtifactVerificationResult(
            status="SEA_NOT_VERIFIED",
            integrity_valid=False,
            level="NONE",
            issues=(EvidenceArtifactIssue("ARTIFACT_JSON_INVALID", str(exc)),),
        )
    return verify_evidence_artifact(artifact, bundle_root=bundle_root)
