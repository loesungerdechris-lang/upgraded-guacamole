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
import stat
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
_WINDOWS_RESERVED_SEGMENT_RE = re.compile(
    r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$",
    re.IGNORECASE,
)
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


def _validate_unicode_scalar_string(value: str, path: str) -> None:
    """Reject isolated UTF-16 surrogates before canonicalization or hashing."""

    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail(f"String contains an isolated Unicode surrogate at {path}")


def _validate_unicode_scalars(value: Any, path: str = "<root>") -> None:
    """Recursively validate Unicode scalar safety for keys and string values."""

    if isinstance(value, str):
        _validate_unicode_scalar_string(value, path)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_unicode_scalars(item, f"{path}/{index}")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                _validate_unicode_scalar_string(key, f"{path}/<key>")
                child_path = f"{path}/{key}" if key.isascii() else f"{path}/<key>"
            else:
                child_path = f"{path}/<non-string-key>"
            _validate_unicode_scalars(item, child_path)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _validate_unicode_scalar_string(key, "<json-key>")
        if key in result:
            _fail(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _secure_open_capability() -> tuple[int, int, int]:
    """Return required secure-open flags or fail closed on this platform."""

    nofollow = int(getattr(os, "O_NOFOLLOW", 0))
    directory = int(getattr(os, "O_DIRECTORY", 0))
    nonblock = int(getattr(os, "O_NONBLOCK", 0))
    if not nofollow or not directory or os.open not in os.supports_dir_fd:
        _fail("Secure no-follow file opening is unavailable on this platform")
    return nofollow, directory, nonblock


def _directory_open_flags() -> int:
    nofollow, directory, _ = _secure_open_capability()
    return (
        os.O_RDONLY
        | nofollow
        | directory
        | int(getattr(os, "O_CLOEXEC", 0))
        | int(getattr(os, "O_BINARY", 0))
    )


def _regular_open_flags(*, nonblocking: bool) -> int:
    nofollow, _, nonblock = _secure_open_capability()
    flags = (
        os.O_RDONLY
        | nofollow
        | int(getattr(os, "O_CLOEXEC", 0))
        | int(getattr(os, "O_BINARY", 0))
    )
    if nonblocking:
        if not nonblock:
            _fail("Secure nonblocking file opening is unavailable on this platform")
        flags |= nonblock
    return flags


def _open_directory_nofollow(path: str | Path) -> int:
    """Open an absolute directory path component-by-component without symlinks."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    if absolute.anchor != os.sep:
        _fail("Secure no-follow directory traversal requires a POSIX path anchor")

    flags = _directory_open_flags()
    current_fd: int | None = None
    try:
        current_fd = os.open(os.sep, flags)
        for part in absolute.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except EvidenceArtifactValidationError:
        if current_fd is not None:
            os.close(current_fd)
        raise
    except OSError as exc:
        if current_fd is not None:
            os.close(current_fd)
        _fail(f"Unable to traverse evidence path safely: {exc}")


def _open_regular_nofollow(
    path: str | Path,
    *,
    nonblocking: bool,
) -> BinaryIO:
    """Open one regular file through a no-follow parent directory handle."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.name:
        _fail("Evidence input path must identify a file")

    parent_fd: int | None = None
    file_fd: int | None = None
    try:
        parent_fd = _open_directory_nofollow(absolute.parent)
        file_fd = os.open(
            absolute.name,
            _regular_open_flags(nonblocking=nonblocking),
            dir_fd=parent_fd,
        )
        opened_stat = os.fstat(file_fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            _fail("Evidence artifact JSON input must be a regular file")
        return os.fdopen(file_fd, "rb", closefd=True)
    except EvidenceArtifactValidationError:
        if file_fd is not None:
            os.close(file_fd)
        raise
    except OSError as exc:
        if file_fd is not None:
            os.close(file_fd)
        _fail(f"Unable to open evidence input safely: {exc}")
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


def _open_bundle_member_nofollow(
    root: str | Path,
    relative: str,
) -> BinaryIO:
    """Open a bundle member beneath root with no-follow openat traversal."""

    segments = relative.split("/")
    current_fd: int | None = None
    file_fd: int | None = None
    try:
        current_fd = _open_directory_nofollow(root)
        directory_flags = _directory_open_flags()
        for part in segments[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        file_fd = os.open(
            segments[-1],
            _regular_open_flags(nonblocking=True),
            dir_fd=current_fd,
        )
        opened_stat = os.fstat(file_fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            _fail("Evidence bundle member must be a regular file")
        return os.fdopen(file_fd, "rb", closefd=True)
    except EvidenceArtifactValidationError:
        if file_fd is not None:
            os.close(file_fd)
        raise
    except OSError as exc:
        if file_fd is not None:
            os.close(file_fd)
        _fail(f"Unable to open bundle member safely: {exc}")
    finally:
        if current_fd is not None:
            os.close(current_fd)


def load_evidence_artifact_json(
    path: str | Path,
    *,
    max_bytes: int = _MAX_JSON_BYTES,
) -> dict[str, Any]:
    """Load bounded strict UTF-8 JSON and reject invalid Unicode scalars."""

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        _fail("Evidence artifact JSON size limit must be a positive integer")

    try:
        with _open_regular_nofollow(path, nonblocking=True) as handle:
            payload = handle.read(max_bytes + 1)
        if len(payload) > max_bytes:
            _fail("Evidence artifact JSON exceeds size limit")
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except EvidenceArtifactValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"Unable to load evidence artifact JSON: {exc}")
    if not isinstance(value, dict):
        _fail("Evidence artifact JSON root must be an object")
    _validate_unicode_scalars(value)
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
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        _validate_unicode_scalar_string(value, path)
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
            if not isinstance(key, str):
                _fail(f"Object keys must be ASCII strings at {path}")
            _validate_unicode_scalar_string(key, f"{path}/<key>")
            if not key.isascii():
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

    if isinstance(data, str):
        _validate_unicode_scalar_string(data, "<hash-input>")
        raw = data.encode("utf-8", errors="strict")
    else:
        raw = data
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
    if ":" in value or "\\" in value or _CONTROL_CHARACTER_RE.search(value):
        _fail("Unsafe evidence bundle path")
    if value.startswith("/") or value.endswith("/"):
        _fail("Non-canonical evidence bundle path")
    segments = value.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        _fail("Non-canonical evidence bundle path")
    if any(
        segment.endswith((" ", "."))
        or _WINDOWS_RESERVED_SEGMENT_RE.fullmatch(segment)
        for segment in segments
    ):
        _fail("Windows-reserved evidence bundle path segment")
    if "/".join(segments) != value or PurePosixPath(value).as_posix() != value:
        _fail("Non-canonical evidence bundle path")
    return value


def _require_unique_member_paths(members: Sequence[Mapping[str, Any]]) -> None:
    """Reject duplicate non-null descriptor paths at every verification level."""

    seen: set[str] = set()
    for member in members:
        path = member["path"]
        if path is None:
            continue
        canonical = _validate_safe_path(path)
        if canonical in seen:
            _fail(f"Duplicate evidence bundle descriptor path: {canonical}")
        seen.add(canonical)


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
    root = Path(os.path.abspath(os.fspath(bundle_root)))

    for index, member in enumerate(members):
        if member["path"] is None:
            _fail(
                f"Member {index} has no bundle path; BYTES verification "
                "requires every member to be path-bound"
            )

    seen_resolved_paths: set[str] = set()
    seen_identities: set[tuple[int, int]] = set()

    for index, member in enumerate(members):
        relative = _validate_safe_path(member["path"])
        candidate = root.joinpath(*relative.split("/"))
        normalized_candidate = os.path.normcase(os.path.abspath(candidate))
        if normalized_candidate in seen_resolved_paths:
            _fail(f"Member {index} resolves to an already-bound filesystem path")
        seen_resolved_paths.add(normalized_candidate)

        try:
            with _open_bundle_member_nofollow(root, relative) as handle:
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
    _require_unique_member_paths(members)

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
