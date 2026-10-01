"""Validation for deterministic SENTINEL Wayback evidence manifests."""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from jsonschema import Draft202012Validator, FormatChecker

from sentinel_core.schema import repository_root
from sentinel_core.wayback import (
    WaybackConfigurationError,
    WaybackSnapshot,
    normalize_target_url,
    validate_restore_path,
    verify_evidence_manifest,
)

_REQUIRED_LIMITS = frozenset(
    {
        "archive timestamp is not automatically the publication timestamp",
        "missing captures do not prove that content never existed",
        "archived replay may omit dynamic or externally hosted resources",
    }
)


class WaybackManifestValidationError(ValueError):
    """Raised when a Wayback evidence manifest fails closed."""


@lru_cache(maxsize=1)
def load_wayback_manifest_schema() -> dict[str, Any]:
    """Load the versioned Wayback evidence schema."""

    schema_path = repository_root() / "schemas" / "sentinel.wayback.evidence.v1.json"
    try:
        with schema_path.open("r", encoding="utf-8") as handle:
            schema = json.load(handle)
    except (OSError, ValueError) as exc:
        raise WaybackManifestValidationError(
            f"Unable to load Wayback manifest schema: {exc}"
        ) from None
    if not isinstance(schema, dict):
        raise WaybackManifestValidationError("Wayback manifest schema must be an object")
    Draft202012Validator.check_schema(schema)
    return schema


@lru_cache(maxsize=1)
def wayback_manifest_validator() -> Draft202012Validator:
    """Return a cached strict validator with URI and date-time format checks."""

    return Draft202012Validator(
        load_wayback_manifest_schema(),
        format_checker=FormatChecker(),
    )


def _fail(message: str) -> None:
    raise WaybackManifestValidationError(message)


def _validate_schema(manifest: Mapping[str, Any]) -> None:
    errors = sorted(
        wayback_manifest_validator().iter_errors(dict(manifest)),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path) or "<root>"
        _fail(f"Schema validation failed at {location}: {first.message}")


def _validate_primary_provenance(manifest: Mapping[str, Any]) -> WaybackSnapshot:
    target_url = manifest["target_url"]
    snapshot_data = manifest["snapshot"]
    if not isinstance(target_url, str) or not isinstance(snapshot_data, Mapping):
        _fail("Primary provenance fields are malformed")

    try:
        normalized_target = normalize_target_url(target_url)
        snapshot = WaybackSnapshot(
            timestamp=snapshot_data["timestamp"],
            original_url=snapshot_data["original_url"],
            status_code=snapshot_data["status_code"],
            replay_url=snapshot_data["replay_url"],
            mime_type=snapshot_data.get("mime_type"),
            archive_digest=snapshot_data.get("archive_digest"),
            length=snapshot_data.get("length"),
        )
    except (KeyError, TypeError, WaybackConfigurationError, ValueError) as exc:
        _fail(f"Primary provenance validation failed: {exc}")

    if normalized_target != snapshot.original_url:
        _fail("target_url must match snapshot.original_url in Phase 1 manifests")
    return snapshot


def _validate_artifacts(
    manifest: Mapping[str, Any],
    snapshot: WaybackSnapshot,
) -> tuple[Mapping[str, Any], ...]:
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list):
        _fail("artifacts must be a list")

    paths: set[str] = set()
    validated: list[Mapping[str, Any]] = []
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, Mapping):
            _fail(f"Artifact {index} is not an object")
        try:
            safe_path = validate_restore_path(artifact["relative_path"])
        except (KeyError, TypeError, WaybackConfigurationError) as exc:
            _fail(f"Artifact {index} has an unsafe path: {exc}")
        if safe_path in paths:
            _fail(f"Duplicate artifact path: {safe_path}")
        paths.add(safe_path)

        if artifact.get("original_url") != snapshot.original_url:
            _fail(f"Artifact {index} original_url does not match the selected snapshot")
        if artifact.get("archive_url") != snapshot.replay_url:
            _fail(f"Artifact {index} archive_url does not match the selected snapshot")
        if artifact.get("snapshot_timestamp") != snapshot.timestamp:
            _fail(f"Artifact {index} timestamp does not match the selected snapshot")
        validated.append(artifact)
    return tuple(validated)


def _validate_limits(manifest: Mapping[str, Any]) -> None:
    limits = manifest["interpretation_limits"]
    if not isinstance(limits, list) or not _REQUIRED_LIMITS.issubset(set(limits)):
        _fail("Manifest does not preserve all mandatory interpretation limits")


def _validate_cross_sources(manifest: Mapping[str, Any]) -> None:
    sources = manifest.get("cross_verification_sources", [])
    if not isinstance(sources, list):
        _fail("cross_verification_sources must be a list")

    seen: set[tuple[str, str, str]] = set()
    target_url = manifest["target_url"]
    for index, source in enumerate(sources):
        if not isinstance(source, Mapping):
            _fail(f"Cross-verification source {index} is not an object")
        if source.get("original_url") != target_url:
            _fail(f"Cross-verification source {index} targets a different original URL")

        archive_url = source.get("archive_url")
        if not isinstance(archive_url, str):
            _fail(f"Cross-verification source {index} lacks an archive URL")
        parsed = urlparse(archive_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            _fail(f"Cross-verification source {index} has an unsafe archive URL")

        identity = (
            str(source.get("source_id")),
            archive_url,
            str(source.get("sha256")),
        )
        if identity in seen:
            _fail(f"Duplicate cross-verification source at index {index}")
        seen.add(identity)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _verify_bundle(
    artifacts: tuple[Mapping[str, Any], ...],
    bundle_root: str | Path,
) -> None:
    root = Path(bundle_root)
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        _fail(f"Bundle root is unavailable: {exc}")

    if not resolved_root.is_dir():
        _fail("Bundle root must be a directory")

    for index, artifact in enumerate(artifacts):
        relative_path = validate_restore_path(artifact["relative_path"])
        candidate = resolved_root.joinpath(*Path(relative_path).parts)
        if candidate.is_symlink():
            _fail(f"Artifact {index} is a symbolic link")
        try:
            resolved_candidate = candidate.resolve(strict=True)
            resolved_candidate.relative_to(resolved_root)
        except (OSError, ValueError):
            _fail(f"Artifact {index} is missing or escapes the bundle root")
        if not resolved_candidate.is_file():
            _fail(f"Artifact {index} is not a regular file")

        actual_size = resolved_candidate.stat().st_size
        if actual_size != artifact["byte_length"]:
            _fail(f"Artifact {index} byte length does not match")
        if _file_sha256(resolved_candidate) != artifact["sha256"]:
            _fail(f"Artifact {index} SHA-256 does not match")


def validate_wayback_manifest(
    manifest: Mapping[str, Any],
    *,
    bundle_root: str | Path | None = None,
    allow_non_hold: bool = False,
) -> None:
    """Validate schema, provenance, HOLD state, hash integrity, and local bytes.

    The normal path accepts only HOLD manifests. VERIFIED requires an explicit
    release-aware internal decision. PUBLISHED remains blocked until the separate
    receipt-bound publication verifier is implemented and independently reviewed.
    """

    if not isinstance(manifest, Mapping):
        _fail("Wayback manifest must be an object")

    _validate_schema(manifest)

    status = manifest["status"]
    if status == "PUBLISHED":
        _fail("PUBLISHED manifests require the separate manual release-receipt gate")
    if status == "VERIFIED" and not allow_non_hold:
        _fail("VERIFIED manifests require explicit release-aware validation")

    if not verify_evidence_manifest(manifest):
        _fail("Manifest hash verification failed")

    snapshot = _validate_primary_provenance(manifest)
    artifacts = _validate_artifacts(manifest, snapshot)
    _validate_limits(manifest)
    _validate_cross_sources(manifest)

    if bundle_root is not None:
        _verify_bundle(artifacts, bundle_root)
