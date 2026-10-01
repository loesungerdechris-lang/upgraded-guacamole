"""Portable multi-signature SENTINEL evidence bundle construction.

This module owns no private key material. It accepts public trust metadata and
external digest signers, builds one complete canonical receipt, obtains every
required signature through the existing narrow signer contract, invokes the
independent verifier, and emits a public five-file bundle only after RC_VERIFIED.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import tempfile
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric import ec

from sentinel_core.external_signing import (
    ExternalDigestSigner,
    SigningContractError,
    sign_receipt_with_external_digest_signer,
)
from sentinel_core.hashchain import canonicalize_json
from sentinel_core.receipt import parse_rfc3339_utc, verify_receipt

_ZERO_HASH = "sha256:" + "0" * 64
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_WORKFLOW_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,127}$")
_RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
_RUN_ATTEMPT_RE = re.compile(r"^[1-9][0-9]{0,5}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_AZURE_VAULT_HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{1,22}[a-z0-9])?\.vault\.azure\.net$"
)
_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,127}$")
_KEY_VERSION_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
_RFC3339_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)
_PUBLIC_JWK_FIELDS = frozenset({"kty", "crv", "x", "y", "ext"})
_PUBLIC_FILE_NAMES = (
    "public-trust-registry.json",
    "signed-receipt.json",
    "subject-manifest.json",
    "verification-report.json",
)
_MAX_SIGNERS = 16


class PortableEvidenceError(RuntimeError):
    """Raised when a portable evidence bundle cannot be produced safely."""


def _canonical_json_bytes(value: Any) -> bytes:
    return (canonicalize_json(value) + "\n").encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _parse_utc(value: str, *, field_name: str):
    if not isinstance(value, str) or _RFC3339_UTC_RE.fullmatch(value) is None:
        raise PortableEvidenceError(f"{field_name} must be an RFC3339 UTC timestamp")
    try:
        return parse_rfc3339_utc(value)
    except (TypeError, ValueError):
        raise PortableEvidenceError(
            f"{field_name} must be an RFC3339 UTC timestamp"
        ) from None


def _decode_coordinate(value: Any, *, field_name: str) -> bytes:
    if not isinstance(value, str) or not value or _BASE64URL_RE.fullmatch(value) is None:
        raise PortableEvidenceError(f"{field_name} must be canonical unpadded base64url")
    try:
        decoded = base64.b64decode(
            (value + "=" * (-len(value) % 4)).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError):
        raise PortableEvidenceError(
            f"{field_name} must be canonical unpadded base64url"
        ) from None
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != value or len(decoded) != 32:
        raise PortableEvidenceError(f"{field_name} must encode exactly 32 bytes")
    return decoded


def _validate_name(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or _NAME_RE.fullmatch(value) is None:
        raise PortableEvidenceError(f"{field_name} contains unsupported characters")
    return value


def _validate_azure_key_id(key_id: Any) -> str:
    message = "signer key ID is not a canonical versioned Azure key ID"
    if not isinstance(key_id, str) or not key_id:
        raise PortableEvidenceError(message)
    try:
        parsed = urlparse(key_id)
        port = parsed.port
    except ValueError:
        raise PortableEvidenceError(message) from None
    path_parts = [part for part in parsed.path.split("/") if part]
    canonical_path = "/" + "/".join(path_parts)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.hostname is None
        or parsed.netloc != parsed.hostname
        or _AZURE_VAULT_HOST_RE.fullmatch(parsed.hostname) is None
        or parsed.path != canonical_path
        or len(path_parts) != 3
        or path_parts[0] != "keys"
        or _KEY_NAME_RE.fullmatch(path_parts[1]) is None
        or _KEY_VERSION_RE.fullmatch(path_parts[2]) is None
    ):
        raise PortableEvidenceError(message)
    return key_id


@dataclass(frozen=True)
class PortableEvidenceContext:
    """Immutable workflow context bound into the portable public evidence."""

    repository: str
    commit_sha: str
    workflow: str
    run_id: str
    run_attempt: str
    created_at: str

    def validate(self) -> None:
        if _REPOSITORY_RE.fullmatch(self.repository) is None:
            raise PortableEvidenceError("repository must use owner/name form")
        if _COMMIT_RE.fullmatch(self.commit_sha) is None:
            raise PortableEvidenceError(
                "commit_sha must be 40 lowercase hexadecimal characters"
            )
        if _WORKFLOW_RE.fullmatch(self.workflow) is None:
            raise PortableEvidenceError("workflow contains unsupported characters")
        if _RUN_ID_RE.fullmatch(self.run_id) is None:
            raise PortableEvidenceError("run_id must be a positive decimal identifier")
        if _RUN_ATTEMPT_RE.fullmatch(self.run_attempt) is None:
            raise PortableEvidenceError(
                "run_attempt must be a positive decimal identifier"
            )
        _parse_utc(self.created_at, field_name="created_at")


@dataclass(frozen=True)
class PortableSignerBinding:
    """One public trust entry paired with an external digest signer."""

    key_id: str
    signer_role: str
    public_jwk: Mapping[str, Any]
    status: str
    not_before: str
    not_after: str
    signer: ExternalDigestSigner

    def validate_for(self, created_at: str) -> None:
        _validate_azure_key_id(self.key_id)
        _validate_name(self.signer_role, field_name="signer_role")
        if self.status not in {"active", "revoked"}:
            raise PortableEvidenceError("trust status must be active or revoked")
        if self.status != "active":
            raise PortableEvidenceError("portable signer key is not active")

        created = _parse_utc(created_at, field_name="created_at")
        not_before = _parse_utc(self.not_before, field_name="not_before")
        not_after = _parse_utc(self.not_after, field_name="not_after")
        if not_before >= not_after:
            raise PortableEvidenceError("trust validity interval is empty or reversed")
        if created < not_before or created > not_after:
            raise PortableEvidenceError(
                "receipt timestamp is outside the signer trust window"
            )

        if not isinstance(self.public_jwk, Mapping):
            raise PortableEvidenceError("public JWK must be an object")
        if frozenset(self.public_jwk.keys()) != _PUBLIC_JWK_FIELDS:
            raise PortableEvidenceError(
                "public JWK must contain exactly kty, crv, x, y and ext"
            )
        if (
            self.public_jwk.get("kty") != "EC"
            or self.public_jwk.get("crv") != "P-256"
            or self.public_jwk.get("ext") is not True
        ):
            raise PortableEvidenceError("public JWK must be exportable EC P-256")
        x = _decode_coordinate(self.public_jwk.get("x"), field_name="public JWK x")
        y = _decode_coordinate(self.public_jwk.get("y"), field_name="public JWK y")
        try:
            ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"),
                int.from_bytes(y, "big"),
                ec.SECP256R1(),
            ).public_key()
        except ValueError:
            raise PortableEvidenceError(
                "public JWK coordinates do not form a valid P-256 point"
            ) from None

    def trust_entry(self) -> dict[str, Any]:
        return {
            "kid": self.key_id,
            "role": self.signer_role,
            "alg": "ES256",
            "status": self.status,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "jwk": dict(self.public_jwk),
        }


@dataclass(frozen=True)
class PortableEvidenceBundle:
    """Five canonical public files for one independently verified receipt."""

    subject_manifest: dict[str, Any]
    signed_receipt: dict[str, Any]
    public_trust_registry: dict[str, Any]
    verification_report: dict[str, Any]
    evidence_manifest: dict[str, Any]

    def serialized_files(self) -> dict[str, bytes]:
        files = {
            "public-trust-registry.json": _canonical_json_bytes(
                self.public_trust_registry
            ),
            "signed-receipt.json": _canonical_json_bytes(self.signed_receipt),
            "subject-manifest.json": _canonical_json_bytes(self.subject_manifest),
            "verification-report.json": _canonical_json_bytes(
                self.verification_report
            ),
            "evidence-manifest.json": _canonical_json_bytes(self.evidence_manifest),
        }
        return dict(sorted(files.items()))


def _verification_report(result) -> dict[str, Any]:
    return {
        "schema_version": "sentinel.verification-report.v1",
        "status": result.status,
        "verified": result.verified,
        "valid_signatures": result.valid_signatures,
        "required_signatures": result.required_signatures,
        "matched_roles": list(result.matched_roles),
        "receipt_hash": result.receipt_hash,
        "issues": [
            {
                "severity": issue.severity,
                "code": issue.code,
                "message": issue.message,
            }
            for issue in result.issues
        ],
    }


def build_portable_evidence_bundle(
    *,
    context: PortableEvidenceContext,
    receipt_id: str,
    entity_type: str,
    entity_id: str,
    release_class: str,
    policy_id: str,
    policy_version: str,
    required_roles: Sequence[str],
    min_signatures: int,
    signer_bindings: Sequence[PortableSignerBinding],
    sequence: int = 1,
    previous_hash: str = _ZERO_HASH,
) -> PortableEvidenceBundle:
    """Build, externally sign, independently verify and package one receipt."""

    context.validate()
    _validate_name(receipt_id, field_name="receipt_id")
    _validate_name(entity_type, field_name="entity_type")
    _validate_name(entity_id, field_name="entity_id")
    _validate_name(policy_id, field_name="policy_id")
    _validate_name(policy_version, field_name="policy_version")

    if release_class not in {"A", "B", "C"}:
        raise PortableEvidenceError("release_class must be A, B or C")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise PortableEvidenceError("sequence must be a positive integer")
    if not isinstance(previous_hash, str) or _SHA256_RE.fullmatch(previous_hash) is None:
        raise PortableEvidenceError(
            "previous_hash must be sha256 followed by 64 lowercase hexadecimal characters"
        )
    if (
        isinstance(min_signatures, bool)
        or not isinstance(min_signatures, int)
        or min_signatures < 1
        or min_signatures > _MAX_SIGNERS
    ):
        raise PortableEvidenceError("min_signatures is invalid")

    roles = sorted(required_roles)
    if not roles or len(roles) > _MAX_SIGNERS:
        raise PortableEvidenceError("required_roles count is invalid")
    if len(set(roles)) != len(roles):
        raise PortableEvidenceError("required_roles must be unique")
    for role in roles:
        _validate_name(role, field_name="required role")
    if release_class == "A" and (min_signatures < 2 or len(roles) < 2):
        raise PortableEvidenceError(
            "Class A requires at least two signatures and two required roles"
        )

    bindings = sorted(signer_bindings, key=lambda item: item.key_id)
    if not bindings or len(bindings) > _MAX_SIGNERS:
        raise PortableEvidenceError("signer binding count is invalid")
    if min_signatures > len(bindings):
        raise PortableEvidenceError("min_signatures exceeds available signers")
    key_ids = [binding.key_id for binding in bindings]
    if len(set(key_ids)) != len(key_ids):
        raise PortableEvidenceError("signer key IDs must be unique")
    signer_roles = {binding.signer_role for binding in bindings}
    if not set(roles).issubset(signer_roles):
        raise PortableEvidenceError("required roles are not covered by signer bindings")
    for binding in bindings:
        binding.validate_for(context.created_at)

    subject_manifest = {
        "schema_version": "sentinel.portable-subject.v1",
        "repository": context.repository,
        "commit_sha": context.commit_sha,
        "workflow": context.workflow,
        "run_id": context.run_id,
        "run_attempt": context.run_attempt,
        "created_at": context.created_at,
        "entity_type": entity_type,
        "entity_id": entity_id,
    }
    subject_bytes = _canonical_json_bytes(subject_manifest)
    subject_hash = _sha256_bytes(subject_bytes)

    receipt: dict[str, Any] = {
        "schema_version": "sentinel.receipt.v1",
        "receipt_id": receipt_id,
        "receipt_type": "release_receipt",
        "subject": {
            "entity_type": entity_type,
            "entity_id": entity_id,
        },
        "created_at": context.created_at,
        "release_class": release_class,
        "policy": {
            "policy_id": policy_id,
            "policy_version": policy_version,
            "required_roles": roles,
            "min_signatures": min_signatures,
        },
        "evidence": {
            "artifact_hash": subject_hash,
            "source_commit": context.commit_sha,
            "pipeline_run_id": f"github:{context.run_id}:{context.run_attempt}",
            "artifact_path": "subject-manifest.json",
        },
        "chain": {
            "sequence": sequence,
            "previous_hash": previous_hash,
            "receipt_hash": "",
        },
        "signatures": [],
    }

    signed_receipt = deepcopy(receipt)
    try:
        for binding in bindings:
            signed_receipt = sign_receipt_with_external_digest_signer(
                signed_receipt,
                key_id=binding.key_id,
                signer_role=binding.signer_role,
                signer=binding.signer,
            )
    except SigningContractError:
        raise PortableEvidenceError("portable receipt signing contract failed") from None

    trust_registry = {binding.key_id: binding.trust_entry() for binding in bindings}
    verification = verify_receipt(signed_receipt, trust_registry=trust_registry)
    report = _verification_report(verification)
    if verification.status != "RC_VERIFIED" or not verification.verified:
        issue_codes = sorted({issue.code for issue in verification.issues})
        suffix = ",".join(issue_codes) if issue_codes else "UNKNOWN"
        raise PortableEvidenceError(
            f"independent portable receipt verification failed: {suffix}"
        )

    public_trust_registry = {
        "schema_version": "sentinel.public-trust-registry.v1",
        "entries": [deepcopy(trust_registry[key_id]) for key_id in sorted(trust_registry)],
    }
    public_files = {
        "public-trust-registry.json": _canonical_json_bytes(public_trust_registry),
        "signed-receipt.json": _canonical_json_bytes(signed_receipt),
        "subject-manifest.json": subject_bytes,
        "verification-report.json": _canonical_json_bytes(report),
    }
    manifest = {
        "schema_version": "sentinel.portable-evidence-manifest.v1",
        "repository": context.repository,
        "commit_sha": context.commit_sha,
        "workflow": context.workflow,
        "run_id": context.run_id,
        "run_attempt": context.run_attempt,
        "created_at": context.created_at,
        "key_ids": sorted(trust_registry),
        "receipt_hash": verification.receipt_hash,
        "verification_status": verification.status,
        "files": [
            {
                "path": name,
                "media_type": "application/json",
                "sha256": _sha256_bytes(public_files[name]),
            }
            for name in sorted(public_files)
        ],
    }

    return PortableEvidenceBundle(
        subject_manifest=subject_manifest,
        signed_receipt=signed_receipt,
        public_trust_registry=public_trust_registry,
        verification_report=report,
        evidence_manifest=manifest,
    )


def write_portable_evidence_bundle(
    bundle: PortableEvidenceBundle,
    output_directory: str | Path,
) -> Path:
    """Write a verified bundle atomically and never overwrite an existing path."""

    if not isinstance(bundle, PortableEvidenceBundle):
        raise PortableEvidenceError("bundle is invalid")
    output = Path(output_directory)
    if output.exists():
        raise PortableEvidenceError("output directory already exists")
    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    try:
        files = bundle.serialized_files()
        if set(files) != set(_PUBLIC_FILE_NAMES) | {"evidence-manifest.json"}:
            raise PortableEvidenceError("portable bundle file set is invalid")
        for name, content in files.items():
            path = temporary / name
            with path.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        temporary.replace(output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return output


__all__ = [
    "PortableEvidenceBundle",
    "PortableEvidenceContext",
    "PortableEvidenceError",
    "PortableSignerBinding",
    "build_portable_evidence_bundle",
    "write_portable_evidence_bundle",
]
