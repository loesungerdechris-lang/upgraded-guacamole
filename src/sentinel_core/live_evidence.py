"""Public evidence builder for protected SENTINEL live signing.

The builder accepts only public key metadata, immutable workflow context and an
external digest signer. It signs a deterministic release receipt, invokes the
existing independent verifier, and emits a minimal public evidence bundle.
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
from typing import Any, Literal, Mapping

from cryptography.hazmat.primitives.asymmetric import ec

from sentinel_core.azure_cli_signing import AzureCliSigningError, validate_azure_key_id
from sentinel_core.external_signing import (
    ExternalDigestSigner,
    SigningContractError,
    sign_receipt_with_external_digest_signer,
)
from sentinel_core.hashchain import canonicalize_json
from sentinel_core.receipt import parse_rfc3339_utc, verify_receipt

TrustStatus = Literal["active", "revoked"]

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_WORKFLOW_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,127}$")
_RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
_RUN_ATTEMPT_RE = re.compile(r"^[1-9][0-9]{0,5}$")
_RFC3339_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)
_ZERO_HASH = "sha256:" + "0" * 64
_PUBLIC_KEY_METADATA_FIELDS = frozenset({"kid", "kty", "crv", "key_ops", "x", "y"})
_PUBLIC_FILE_NAMES = (
    "public-trust-entry.json",
    "signed-receipt.json",
    "subject-manifest.json",
    "verification-report.json",
)


class LiveEvidenceError(RuntimeError):
    """Raised when live evidence cannot be produced safely."""


def _b64url_decode_32(value: str, *, field_name: str) -> bytes:
    if not isinstance(value, str) or not value or not _BASE64URL_RE.fullmatch(value):
        raise LiveEvidenceError(f"{field_name} must be canonical unpadded base64url")

    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(
            (value + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError):
        raise LiveEvidenceError(
            f"{field_name} must be canonical unpadded base64url"
        ) from None

    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != value or len(decoded) != 32:
        raise LiveEvidenceError(f"{field_name} must encode exactly 32 bytes")
    return decoded


def _parse_utc_timestamp(value: str, *, field_name: str):
    if not isinstance(value, str) or _RFC3339_UTC_RE.fullmatch(value) is None:
        raise LiveEvidenceError(f"{field_name} must be an RFC3339 UTC timestamp")
    try:
        return parse_rfc3339_utc(value)
    except (TypeError, ValueError):
        raise LiveEvidenceError(f"{field_name} must be an RFC3339 UTC timestamp") from None


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return (canonicalize_json(value) + "\n").encode("utf-8")


@dataclass(frozen=True)
class PublicKeyMetadata:
    """Public versioned Azure Key Vault P-256 metadata."""

    kid: str
    kty: str
    crv: str
    key_ops: tuple[str, ...]
    x: str
    y: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> PublicKeyMetadata:
        """Build validated metadata from a JSON-compatible mapping."""

        if not isinstance(value, Mapping):
            raise LiveEvidenceError("public key metadata must be an object")
        if frozenset(value.keys()) != _PUBLIC_KEY_METADATA_FIELDS:
            raise LiveEvidenceError(
                "public key metadata must contain exactly the approved public fields"
            )

        key_ops = value.get("key_ops")
        if not isinstance(key_ops, list) or not all(
            isinstance(item, str) for item in key_ops
        ):
            raise LiveEvidenceError("public key operations must be a string list")

        metadata = cls(
            kid=value.get("kid"),
            kty=value.get("kty"),
            crv=value.get("crv"),
            key_ops=tuple(key_ops),
            x=value.get("x"),
            y=value.get("y"),
        )
        metadata.validate()
        return metadata

    def validate(self) -> None:
        """Validate the frozen public key profile."""

        try:
            validate_azure_key_id(self.kid)
        except AzureCliSigningError:
            raise LiveEvidenceError("public key ID is not a canonical Azure key ID") from None

        if self.kty != "EC" or self.crv != "P-256":
            raise LiveEvidenceError("public key must be EC P-256")
        if len(self.key_ops) != 2 or set(self.key_ops) != {"sign", "verify"}:
            raise LiveEvidenceError("public key operations must be exactly sign and verify")

        x_bytes = _b64url_decode_32(self.x, field_name="public JWK x")
        y_bytes = _b64url_decode_32(self.y, field_name="public JWK y")
        try:
            ec.EllipticCurvePublicNumbers(
                int.from_bytes(x_bytes, "big"),
                int.from_bytes(y_bytes, "big"),
                ec.SECP256R1(),
            ).public_key()
        except ValueError:
            raise LiveEvidenceError(
                "public JWK coordinates do not form a valid P-256 point"
            ) from None

    def public_jwk(self) -> dict[str, Any]:
        """Return the public-only JWK used by the independent verifier."""

        self.validate()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": self.x,
            "y": self.y,
            "ext": True,
        }


@dataclass(frozen=True)
class LiveEvidenceContext:
    """Immutable GitHub Actions context bound into the public evidence."""

    repository: str
    commit_sha: str
    workflow: str
    run_id: str
    run_attempt: str
    created_at: str

    def validate(self) -> None:
        if _REPOSITORY_RE.fullmatch(self.repository) is None:
            raise LiveEvidenceError("repository must use owner/name form")
        if _COMMIT_RE.fullmatch(self.commit_sha) is None:
            raise LiveEvidenceError("commit_sha must be 40 lowercase hexadecimal characters")
        if _WORKFLOW_RE.fullmatch(self.workflow) is None:
            raise LiveEvidenceError("workflow contains unsupported characters")
        if _RUN_ID_RE.fullmatch(self.run_id) is None:
            raise LiveEvidenceError("run_id must be a positive decimal identifier")
        if _RUN_ATTEMPT_RE.fullmatch(self.run_attempt) is None:
            raise LiveEvidenceError("run_attempt must be a positive decimal identifier")
        _parse_utc_timestamp(self.created_at, field_name="created_at")


@dataclass(frozen=True)
class PublicTrustPolicy:
    """Public trust state applied by the independent verifier."""

    role: str
    status: TrustStatus
    not_before: str
    not_after: str

    def validate_for(self, created_at: str) -> None:
        if self.role != "release_signer":
            raise LiveEvidenceError("live signing role must be release_signer")
        if self.status not in ("active", "revoked"):
            raise LiveEvidenceError("trust status must be active or revoked")

        created = _parse_utc_timestamp(created_at, field_name="created_at")
        not_before = _parse_utc_timestamp(self.not_before, field_name="not_before")
        not_after = _parse_utc_timestamp(self.not_after, field_name="not_after")
        if not_before >= not_after:
            raise LiveEvidenceError("trust validity interval is empty or reversed")
        if self.status != "active":
            raise LiveEvidenceError("public signing key is not active")
        if created < not_before or created > not_after:
            raise LiveEvidenceError("receipt timestamp is outside the public trust window")


@dataclass(frozen=True)
class LiveEvidenceBundle:
    """Verified public files produced by one protected live-signing run."""

    subject_manifest: dict[str, Any]
    signed_receipt: dict[str, Any]
    public_trust_entry: dict[str, Any]
    verification_report: dict[str, Any]
    evidence_manifest: dict[str, Any]

    def serialized_files(self) -> dict[str, bytes]:
        """Return canonical UTF-8 bytes for the complete public bundle."""

        files = {
            "public-trust-entry.json": _canonical_json_bytes(self.public_trust_entry),
            "signed-receipt.json": _canonical_json_bytes(self.signed_receipt),
            "subject-manifest.json": _canonical_json_bytes(self.subject_manifest),
            "verification-report.json": _canonical_json_bytes(
                self.verification_report
            ),
            "evidence-manifest.json": _canonical_json_bytes(self.evidence_manifest),
        }
        return dict(sorted(files.items()))


def _build_subject_manifest(context: LiveEvidenceContext) -> dict[str, Any]:
    return {
        "schema_version": "sentinel.live-signing-subject.v1",
        "repository": context.repository,
        "commit_sha": context.commit_sha,
        "workflow": context.workflow,
        "run_id": context.run_id,
        "run_attempt": context.run_attempt,
        "created_at": context.created_at,
    }


def _build_receipt(
    context: LiveEvidenceContext,
    *,
    subject_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": "sentinel.receipt.v1",
        "receipt_id": f"REC-AZURE-LIVE-{context.run_id}-{context.run_attempt}",
        "receipt_type": "release_receipt",
        "subject": {
            "entity_type": "release_artifact",
            "entity_id": f"{context.repository}@{context.commit_sha}",
        },
        "created_at": context.created_at,
        "release_class": "B",
        "policy": {
            "policy_id": "sentinel.azure-live-signing",
            "policy_version": "1.0.0",
            "required_roles": ["release_signer"],
            "min_signatures": 1,
        },
        "evidence": {
            "artifact_hash": subject_hash,
            "source_commit": context.commit_sha,
            "pipeline_run_id": (
                f"github:{context.run_id}:{context.run_attempt}"
            ),
            "artifact_path": "subject-manifest.json",
        },
        "chain": {
            "sequence": 1,
            "previous_hash": _ZERO_HASH,
            "receipt_hash": "",
        },
        "signatures": [],
    }


def _build_trust_entry(
    metadata: PublicKeyMetadata,
    policy: PublicTrustPolicy,
) -> tuple[dict[str, Any], dict[str, Any]]:
    entry = {
        "kid": metadata.kid,
        "role": policy.role,
        "alg": "ES256",
        "status": policy.status,
        "not_before": policy.not_before,
        "not_after": policy.not_after,
        "jwk": metadata.public_jwk(),
    }
    public_file = {
        "schema_version": "sentinel.public-trust-entry.v1",
        "entry": deepcopy(entry),
    }
    return entry, public_file


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


def build_live_evidence_bundle(
    *,
    metadata: PublicKeyMetadata,
    context: LiveEvidenceContext,
    trust_policy: PublicTrustPolicy,
    signer: ExternalDigestSigner,
) -> LiveEvidenceBundle:
    """Sign, independently verify, and package one public evidence bundle."""

    metadata.validate()
    context.validate()
    trust_policy.validate_for(context.created_at)

    subject_manifest = _build_subject_manifest(context)
    subject_bytes = _canonical_json_bytes(subject_manifest)
    subject_hash = _sha256_bytes(subject_bytes)
    unsigned_receipt = _build_receipt(context, subject_hash=subject_hash)
    trust_entry, public_trust_file = _build_trust_entry(metadata, trust_policy)

    try:
        signed_receipt = sign_receipt_with_external_digest_signer(
            unsigned_receipt,
            key_id=metadata.kid,
            signer_role=trust_policy.role,
            signer=signer,
        )
    except SigningContractError:
        raise LiveEvidenceError("live receipt signing contract failed") from None

    verification = verify_receipt(
        signed_receipt,
        trust_registry={metadata.kid: trust_entry},
    )
    verification_report = _verification_report(verification)
    if verification.status != "RC_VERIFIED" or not verification.verified:
        issue_codes = sorted({issue.code for issue in verification.issues})
        suffix = ",".join(issue_codes) if issue_codes else "UNKNOWN"
        raise LiveEvidenceError(
            f"independent receipt verification failed: {suffix}"
        )

    public_files = {
        "public-trust-entry.json": _canonical_json_bytes(public_trust_file),
        "signed-receipt.json": _canonical_json_bytes(signed_receipt),
        "subject-manifest.json": subject_bytes,
        "verification-report.json": _canonical_json_bytes(verification_report),
    }
    evidence_manifest = {
        "schema_version": "sentinel.live-evidence-manifest.v1",
        "repository": context.repository,
        "commit_sha": context.commit_sha,
        "workflow": context.workflow,
        "run_id": context.run_id,
        "run_attempt": context.run_attempt,
        "created_at": context.created_at,
        "key_id": metadata.kid,
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

    return LiveEvidenceBundle(
        subject_manifest=subject_manifest,
        signed_receipt=signed_receipt,
        public_trust_entry=public_trust_file,
        verification_report=verification_report,
        evidence_manifest=evidence_manifest,
    )


def write_live_evidence_bundle(
    bundle: LiveEvidenceBundle,
    output_directory: str | Path,
) -> Path:
    """Write a verified bundle through an atomic same-filesystem rename."""

    if not isinstance(bundle, LiveEvidenceBundle):
        raise LiveEvidenceError("bundle is invalid")

    output = Path(output_directory)
    if output.name in ("", ".", ".."):
        raise LiveEvidenceError("output directory must name a new directory")
    if output.exists() or output.is_symlink():
        raise LiveEvidenceError("output directory already exists")

    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True)
    if not parent.is_dir() or parent.is_symlink():
        raise LiveEvidenceError("output parent must be a real directory")

    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.", dir=str(parent))
    )
    try:
        serialized = bundle.serialized_files()
        expected_names = set(_PUBLIC_FILE_NAMES) | {"evidence-manifest.json"}
        if set(serialized) != expected_names:
            raise LiveEvidenceError("bundle contains an unexpected public file set")

        for name, content in serialized.items():
            target = temporary / name
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o644,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())

        os.replace(temporary, output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    return output
