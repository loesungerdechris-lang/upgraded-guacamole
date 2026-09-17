"""Strict verifier for the non-production SENTINEL demo profile."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Callable

PROFILE = "sentinel-demo-mvp/v0.1"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
BUNDLE_MEDIA = "application/vnd.dev.sigstore.bundle.v0.3+json"
ROOT_TYPE = "https://sentinel.example/demo/evidence-manifest/v1"
GOVERNANCE_TYPE = "https://sentinel.example/demo/governance/v1"
SBOM_TYPE = "https://cyclonedx.org/bom"
STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1"
MAX_OBJECT_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LIMITATIONS = [
    "NONPRODUCTION_DEMO",
    "MOCK_GOVERNANCE",
    "NO_TRANSPARENCY_LOG_OR_TIMESTAMP",
    "SINGLE_PLATFORM_IMAGE_ONLY",
    "NO_VULNERABILITY_OR_SBOM_COMPLETENESS_GUARANTEE",
]


class _Decision(Exception):
    def __init__(self, status: str, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


class _Budget:
    def __init__(self, initial: int = 0) -> None:
        self.total = initial
        if initial > MAX_TOTAL_BYTES:
            raise _Decision("ERROR", "SIZE_LIMIT_EXCEEDED")

    def include(self, value: Any) -> bytes:
        if not isinstance(value, bytes):
            raise _Decision("ERROR", "MALFORMED_OBJECT")
        if len(value) > MAX_OBJECT_BYTES:
            raise _Decision("ERROR", "SIZE_LIMIT_EXCEEDED")
        self.total += len(value)
        if self.total > MAX_TOTAL_BYTES:
            raise _Decision("ERROR", "SIZE_LIMIT_EXCEEDED")
        return value


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_non_finite(number: str) -> None:
    raise ValueError(f"non-finite JSON number: {number}")


def _json_object(value: bytes, reason: str = "MALFORMED_OBJECT") -> dict[str, Any]:
    try:
        parsed = json.loads(
            value,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_non_finite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _Decision("ERROR", reason) from exc
    if not isinstance(parsed, dict):
        raise _Decision("ERROR", reason)
    return parsed


def _exact_keys(value: dict[str, Any], keys: set[str], reason: str) -> None:
    if set(value) != keys:
        raise _Decision("ERROR", reason)


def _descriptor(value: Any, expected_media: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _Decision("ERROR", "MALFORMED_DESCRIPTOR")
    _exact_keys(value, {"digest", "size", "mediaType"}, "MALFORMED_DESCRIPTOR")
    object_digest = value.get("digest")
    size = value.get("size")
    media_type = value.get("mediaType")
    if not isinstance(object_digest, str) or _DIGEST.fullmatch(object_digest) is None:
        raise _Decision("ERROR", "MALFORMED_DESCRIPTOR")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise _Decision("ERROR", "MALFORMED_DESCRIPTOR")
    if not isinstance(media_type, str) or not media_type:
        raise _Decision("ERROR", "MALFORMED_DESCRIPTOR")
    if expected_media is not None and media_type != expected_media:
        raise _Decision("BLOCKED", "DESCRIPTOR_MISMATCH")
    return value


def _artifact_ref(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _Decision("ERROR", "MALFORMED_DESCRIPTOR")
    _exact_keys(value, {"artifact", "payload"}, "MALFORMED_DESCRIPTOR")
    _descriptor(value["artifact"], OCI_MANIFEST)
    _descriptor(value["payload"], BUNDLE_MEDIA)
    return value


def _validate_content(value: bytes, expected: dict[str, Any]) -> None:
    if len(value) != expected["size"] or _sha256(value) != expected["digest"]:
        raise _Decision("BLOCKED", "DIGEST_MISMATCH")


def _result(status: str, reason: str, checks: dict[str, bool], image_digest: str) -> dict[str, Any]:
    exit_codes = {"PASS": 0, "HOLD": 2, "BLOCKED": 3, "ERROR": 4}
    return {
        "profile": PROFILE,
        "status": status,
        "exitCode": exit_codes[status],
        "reasonCodes": [reason],
        "checks": checks,
        "imageDigest": image_digest,
        "productionAcceptance": False,
        "limitations": list(_LIMITATIONS),
    }


def _store_read(reader: Callable[[str], bytes], object_digest: str, budget: _Budget, missing_reason: str) -> bytes:
    try:
        value = reader(object_digest)
    except FileNotFoundError as exc:
        raise _Decision("HOLD", missing_reason) from exc
    except Exception as exc:
        raise _Decision("ERROR", "STORE_ERROR") from exc
    return budget.include(value)


def _read_descriptor(reader: Callable[[str], bytes], expected: dict[str, Any], budget: _Budget, missing_reason: str) -> bytes:
    value = _store_read(reader, expected["digest"], budget, missing_reason)
    _validate_content(value, expected)
    return value


def _validate_artifact(artifact_bytes: bytes, artifact_ref: dict[str, Any], image_digest: str, image_size: int, predicate_type: str) -> None:
    artifact = _json_object(artifact_bytes, "MALFORMED_OCI_MANIFEST")
    if artifact.get("schemaVersion") != 2 or artifact.get("mediaType") != OCI_MANIFEST:
        raise _Decision("ERROR", "UNSUPPORTED_OCI_MANIFEST")
    if artifact.get("artifactType") != BUNDLE_MEDIA:
        raise _Decision("BLOCKED", "CONTEXT_MISMATCH")
    config = artifact.get("config")
    if not isinstance(config, dict) or not set(config).issubset(
        {"digest", "size", "mediaType", "artifactType"}
    ):
        raise _Decision("ERROR", "MALFORMED_DESCRIPTOR")
    config_descriptor = {key: config[key] for key in ("digest", "size", "mediaType") if key in config}
    _descriptor(config_descriptor, "application/vnd.oci.empty.v1+json")
    if "artifactType" in config and config["artifactType"] != BUNDLE_MEDIA:
        raise _Decision("BLOCKED", "CONTEXT_MISMATCH")
    layers = artifact.get("layers")
    if not isinstance(layers, list) or len(layers) != 1:
        raise _Decision("BLOCKED", "DESCRIPTOR_MISMATCH")
    layer = _descriptor(layers[0], BUNDLE_MEDIA)
    if layer != artifact_ref["payload"]:
        raise _Decision("BLOCKED", "DESCRIPTOR_MISMATCH")
    subject = artifact.get("subject")
    if not isinstance(subject, dict):
        raise _Decision("BLOCKED", "CONTEXT_MISMATCH")
    if (subject.get("digest") != image_digest or subject.get("mediaType") != OCI_MANIFEST or subject.get("size") != image_size):
        raise _Decision("BLOCKED", "CONTEXT_MISMATCH")


def _verify_and_extract_statement(bundle_bytes: bytes, predicate_type: str, image_digest: str, public_key_bytes: bytes, cosign_binary: str) -> dict[str, Any]:
    if not isinstance(cosign_binary, str) or not cosign_binary:
        raise _Decision("ERROR", "CRYPTO_VERIFIER_ERROR")
    if os.path.dirname(cosign_binary):
        resolved_cosign = str(Path(cosign_binary).resolve())
    else:
        found_cosign = shutil.which(cosign_binary)
        if found_cosign is None:
            raise _Decision("ERROR", "CRYPTO_VERIFIER_ERROR")
        resolved_cosign = str(Path(found_cosign).resolve())
    with tempfile.TemporaryDirectory(prefix="sentinel-cosign-verify-") as directory:
        bundle_path = Path(directory) / "bundle.json"
        public_key_snapshot = Path(directory) / "public.pem"
        bundle_path.write_bytes(bundle_bytes)
        public_key_snapshot.write_bytes(public_key_bytes)
        cache_path = Path(directory) / "cache"
        cache_path.mkdir()
        command = [
            resolved_cosign, "verify-blob-attestation", "--key", str(public_key_snapshot),
            "--bundle", str(bundle_path), "--type", predicate_type,
            "--insecure-ignore-tlog", "--digest", image_digest.removeprefix("sha256:"),
            "--digestAlg", "sha256",
        ]
        try:
            completed = subprocess.run(
                command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=30,
                env={
                    "PATH": os.defpath,
                    "TMPDIR": directory,
                    "XDG_CACHE_HOME": str(cache_path),
                },
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise _Decision("ERROR", "CRYPTO_VERIFIER_ERROR") from exc
        if completed.returncode != 0:
            raise _Decision("BLOCKED", "INVALID_SIGNATURE")

    bundle = _json_object(bundle_bytes, "MALFORMED_BUNDLE")
    if bundle.get("mediaType") != BUNDLE_MEDIA:
        raise _Decision("ERROR", "MALFORMED_BUNDLE")
    envelope = bundle.get("dsseEnvelope")
    if not isinstance(envelope, dict) or envelope.get("payloadType") != "application/vnd.in-toto+json":
        raise _Decision("ERROR", "MALFORMED_BUNDLE")
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        raise _Decision("ERROR", "MALFORMED_BUNDLE")
    try:
        statement_bytes = base64.b64decode(payload, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise _Decision("ERROR", "MALFORMED_BUNDLE") from exc
    statement = _json_object(statement_bytes, "MALFORMED_STATEMENT")
    if statement.get("_type") != STATEMENT_TYPE or statement.get("predicateType") != predicate_type:
        raise _Decision("BLOCKED", "CONTEXT_MISMATCH")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise _Decision("BLOCKED", "CONTEXT_MISMATCH")
    subject = subjects[0]
    if not isinstance(subject, dict) or not isinstance(subject.get("name"), str) or not subject["name"]:
        raise _Decision("BLOCKED", "CONTEXT_MISMATCH")
    subject_digest = subject.get("digest")
    if not isinstance(subject_digest, dict) or set(subject_digest) != {"sha256"}:
        raise _Decision("BLOCKED", "CONTEXT_MISMATCH")
    if subject_digest.get("sha256") != image_digest.removeprefix("sha256:"):
        raise _Decision("BLOCKED", "CONTEXT_MISMATCH")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise _Decision("ERROR", "MALFORMED_STATEMENT")
    return predicate


def _read_signed_artifact(reference: dict[str, Any], predicate_type: str, image_digest: str, image_size: int, public_key_bytes: bytes, store: Any, cosign_binary: str, budget: _Budget, missing_reason: str) -> dict[str, Any]:
    _artifact_ref(reference)
    artifact_bytes = _read_descriptor(store.read_manifest, reference["artifact"], budget, missing_reason)
    _validate_artifact(artifact_bytes, reference, image_digest, image_size, predicate_type)
    bundle_bytes = _read_descriptor(store.read_blob, reference["payload"], budget, missing_reason)
    return _verify_and_extract_statement(bundle_bytes, predicate_type, image_digest, public_key_bytes, cosign_binary)


def _validate_policy(policy: dict[str, Any]) -> None:
    expected = {
        "profile": PROFILE,
        "allowMockGovernance": True,
        "productionAcceptance": False,
        "requiredRoles": ["sbom", "governance"],
        "sbomSpecVersion": "1.6",
    }
    _exact_keys(policy, set(expected), "MALFORMED_POLICY")
    if (
        policy != expected
        or policy.get("allowMockGovernance") is not True
        or policy.get("productionAcceptance") is not False
    ):
        raise _Decision("BLOCKED", "POLICY_VIOLATION")


def _validate_root_predicate(predicate: dict[str, Any], request: dict[str, Any], image_digest: str) -> dict[str, dict[str, Any]]:
    _exact_keys(predicate, {"profile", "runId", "imageDigest", "policySha256", "entries"}, "MALFORMED_MANIFEST")
    if (predicate.get("profile") != PROFILE or predicate.get("runId") != request["runId"] or predicate.get("imageDigest") != image_digest or predicate.get("policySha256") != request["policySha256"]):
        raise _Decision("BLOCKED", "CONTEXT_MISMATCH")
    entries = predicate.get("entries")
    if not isinstance(entries, list):
        raise _Decision("ERROR", "MALFORMED_MANIFEST")
    by_role: dict[str, dict[str, Any]] = {}
    expected_types = {"sbom": SBOM_TYPE, "governance": GOVERNANCE_TYPE}
    for entry in entries:
        if not isinstance(entry, dict):
            raise _Decision("ERROR", "MALFORMED_MANIFEST")
        _exact_keys(entry, {"role", "predicateType", "artifact", "payload"}, "MALFORMED_MANIFEST")
        role = entry.get("role")
        if role not in expected_types or role in by_role or entry.get("predicateType") != expected_types.get(role):
            raise _Decision("BLOCKED", "EVIDENCE_SET_MISMATCH")
        _artifact_ref({"artifact": entry["artifact"], "payload": entry["payload"]})
        by_role[role] = entry
    if set(by_role) != set(expected_types):
        raise _Decision("BLOCKED", "EVIDENCE_SET_MISMATCH")
    return by_role


def _validate_sbom(predicate: dict[str, Any]) -> None:
    version = predicate.get("version")
    if (predicate.get("bomFormat") != "CycloneDX" or predicate.get("specVersion") != "1.6" or not isinstance(version, int) or isinstance(version, bool) or version < 1):
        raise _Decision("BLOCKED", "INVALID_SBOM")


def _validate_governance(predicate: dict[str, Any], request: dict[str, Any], image_digest: str) -> None:
    _exact_keys(predicate, {"profile", "fixture", "productionApproval", "runId", "imageDigest", "policySha256", "checks"}, "MALFORMED_GOVERNANCE")
    expected_checks = {"buildPassed": True, "testsPassed": True, "sbomGenerated": True}
    checks = predicate.get("checks")
    if (predicate.get("profile") != PROFILE or predicate.get("fixture") is not True or predicate.get("productionApproval") is not False or predicate.get("runId") != request["runId"] or predicate.get("imageDigest") != image_digest or predicate.get("policySha256") != request["policySha256"] or checks != expected_checks or not isinstance(checks, dict) or any(value is not True for value in checks.values())):
        raise _Decision("BLOCKED", "INVALID_GOVERNANCE")


def verify_bundle(request: dict[str, Any], policy_bytes: bytes, public_key_path: Path, store: Any, cosign_binary: str) -> dict[str, Any]:
    """Verify a completely pinned demo evidence graph and return a stable decision."""
    checks = {"request": False, "policy": False, "publicKey": False, "image": False, "manifest": False, "sbom": False, "governance": False}
    image_digest = ""
    try:
        if not isinstance(request, dict):
            raise _Decision("ERROR", "MALFORMED_REQUEST")
        _exact_keys(request, {"profile", "image", "manifest", "runId", "policySha256", "publicKeySha256"}, "MALFORMED_REQUEST")
        if request.get("profile") != PROFILE:
            raise _Decision("ERROR", "UNSUPPORTED_PROFILE")
        image = request.get("image")
        if not isinstance(image, str) or image.count("@") != 1:
            raise _Decision("ERROR", "MALFORMED_REQUEST")
        repository, image_digest = image.split("@", 1)
        if not repository or _DIGEST.fullmatch(image_digest) is None:
            raise _Decision("ERROR", "MALFORMED_REQUEST")
        if not isinstance(request.get("runId"), str) or not request["runId"]:
            raise _Decision("ERROR", "MALFORMED_REQUEST")
        for pin in ("policySha256", "publicKeySha256"):
            if not isinstance(request.get(pin), str) or _DIGEST.fullmatch(request[pin]) is None:
                raise _Decision("ERROR", "MALFORMED_REQUEST")
        _artifact_ref(request.get("manifest"))
        checks["request"] = True

        if not isinstance(policy_bytes, bytes) or len(policy_bytes) > MAX_OBJECT_BYTES:
            raise _Decision("ERROR", "SIZE_LIMIT_EXCEEDED")
        budget = _Budget(len(policy_bytes))
        if _sha256(policy_bytes) != request["policySha256"]:
            raise _Decision("BLOCKED", "POLICY_MISMATCH")
        _validate_policy(_json_object(policy_bytes, "MALFORMED_POLICY"))
        checks["policy"] = True

        try:
            with Path(public_key_path).open("rb") as key_file:
                key_bytes = key_file.read(MAX_OBJECT_BYTES + 1)
        except (OSError, TypeError, ValueError) as exc:
            raise _Decision("ERROR", "PUBLIC_KEY_UNAVAILABLE") from exc
        budget.include(key_bytes)
        if _sha256(key_bytes) != request["publicKeySha256"]:
            raise _Decision("BLOCKED", "PUBLIC_KEY_MISMATCH")
        checks["publicKey"] = True

        image_bytes = _store_read(store.read_manifest, image_digest, budget, "MISSING_IMAGE")
        if _sha256(image_bytes) != image_digest:
            raise _Decision("BLOCKED", "DIGEST_MISMATCH")
        image_manifest = _json_object(image_bytes, "MALFORMED_OCI_MANIFEST")
        if image_manifest.get("schemaVersion") != 2 or image_manifest.get("mediaType") != OCI_MANIFEST:
            raise _Decision("ERROR", "UNSUPPORTED_OCI_MANIFEST")
        image_config = _descriptor(image_manifest.get("config"))
        layers = image_manifest.get("layers")
        if not isinstance(layers, list):
            raise _Decision("ERROR", "MALFORMED_OCI_MANIFEST")
        _read_descriptor(store.read_blob, image_config, budget, "MISSING_IMAGE")
        for layer in layers:
            _read_descriptor(store.read_blob, _descriptor(layer), budget, "MISSING_IMAGE")
        checks["image"] = True

        root_predicate = _read_signed_artifact(request["manifest"], ROOT_TYPE, image_digest, len(image_bytes), key_bytes, store, cosign_binary, budget, "MISSING_MANIFEST")
        entries = _validate_root_predicate(root_predicate, request, image_digest)
        checks["manifest"] = True

        sbom_entry = entries["sbom"]
        sbom = _read_signed_artifact({"artifact": sbom_entry["artifact"], "payload": sbom_entry["payload"]}, SBOM_TYPE, image_digest, len(image_bytes), key_bytes, store, cosign_binary, budget, "MISSING_SBOM")
        _validate_sbom(sbom)
        checks["sbom"] = True

        governance_entry = entries["governance"]
        governance = _read_signed_artifact({"artifact": governance_entry["artifact"], "payload": governance_entry["payload"]}, GOVERNANCE_TYPE, image_digest, len(image_bytes), key_bytes, store, cosign_binary, budget, "MISSING_GOVERNANCE")
        _validate_governance(governance, request, image_digest)
        checks["governance"] = True
        return _result("PASS", "VERIFIED", checks, image_digest)
    except _Decision as decision:
        return _result(decision.status, decision.reason, checks, image_digest)
    except Exception:
        return _result("ERROR", "INTERNAL_ERROR", checks, image_digest)
