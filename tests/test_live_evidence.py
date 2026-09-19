from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
)

from sentinel_core.external_signing import (
    DigestSigningRequest,
    ExternalSignatureResult,
)
from sentinel_core.hashchain import canonicalize_json
from sentinel_core.live_evidence import (
    LiveEvidenceContext,
    LiveEvidenceError,
    PublicKeyMetadata,
    PublicTrustPolicy,
    build_live_evidence_bundle,
    write_live_evidence_bundle,
)

KEY_ID = (
    "https://sentinel-evidence.vault.azure.net/keys/"
    "sentinel-receipt-es256/0123456789abcdef0123456789abcdef"
)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _public_metadata(
    public_key: ec.EllipticCurvePublicKey,
    *,
    key_ops: list[str] | None = None,
    x: str | None = None,
    y: str | None = None,
) -> PublicKeyMetadata:
    numbers = public_key.public_numbers()
    return PublicKeyMetadata.from_mapping(
        {
            "kid": KEY_ID,
            "kty": "EC",
            "crv": "P-256",
            "key_ops": key_ops or ["sign", "verify"],
            "x": x or _b64url_encode(numbers.x.to_bytes(32, "big")),
            "y": y or _b64url_encode(numbers.y.to_bytes(32, "big")),
        }
    )


def _context() -> LiveEvidenceContext:
    return LiveEvidenceContext(
        repository="loesungerdechris-lang/upgraded-guacamole",
        commit_sha="e80babc981941d8f377137e4a03ca4eb331458a2",
        workflow="SENTINEL Azure Live Sign Verify",
        run_id="29000000001",
        run_attempt="1",
        created_at="2026-07-10T09:15:00.000Z",
    )


def _policy(
    *,
    status: str = "active",
    not_before: str = "2026-07-10T09:00:00.000Z",
    not_after: str = "2027-07-10T09:00:00.000Z",
) -> PublicTrustPolicy:
    return PublicTrustPolicy(
        role="release_signer",
        status=status,  # type: ignore[arg-type]
        not_before=not_before,
        not_after=not_after,
    )


class CachingDigestSigner:
    """Test-only signer returning one stable raw ES256 result per digest."""

    def __init__(self, key: ec.EllipticCurvePrivateKey, key_id: str = KEY_ID) -> None:
        self.key = key
        self.key_id = key_id
        self.calls: list[DigestSigningRequest] = []
        self.cache: dict[str, str] = {}

    def sign_digest(self, request: DigestSigningRequest) -> ExternalSignatureResult:
        self.calls.append(request)
        signature = self.cache.get(request.digest_b64url)
        if signature is None:
            digest = base64.urlsafe_b64decode(
                (request.digest_b64url + "=" * (-len(request.digest_b64url) % 4)).encode(
                    "ascii"
                )
            )
            der = self.key.sign(
                digest,
                ec.ECDSA(Prehashed(hashes.SHA256())),
            )
            r, s = decode_dss_signature(der)
            signature = _b64url_encode(
                r.to_bytes(32, "big") + s.to_bytes(32, "big")
            )
            self.cache[request.digest_b64url] = signature
        return ExternalSignatureResult(
            algorithm="ES256",
            key_id=self.key_id,
            signature_b64url=signature,
        )


class FailingIfCalledSigner:
    def __init__(self) -> None:
        self.called = False

    def sign_digest(self, request: DigestSigningRequest) -> ExternalSignatureResult:
        self.called = True
        raise AssertionError("invalid public trust must fail before signing")


def _sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def test_builds_deterministic_verified_public_evidence_bundle() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    metadata = _public_metadata(key.public_key())
    signer = CachingDigestSigner(key)

    first = build_live_evidence_bundle(
        metadata=metadata,
        context=_context(),
        trust_policy=_policy(),
        signer=signer,
    )
    second = build_live_evidence_bundle(
        metadata=metadata,
        context=_context(),
        trust_policy=_policy(),
        signer=signer,
    )

    assert first == second
    assert first.verification_report["status"] == "RC_VERIFIED"
    assert first.verification_report["verified"] is True
    assert first.verification_report["issues"] == []
    assert first.signed_receipt["evidence"]["artifact_path"] == "subject-manifest.json"
    assert first.signed_receipt["signatures"][0]["kid"] == KEY_ID
    assert first.public_trust_entry["entry"]["jwk"] == metadata.public_jwk()
    assert "d" not in first.public_trust_entry["entry"]["jwk"]
    assert len(signer.calls) == 2
    assert set(signer.calls[0].__dict__) == {"algorithm", "key_id", "digest_b64url"}


def test_evidence_manifest_hashes_exact_canonical_file_bytes() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    bundle = build_live_evidence_bundle(
        metadata=_public_metadata(key.public_key()),
        context=_context(),
        trust_policy=_policy(),
        signer=CachingDigestSigner(key),
    )
    files = bundle.serialized_files()

    listed = {
        item["path"]: item["sha256"]
        for item in bundle.evidence_manifest["files"]
    }
    assert set(listed) == {
        "public-trust-entry.json",
        "signed-receipt.json",
        "subject-manifest.json",
        "verification-report.json",
    }
    for name, expected_hash in listed.items():
        assert expected_hash == _sha256_prefixed(files[name])

    subject_text = canonicalize_json(bundle.subject_manifest) + "\n"
    assert files["subject-manifest.json"] == subject_text.encode("utf-8")


def test_wrong_signing_key_fails_independent_verification() -> None:
    trusted_key = ec.generate_private_key(ec.SECP256R1())
    wrong_key = ec.generate_private_key(ec.SECP256R1())

    with pytest.raises(LiveEvidenceError, match="independent receipt verification failed"):
        build_live_evidence_bundle(
            metadata=_public_metadata(trusted_key.public_key()),
            context=_context(),
            trust_policy=_policy(),
            signer=CachingDigestSigner(wrong_key),
        )


@pytest.mark.parametrize(
    "policy",
    [
        _policy(status="revoked"),
        _policy(not_after="2026-07-10T09:14:59.999Z"),
        _policy(not_before="2026-07-10T09:15:00.001Z"),
        _policy(
            not_before="2027-01-01T00:00:00.000Z",
            not_after="2026-01-01T00:00:00.000Z",
        ),
    ],
)
def test_revoked_expired_or_invalid_trust_fails_before_signing(
    policy: PublicTrustPolicy,
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    signer = FailingIfCalledSigner()

    with pytest.raises(LiveEvidenceError):
        build_live_evidence_bundle(
            metadata=_public_metadata(key.public_key()),
            context=_context(),
            trust_policy=policy,
            signer=signer,
        )

    assert signer.called is False


@pytest.mark.parametrize(
    "mapping",
    [
        {
            "kid": KEY_ID,
            "kty": "RSA",
            "crv": "P-256",
            "key_ops": ["sign", "verify"],
            "x": _b64url_encode(b"\x01" * 32),
            "y": _b64url_encode(b"\x02" * 32),
        },
        {
            "kid": KEY_ID,
            "kty": "EC",
            "crv": "P-256",
            "key_ops": ["sign", "verify", "export"],
            "x": _b64url_encode(b"\x01" * 32),
            "y": _b64url_encode(b"\x02" * 32),
        },
        {
            "kid": KEY_ID,
            "kty": "EC",
            "crv": "P-256",
            "key_ops": ["sign", "verify"],
            "x": _b64url_encode(b"\x01" * 31),
            "y": _b64url_encode(b"\x02" * 32),
        },
        {
            "kid": "https://evil.example/keys/key/version",
            "kty": "EC",
            "crv": "P-256",
            "key_ops": ["sign", "verify"],
            "x": _b64url_encode(b"\x01" * 32),
            "y": _b64url_encode(b"\x02" * 32),
        },
    ],
)
def test_rejects_malformed_or_overbroad_public_key_metadata(
    mapping: dict[str, Any],
) -> None:
    with pytest.raises(LiveEvidenceError):
        PublicKeyMetadata.from_mapping(mapping)


def test_writes_exact_public_file_set_atomically(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    bundle = build_live_evidence_bundle(
        metadata=_public_metadata(key.public_key()),
        context=_context(),
        trust_policy=_policy(),
        signer=CachingDigestSigner(key),
    )
    output = tmp_path / "sentinel-live-evidence"

    written = write_live_evidence_bundle(bundle, output)

    assert written == output
    assert sorted(path.name for path in output.iterdir()) == [
        "evidence-manifest.json",
        "public-trust-entry.json",
        "signed-receipt.json",
        "subject-manifest.json",
        "verification-report.json",
    ]
    for path in output.iterdir():
        parsed = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(parsed, dict)

    assert list(tmp_path.glob(".sentinel-live-evidence.*")) == []


def test_refuses_existing_output_directory_without_mutation(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    bundle = build_live_evidence_bundle(
        metadata=_public_metadata(key.public_key()),
        context=_context(),
        trust_policy=_policy(),
        signer=CachingDigestSigner(key),
    )
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "keep.txt"
    sentinel.write_text("unchanged", encoding="utf-8")

    with pytest.raises(LiveEvidenceError, match="already exists"):
        write_live_evidence_bundle(bundle, output)

    assert sentinel.read_text(encoding="utf-8") == "unchanged"
