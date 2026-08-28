from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from sentinel_core.external_signing import DigestSigningRequest, ExternalSignatureResult
from sentinel_core.portable_evidence import (
    PortableEvidenceContext,
    PortableEvidenceError,
    PortableSignerBinding,
    build_portable_evidence_bundle,
    write_portable_evidence_bundle,
)
from sentinel_core.receipt import verify_receipt


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))


def _public_jwk(key: ec.EllipticCurvePublicKey) -> dict[str, str | bool]:
    numbers = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
        "ext": True,
    }


@dataclass
class IsolatedDigestSigner:
    key_id: str
    signing_key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    requests: list[DigestSigningRequest] = field(default_factory=list)

    @property
    def public_jwk(self) -> dict[str, str | bool]:
        return _public_jwk(self.signing_key.public_key())

    def sign_digest(self, request: DigestSigningRequest) -> ExternalSignatureResult:
        self.requests.append(request)
        der = self.signing_key.sign(
            _decode_b64url(request.digest_b64url),
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
        r, s = decode_dss_signature(der)
        return ExternalSignatureResult(
            algorithm="ES256",
            key_id=self.key_id,
            signature_b64url=_b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big")),
        )


def _context() -> PortableEvidenceContext:
    return PortableEvidenceContext(
        repository="loesungerdechris-lang/upgraded-guacamole",
        commit_sha="a" * 40,
        workflow="SENTINEL Portable Evidence",
        run_id="12345",
        run_attempt="1",
        created_at="2026-07-05T13:45:00Z",
    )


def _bindings() -> list[PortableSignerBinding]:
    marketing_id = (
        "https://sentinel-marketing.vault.azure.net/keys/"
        "campaign-release/11111111111111111111111111111111"
    )
    legal_id = (
        "https://sentinel-legal.vault.azure.net/keys/"
        "campaign-release/22222222222222222222222222222222"
    )
    marketing = IsolatedDigestSigner(marketing_id)
    legal = IsolatedDigestSigner(legal_id)
    return [
        PortableSignerBinding(
            key_id=marketing_id,
            signer_role="marketing_lead",
            public_jwk=marketing.public_jwk,
            status="active",
            not_before="2026-01-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
            signer=marketing,
        ),
        PortableSignerBinding(
            key_id=legal_id,
            signer_role="legal_officer",
            public_jwk=legal.public_jwk,
            status="active",
            not_before="2026-01-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
            signer=legal,
        ),
    ]


def _build(bindings: list[PortableSignerBinding] | None = None):
    return build_portable_evidence_bundle(
        context=_context(),
        receipt_id="REC-MRESFOEY",
        entity_type="strategic_campaign",
        entity_id="NIS2_Q3_ULTIMATE_LAUNCH",
        release_class="A",
        policy_id="sentinel.strategic-campaign-release",
        policy_version="1.0.0",
        required_roles=["marketing_lead", "legal_officer"],
        min_signatures=2,
        signer_bindings=bindings or _bindings(),
    )


def test_builds_verified_class_a_portable_bundle() -> None:
    bindings = _bindings()
    bundle = _build(bindings)

    assert bundle.verification_report["status"] == "RC_VERIFIED"
    assert bundle.verification_report["verified"] is True
    assert bundle.verification_report["valid_signatures"] == 2
    assert bundle.verification_report["required_signatures"] == 2
    assert bundle.verification_report["matched_roles"] == [
        "legal_officer",
        "marketing_lead",
    ]
    assert len(bundle.signed_receipt["signatures"]) == 2
    assert bundle.signed_receipt["policy"]["required_roles"] == [
        "legal_officer",
        "marketing_lead",
    ]
    assert bundle.subject_manifest["schema_version"] == "sentinel.portable-subject.v1"
    assert bundle.subject_manifest["entity_id"] == "NIS2_Q3_ULTIMATE_LAUNCH"
    assert bundle.evidence_manifest["schema_version"] == (
        "sentinel.portable-evidence-manifest.v1"
    )
    assert bundle.evidence_manifest["key_ids"] == sorted(
        binding.key_id for binding in bindings
    )
    assert [item["path"] for item in bundle.evidence_manifest["files"]] == [
        "public-trust-registry.json",
        "signed-receipt.json",
        "subject-manifest.json",
        "verification-report.json",
    ]
    assert all(len(binding.signer.requests) == 1 for binding in bindings)

    trust = {
        entry["kid"]: entry
        for entry in bundle.public_trust_registry["entries"]
    }
    result = verify_receipt(bundle.signed_receipt, trust_registry=trust)
    assert result.status == "RC_VERIFIED"
    assert result.verified is True


def test_serialized_bundle_is_exact_and_canonical() -> None:
    files = _build().serialized_files()
    assert list(files) == [
        "evidence-manifest.json",
        "public-trust-registry.json",
        "signed-receipt.json",
        "subject-manifest.json",
        "verification-report.json",
    ]
    assert all(content.endswith(b"\n") for content in files.values())
    assert all(not content.startswith(b"\xef\xbb\xbf") for content in files.values())


def test_write_is_atomic_and_refuses_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "portable-evidence"
    written = write_portable_evidence_bundle(_build(), output)
    assert written == output
    assert sorted(path.name for path in output.iterdir()) == [
        "evidence-manifest.json",
        "public-trust-registry.json",
        "signed-receipt.json",
        "subject-manifest.json",
        "verification-report.json",
    ]
    with pytest.raises(PortableEvidenceError, match="already exists"):
        write_portable_evidence_bundle(_build(), output)


def test_class_a_rejects_insufficient_signers_before_signing() -> None:
    bindings = _bindings()[:1]
    with pytest.raises(PortableEvidenceError, match="exceeds available signers"):
        _build(bindings)
    assert len(bindings[0].signer.requests) == 0


def test_rejects_private_jwk_field_before_signing() -> None:
    bindings = _bindings()
    first = bindings[0]
    binding = PortableSignerBinding(
        key_id=first.key_id,
        signer_role=first.signer_role,
        public_jwk={**first.public_jwk, "d": "private-member-for-rejection"},
        status=first.status,
        not_before=first.not_before,
        not_after=first.not_after,
        signer=first.signer,
    )
    with pytest.raises(PortableEvidenceError, match="exactly kty, crv, x, y and ext"):
        _build([binding, bindings[1]])
    assert len(first.signer.requests) == 0


def test_rejects_expired_trust_before_signing() -> None:
    bindings = _bindings()
    first = bindings[0]
    expired = PortableSignerBinding(
        key_id=first.key_id,
        signer_role=first.signer_role,
        public_jwk=first.public_jwk,
        status="active",
        not_before="2025-01-01T00:00:00Z",
        not_after="2025-12-31T23:59:59Z",
        signer=first.signer,
    )
    with pytest.raises(PortableEvidenceError, match="outside the signer trust window"):
        _build([expired, bindings[1]])
    assert len(first.signer.requests) == 0
