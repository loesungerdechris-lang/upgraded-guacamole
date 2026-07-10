from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
)

from sentinel_core.external_signing import DigestSigningRequest, ExternalSignatureResult
from sentinel_core.live_evidence import (
    LiveEvidenceContext,
    PublicKeyMetadata,
    PublicTrustPolicy,
    build_live_evidence_bundle,
)

KEY_ID = (
    "https://sentinel-evidence.vault.azure.net/keys/"
    "sentinel-receipt-es256/0123456789abcdef0123456789abcdef"
)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class DigestSigner:
    def __init__(self, key: ec.EllipticCurvePrivateKey) -> None:
        self.key = key

    def sign_digest(self, request: DigestSigningRequest) -> ExternalSignatureResult:
        digest = base64.urlsafe_b64decode(
            (request.digest_b64url + "=" * (-len(request.digest_b64url) % 4)).encode(
                "ascii"
            )
        )
        der = self.key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        r, s = decode_dss_signature(der)
        return ExternalSignatureResult(
            algorithm="ES256",
            key_id=request.key_id,
            signature_b64url=_b64url(
                r.to_bytes(32, "big") + s.to_bytes(32, "big")
            ),
        )


def test_receipt_artifact_hash_binds_exact_emitted_subject_bytes() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    metadata = PublicKeyMetadata.from_mapping(
        {
            "kid": KEY_ID,
            "kty": "EC",
            "crv": "P-256",
            "key_ops": ["sign", "verify"],
            "x": _b64url(numbers.x.to_bytes(32, "big")),
            "y": _b64url(numbers.y.to_bytes(32, "big")),
        }
    )
    bundle = build_live_evidence_bundle(
        metadata=metadata,
        context=LiveEvidenceContext(
            repository="loesungerdechris-lang/upgraded-guacamole",
            commit_sha="e80babc981941d8f377137e4a03ca4eb331458a2",
            workflow="SENTINEL Azure Live Sign Verify",
            run_id="29000000002",
            run_attempt="1",
            created_at="2026-07-10T10:00:00.000Z",
        ),
        trust_policy=PublicTrustPolicy(
            role="release_signer",
            status="active",
            not_before="2026-07-10T09:00:00.000Z",
            not_after="2027-07-10T09:00:00.000Z",
        ),
        signer=DigestSigner(key),
    )

    subject_bytes = bundle.serialized_files()["subject-manifest.json"]
    expected = "sha256:" + hashlib.sha256(subject_bytes).hexdigest()
    listed = {
        item["path"]: item["sha256"]
        for item in bundle.evidence_manifest["files"]
    }

    assert bundle.signed_receipt["evidence"]["artifact_hash"] == expected
    assert listed["subject-manifest.json"] == expected
