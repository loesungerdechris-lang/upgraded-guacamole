from __future__ import annotations

import base64
import json
import subprocess
from dataclasses import asdict
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
)

from sentinel_core.azure_cli_signing import (
    AzureCliKeyVaultDigestSigner,
    AzureCliSigningError,
)
from sentinel_core.external_signing import (
    DigestSigningRequest,
    sign_receipt_with_external_digest_signer,
)
from sentinel_core.receipt import verify_receipt

KEY_ID = (
    "https://sentinel-test.vault.azure.net/keys/"
    "sentinel-receipt-es256/0123456789abcdef0123456789abcdef"
)
ZERO_HASH = "sha256:" + "0" * 64


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))


def _request(digest: bytes = b"\xfb" * 32) -> DigestSigningRequest:
    return DigestSigningRequest(
        algorithm="ES256",
        key_id=KEY_ID,
        digest_b64url=_b64url_encode(digest),
    )


def _signature_value() -> str:
    return _b64url_encode(b"\x01" * 64)


def _completed(
    *,
    payload: Any = None,
    returncode: int = 0,
    stdout: str | None = None,
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    if stdout is None:
        stdout = json.dumps(payload if payload is not None else {"kid": KEY_ID, "value": _signature_value()})
    return subprocess.CompletedProcess(
        args=["az"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


class CapturingRunner:
    def __init__(self, completed: subprocess.CompletedProcess[str]) -> None:
        self.completed = completed
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append((arguments, kwargs))
        return self.completed


def _public_jwk(public_key: ec.EllipticCurvePublicKey) -> dict[str, str | bool]:
    numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_encode(numbers.x.to_bytes(32, "big")),
        "y": _b64url_encode(numbers.y.to_bytes(32, "big")),
        "ext": True,
    }


def _unsigned_receipt() -> dict[str, Any]:
    return {
        "schema_version": "sentinel.receipt.v1",
        "receipt_id": "REC-AZURE-CLI-ADAPTER-0001",
        "receipt_type": "release_receipt",
        "subject": {
            "entity_type": "release_artifact",
            "entity_id": "SENTINEL-AZURE-CLI-ADAPTER",
        },
        "created_at": "2026-07-10T09:00:00.000Z",
        "release_class": "B",
        "policy": {
            "policy_id": "sentinel.azure-cli-signing",
            "policy_version": "1.0.0",
            "required_roles": ["release_signer"],
            "min_signatures": 1,
        },
        "evidence": {
            "artifact_hash": "sha256:" + "2" * 64,
            "source_commit": "fd8c99a0bce2c6dee235285e751fe3d909dee17b",
            "pipeline_run_id": "run-azure-cli-adapter-001",
            "artifact_path": "dist/release.json",
        },
        "chain": {
            "sequence": 1,
            "previous_hash": ZERO_HASH,
            "receipt_hash": "",
        },
        "signatures": [],
    }


def test_invokes_azure_cli_without_shell_or_custom_environment() -> None:
    runner = CapturingRunner(_completed())
    signer = AzureCliKeyVaultDigestSigner(runner=runner, timeout_seconds=17)
    request = _request()

    result = signer.sign_digest(request)

    assert asdict(result) == {
        "algorithm": "ES256",
        "key_id": KEY_ID,
        "signature_b64url": _signature_value(),
    }
    assert len(runner.calls) == 1
    arguments, kwargs = runner.calls[0]
    assert arguments == [
        "az",
        "keyvault",
        "key",
        "sign",
        "--id",
        KEY_ID,
        "--algorithm",
        "ES256",
        "--digest",
        base64.b64encode(b"\xfb" * 32).decode("ascii"),
        "--only-show-errors",
        "--output",
        "json",
    ]
    assert kwargs == {
        "shell": False,
        "check": False,
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "strict",
        "timeout": 17.0,
        "stdin": subprocess.DEVNULL,
        "env": None,
    }


def test_accepts_cli_result_alias_for_compatibility() -> None:
    runner = CapturingRunner(_completed(payload={"kid": KEY_ID, "result": _signature_value()}))
    signer = AzureCliKeyVaultDigestSigner(runner=runner)

    result = signer.sign_digest(_request())

    assert result.signature_b64url == _signature_value()


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ([], "invalid signing response"),
        ({}, "exactly one signature value"),
        ({"kid": KEY_ID, "value": _signature_value(), "result": _signature_value()}, "exactly one"),
        ({"kid": KEY_ID + "-wrong", "value": _signature_value()}, "unexpected versioned key"),
        ({"kid": 123, "value": _signature_value()}, "unexpected versioned key"),
        ({"kid": KEY_ID, "value": 123}, "invalid signature value"),
        ({"kid": KEY_ID, "value": "not+base64url"}, "canonical unpadded base64url"),
        ({"kid": KEY_ID, "value": _b64url_encode(b"\x01" * 63)}, "exactly 64 raw bytes"),
    ],
)
def test_rejects_malformed_cli_responses(payload: Any, message: str) -> None:
    signer = AzureCliKeyVaultDigestSigner(runner=CapturingRunner(_completed(payload=payload)))

    with pytest.raises(AzureCliSigningError, match=message):
        signer.sign_digest(_request())


@pytest.mark.parametrize("stdout", ["", "not-json", "null"])
def test_rejects_missing_or_invalid_cli_output(stdout: str) -> None:
    signer = AzureCliKeyVaultDigestSigner(runner=CapturingRunner(_completed(stdout=stdout)))

    with pytest.raises(AzureCliSigningError):
        signer.sign_digest(_request())


def test_rejects_wrong_algorithm_before_process_call() -> None:
    runner = CapturingRunner(_completed())
    signer = AzureCliKeyVaultDigestSigner(runner=runner)
    request = DigestSigningRequest(
        algorithm="RS256",  # type: ignore[arg-type]
        key_id=KEY_ID,
        digest_b64url=_b64url_encode(b"\x01" * 32),
    )

    with pytest.raises(AzureCliSigningError, match="only ES256"):
        signer.sign_digest(request)

    assert runner.calls == []


@pytest.mark.parametrize("digest", [b"", b"\x01" * 31, b"\x01" * 33])
def test_rejects_non_sha256_digest_lengths(digest: bytes) -> None:
    runner = CapturingRunner(_completed())
    signer = AzureCliKeyVaultDigestSigner(runner=runner)

    with pytest.raises(AzureCliSigningError):
        signer.sign_digest(_request(digest))

    assert runner.calls == []


def test_sanitizes_nonzero_exit_without_leaking_process_output() -> None:
    secret_digest = "DIGEST-MUST-NOT-LEAK"
    secret_token = "Bearer TOKEN-MUST-NOT-LEAK"
    completed = _completed(returncode=7, stdout=secret_digest, stderr=secret_token)
    signer = AzureCliKeyVaultDigestSigner(runner=CapturingRunner(completed))

    with pytest.raises(AzureCliSigningError) as exc_info:
        signer.sign_digest(_request())

    message = str(exc_info.value)
    assert message == "Azure CLI signing operation failed"
    assert secret_digest not in message
    assert secret_token not in message
    assert KEY_ID not in message


def test_handles_missing_executable_without_command_disclosure() -> None:
    def missing_runner(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("sensitive executable path")

    signer = AzureCliKeyVaultDigestSigner(runner=missing_runner)

    with pytest.raises(AzureCliSigningError, match="executable was not found") as exc_info:
        signer.sign_digest(_request())

    assert KEY_ID not in str(exc_info.value)


def test_handles_timeout_without_digest_disclosure() -> None:
    def timeout_runner(arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=arguments, timeout=kwargs["timeout"])

    signer = AzureCliKeyVaultDigestSigner(runner=timeout_runner)

    with pytest.raises(AzureCliSigningError, match="timed out") as exc_info:
        signer.sign_digest(_request())

    assert _request().digest_b64url not in str(exc_info.value)


def test_adapter_integrates_with_receipt_signer_and_independent_verifier() -> None:
    signing_key = ec.generate_private_key(ec.SECP256R1())

    def cryptographic_runner(
        arguments: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        digest_index = arguments.index("--digest") + 1
        digest = base64.b64decode(arguments[digest_index], validate=True)
        der_signature = signing_key.sign(
            digest,
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
        r, s = decode_dss_signature(der_signature)
        raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return _completed(
            payload={"kid": KEY_ID, "value": _b64url_encode(raw_signature)}
        )

    signer = AzureCliKeyVaultDigestSigner(runner=cryptographic_runner)
    signed_receipt = sign_receipt_with_external_digest_signer(
        _unsigned_receipt(),
        key_id=KEY_ID,
        signer_role="release_signer",
        signer=signer,
    )
    trust_registry = {
        KEY_ID: {
            "kid": KEY_ID,
            "role": "release_signer",
            "alg": "ES256",
            "status": "active",
            "not_before": "2026-01-01T00:00:00.000Z",
            "not_after": "2027-01-01T00:00:00.000Z",
            "jwk": _public_jwk(signing_key.public_key()),
        }
    }

    verification = verify_receipt(signed_receipt, trust_registry=trust_registry)

    assert verification.status == "RC_VERIFIED"
    assert verification.verified is True
    assert verification.valid_signatures == 1
