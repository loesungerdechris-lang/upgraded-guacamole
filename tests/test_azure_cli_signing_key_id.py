from __future__ import annotations

import base64
import subprocess
from typing import Any

import pytest

from sentinel_core.azure_cli_signing import (
    AzureCliKeyVaultDigestSigner,
    AzureCliSigningError,
)
from sentinel_core.external_signing import DigestSigningRequest

VALID_DIGEST = base64.urlsafe_b64encode(b"\x01" * 32).decode("ascii").rstrip("=")


class RejectingRunner:
    def __init__(self) -> None:
        self.called = False

    def __call__(self, *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.called = True
        raise AssertionError("invalid key IDs must be rejected before process execution")


@pytest.mark.parametrize(
    "key_id",
    [
        "",
        "http://sentinel-test.vault.azure.net/keys/key/version",
        "https://evil.example/keys/key/version",
        "https://sentinel-test.vault.azure.net/keys/key",
        "https://sentinel-test.vault.azure.net/keys/key/version/extra",
        "https://sentinel-test.vault.azure.net/secrets/key/version",
        "https://sentinel-test.vault.azure.net/keys/key/version?api-version=1",
        "https://sentinel-test.vault.azure.net/keys/key/version#fragment",
        "https://user@sentinel-test.vault.azure.net/keys/key/version",
        "https://sentinel-test.vault.azure.net:443/keys/key/version",
        "https://-invalid.vault.azure.net/keys/key/version",
        "https://invalid-.vault.azure.net/keys/key/version",
        "https://ab.vault.azure.net/keys/key/version",
        "https://this-vault-name-is-far-too-long.vault.azure.net/keys/key/version",
        "https://sentinel-test.vault.azure.net/keys/key_name/version",
        "https://sentinel-test.vault.azure.net/keys/key/version.with.dot",
    ],
)
def test_rejects_noncanonical_or_non_azure_key_ids_before_cli(key_id: str) -> None:
    runner = RejectingRunner()
    signer = AzureCliKeyVaultDigestSigner(runner=runner)
    request = DigestSigningRequest(
        algorithm="ES256",
        key_id=key_id,
        digest_b64url=VALID_DIGEST,
    )

    with pytest.raises(AzureCliSigningError, match="exact versioned Azure Key Vault"):
        signer.sign_digest(request)

    assert runner.called is False


@pytest.mark.parametrize(
    "key_id",
    [
        "https://abc.vault.azure.net/keys/k/v",
        "https://sentinel-test.vault.azure.net/keys/sentinel-receipt-es256/0123456789abcdef0123456789abcdef",
        "https://a1-b2-c3.vault.azure.net/keys/Key-Name/version-01",
    ],
)
def test_accepts_safe_versioned_public_azure_key_ids(key_id: str) -> None:
    signature = base64.urlsafe_b64encode(b"\x01" * 64).decode("ascii").rstrip("=")

    def runner(arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=arguments,
            returncode=0,
            stdout=f'{{"kid":"{key_id}","value":"{signature}"}}',
            stderr="",
        )

    signer = AzureCliKeyVaultDigestSigner(runner=runner)
    result = signer.sign_digest(
        DigestSigningRequest(
            algorithm="ES256",
            key_id=key_id,
            digest_b64url=VALID_DIGEST,
        )
    )

    assert result.key_id == key_id


def test_timeout_error_suppresses_sensitive_exception_cause() -> None:
    def runner(arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=arguments, timeout=kwargs["timeout"])

    signer = AzureCliKeyVaultDigestSigner(runner=runner)
    request = DigestSigningRequest(
        algorithm="ES256",
        key_id=(
            "https://sentinel-test.vault.azure.net/keys/"
            "sentinel-receipt-es256/0123456789abcdef0123456789abcdef"
        ),
        digest_b64url=VALID_DIGEST,
    )

    with pytest.raises(AzureCliSigningError) as exc_info:
        signer.sign_digest(request)

    assert exc_info.value.__cause__ is None
    assert request.key_id not in str(exc_info.value)
    assert request.digest_b64url not in str(exc_info.value)
