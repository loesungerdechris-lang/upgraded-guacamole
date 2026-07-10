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

DIGEST = base64.urlsafe_b64encode(b"\x01" * 32).decode("ascii").rstrip("=")


@pytest.mark.parametrize(
    "key_id",
    [
        "https://[invalid/keys/key/version",
        "https://sentinel-test.vault.azure.net/keys/key/version/",
        "https://sentinel-test.vault.azure.net//keys/key/version",
        "https://SENTINEL-TEST.vault.azure.net/keys/key/version",
    ],
)
def test_malformed_or_noncanonical_key_url_fails_without_process_call(key_id: str) -> None:
    called = False

    def runner(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        raise AssertionError("invalid key URL reached the process boundary")

    signer = AzureCliKeyVaultDigestSigner(runner=runner)
    request = DigestSigningRequest(
        algorithm="ES256",
        key_id=key_id,
        digest_b64url=DIGEST,
    )

    with pytest.raises(AzureCliSigningError, match="exact versioned Azure Key Vault"):
        signer.sign_digest(request)

    assert called is False
