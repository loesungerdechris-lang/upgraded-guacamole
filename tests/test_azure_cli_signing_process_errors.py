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

KEY_ID = (
    "https://sentinel-test.vault.azure.net/keys/"
    "sentinel-receipt-es256/0123456789abcdef0123456789abcdef"
)
DIGEST = base64.urlsafe_b64encode(b"\x01" * 32).decode("ascii").rstrip("=")


def test_called_process_error_cannot_disclose_command_vector() -> None:
    def runner(arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(
            returncode=7,
            cmd=arguments,
            output="SIGNATURE-MUST-NOT-LEAK",
            stderr="Bearer TOKEN-MUST-NOT-LEAK",
        )

    signer = AzureCliKeyVaultDigestSigner(runner=runner)
    request = DigestSigningRequest(
        algorithm="ES256",
        key_id=KEY_ID,
        digest_b64url=DIGEST,
    )

    with pytest.raises(AzureCliSigningError) as exc_info:
        signer.sign_digest(request)

    assert str(exc_info.value) == "Azure CLI signing operation failed"
    assert exc_info.value.__cause__ is None
    assert KEY_ID not in str(exc_info.value)
    assert DIGEST not in str(exc_info.value)
