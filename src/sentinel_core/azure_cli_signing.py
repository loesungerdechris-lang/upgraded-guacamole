"""Azure CLI adapter for the SENTINEL external digest-signing contract.

The adapter relies on an already authenticated Azure CLI context, such as the
OIDC session established by ``azure/login``. It does not acquire credentials,
store private material, attach receipt signatures, or verify receipts.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable

from sentinel_core.external_signing import DigestSigningRequest, ExternalSignatureResult

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_RESPONSE_BYTES = 131_072

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


class AzureCliSigningError(RuntimeError):
    """Raised when the Azure CLI signing boundary fails closed."""


def _b64url_decode_strict(value: str, *, field_name: str) -> bytes:
    if not isinstance(value, str) or not value or not _BASE64URL_RE.fullmatch(value):
        raise AzureCliSigningError(f"{field_name} must be canonical unpadded base64url")

    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(
            (value + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError) as exc:
        raise AzureCliSigningError(f"{field_name} must be canonical unpadded base64url") from exc

    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != value:
        raise AzureCliSigningError(f"{field_name} must be canonical unpadded base64url")
    return decoded


def _parse_operation_result(stdout: str, *, expected_key_id: str) -> str:
    if not isinstance(stdout, str) or not stdout.strip():
        raise AzureCliSigningError("Azure CLI returned no signing result")
    if len(stdout.encode("utf-8")) > _MAX_RESPONSE_BYTES:
        raise AzureCliSigningError("Azure CLI signing response exceeded the size limit")

    try:
        payload: Any = json.loads(stdout)
    except (TypeError, ValueError) as exc:
        raise AzureCliSigningError("Azure CLI returned an invalid signing response") from exc
    if not isinstance(payload, dict):
        raise AzureCliSigningError("Azure CLI returned an invalid signing response")

    returned_key_id = payload.get("kid")
    if not isinstance(returned_key_id, str) or returned_key_id != expected_key_id:
        raise AzureCliSigningError("Azure CLI returned an unexpected versioned key identifier")

    value_present = "value" in payload
    result_present = "result" in payload
    if value_present == result_present:
        raise AzureCliSigningError("Azure CLI signing response must contain exactly one signature value")

    signature_value = payload.get("value") if value_present else payload.get("result")
    if not isinstance(signature_value, str):
        raise AzureCliSigningError("Azure CLI signing response contains an invalid signature value")

    raw_signature = _b64url_decode_strict(
        signature_value,
        field_name="Azure CLI signature",
    )
    if len(raw_signature) != 64:
        raise AzureCliSigningError("Azure CLI ES256 signature must be exactly 64 raw bytes")
    return signature_value


@dataclass(frozen=True)
class AzureCliKeyVaultDigestSigner:
    """Sign SENTINEL digest requests through an authenticated Azure CLI session."""

    executable: str = "az"
    timeout_seconds: float = 30.0
    runner: CommandRunner = field(default=subprocess.run, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.executable, str) or not self.executable.strip():
            raise ValueError("executable must be a non-empty command path")
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(
            self.timeout_seconds,
            bool,
        ):
            raise ValueError("timeout_seconds must be numeric")
        if not 0 < float(self.timeout_seconds) <= 120:
            raise ValueError("timeout_seconds must be greater than zero and at most 120")
        if not callable(self.runner):
            raise ValueError("runner must be callable")

    def sign_digest(self, request: DigestSigningRequest) -> ExternalSignatureResult:
        """Sign one validated SHA-256 digest with the exact versioned Key Vault key."""

        if not isinstance(request, DigestSigningRequest):
            raise AzureCliSigningError("signing request is invalid")
        if request.algorithm != "ES256":
            raise AzureCliSigningError("Azure CLI signer accepts only ES256")

        digest = _b64url_decode_strict(
            request.digest_b64url,
            field_name="signing digest",
        )
        if len(digest) != 32:
            raise AzureCliSigningError("signing digest must contain exactly 32 bytes")
        digest_base64 = base64.b64encode(digest).decode("ascii")

        arguments = [
            self.executable,
            "keyvault",
            "key",
            "sign",
            "--id",
            request.key_id,
            "--algorithm",
            "ES256",
            "--digest",
            digest_base64,
            "--only-show-errors",
            "--output",
            "json",
        ]

        try:
            completed = self.runner(
                arguments,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=float(self.timeout_seconds),
                stdin=subprocess.DEVNULL,
                env=None,
            )
        except FileNotFoundError as exc:
            raise AzureCliSigningError("Azure CLI executable was not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise AzureCliSigningError("Azure CLI signing operation timed out") from exc
        except (OSError, UnicodeError) as exc:
            raise AzureCliSigningError("Azure CLI signing operation failed") from exc

        if not isinstance(completed, subprocess.CompletedProcess):
            raise AzureCliSigningError("Azure CLI runner returned an invalid process result")
        if completed.returncode != 0:
            raise AzureCliSigningError("Azure CLI signing operation failed")

        signature_value = _parse_operation_result(
            completed.stdout,
            expected_key_id=request.key_id,
        )
        return ExternalSignatureResult(
            algorithm="ES256",
            key_id=request.key_id,
            signature_b64url=signature_value,
        )
