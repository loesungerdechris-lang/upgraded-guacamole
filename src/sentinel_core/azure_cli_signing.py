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
from urllib.parse import urlparse

from sentinel_core.external_signing import DigestSigningRequest, ExternalSignatureResult

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_AZURE_VAULT_HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{1,22}[a-z0-9])?\.vault\.azure\.net$"
)
_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,127}$")
_KEY_VERSION_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
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
    except (ValueError, UnicodeEncodeError):
        raise AzureCliSigningError(
            f"{field_name} must be canonical unpadded base64url"
        ) from None

    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != value:
        raise AzureCliSigningError(f"{field_name} must be canonical unpadded base64url")
    return decoded


def _validate_azure_key_id(key_id: str) -> None:
    message = "key_id must be an exact versioned Azure Key Vault HTTPS identifier"
    if not isinstance(key_id, str) or not key_id:
        raise AzureCliSigningError(message)

    try:
        parsed = urlparse(key_id)
        port = parsed.port
    except ValueError:
        raise AzureCliSigningError(message) from None

    path_parts = [part for part in parsed.path.split("/") if part]
    canonical_path = "/" + "/".join(path_parts)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.hostname is None
        or parsed.netloc != parsed.hostname
        or _AZURE_VAULT_HOST_RE.fullmatch(parsed.hostname) is None
        or parsed.path != canonical_path
        or len(path_parts) != 3
        or path_parts[0] != "keys"
        or _KEY_NAME_RE.fullmatch(path_parts[1]) is None
        or _KEY_VERSION_RE.fullmatch(path_parts[2]) is None
    ):
        raise AzureCliSigningError(message)


def _parse_operation_result(stdout: str, *, expected_key_id: str) -> str:
    if not isinstance(stdout, str) or not stdout.strip():
        raise AzureCliSigningError("Azure CLI returned no signing result")
    try:
        response_size = len(stdout.encode("utf-8"))
    except UnicodeError:
        raise AzureCliSigningError("Azure CLI returned an invalid signing response") from None
    if response_size > _MAX_RESPONSE_BYTES:
        raise AzureCliSigningError("Azure CLI signing response exceeded the size limit")

    try:
        payload: Any = json.loads(stdout)
    except (TypeError, ValueError):
        raise AzureCliSigningError("Azure CLI returned an invalid signing response") from None
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
        _validate_azure_key_id(request.key_id)

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
        except FileNotFoundError:
            raise AzureCliSigningError("Azure CLI executable was not found") from None
        except subprocess.TimeoutExpired:
            raise AzureCliSigningError("Azure CLI signing operation timed out") from None
        except (OSError, UnicodeError):
            raise AzureCliSigningError("Azure CLI signing operation failed") from None

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
