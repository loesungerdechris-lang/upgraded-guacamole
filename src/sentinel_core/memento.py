"""Fail-closed Memento TimeMap discovery adapter for SENTINEL Phase 3.

The adapter is disabled by default, performs discovery only, never fetches
Memento content, and never elevates evidence status. Candidate archive hosts
are retained as declared provenance and remain unverified until acquisition.
"""

from __future__ import annotations

import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Mapping
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from sentinel_core.memento_model import (
    DEFAULT_MEMENTO_USER_AGENT,
    HOLD_STATUS,
    MAX_TIMEMAP_BYTES,
    MEMENTO_SOURCE_ORIGIN,
    SEPARATE_POLICY_REQUIRED,
    ArchiveHTTPResponse,
    MementoAdapterError,
    MementoConfigurationError,
    MementoDiscoveryResult,
    MementoRecord,
    MementoRequestError,
    MementoResponseError,
    ParsedTimeMap,
    Sleeper,
    Transport,
    utc_now,
)
from sentinel_core.memento_parser import (
    parse_timemap_document,
    parse_timemap_link_format,
)
from sentinel_core.memento_validation import (
    header_value,
    public_dns_host,
    timemap_base_url,
)
from sentinel_core.wayback import normalize_target_url

__all__ = [
    "ArchiveHTTPResponse",
    "BaseArchiveAdapter",
    "MementoAdapter",
    "MementoAdapterError",
    "MementoConfigurationError",
    "MementoDiscoveryResult",
    "MementoRecord",
    "MementoRequestError",
    "MementoResponseError",
    "ParsedTimeMap",
    "parse_timemap_document",
    "parse_timemap_link_format",
]


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise MementoResponseError("Memento redirects are disabled")


def _default_transport(
    url: str,
    headers: Mapping[str, str],
    timeout_seconds: float,
    max_bytes: int,
) -> ArchiveHTTPResponse:
    request = Request(url, headers=dict(headers), method="GET")
    opener = build_opener(_NoRedirectHandler())
    try:
        with opener.open(request, timeout=timeout_seconds) as response:  # noqa: S310
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    if int(content_length) > max_bytes:
                        raise MementoResponseError("TimeMap response exceeded size limit")
                except ValueError:
                    raise MementoResponseError("TimeMap returned an invalid length") from None
            body = response.read(max_bytes + 1)
            status_code = int(response.getcode())
            response_headers = dict(response.headers.items())
    except HTTPError as exc:
        if exc.code == 404:
            headers_out = dict(exc.headers.items()) if exc.headers else {}
            return ArchiveHTTPResponse(404, headers_out, b"")
        raise
    if len(body) > max_bytes:
        raise MementoResponseError("TimeMap response exceeded size limit")
    return ArchiveHTTPResponse(status_code, response_headers, body)


@dataclass(frozen=True, kw_only=True)
class BaseArchiveAdapter(ABC):
    """Common bounded adapter controls. Network use is disabled by default."""

    user_agent: str = DEFAULT_MEMENTO_USER_AGENT
    timeout_seconds: float = 20.0
    max_attempts: int = 3
    max_response_bytes: int = MAX_TIMEMAP_BYTES
    enabled: bool = False
    transport: Transport = field(default=_default_transport, repr=False, compare=False)
    sleeper: Sleeper = field(default=time.sleep, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.user_agent, str) or not self.user_agent.strip():
            raise MementoConfigurationError("user_agent must identify the automated client")
        if self.user_agent == DEFAULT_MEMENTO_USER_AGENT:
            raise MementoConfigurationError("user_agent must include a reviewed contact identity")
        if self.enabled and self.transport is _default_transport:
            raise MementoConfigurationError(
                "enabled adapters require a separately reviewed network transport"
            )
        if not 0 < self.timeout_seconds <= 120:
            raise MementoConfigurationError("timeout_seconds must be between 0 and 120")
        if isinstance(self.max_attempts, bool) or not 1 <= self.max_attempts <= 5:
            raise MementoConfigurationError("max_attempts must be between 1 and 5")
        invalid_size = (
            isinstance(self.max_response_bytes, bool)
            or not 1 <= self.max_response_bytes <= MAX_TIMEMAP_BYTES
        )
        if invalid_size:
            raise MementoConfigurationError(
                f"max_response_bytes must be between 1 and {MAX_TIMEMAP_BYTES}"
            )

    @abstractmethod
    def discover(self, original_url: str) -> MementoDiscoveryResult:
        """Discover source records without acquiring or publishing content."""


@dataclass(frozen=True, kw_only=True)
class MementoAdapter(BaseArchiveAdapter):
    """RFC 7089 TimeMap discovery adapter with exact source-policy boundaries."""

    timemap_base_url: str
    allowed_archive_hosts: tuple[str, ...]
    policy_version: str
    source_id: str = "memento-timemap"
    max_mementos: int = 1000

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise MementoConfigurationError("policy_version must be a non-empty string")
        if not isinstance(self.source_id, str) or not self.source_id.strip():
            raise MementoConfigurationError("source_id must be a non-empty string")
        if isinstance(self.max_mementos, bool) or not 1 <= self.max_mementos <= 10_000:
            raise MementoConfigurationError("max_mementos must be between 1 and 10000")
        normalized_base = timemap_base_url(self.timemap_base_url)
        normalized_hosts = tuple(
            sorted({public_dns_host(host) for host in self.allowed_archive_hosts})
        )
        if not normalized_hosts:
            raise MementoConfigurationError("allowed_archive_hosts must not be empty")
        object.__setattr__(self, "timemap_base_url", normalized_base)
        object.__setattr__(self, "allowed_archive_hosts", normalized_hosts)

    def build_timemap_url(self, original_url: str) -> str:
        normalized = normalize_target_url(original_url)
        request_url = self.timemap_base_url + quote(normalized, safe="")
        base = urlparse(self.timemap_base_url)
        parsed = urlparse(request_url)
        escaped = (
            parsed.scheme != "https"
            or parsed.hostname != base.hostname
            or parsed.port is not None
            or parsed.username is not None
            or parsed.password is not None
            or bool(parsed.query)
            or bool(parsed.fragment)
            or not parsed.path.startswith(base.path)
        )
        if escaped:
            raise MementoConfigurationError(
                "constructed TimeMap URL escaped the configured endpoint"
            )
        return request_url

    def _request(self, url: str) -> ArchiveHTTPResponse:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/link-format",
            "Connection": "close",
        }
        for attempt in range(1, self.max_attempts + 1):
            try:
                response = self.transport(
                    url, headers, self.timeout_seconds, self.max_response_bytes
                )
                self._validate_transport_response(response)
                if response.status_code == 404:
                    return response
                if response.status_code == 429 or 500 <= response.status_code <= 599:
                    if attempt == self.max_attempts:
                        raise MementoRequestError(
                            f"TimeMap request failed with HTTP {response.status_code}"
                        )
                    retry_after = header_value(response.headers, "Retry-After")
                    try:
                        delay = (
                            min(float(retry_after), 30.0)
                            if retry_after
                            else 2 ** (attempt - 1)
                        )
                    except ValueError:
                        delay = 2 ** (attempt - 1)
                    self.sleeper(float(delay))
                    continue
                if response.status_code != 200:
                    raise MementoRequestError(
                        f"TimeMap request failed with HTTP {response.status_code}"
                    )
                return response
            except HTTPError as exc:
                retryable = exc.code == 429 or 500 <= exc.code <= 599
                if not retryable or attempt == self.max_attempts:
                    raise MementoRequestError(
                        f"TimeMap request failed with HTTP {exc.code}"
                    ) from None
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                try:
                    delay = (
                        min(float(retry_after), 30.0)
                        if retry_after
                        else 2 ** (attempt - 1)
                    )
                except ValueError:
                    delay = 2 ** (attempt - 1)
                self.sleeper(float(delay))
            except OSError:
                if attempt == self.max_attempts:
                    raise MementoRequestError("TimeMap request failed") from None
                self.sleeper(float(2 ** (attempt - 1)))
        raise MementoRequestError("TimeMap request failed")

    def _validate_transport_response(self, response: ArchiveHTTPResponse) -> None:
        if not isinstance(response, ArchiveHTTPResponse):
            raise MementoResponseError("transport returned an invalid response object")
        invalid_status = (
            isinstance(response.status_code, bool)
            or not isinstance(response.status_code, int)
            or not 100 <= response.status_code <= 599
        )
        if invalid_status:
            raise MementoResponseError("transport returned an invalid HTTP status")
        if not isinstance(response.headers, Mapping):
            raise MementoResponseError("transport returned invalid HTTP headers")
        if not isinstance(response.body, bytes):
            raise MementoResponseError("transport returned a non-bytes body")
        if len(response.body) > self.max_response_bytes:
            raise MementoResponseError("TimeMap response exceeded size limit")

    def _result(
        self,
        *,
        original_url: str,
        timemap_url: str | None,
        result_class: str,
        mementos: tuple[MementoRecord, ...] = (),
        linked_timemaps: tuple[str, ...] = (),
        response: ArchiveHTTPResponse | None = None,
        error_code: str | None = None,
        error_msg: str | None = None,
    ) -> MementoDiscoveryResult:
        body = response.body if response is not None else None
        content_type = (
            header_value(response.headers, "Content-Type")
            if response is not None
            else None
        )
        return MementoDiscoveryResult(
            source_id=self.source_id,
            source_origin=MEMENTO_SOURCE_ORIGIN,
            policy_version=self.policy_version,
            original_url=original_url,
            timemap_url=timemap_url,
            retrieved_at=utc_now(),
            result_class=result_class,
            mementos=mementos,
            linked_timemaps=linked_timemaps,
            timemap_sha256=(
                "sha256:" + hashlib.sha256(body).hexdigest() if body is not None else None
            ),
            timemap_byte_length=len(body) if body is not None else None,
            http_status=response.status_code if response is not None else None,
            content_type=content_type,
            error_code=error_code,
            error_msg=error_msg,
        )

    def discover(self, original_url: str) -> MementoDiscoveryResult:
        normalized = normalize_target_url(original_url)
        if not self.enabled:
            return self._result(
                original_url=normalized,
                timemap_url=None,
                result_class="POLICY_BLOCKED",
                error_code="SOURCE_POLICY_NOT_AUTHORIZED",
                error_msg="Memento acquisition is disabled by source policy",
            )

        timemap_url = self.build_timemap_url(normalized)
        response: ArchiveHTTPResponse | None = None
        try:
            response = self._request(timemap_url)
            if response.status_code == 404:
                return self._result(
                    original_url=normalized,
                    timemap_url=timemap_url,
                    result_class="NOT_FOUND",
                    response=response,
                )
            content_type = (header_value(response.headers, "Content-Type") or "").lower()
            if content_type.split(";", 1)[0].strip() != "application/link-format":
                raise MementoResponseError(
                    "TimeMap response has an unexpected content type"
                )
            document = parse_timemap_document(
                response.body,
                expected_original_url=normalized,
                allowed_archive_hosts=self.allowed_archive_hosts,
                max_mementos=self.max_mementos,
            )
        except (MementoRequestError, MementoResponseError) as exc:
            return self._result(
                original_url=normalized,
                timemap_url=timemap_url,
                result_class="QUERY_FAILED",
                response=response,
                error_code=type(exc).__name__.upper(),
                error_msg=str(exc),
            )

        if document.linked_timemaps:
            result_class = "PARTIAL" if document.mementos else "PAGINATION_REQUIRED"
        else:
            result_class = "SUCCESS" if document.mementos else "NOT_FOUND"
        return self._result(
            original_url=normalized,
            timemap_url=timemap_url,
            result_class=result_class,
            mementos=document.mementos,
            linked_timemaps=document.linked_timemaps,
            response=response,
        )
