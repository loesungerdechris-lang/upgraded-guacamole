"""Fail-closed Memento TimeMap discovery adapter for SENTINEL Phase 3.

The adapter is disabled by default, performs discovery only, never fetches
Memento content, and never elevates evidence status. Every discovered Memento
retains its actual archive host as source provenance.
"""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from sentinel_core.wayback import WaybackConfigurationError, normalize_target_url

DEFAULT_MEMENTO_USER_AGENT = "SENTINEL-Memento-Discovery/0.1 (contact-required)"
MEMENTO_SOURCE_ORIGIN = "memento-protocol-discovery"
SEPARATE_POLICY_REQUIRED = "separate_policy_required"
HOLD_STATUS = "HOLD"

_MAX_TIMEMAP_BYTES = 8 * 1024 * 1024
_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")

Sleeper = Callable[[float], None]


class MementoAdapterError(RuntimeError):
    """Base exception for the Phase 3 Memento boundary."""


class MementoConfigurationError(MementoAdapterError):
    """Raised when adapter configuration escapes its reviewed boundary."""


class MementoRequestError(MementoAdapterError):
    """Raised when a TimeMap request fails safely."""


class MementoResponseError(MementoAdapterError):
    """Raised when a TimeMap response is malformed or unsafe."""


@dataclass(frozen=True)
class ArchiveHTTPResponse:
    """Bounded transport response used by injected and default transports."""

    status_code: int
    headers: Mapping[str, str]
    body: bytes


Transport = Callable[[str, Mapping[str, str], float, int], ArchiveHTTPResponse]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


def _public_host(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MementoConfigurationError("archive host must be a non-empty string")
    candidate = value.strip()
    if any(char in candidate for char in "/?#@"):
        raise MementoConfigurationError("archive host must be a hostname only")
    try:
        normalized = normalize_target_url(f"https://{candidate}/")
    except WaybackConfigurationError as exc:
        raise MementoConfigurationError(str(exc)) from None
    parsed = urlparse(normalized)
    if parsed.port is not None or parsed.hostname is None:
        raise MementoConfigurationError("archive host must not contain a port")
    return parsed.hostname


def _timemap_base_url(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MementoConfigurationError("timemap_base_url must be a non-empty string")
    try:
        parsed = urlparse(value.strip())
        port = parsed.port
    except ValueError:
        raise MementoConfigurationError("timemap_base_url is invalid") from None
    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise MementoConfigurationError(
            "timemap_base_url must be an exact credential-free HTTPS base URL"
        )
    try:
        normalized = normalize_target_url(value.strip())
    except WaybackConfigurationError as exc:
        raise MementoConfigurationError(str(exc)) from None
    stable = urlparse(normalized)
    path = stable.path if stable.path.endswith("/") else stable.path + "/"
    return urlunparse(("https", stable.netloc, path, "", "", ""))


def _normalize_discovered_url(value: str, field_name: str) -> str:
    try:
        normalized = normalize_target_url(value)
    except WaybackConfigurationError as exc:
        raise MementoResponseError(f"{field_name} is not a public HTTP(S) URL") from exc
    parsed = urlparse(normalized)
    if parsed.port is not None:
        raise MementoResponseError(f"{field_name} must not contain a port")
    return normalized


def _parse_rfc1123_datetime(value: str) -> str:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        raise MementoResponseError("memento datetime is invalid") from None
    if parsed.tzinfo is None:
        raise MementoResponseError("memento datetime must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _split_top_level(value: str, delimiter: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    in_quote = False
    escaped = False
    in_angle = False

    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if in_quote and char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"' and not in_angle:
            in_quote = not in_quote
            current.append(char)
            continue
        if char == "<" and not in_quote:
            if in_angle:
                raise MementoResponseError("nested angle bracket in TimeMap")
            in_angle = True
            current.append(char)
            continue
        if char == ">" and not in_quote:
            if not in_angle:
                raise MementoResponseError("unmatched angle bracket in TimeMap")
            in_angle = False
            current.append(char)
            continue
        if char == delimiter and not in_quote and not in_angle:
            item = "".join(current).strip()
            if not item:
                raise MementoResponseError("empty link-value in TimeMap")
            parts.append(item)
            current = []
            continue
        current.append(char)

    if escaped or in_quote or in_angle:
        raise MementoResponseError("unterminated quoted or URI value in TimeMap")
    item = "".join(current).strip()
    if item:
        parts.append(item)
    elif parts:
        raise MementoResponseError("trailing delimiter in TimeMap")
    return parts


def _quoted_or_token(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise MementoResponseError("empty TimeMap parameter value")
    if not raw.startswith('"'):
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
            raise MementoResponseError("control character in TimeMap parameter")
        return raw
    if len(raw) < 2 or not raw.endswith('"'):
        raise MementoResponseError("unterminated TimeMap quoted value")
    result: list[str] = []
    escaped = False
    for char in raw[1:-1]:
        if escaped:
            result.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            raise MementoResponseError("unescaped quote in TimeMap parameter")
        else:
            result.append(char)
    if escaped:
        raise MementoResponseError("dangling escape in TimeMap parameter")
    return "".join(result)


def _parse_link_value(value: str) -> tuple[str, dict[str, str]]:
    stripped = value.strip()
    if not stripped.startswith("<"):
        raise MementoResponseError("TimeMap link-value must begin with '<'")
    end = stripped.find(">")
    if end <= 1:
        raise MementoResponseError("TimeMap link target is missing")
    target = stripped[1:end]
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in target):
        raise MementoResponseError("control character in TimeMap link target")
    remainder = stripped[end + 1 :].strip()
    params: dict[str, str] = {}
    if remainder:
        if not remainder.startswith(";"):
            raise MementoResponseError("unexpected content after TimeMap link target")
        for raw_param in _split_top_level(remainder[1:], ";"):
            if "=" in raw_param:
                raw_name, raw_value = raw_param.split("=", 1)
                name = raw_name.strip().lower()
                parsed_value = _quoted_or_token(raw_value)
            else:
                name = raw_param.strip().lower()
                parsed_value = ""
            if _PARAM_NAME_RE.fullmatch(name) is None:
                raise MementoResponseError("invalid TimeMap parameter name")
            if name in params:
                raise MementoResponseError("duplicate TimeMap parameter")
            params[name] = parsed_value
    return target, params


@dataclass(frozen=True)
class MementoRecord:
    """One discovered Memento with source-archive provenance."""

    original_url: str
    memento_url: str
    memento_datetime: str
    memento_datetime_raw: str
    source_archive: str
    relations: tuple[str, ...]
    source_origin: str = MEMENTO_SOURCE_ORIGIN
    acquisition_authority: str = SEPARATE_POLICY_REQUIRED
    artifact_acquired: bool = False
    status: str = HOLD_STATUS

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_origin": self.source_origin,
            "source_archive": self.source_archive,
            "original_url": self.original_url,
            "memento_url": self.memento_url,
            "memento_datetime": self.memento_datetime,
            "memento_datetime_raw": self.memento_datetime_raw,
            "relations": list(self.relations),
            "acquisition_authority": self.acquisition_authority,
            "artifact_acquired": self.artifact_acquired,
            "status": self.status,
        }


@dataclass(frozen=True)
class MementoDiscoveryResult:
    """Fail-closed metadata result; errors are never represented as absence."""

    source_id: str
    source_origin: str
    policy_version: str
    original_url: str
    timemap_url: str | None
    retrieved_at: str
    result_class: str
    mementos: tuple[MementoRecord, ...] = ()
    acquisition_authority: str = SEPARATE_POLICY_REQUIRED
    status: str = HOLD_STATUS
    error_code: str | None = None
    error_msg: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_origin": self.source_origin,
            "policy_version": self.policy_version,
            "original_url": self.original_url,
            "timemap_url": self.timemap_url,
            "retrieved_at": self.retrieved_at,
            "result_class": self.result_class,
            "mementos": [record.as_dict() for record in self.mementos],
            "acquisition_authority": self.acquisition_authority,
            "status": self.status,
            "error_code": self.error_code,
            "error_msg": self.error_msg,
        }


def parse_timemap_link_format(
    payload: bytes,
    *,
    expected_original_url: str,
    allowed_archive_hosts: tuple[str, ...],
    max_mementos: int = 1000,
) -> tuple[MementoRecord, ...]:
    """Parse RFC 7089 link-format without following links or acquiring bytes."""

    if not isinstance(payload, bytes):
        raise TypeError("TimeMap payload must be bytes")
    if isinstance(max_mementos, bool) or not 1 <= max_mementos <= 10_000:
        raise MementoConfigurationError("max_mementos must be between 1 and 10000")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise MementoResponseError("TimeMap is not valid UTF-8") from None

    expected = normalize_target_url(expected_original_url)
    allowed = frozenset(_public_host(host) for host in allowed_archive_hosts)
    if not allowed:
        raise MementoConfigurationError("at least one allowed archive host is required")

    links = [_parse_link_value(item) for item in _split_top_level(text, ",")]
    originals: list[str] = []
    records: list[MementoRecord] = []
    seen: dict[str, str] = {}

    for target, params in links:
        relations = tuple(sorted(set(params.get("rel", "").lower().split())))
        if "original" in relations:
            originals.append(_normalize_discovered_url(target, "original link"))
        if "memento" not in relations:
            continue
        raw_datetime = params.get("datetime")
        if raw_datetime is None:
            raise MementoResponseError("memento link is missing datetime")
        memento_url = _normalize_discovered_url(target, "memento link")
        host = urlparse(memento_url).hostname
        if host is None or host not in allowed:
            raise MementoResponseError("memento link points to an unapproved source archive")
        normalized_datetime = _parse_rfc1123_datetime(raw_datetime)
        previous = seen.get(memento_url)
        if previous is not None:
            if previous != normalized_datetime:
                raise MementoResponseError("one Memento URL has conflicting datetimes")
            continue
        seen[memento_url] = normalized_datetime
        records.append(
            MementoRecord(
                original_url=expected,
                memento_url=memento_url,
                memento_datetime=normalized_datetime,
                memento_datetime_raw=raw_datetime,
                source_archive=host,
                relations=relations,
            )
        )
        if len(records) > max_mementos:
            raise MementoResponseError("TimeMap contains too many Mementos")

    if len(originals) != 1:
        raise MementoResponseError("TimeMap must identify exactly one original resource")
    if originals[0] != expected:
        raise MementoResponseError("TimeMap original resource does not match the requested URL")

    records.sort(key=lambda record: (record.memento_datetime, record.memento_url))
    return tuple(records)


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
            return ArchiveHTTPResponse(
                404,
                dict(exc.headers.items()) if exc.headers else {},
                b"",
            )
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
    max_response_bytes: int = _MAX_TIMEMAP_BYTES
    enabled: bool = False
    transport: Transport = field(default=_default_transport, repr=False, compare=False)
    sleeper: Sleeper = field(default=time.sleep, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.user_agent, str) or not self.user_agent.strip():
            raise MementoConfigurationError("user_agent must identify the automated client")
        if self.user_agent == DEFAULT_MEMENTO_USER_AGENT:
            raise MementoConfigurationError(
                "user_agent must include a reviewed contact identity"
            )
        if not 0 < self.timeout_seconds <= 120:
            raise MementoConfigurationError("timeout_seconds must be between 0 and 120")
        if isinstance(self.max_attempts, bool) or not 1 <= self.max_attempts <= 5:
            raise MementoConfigurationError("max_attempts must be between 1 and 5")
        if (
            isinstance(self.max_response_bytes, bool)
            or not 1 <= self.max_response_bytes <= _MAX_TIMEMAP_BYTES
        ):
            raise MementoConfigurationError(
                f"max_response_bytes must be between 1 and {_MAX_TIMEMAP_BYTES}"
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
        normalized_base = _timemap_base_url(self.timemap_base_url)
        normalized_hosts = tuple(
            sorted({_public_host(host) for host in self.allowed_archive_hosts})
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
        if (
            parsed.scheme != "https"
            or parsed.hostname != base.hostname
            or parsed.port is not None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not parsed.path.startswith(base.path)
        ):
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
                    url,
                    headers,
                    self.timeout_seconds,
                    self.max_response_bytes,
                )
                if not isinstance(response, ArchiveHTTPResponse):
                    raise MementoResponseError(
                        "transport returned an invalid response object"
                    )
                if response.status_code == 404:
                    return response
                if response.status_code == 429 or 500 <= response.status_code <= 599:
                    if attempt == self.max_attempts:
                        raise MementoRequestError(
                            f"TimeMap request failed with HTTP {response.status_code}"
                        )
                    retry_after = _header(response.headers, "Retry-After")
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
            except URLError:
                if attempt == self.max_attempts:
                    raise MementoRequestError("TimeMap request failed") from None
                self.sleeper(float(2 ** (attempt - 1)))
        raise MementoRequestError("TimeMap request failed")

    def _result(
        self,
        *,
        original_url: str,
        timemap_url: str | None,
        result_class: str,
        mementos: tuple[MementoRecord, ...] = (),
        error_code: str | None = None,
        error_msg: str | None = None,
    ) -> MementoDiscoveryResult:
        return MementoDiscoveryResult(
            source_id=self.source_id,
            source_origin=MEMENTO_SOURCE_ORIGIN,
            policy_version=self.policy_version,
            original_url=original_url,
            timemap_url=timemap_url,
            retrieved_at=_utc_now(),
            result_class=result_class,
            mementos=mementos,
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
        try:
            response = self._request(timemap_url)
            if response.status_code == 404:
                return self._result(
                    original_url=normalized,
                    timemap_url=timemap_url,
                    result_class="NOT_FOUND",
                )
            content_type = (_header(response.headers, "Content-Type") or "").lower()
            if content_type.split(";", 1)[0].strip() != "application/link-format":
                raise MementoResponseError(
                    "TimeMap response has an unexpected content type"
                )
            mementos = parse_timemap_link_format(
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
                error_code=type(exc).__name__.upper(),
                error_msg=str(exc),
            )

        return self._result(
            original_url=normalized,
            timemap_url=timemap_url,
            result_class="SUCCESS" if mementos else "NOT_FOUND",
            mementos=mementos,
        )
