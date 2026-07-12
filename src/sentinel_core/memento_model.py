"""Immutable data contracts for SENTINEL Memento discovery."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

DEFAULT_MEMENTO_USER_AGENT = "SENTINEL-Memento-Discovery/0.1 (contact-required)"
MEMENTO_SOURCE_ORIGIN = "memento-protocol-discovery"
SEPARATE_POLICY_REQUIRED = "separate_policy_required"
HOLD_STATUS = "HOLD"
MAX_TIMEMAP_BYTES = 8 * 1024 * 1024

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


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class MementoRecord:
    """One candidate Memento with declared, not yet verified, archive provenance."""

    original_url: str
    memento_url: str
    memento_datetime: str
    memento_datetime_raw: str
    source_archive: str
    relations: tuple[str, ...]
    source_origin: str = MEMENTO_SOURCE_ORIGIN
    acquisition_authority: str = SEPARATE_POLICY_REQUIRED
    source_archive_verified: bool = False
    datetime_verified: bool = False
    artifact_acquired: bool = False
    status: str = HOLD_STATUS

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_origin": self.source_origin,
            "source_archive": self.source_archive,
            "source_archive_verified": self.source_archive_verified,
            "original_url": self.original_url,
            "memento_url": self.memento_url,
            "memento_datetime": self.memento_datetime,
            "memento_datetime_raw": self.memento_datetime_raw,
            "datetime_verified": self.datetime_verified,
            "relations": list(self.relations),
            "acquisition_authority": self.acquisition_authority,
            "artifact_acquired": self.artifact_acquired,
            "status": self.status,
        }


@dataclass(frozen=True)
class ParsedTimeMap:
    """Parsed discovery metadata; linked TimeMaps are never followed automatically."""

    mementos: tuple[MementoRecord, ...]
    linked_timemaps: tuple[str, ...]


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
    linked_timemaps: tuple[str, ...] = ()
    timemap_sha256: str | None = None
    timemap_byte_length: int | None = None
    http_status: int | None = None
    content_type: str | None = None
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
            "linked_timemaps": list(self.linked_timemaps),
            "timemap_sha256": self.timemap_sha256,
            "timemap_byte_length": self.timemap_byte_length,
            "http_status": self.http_status,
            "content_type": self.content_type,
            "acquisition_authority": self.acquisition_authority,
            "status": self.status,
            "error_code": self.error_code,
            "error_msg": self.error_msg,
        }
