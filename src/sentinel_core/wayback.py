"""Fail-closed Internet Archive Wayback evidence helpers.

Only fixed Internet Archive hosts are trusted. The module performs read-only
snapshot discovery and retrieval, hashes acquired bytes, and writes local-only
restore bundles. It never publishes restored content or decides reuse rights.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from sentinel_core.hashchain import canonicalize_json, sha256_prefixed

WAYBACK_AVAILABILITY_ENDPOINT = "https://archive.org/wayback/available"
WAYBACK_CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
WAYBACK_REPLAY_ORIGIN = "https://web.archive.org"
WAYBACK_SOURCE_ID = "internet-archive-wayback"
DEFAULT_USER_AGENT = "SENTINEL-Wayback-Evidence/0.1 (GPT-5.6-Thinking)"

_ARCHIVE_HOSTS = frozenset({"archive.org", "www.archive.org", "web.archive.org"})
_TIMESTAMP_RE = re.compile(r"^[0-9]{14}$")
_MAX_JSON_BYTES = 8 * 1024 * 1024
_MAX_CAPTURE_BYTES = 64 * 1024 * 1024

Transport = Callable[[str, Mapping[str, str], float, int], bytes]
Sleeper = Callable[[float], None]


class WaybackError(RuntimeError):
    """Base exception for the Wayback evidence boundary."""


class WaybackConfigurationError(WaybackError):
    """Raised when configuration escapes a frozen trust boundary."""


class WaybackRequestError(WaybackError):
    """Raised when an Internet Archive request fails safely."""


class WaybackResponseError(WaybackError):
    """Raised when an archive response is malformed or oversized."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _public_hostname(hostname: str) -> str:
    try:
        host = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise WaybackConfigurationError("target URL contains an invalid hostname") from None

    if (
        host in {"localhost", "localhost.localdomain"}
        or host.endswith(".localhost")
        or host.endswith(".local")
        or host.endswith(".internal")
    ):
        raise WaybackConfigurationError("target URL must identify a public web host")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    if not address.is_global:
        raise WaybackConfigurationError("target URL must not use a non-public IP address")
    return host


def normalize_target_url(value: str) -> str:
    """Return a stable public HTTP(S) URL with no fragment or credentials."""

    if not isinstance(value, str) or not value.strip():
        raise WaybackConfigurationError("target URL must be a non-empty string")
    try:
        parsed = urlparse(value.strip())
        port = parsed.port
    except ValueError:
        raise WaybackConfigurationError("target URL is invalid") from None

    if parsed.scheme.lower() not in {"http", "https"}:
        raise WaybackConfigurationError("target URL must use HTTP or HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise WaybackConfigurationError("target URL must not contain credentials")
    if parsed.hostname is None:
        raise WaybackConfigurationError("target URL must contain a hostname")

    host = _public_hostname(parsed.hostname)
    host = f"[{host}]" if ":" in host else host
    netloc = host if port is None else f"{host}:{port}"
    return urlunparse(
        (
            parsed.scheme.lower(),
            netloc,
            parsed.path or "/",
            parsed.params,
            parsed.query,
            "",
        )
    )


def _archive_url(value: str) -> str:
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        raise WaybackConfigurationError("archive request URL is invalid") from None
    if (
        parsed.scheme != "https"
        or parsed.hostname not in _ARCHIVE_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.fragment
    ):
        raise WaybackConfigurationError(
            "archive request escaped the fixed Internet Archive boundary"
        )
    return value


def _timestamp(value: str, field_name: str = "timestamp") -> str:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise WaybackConfigurationError(f"{field_name} must use YYYYMMDDhhmmss")
    return value


def build_availability_url(target_url: str, *, timestamp: str | None = None) -> str:
    params = [("url", normalize_target_url(target_url))]
    if timestamp is not None:
        params.append(("timestamp", _timestamp(timestamp)))
    return f"{WAYBACK_AVAILABILITY_ENDPOINT}?{urlencode(params)}"


def build_cdx_url(
    target_url: str,
    *,
    match_type: str = "exact",
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
    limit: int = 1000,
    collapse_digest: bool = True,
) -> str:
    """Build a bounded exact, prefix, or domain CDX query."""

    if match_type not in {"exact", "prefix", "domain"}:
        raise WaybackConfigurationError("match_type must be exact, prefix, or domain")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10_000:
        raise WaybackConfigurationError("limit must be an integer between 1 and 10000")

    params: list[tuple[str, str]] = [
        ("url", normalize_target_url(target_url)),
        ("output", "json"),
        ("fl", "timestamp,original,statuscode,mimetype,digest,length"),
        ("filter", "statuscode:200"),
        ("matchType", match_type),
        ("limit", str(limit)),
    ]
    if from_timestamp is not None:
        params.append(("from", _timestamp(from_timestamp, "from_timestamp")))
    if to_timestamp is not None:
        params.append(("to", _timestamp(to_timestamp, "to_timestamp")))
    if collapse_digest:
        params.append(("collapse", "digest"))
    return f"{WAYBACK_CDX_ENDPOINT}?{urlencode(params)}"


def build_replay_url(timestamp: str, original_url: str) -> str:
    normalized = normalize_target_url(original_url)
    return f"{WAYBACK_REPLAY_ORIGIN}/web/{_timestamp(timestamp)}/{normalized}"


@dataclass(frozen=True)
class WaybackSnapshot:
    """One immutable archived snapshot description."""

    timestamp: str
    original_url: str
    status_code: int
    replay_url: str
    mime_type: str | None = None
    archive_digest: str | None = None
    length: int | None = None

    def __post_init__(self) -> None:
        _timestamp(self.timestamp, "snapshot timestamp")
        normalize_target_url(self.original_url)
        _archive_url(self.replay_url)
        if isinstance(self.status_code, bool) or not isinstance(self.status_code, int):
            raise WaybackResponseError("snapshot status code is invalid")
        if self.length is not None and (
            isinstance(self.length, bool) or not isinstance(self.length, int) or self.length < 0
        ):
            raise WaybackResponseError("snapshot length is invalid")

    def as_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "original_url": self.original_url,
            "status_code": self.status_code,
            "replay_url": self.replay_url,
            "mime_type": self.mime_type,
            "archive_digest": self.archive_digest,
            "length": self.length,
        }


def parse_availability_response(payload: Mapping[str, Any]) -> WaybackSnapshot | None:
    archived = payload.get("archived_snapshots")
    if not isinstance(archived, Mapping):
        raise WaybackResponseError("availability response lacks archived_snapshots")
    closest = archived.get("closest")
    if closest in (None, {}):
        return None
    if not isinstance(closest, Mapping):
        raise WaybackResponseError("availability response closest snapshot is invalid")
    if closest.get("available") is not True:
        return None

    original = payload.get("url")
    timestamp = closest.get("timestamp")
    replay = closest.get("url")
    if not all(isinstance(item, str) for item in (original, timestamp, replay)):
        raise WaybackResponseError("availability response snapshot metadata is incomplete")
    try:
        status_code = int(closest.get("status"))
    except (TypeError, ValueError):
        raise WaybackResponseError("availability response status is invalid") from None

    secure_replay = urlunparse(urlparse(replay)._replace(scheme="https"))
    return WaybackSnapshot(
        timestamp=timestamp,
        original_url=normalize_target_url(original),
        status_code=status_code,
        replay_url=_archive_url(secure_replay),
    )


def parse_cdx_response(payload: Any) -> tuple[WaybackSnapshot, ...]:
    if not isinstance(payload, list) or not payload:
        return ()
    header = payload[0]
    required = {"timestamp", "original", "statuscode", "mimetype", "digest", "length"}
    if not isinstance(header, list) or not required.issubset(set(header)):
        raise WaybackResponseError("CDX response header is invalid")

    result: list[WaybackSnapshot] = []
    seen: set[tuple[str, str]] = set()
    for raw_row in payload[1:]:
        if not isinstance(raw_row, list) or len(raw_row) != len(header):
            raise WaybackResponseError("CDX response row is invalid")
        row = dict(zip(header, raw_row, strict=True))
        timestamp = row["timestamp"]
        original = row["original"]
        if not isinstance(timestamp, str) or not isinstance(original, str):
            raise WaybackResponseError("CDX snapshot identity is invalid")
        try:
            status_code = int(row["statuscode"])
            length = int(row["length"]) if row["length"] not in (None, "-") else None
        except (TypeError, ValueError):
            raise WaybackResponseError("CDX numeric field is invalid") from None
        key = (timestamp, original)
        if key in seen:
            continue
        seen.add(key)
        result.append(
            WaybackSnapshot(
                timestamp=timestamp,
                original_url=normalize_target_url(original),
                status_code=status_code,
                replay_url=build_replay_url(timestamp, original),
                mime_type=row["mimetype"] if isinstance(row["mimetype"], str) else None,
                archive_digest=row["digest"] if isinstance(row["digest"], str) else None,
                length=length,
            )
        )
    return tuple(result)


def hash_artifact(content: bytes) -> str:
    if not isinstance(content, bytes):
        raise TypeError("artifact content must be bytes")
    return "sha256:" + hashlib.sha256(content).hexdigest()


def validate_restore_path(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise WaybackConfigurationError("restore path must be a non-empty string")
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise WaybackConfigurationError("restore path must stay within the bundle root")
    return path.as_posix()


def build_artifact_record(
    *,
    snapshot: WaybackSnapshot,
    content: bytes,
    content_type: str | None,
    relative_path: str,
    retrieved_at: str | None = None,
) -> dict[str, Any]:
    return {
        "original_url": snapshot.original_url,
        "archive_url": snapshot.replay_url,
        "snapshot_timestamp": snapshot.timestamp,
        "retrieved_at": retrieved_at or _utc_now(),
        "content_type": content_type,
        "byte_length": len(content),
        "sha256": hash_artifact(content),
        "relative_path": validate_restore_path(relative_path),
    }


def build_evidence_manifest(
    *,
    target_url: str,
    snapshot: WaybackSnapshot,
    artifacts: list[dict[str, Any]],
    observed_at: str | None = None,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": "sentinel.wayback.evidence.v1",
        "source": {
            "id": WAYBACK_SOURCE_ID,
            "provider": "Internet Archive",
            "official_hosts": sorted(_ARCHIVE_HOSTS),
        },
        "target_url": normalize_target_url(target_url),
        "snapshot": snapshot.as_dict(),
        "observed_at": observed_at or _utc_now(),
        "artifacts": artifacts,
        "interpretation_limits": [
            "archive timestamp is not automatically the publication timestamp",
            "missing captures do not prove that content never existed",
            "archived replay may omit dynamic or externally hosted resources",
        ],
        "release_gate": {
            "mode": "offline_preview_only",
            "rights_review_status": "required",
            "publish_restored_content": False,
        },
    }
    manifest["manifest_hash"] = sha256_prefixed(canonicalize_json(manifest))
    return manifest


def verify_evidence_manifest(manifest: Mapping[str, Any]) -> bool:
    claimed = manifest.get("manifest_hash")
    if not isinstance(claimed, str):
        return False
    unsigned = dict(manifest)
    unsigned.pop("manifest_hash", None)
    return claimed == sha256_prefixed(canonicalize_json(unsigned))


def materialize_offline_restore(
    files: Mapping[str, bytes],
    destination: str | Path,
    *,
    overwrite: bool = False,
) -> tuple[dict[str, Any], ...]:
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    for relative_path, content in sorted(files.items()):
        safe_path = validate_restore_path(relative_path)
        if not isinstance(content, bytes):
            raise TypeError("restore file content must be bytes")
        target = root.joinpath(*PurePosixPath(safe_path).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not overwrite:
            raise FileExistsError(f"restore target already exists: {safe_path}")
        temporary = target.with_name(target.name + ".sentinel-tmp")
        temporary.write_bytes(content)
        temporary.replace(target)
        records.append(
            {
                "relative_path": safe_path,
                "byte_length": len(content),
                "sha256": hash_artifact(content),
            }
        )
    return tuple(records)


class _ArchiveOnlyRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        _archive_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _default_transport(
    url: str,
    headers: Mapping[str, str],
    timeout_seconds: float,
    max_bytes: int,
) -> bytes:
    request = Request(_archive_url(url), headers=dict(headers), method="GET")
    opener = build_opener(_ArchiveOnlyRedirectHandler())
    with opener.open(request, timeout=timeout_seconds) as response:  # noqa: S310
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                if int(content_length) > max_bytes:
                    raise WaybackResponseError("Internet Archive response exceeded size limit")
            except ValueError:
                raise WaybackResponseError("Internet Archive returned invalid length") from None
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise WaybackResponseError("Internet Archive response exceeded size limit")
    return data


@dataclass(frozen=True)
class WaybackClient:
    """Bounded read-only client for official Wayback endpoints."""

    user_agent: str = DEFAULT_USER_AGENT
    timeout_seconds: float = 20.0
    max_attempts: int = 3
    transport: Transport = field(default=_default_transport, repr=False, compare=False)
    sleeper: Sleeper = field(default=time.sleep, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.user_agent, str) or not self.user_agent.strip():
            raise WaybackConfigurationError("user_agent must identify the automated client")
        if not 0 < self.timeout_seconds <= 120:
            raise WaybackConfigurationError("timeout_seconds must be between 0 and 120")
        if isinstance(self.max_attempts, bool) or not 1 <= self.max_attempts <= 5:
            raise WaybackConfigurationError("max_attempts must be between 1 and 5")

    def _request(self, url: str, *, accept: str, max_bytes: int) -> bytes:
        headers = {"User-Agent": self.user_agent, "Accept": accept}
        for attempt in range(1, self.max_attempts + 1):
            try:
                return self.transport(
                    _archive_url(url), headers, self.timeout_seconds, max_bytes
                )
            except HTTPError as exc:
                retryable = exc.code == 429 or 500 <= exc.code <= 599
                if not retryable or attempt == self.max_attempts:
                    raise WaybackRequestError(
                        f"Internet Archive request failed with HTTP {exc.code}"
                    ) from None
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                try:
                    delay = min(float(retry_after), 30.0) if retry_after else 2 ** (attempt - 1)
                except ValueError:
                    delay = 2 ** (attempt - 1)
                self.sleeper(float(delay))
            except URLError:
                if attempt == self.max_attempts:
                    raise WaybackRequestError("Internet Archive request failed") from None
                self.sleeper(float(2 ** (attempt - 1)))
        raise WaybackRequestError("Internet Archive request failed")

    def _request_json(self, url: str) -> Any:
        raw = self._request(url, accept="application/json", max_bytes=_MAX_JSON_BYTES)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise WaybackResponseError("Internet Archive returned invalid JSON") from None

    def closest_snapshot(
        self, target_url: str, *, timestamp: str | None = None
    ) -> WaybackSnapshot | None:
        payload = self._request_json(build_availability_url(target_url, timestamp=timestamp))
        if not isinstance(payload, Mapping):
            raise WaybackResponseError("availability response must be a JSON object")
        return parse_availability_response(payload)

    def list_snapshots(
        self,
        target_url: str,
        *,
        match_type: str = "exact",
        from_timestamp: str | None = None,
        to_timestamp: str | None = None,
        limit: int = 1000,
    ) -> tuple[WaybackSnapshot, ...]:
        url = build_cdx_url(
            target_url,
            match_type=match_type,
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
            limit=limit,
        )
        return parse_cdx_response(self._request_json(url))

    def fetch_capture(self, snapshot: WaybackSnapshot) -> bytes:
        """Fetch archived bytes without executing them or following page links."""

        return self._request(
            snapshot.replay_url,
            accept="*/*",
            max_bytes=_MAX_CAPTURE_BYTES,
        )
