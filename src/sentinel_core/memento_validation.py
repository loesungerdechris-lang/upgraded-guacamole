"""URL, host, and datetime validation for Memento discovery."""

from __future__ import annotations

import ipaddress
import re
from datetime import timezone
from email.utils import format_datetime, parsedate_to_datetime
from typing import Mapping
from urllib.parse import unquote, urlparse, urlunparse

from sentinel_core.memento_model import (
    MementoConfigurationError,
    MementoResponseError,
)
from sentinel_core.wayback import WaybackConfigurationError, normalize_target_url

_RFC1123_GMT_RE = re.compile(
    r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} "
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT$"
)


def header_value(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


def public_dns_host(value: str) -> str:
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
    host = parsed.hostname
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.rstrip(".").split(".")
        invalid = (
            len(host) > 253
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                for label in labels
            )
        )
        if invalid:
            raise MementoConfigurationError("archive host is not a valid exact DNS name")
    else:
        raise MementoConfigurationError("archive host must be an exact DNS hostname")
    return host


def timemap_base_url(value: str) -> str:
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
    decoded_segments = [unquote(part) for part in stable.path.split("/")]
    if any(part in {".", ".."} for part in decoded_segments):
        raise MementoConfigurationError("timemap_base_url contains a dot path segment")
    path = stable.path if stable.path.endswith("/") else stable.path + "/"
    return urlunparse(("https", stable.netloc, path, "", "", ""))


def normalize_discovered_url(value: str, field_name: str) -> str:
    try:
        normalized = normalize_target_url(value)
    except WaybackConfigurationError as exc:
        raise MementoResponseError(f"{field_name} is not a public HTTP(S) URL") from exc
    parsed = urlparse(normalized)
    if parsed.port is not None:
        raise MementoResponseError(f"{field_name} must not contain a port")
    return normalized


def parse_rfc1123_datetime(value: str) -> str:
    if not isinstance(value, str) or _RFC1123_GMT_RE.fullmatch(value) is None:
        raise MementoResponseError("memento datetime must use RFC 1123 GMT format")
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        raise MementoResponseError("memento datetime is invalid") from None
    if parsed.tzinfo is None:
        raise MementoResponseError("memento datetime must include a timezone")
    utc_value = parsed.astimezone(timezone.utc)
    if format_datetime(utc_value, usegmt=True) != value:
        raise MementoResponseError("memento datetime weekday or value is inconsistent")
    return utc_value.isoformat().replace("+00:00", "Z")
