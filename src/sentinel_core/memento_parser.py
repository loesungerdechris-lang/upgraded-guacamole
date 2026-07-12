"""Bounded RFC 7089 link-format parsing for Memento TimeMaps."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from sentinel_core.memento_model import (
    MementoConfigurationError,
    MementoRecord,
    MementoResponseError,
    ParsedTimeMap,
)
from sentinel_core.memento_validation import (
    normalize_discovered_url,
    parse_rfc1123_datetime,
    public_dns_host,
)
from sentinel_core.wayback import normalize_target_url

_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")


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


def parse_timemap_document(
    payload: bytes,
    *,
    expected_original_url: str,
    allowed_archive_hosts: tuple[str, ...],
    max_mementos: int = 1000,
) -> ParsedTimeMap:
    """Parse link-format without following linked TimeMaps or acquiring bytes."""

    if not isinstance(payload, bytes):
        raise TypeError("TimeMap payload must be bytes")
    if isinstance(max_mementos, bool) or not 1 <= max_mementos <= 10_000:
        raise MementoConfigurationError("max_mementos must be between 1 and 10000")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise MementoResponseError("TimeMap is not valid UTF-8") from None

    expected = normalize_target_url(expected_original_url)
    allowed = frozenset(public_dns_host(host) for host in allowed_archive_hosts)
    if not allowed:
        raise MementoConfigurationError("at least one allowed archive host is required")

    links = [_parse_link_value(item) for item in _split_top_level(text, ",")]
    originals: list[str] = []
    records: list[MementoRecord] = []
    linked_timemaps: set[str] = set()
    seen: dict[str, str] = {}

    for target, params in links:
        relations = tuple(sorted(set(params.get("rel", "").lower().split())))
        anchor = params.get("anchor")
        if anchor is not None:
            normalized_anchor = normalize_discovered_url(anchor, "anchor")
            if normalized_anchor != expected:
                raise MementoResponseError("TimeMap link anchor does not match the original URL")

        if "original" in relations:
            if anchor is not None:
                raise MementoResponseError("original link must not override its context")
            originals.append(normalize_discovered_url(target, "original link"))

        if "timemap" in relations:
            linked_timemaps.add(normalize_discovered_url(target, "linked TimeMap"))

        if "memento" not in relations:
            continue
        raw_datetime = params.get("datetime")
        if raw_datetime is None:
            raise MementoResponseError("memento link is missing datetime")
        memento_url = normalize_discovered_url(target, "memento link")
        host = urlparse(memento_url).hostname
        if host is None or host not in allowed:
            raise MementoResponseError("memento link points to an unapproved source archive")
        normalized_datetime = parse_rfc1123_datetime(raw_datetime)
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
    return ParsedTimeMap(
        mementos=tuple(records),
        linked_timemaps=tuple(sorted(linked_timemaps)),
    )


def parse_timemap_link_format(
    payload: bytes,
    *,
    expected_original_url: str,
    allowed_archive_hosts: tuple[str, ...],
    max_mementos: int = 1000,
) -> tuple[MementoRecord, ...]:
    """Compatibility helper that returns only candidate Memento records."""

    return parse_timemap_document(
        payload,
        expected_original_url=expected_original_url,
        allowed_archive_hosts=allowed_archive_hosts,
        max_mementos=max_mementos,
    ).mementos
