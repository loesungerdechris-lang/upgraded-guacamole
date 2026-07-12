from __future__ import annotations

from urllib.error import URLError

import pytest

from sentinel_core.memento import (
    ArchiveHTTPResponse,
    MementoAdapter,
    MementoConfigurationError,
    parse_timemap_link_format,
)

USER_AGENT = "SENTINEL-Memento-Test/0.1 (security@example.invalid)"
BASE_URL = "https://aggregator.example.org/timemap/link/"
ALLOWED = ("archive.example.org", "second.example.net")


def timemap(*entries: str) -> bytes:
    original = '<https://example.com/page>; rel="original"'
    return (",\n ".join((original, *entries))).encode()


def memento_entry(
    url: str = "https://archive.example.org/web/20200101120000/https://example.com/page",
    datetime_value: str = "Wed, 01 Jan 2020 12:00:00 GMT",
    rel: str = "first memento",
) -> str:
    return f'<{url}>; rel="{rel}"; datetime="{datetime_value}"'


def adapter(*, enabled: bool, transport, sleeper=lambda _: None, max_attempts: int = 3):
    return MementoAdapter(
        timemap_base_url=BASE_URL,
        allowed_archive_hosts=ALLOWED,
        policy_version="memento-policy.v1-draft",
        enabled=enabled,
        user_agent=USER_AGENT,
        transport=transport,
        sleeper=sleeper,
        max_attempts=max_attempts,
    )


def ok_transport(body: bytes):
    def transport(url, headers, timeout, max_bytes):
        assert url.startswith(BASE_URL)
        assert headers["Accept"] == "application/link-format"
        assert headers["User-Agent"] == USER_AGENT
        assert timeout == 20.0
        assert len(body) <= max_bytes
        return ArchiveHTTPResponse(
            200,
            {"Content-Type": "application/link-format; charset=utf-8"},
            body,
        )

    return transport


def test_adapter_is_disabled_by_default_and_never_calls_transport():
    calls = []

    def forbidden(*args):
        calls.append(args)
        raise AssertionError("transport must not be called")

    result = adapter(enabled=False, transport=forbidden).discover("https://example.com/page")

    assert result.status == "HOLD"
    assert result.result_class == "POLICY_BLOCKED"
    assert result.error_code == "SOURCE_POLICY_NOT_AUTHORIZED"
    assert result.mementos == ()
    assert calls == []


def test_happy_path_preserves_actual_archive_provenance():
    body = timemap(
        memento_entry(),
        memento_entry(
            url="https://second.example.net/capture/20210102030405/https://example.com/page",
            datetime_value="Sat, 02 Jan 2021 03:04:05 GMT",
            rel="last memento",
        ),
    )

    result = adapter(enabled=True, transport=ok_transport(body)).discover(
        "https://example.com/page"
    )

    assert result.result_class == "SUCCESS"
    assert result.status == "HOLD"
    assert result.acquisition_authority == "separate_policy_required"
    assert [record.source_archive for record in result.mementos] == [
        "archive.example.org",
        "second.example.net",
    ]
    assert all(record.artifact_acquired is False for record in result.mementos)
    assert all(
        record.source_origin == "memento-protocol-discovery" for record in result.mementos
    )
    assert result.mementos[0].memento_datetime == "2020-01-01T12:00:00Z"


def test_rfc1123_comma_inside_quoted_datetime_is_not_split():
    records = parse_timemap_link_format(
        timemap(memento_entry()),
        expected_original_url="https://example.com/page",
        allowed_archive_hosts=ALLOWED,
    )
    assert len(records) == 1


def test_original_resource_must_match_request():
    body = (
        '<https://other.example/page>; rel="original",\n' + memento_entry()
    ).encode()

    result = adapter(enabled=True, transport=ok_transport(body)).discover(
        "https://example.com/page"
    )

    assert result.result_class == "QUERY_FAILED"
    assert "does not match" in result.error_msg
    assert result.mementos == ()


def test_missing_original_is_query_failure_not_absence():
    body = memento_entry().encode()
    result = adapter(enabled=True, transport=ok_transport(body)).discover(
        "https://example.com/page"
    )
    assert result.result_class == "QUERY_FAILED"
    assert result.mementos == ()


def test_unapproved_source_archive_fails_closed():
    body = timemap(
        memento_entry(
            url="https://evil.example/capture/1/https://example.com/page",
        )
    )
    result = adapter(enabled=True, transport=ok_transport(body)).discover(
        "https://example.com/page"
    )
    assert result.result_class == "QUERY_FAILED"
    assert "unapproved source archive" in result.error_msg


def test_conflicting_datetime_for_same_memento_url_fails_closed():
    url = "https://archive.example.org/web/1/https://example.com/page"
    body = timemap(
        memento_entry(url=url, datetime_value="Wed, 01 Jan 2020 12:00:00 GMT"),
        memento_entry(url=url, datetime_value="Thu, 02 Jan 2020 12:00:00 GMT"),
    )
    result = adapter(enabled=True, transport=ok_transport(body)).discover(
        "https://example.com/page"
    )
    assert result.result_class == "QUERY_FAILED"
    assert "conflicting datetimes" in result.error_msg


def test_404_is_not_found_not_query_failed():
    def transport(*args):
        return ArchiveHTTPResponse(404, {}, b"")

    result = adapter(enabled=True, transport=transport).discover("https://example.com/page")
    assert result.result_class == "NOT_FOUND"
    assert result.error_code is None


def test_network_failure_is_query_failed_not_not_found():
    def transport(*args):
        raise URLError("offline")

    result = adapter(enabled=True, transport=transport, max_attempts=1).discover(
        "https://example.com/page"
    )
    assert result.result_class == "QUERY_FAILED"
    assert result.error_code == "MEMENTOREQUESTERROR"


def test_retry_after_is_honored_for_429():
    calls = 0
    delays = []
    body = timemap(memento_entry())

    def transport(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ArchiveHTTPResponse(429, {"Retry-After": "3"}, b"")
        return ArchiveHTTPResponse(200, {"Content-Type": "application/link-format"}, body)

    result = adapter(enabled=True, transport=transport, sleeper=delays.append).discover(
        "https://example.com/page"
    )

    assert result.result_class == "SUCCESS"
    assert calls == 2
    assert delays == [3.0]


def test_unexpected_content_type_is_query_failure():
    def transport(*args):
        return ArchiveHTTPResponse(200, {"Content-Type": "text/html"}, b"<html></html>")

    result = adapter(enabled=True, transport=transport).discover("https://example.com/page")
    assert result.result_class == "QUERY_FAILED"
    assert "content type" in result.error_msg


def test_malformed_datetime_is_rejected():
    body = timemap(memento_entry(datetime_value="not-a-date"))
    result = adapter(enabled=True, transport=ok_transport(body)).discover(
        "https://example.com/page"
    )
    assert result.result_class == "QUERY_FAILED"
    assert "datetime is invalid" in result.error_msg


def test_empty_valid_timemap_returns_not_found():
    body = b'<https://example.com/page>; rel="original"'
    result = adapter(enabled=True, transport=ok_transport(body)).discover(
        "https://example.com/page"
    )
    assert result.result_class == "NOT_FOUND"
    assert result.mementos == ()


def test_endpoint_requires_https_and_no_credentials():
    with pytest.raises(MementoConfigurationError):
        MementoAdapter(
            timemap_base_url="http://aggregator.example.org/timemap/",
            allowed_archive_hosts=ALLOWED,
            policy_version="v1",
            user_agent=USER_AGENT,
        )
    with pytest.raises(MementoConfigurationError):
        MementoAdapter(
            timemap_base_url="https://user:pass@aggregator.example.org/timemap/",
            allowed_archive_hosts=ALLOWED,
            policy_version="v1",
            user_agent=USER_AGENT,
        )


def test_placeholder_user_agent_is_rejected():
    with pytest.raises(MementoConfigurationError):
        MementoAdapter(
            timemap_base_url=BASE_URL,
            allowed_archive_hosts=ALLOWED,
            policy_version="v1",
        )


def test_builder_percent_encodes_original_url_and_stays_on_endpoint():
    instance = adapter(enabled=False, transport=lambda *args: None)
    url = instance.build_timemap_url("https://example.com/a?x=1&y=2")
    assert url.startswith(BASE_URL)
    assert "https%3A%2F%2Fexample.com%2Fa%3Fx%3D1%26y%3D2" in url


def test_duplicate_identical_record_is_deduplicated():
    entry = memento_entry()
    records = parse_timemap_link_format(
        timemap(entry, entry),
        expected_original_url="https://example.com/page",
        allowed_archive_hosts=ALLOWED,
    )
    assert len(records) == 1


def test_result_serialization_retains_hold_and_source_archive():
    result = adapter(enabled=True, transport=ok_transport(timemap(memento_entry()))).discover(
        "https://example.com/page"
    )
    data = result.as_dict()
    assert data["status"] == "HOLD"
    assert data["acquisition_authority"] == "separate_policy_required"
    assert data["mementos"][0]["source_archive"] == "archive.example.org"
