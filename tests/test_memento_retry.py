from email.message import Message
from urllib.error import HTTPError

from sentinel_core.memento import ArchiveHTTPResponse, MementoAdapter

USER_AGENT = "SENTINEL-Memento-Test/0.1 (security@example.invalid)"
BASE_URL = "https://aggregator.example.org/timemap/link/"
ALLOWED = ("archive.example.org",)
BODY = (
    '<https://example.com/page>; rel="original", '
    '<https://archive.example.org/capture>; rel="memento"; '
    'datetime="Wed, 01 Jan 2020 12:00:00 GMT"'
).encode()


def make_adapter(transport, delays):
    return MementoAdapter(
        timemap_base_url=BASE_URL,
        allowed_archive_hosts=ALLOWED,
        policy_version="v1",
        enabled=True,
        user_agent=USER_AGENT,
        transport=transport,
        sleeper=delays.append,
    )


def test_negative_retry_after_uses_bounded_fallback():
    calls = 0
    delays = []

    def transport(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ArchiveHTTPResponse(429, {"Retry-After": "-1"}, b"")
        return ArchiveHTTPResponse(200, {"Content-Type": "application/link-format"}, BODY)

    result = make_adapter(transport, delays).discover("https://example.com/page")

    assert result.result_class == "SUCCESS"
    assert delays == [1.0]


def test_non_finite_http_error_retry_after_uses_bounded_fallback():
    calls = 0
    delays = []

    def transport(url, *args):
        nonlocal calls
        calls += 1
        if calls == 1:
            headers = Message()
            headers["Retry-After"] = "nan"
            raise HTTPError(url, 429, "rate limited", headers, None)
        return ArchiveHTTPResponse(200, {"Content-Type": "application/link-format"}, BODY)

    result = make_adapter(transport, delays).discover("https://example.com/page")

    assert result.result_class == "SUCCESS"
    assert delays == [1.0]
