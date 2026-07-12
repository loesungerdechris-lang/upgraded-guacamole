from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import pytest

from sentinel_core.wayback import (
    DEFAULT_USER_AGENT,
    WaybackClient,
    WaybackConfigurationError,
    WaybackSnapshot,
    build_artifact_record,
    build_cdx_url,
    build_evidence_manifest,
    materialize_offline_restore,
    normalize_target_url,
    parse_availability_response,
    parse_cdx_response,
    verify_evidence_manifest,
)


def test_normalize_target_url_is_stable_and_drops_fragment() -> None:
    assert (
        normalize_target_url("HTTPS://Example.COM/report?a=1#section")
        == "https://example.com/report?a=1"
    )


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://user:secret@example.com/",
        "http://localhost/admin",
        "http://127.0.0.1/private",
        "http://10.0.0.4/private",
    ],
)
def test_normalize_target_url_rejects_unsafe_targets(url: str) -> None:
    with pytest.raises(WaybackConfigurationError):
        normalize_target_url(url)


def test_build_cdx_url_is_fixed_to_official_endpoint() -> None:
    built = build_cdx_url(
        "https://example.com/page",
        from_timestamp="20200101000000",
        to_timestamp="20261231235959",
        limit=25,
    )
    parsed = urlparse(built)
    query = parse_qs(parsed.query)
    assert parsed.scheme == "https"
    assert parsed.hostname == "web.archive.org"
    assert parsed.path == "/cdx/search/cdx"
    assert query["url"] == ["https://example.com/page"]
    assert query["filter"] == ["statuscode:200"]
    assert query["collapse"] == ["digest"]


def test_parse_availability_response() -> None:
    payload = {
        "url": "https://example.com/",
        "archived_snapshots": {
            "closest": {
                "status": "200",
                "available": True,
                "url": "http://web.archive.org/web/20240102030405/https://example.com/",
                "timestamp": "20240102030405",
            }
        },
    }
    snapshot = parse_availability_response(payload)
    assert snapshot is not None
    assert snapshot.timestamp == "20240102030405"
    assert snapshot.replay_url.startswith("https://web.archive.org/")


def test_parse_cdx_response() -> None:
    payload = [
        ["timestamp", "original", "statuscode", "mimetype", "digest", "length"],
        [
            "20240102030405",
            "https://example.com/",
            "200",
            "text/html",
            "ABC123",
            "1200",
        ],
    ]
    snapshots = parse_cdx_response(payload)
    assert len(snapshots) == 1
    assert snapshots[0].archive_digest == "ABC123"
    assert snapshots[0].length == 1200


def test_manifest_hash_detects_tampering() -> None:
    snapshot = WaybackSnapshot(
        timestamp="20240102030405",
        original_url="https://example.com/",
        status_code=200,
        replay_url="https://web.archive.org/web/20240102030405/https://example.com/",
        mime_type="text/html",
    )
    artifact = build_artifact_record(
        snapshot=snapshot,
        content=b"<html>archive</html>",
        content_type="text/html",
        relative_path="site/index.html",
        retrieved_at="2026-07-12T08:00:00Z",
    )
    manifest = build_evidence_manifest(
        target_url="https://example.com/",
        snapshot=snapshot,
        artifacts=[artifact],
        observed_at="2026-07-12T08:00:00Z",
    )
    assert verify_evidence_manifest(manifest)
    manifest["artifacts"][0]["byte_length"] = 1
    assert not verify_evidence_manifest(manifest)


def test_materialize_offline_restore_stays_inside_root(tmp_path) -> None:
    records = materialize_offline_restore(
        {"site/index.html": b"ok", "site/assets/app.css": b"body{}"},
        tmp_path,
    )
    assert (tmp_path / "site" / "index.html").read_bytes() == b"ok"
    assert len(records) == 2
    with pytest.raises(WaybackConfigurationError):
        materialize_offline_restore({"../escape.txt": b"no"}, tmp_path)


def test_client_identifies_itself_and_uses_fixed_endpoint() -> None:
    calls: list[tuple[str, dict[str, str]]] = []

    def transport(url: str, headers, timeout: float, max_bytes: int) -> bytes:
        calls.append((url, dict(headers)))
        return json.dumps(
            {"url": "https://example.com/", "archived_snapshots": {}}
        ).encode()

    client = WaybackClient(transport=transport, sleeper=lambda _: None)
    assert client.closest_snapshot("https://example.com/") is None
    assert calls[0][0].startswith("https://archive.org/wayback/available?")
    assert calls[0][1]["User-Agent"] == DEFAULT_USER_AGENT
