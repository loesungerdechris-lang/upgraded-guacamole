# SENTINEL Wayback Evidence Layer

## Status

Implementation status: **read-only bootstrap, offline restore preview only**.

The Internet Archive Wayback Machine is registered as a fixed external evidence source. The boundary is intentionally narrow and fail-closed.

## Purpose

The layer supports:

1. checking whether a public URL has archived captures;
2. enumerating historical captures through the CDX API;
3. retrieving a selected archived representation without executing it;
4. hashing locally acquired bytes with SHA-256;
5. creating a deterministic evidence manifest;
6. materializing a local-only reconstruction bundle from verified bytes.

It does not make an archived page true merely because it was captured. It records what the archive returned at a particular archive timestamp.

## Frozen official endpoints

```text
Availability API  https://archive.org/wayback/available
CDX API           https://web.archive.org/cdx/search/cdx
Replay origin     https://web.archive.org
```

Requests that leave these official hosts fail closed. Third-party rebuild services are not trusted dependencies.

## Operational modes

### Discovery

Read-only Availability and CDX queries identify candidate captures. CDX requests are bounded, request successful captures, and can collapse identical archive digests.

### Acquisition

A selected replay URL is fetched as bytes. The client does not render the page, execute archived JavaScript, submit forms, follow links, or crawl the live target.

Each acquired file receives:

- original URL;
- archive replay URL;
- capture timestamp;
- local retrieval timestamp;
- content type;
- byte length;
- SHA-256 hash;
- safe relative bundle path.

### Evidence manifest

`sentinel.wayback.evidence.v1` binds the source, target URL, selected snapshot, local artifacts, interpretation limits, and release gate into a deterministic manifest hash.

### Offline restoration

`materialize_offline_restore()` writes only caller-supplied, already acquired bytes into a selected local directory. It rejects absolute paths and traversal attempts and uses temporary files before replacement.

This is reconstruction, not publication. The generated bundle remains `offline_preview_only`.

## Required interpretation limits

- A Wayback timestamp is an archive capture timestamp, not automatically the page's publication date.
- Missing captures do not prove that a page never existed.
- A replay may omit JavaScript, forms, images, stylesheets, fonts, videos, APIs, or resources hosted by another domain.
- A historical capture can be incomplete or composed from resources captured at different times.
- Archived material may still be protected by copyright, privacy, confidentiality, personality rights, database rights, or contractual restrictions.

## Release and legal gate

No restored page may be published automatically. Publication requires a separate documented review covering at least:

1. ownership or a valid reuse basis;
2. personal data and sensitive information;
3. trademarks and third-party assets;
4. whether the reconstructed page could be mistaken for a current official page;
5. preservation of provenance and archive timestamps;
6. approval under the SENTINEL release policy.

For investigative work, preserve the archived replay link, local bytes, SHA-256, retrieval time, browser screenshot or PDF where relevant, and the human interpretation note. Important claims should be corroborated by an additional primary source.

## Automated-access discipline

The client identifies itself with a descriptive User-Agent, bounds response sizes and timeouts, retries only transient failures, honors `Retry-After` when present, and applies exponential backoff. Bulk crawling and aggressive concurrency are intentionally absent.

## Example

```python
from sentinel_core.wayback import WaybackClient, build_artifact_record, build_evidence_manifest

client = WaybackClient()
snapshot = client.closest_snapshot("https://example.org/project")
if snapshot is None:
    raise SystemExit("No archived snapshot found")

content = client.fetch_capture(snapshot)
artifact = build_artifact_record(
    snapshot=snapshot,
    content=content,
    content_type=snapshot.mime_type,
    relative_path="site/index.html",
)
manifest = build_evidence_manifest(
    target_url=snapshot.original_url,
    snapshot=snapshot,
    artifacts=[artifact],
)
```

## Current non-goals

- no automated Save Page Now submission;
- no authenticated Archive-It collection management;
- no whole-domain crawler;
- no live-site mirroring;
- no JavaScript execution;
- no automatic publication;
- no claim that an archive capture is a certified court record.

A later stage may add domain watchlists, scheduled change detection, asset-graph reconstruction, WARC export handling, and signed SENTINEL receipts. Those remain separate reviewed changes.
