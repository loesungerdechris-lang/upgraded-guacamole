# SENTINEL Memento TimeMap Adapter Boundary

**Document ID:** `sentinel.memento.adapter-boundary.v1-draft`  
**Status:** DRAFT / HOLD  
**Scope:** Phase 3 discovery adapter only  
**Parent:** Issue #29  
**Stacked dependency:** Draft PR #27

## 1. Purpose

This document defines the implementation boundary for the first executable Memento component in SENTINEL Phase 3.

The adapter parses RFC 7089 TimeMaps in `application/link-format` and records candidate Mementos with the archive host declared by each Memento URI. It does not acquire Memento bytes, verify the declared archive identity, render archived pages, recursively follow TimeMaps, change evidence status, sign receipts, or publish content.

## 2. Hard boundary

```text
Memento TimeMap response
    -> bounded parser
    -> hashed TimeMap observation
    -> source-isolated candidate records
    -> HOLD discovery result
```

The Memento service is discovery provenance only. The archive host contained in each candidate URI is retained as `source_archive`, but it remains `source_archive_verified: false` until a separately approved adapter acquires and verifies that source.

The Memento datetime is preserved as supplied and normalized only after strict RFC 1123 GMT validation. It remains `datetime_verified: false` until source-specific acquisition establishes its meaning.

Discovery never grants acquisition authority.

## 3. Default state

The adapter and repository policy are disabled by default:

```text
status: HOLD
enabled: false
acquisition_authority: separate_policy_required
requires_reviewed_transport: true
memento_content_acquisition: false
source_archive_identity_verified: false
active_content_execution: false
automatic_status_elevation: false
publication: false
```

Listing an adapter, endpoint, archive host, or Memento in configuration never enables network use by itself. An enabled adapter refuses the bundled default transport and requires a separately reviewed injected transport.

## 4. Request controls

An enabled test or future reviewed operation must provide:

- an exact credential-free HTTPS TimeMap base URL;
- a descriptive User-Agent with reviewed contact identity;
- a separately reviewed transport implementation;
- an explicit allowlist of candidate source-archive DNS hosts;
- bounded timeout, attempt, response-size, and Memento-count limits;
- GET-only operation;
- `Accept: application/link-format`;
- redirects disabled;
- no cookies, credentials, authorization headers, or case metadata;
- `Retry-After` handling with finite, nonnegative clamping and bounded fallback.

The repository contains no active production endpoint, no approved external source allowlist, and no operational transport approval.

## 5. Parser rules

The parser:

- requires valid UTF-8 link-format input;
- handles commas inside quoted RFC 1123 datetimes;
- requires exact RFC 1123 GMT syntax and checks weekday consistency;
- requires exactly one `rel="original"` link;
- binds the original link and any `anchor` parameter to the requested normalized URL;
- requires every `rel="memento"` link to contain a valid datetime;
- accepts only explicitly allowlisted public DNS archive hosts, not literal IP addresses;
- rejects credentials, private targets, ports, dot-path endpoints, malformed parameters, duplicate parameters, conflicting datetimes, and oversized record sets;
- deduplicates only identical candidate URI and datetime pairs;
- preserves raw and normalized datetime values;
- records linked index or paging TimeMaps without following them;
- performs no content retrieval or semantic interpretation.

RFC 7089 defines TimeMaps as lists of the original resource and Memento URIs with archival datetimes. Link-format serialization is requested with `Accept: application/link-format`.

## 6. Result classes

The result classes are intentionally distinct:

- `SUCCESS` — a complete valid TimeMap yielded approved candidate records and no linked TimeMap pages;
- `PARTIAL` — candidate records were returned but linked index or paging TimeMaps remain unqueried;
- `PAGINATION_REQUIRED` — the TimeMap contains linked TimeMaps but no local candidate records;
- `NOT_FOUND` — a valid 404 or complete valid TimeMap with no Memento records;
- `QUERY_FAILED` — transport, content-type, parser, identity, or source-policy validation failed;
- `POLICY_BLOCKED` — discovery was not enabled by reviewed source policy.

`QUERY_FAILED`, `POLICY_BLOCKED`, `PAGINATION_REQUIRED`, `PARTIAL`, and `NOT_FOUND` must never be collapsed into one absence value.

Every result remains:

```text
status: HOLD
acquisition_authority: separate_policy_required
```

## 7. TimeMap response integrity

Every received TimeMap response records:

- request URL;
- retrieval timestamp;
- HTTP status;
- content type;
- byte length;
- SHA-256 of the exact received bytes.

This hash proves which TimeMap serialization was parsed. It does not prove that the aggregator or candidate archive statement was truthful.

## 8. Redirect and recursion policy

Implicit redirects are disabled. The adapter identifies `rel="timemap"` links but does not follow them.

A future redirect or recursive traversal capability requires:

- source-specific host validation at every hop;
- transport-level DNS and address validation;
- cycle, page-count, depth, and total-byte limits;
- updated privacy and SSRF analysis;
- dedicated negative tests;
- separate review and explicit GO.

Until then, index and paging TimeMaps are reported as `PARTIAL` or `PAGINATION_REQUIRED` rather than silently treated as absence.

## 9. Security properties

The implementation addresses:

- Memento aggregator spoofing;
- provenance laundering;
- redirect-chain attacks;
- private-address and credential-bearing URLs;
- malformed link-format and parser ambiguity;
- unapproved archive injection;
- conflicting or non-GMT datetimes;
- `anchor`-based context substitution;
- service throttling and retry abuse;
- negative, malformed, and non-finite `Retry-After` values;
- response-size exhaustion, including injected transports;
- silent conversion of failures or pagination into absence;
- accidental trust claims about candidate archive identity;
- cross-source status elevation.

## 10. Current test evidence

The focused suite covers 27 offline cases, including:

- disabled-by-default behavior with zero transport calls;
- enabled adapter rejection without a reviewed transport;
- successful multi-archive discovery;
- declared `source_archive` preservation with verification flags false;
- quoted RFC 1123 datetime parsing and strict GMT enforcement;
- original-resource and anchor mismatch;
- missing original relation;
- unapproved source archive;
- conflicting datetime for one Memento URI;
- 404 versus query failure;
- network failure;
- valid `Retry-After` behavior;
- negative `Retry-After` fallback;
- non-finite `Retry-After` fallback from an HTTP error;
- content-type rejection;
- empty complete TimeMap;
- endpoint and credential rejection;
- placeholder User-Agent rejection;
- URL construction containment;
- deterministic duplicate removal;
- injected-transport response-size enforcement;
- index TimeMap classification as `PAGINATION_REQUIRED`;
- paging TimeMap classification as `PARTIAL`;
- TimeMap SHA-256, byte length, HTTP status, and content-type recording;
- HOLD-preserving serialization.

All tests use injected offline transports. CI performs no live Memento request.

## 11. Non-goals

This change does not:

- activate a Memento aggregator;
- approve an archive host or transport;
- verify that a candidate URI is genuinely operated by the declared archive;
- acquire or hash Memento content;
- execute archived JavaScript;
- perform semantic comparison;
- recurse across TimeMaps;
- add recurring watchlists;
- modify `sentinel.wayback.evidence.v1`;
- create or sign receipts;
- implement Issue #30;
- authorize merge, production activation, or publication.

## 12. Promotion gates

Before any real endpoint is enabled, the source-specific change must provide:

- reviewed service terms and automated-access basis;
- exact host, DNS, address, and redirect policy;
- a reviewed transport implementation and tests;
- privacy assessment for URL-query disclosure;
- approved User-Agent identity;
- explicit TimeMap and source-archive allowlists;
- bounded pilot plan using approved public URLs;
- independent review and green required CI;
- documented SENTINEL activation GO.

Until then, the adapter remains testable but operationally disabled and all outputs remain HOLD.
