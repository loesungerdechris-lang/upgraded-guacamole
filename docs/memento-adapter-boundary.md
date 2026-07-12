# SENTINEL Memento TimeMap Adapter Boundary

**Document ID:** `sentinel.memento.adapter-boundary.v1-draft`  
**Status:** DRAFT / HOLD  
**Scope:** Phase 3 discovery adapter only  
**Parent:** Issue #29  
**Stacked dependency:** Draft PR #27

## 1. Purpose

This document defines the implementation boundary for the first executable Memento component in SENTINEL Phase 3.

The adapter parses RFC 7089 TimeMaps in `application/link-format` and records candidate Mementos with their actual source archive. It does not acquire the Memento bytes, render archived pages, recursively follow TimeMaps, change evidence status, sign receipts, or publish content.

## 2. Hard boundary

```text
Memento TimeMap response
    -> bounded parser
    -> source-isolated candidate records
    -> HOLD discovery result
```

The Memento service is discovery provenance only. The archive host contained in each Memento URI is the candidate capture source and is retained as `source_archive`.

A future acquisition operation must use a separately approved source adapter and policy for that actual archive. Discovery does not grant acquisition authority.

## 3. Default state

The adapter and repository policy are disabled by default:

```text
status: HOLD
enabled: false
acquisition_authority: separate_policy_required
memento_content_acquisition: false
active_content_execution: false
automatic_status_elevation: false
publication: false
```

Listing an adapter, endpoint, archive host, or Memento in configuration never enables network use by itself.

## 4. Request controls

An enabled test or future reviewed operation must provide:

- an exact credential-free HTTPS TimeMap base URL;
- a descriptive User-Agent with reviewed contact identity;
- an explicit allowlist of candidate source-archive hosts;
- bounded timeout, attempt, response-size, and Memento-count limits;
- GET-only operation;
- `Accept: application/link-format`;
- redirects disabled;
- no cookies, credentials, authorization headers, or case metadata;
- `Retry-After` handling and bounded backoff.

The repository contains no active production endpoint and no approved external source allowlist.

## 5. Parser rules

The parser:

- requires valid UTF-8 link-format input;
- handles commas inside quoted RFC 1123 datetimes;
- requires exactly one `rel="original"` link;
- binds that original link to the requested normalized URL;
- requires every `rel="memento"` link to contain a valid datetime;
- accepts only explicitly allowlisted public archive hosts;
- rejects credentials, private targets, ports, malformed parameters, duplicate parameters, conflicting datetimes, and oversized record sets;
- deduplicates only byte-equivalent candidate identity pairs;
- preserves raw and normalized datetime values;
- performs no content retrieval or semantic interpretation.

RFC 7089 defines TimeMaps as lists of Memento URIs and archival datetimes and requires support for the link-value serialization requested with `application/link-format`.

## 6. Result classes

The result classes are intentionally distinct:

- `SUCCESS` — a valid TimeMap yielded approved candidate records;
- `NOT_FOUND` — a valid 404 or valid TimeMap with no Memento records;
- `QUERY_FAILED` — transport, content-type, parser, identity, or source-policy validation failed;
- `POLICY_BLOCKED` — acquisition was not enabled by reviewed source policy.

`QUERY_FAILED`, `POLICY_BLOCKED`, and `NOT_FOUND` must never be collapsed into one absence value.

Every result remains:

```text
status: HOLD
acquisition_authority: separate_policy_required
```

## 7. Redirect and recursion policy

Implicit redirects are disabled. The adapter does not follow `rel="timemap"` links and does not recursively traverse index or paging TimeMaps.

A future redirect or recursive traversal capability requires:

- source-specific host validation at every hop;
- cycle and depth limits;
- updated privacy and SSRF analysis;
- dedicated negative tests;
- separate review and explicit GO.

## 8. Security properties

The implementation addresses:

- Memento aggregator spoofing;
- provenance laundering;
- redirect-chain attacks;
- private-address and credential-bearing URLs;
- malformed link-format and parser ambiguity;
- unapproved archive injection;
- conflicting archive datetimes;
- service throttling and retry abuse;
- response-size exhaustion;
- silent conversion of errors into absence;
- cross-source status elevation.

## 9. Current test evidence

The focused suite covers:

- disabled-by-default behavior with zero transport calls;
- successful multi-archive discovery;
- actual `source_archive` preservation;
- quoted datetime parsing;
- original-resource mismatch;
- missing original relation;
- unapproved source archive;
- conflicting datetime for one Memento URI;
- 404 versus query failure;
- network failure;
- `Retry-After` behavior;
- content-type rejection;
- malformed datetime;
- empty valid TimeMap;
- endpoint and credential rejection;
- placeholder User-Agent rejection;
- URL construction containment;
- deterministic duplicate removal;
- HOLD-preserving serialization.

All tests use injected offline transports. CI performs no live Memento request.

## 10. Non-goals

This change does not:

- activate a Memento aggregator;
- approve any archive host;
- acquire or hash Memento content;
- execute archived JavaScript;
- perform semantic comparison;
- recurse across TimeMaps;
- add recurring watchlists;
- modify `sentinel.wayback.evidence.v1`;
- create or sign receipts;
- implement Issue #30;
- authorize merge, production activation, or publication.

## 11. Promotion gates

Before any real endpoint is enabled, the source-specific change must provide:

- reviewed service terms and automated-access basis;
- exact host and redirect policy;
- privacy assessment for URL-query disclosure;
- approved User-Agent identity;
- explicit source-archive allowlist;
- bounded pilot plan using approved public URLs;
- independent review and green required CI;
- documented SENTINEL activation GO.

Until then, the adapter remains a testable but operationally disabled Phase 3 component.
