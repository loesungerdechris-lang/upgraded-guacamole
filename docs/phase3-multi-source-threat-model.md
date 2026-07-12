# SENTINEL Phase 3 Multi-Source Historical Evidence Threat Model

**Threat model ID:** `sentinel.historical-web.multi-source.threat-model.v1-draft`  
**Status:** DRAFT / HOLD  
**Date:** 2026-07-12  
**Applies to:** Issue #29 and reviewed Phase 3 successors  
**Dependencies:** Draft PR #27, Issue #28, `docs/phase3-multi-source-historical-evidence-spec.md`  
**Publication dependency:** Issue #30

## 1. Security objective

The Phase 3 engine must increase historical-web coverage and comparison capability without widening source trust implicitly, confusing provenance, executing untrusted active content, leaking sensitive case context, converting source redundancy into truth claims, or weakening the `HOLD` release boundary.

The system records what independently governed sources returned. It does not certify that archived statements are true, complete, original, continuously available, legally admissible, or published at an archive capture timestamp.

## 2. Scope

This threat model covers:

- source-policy resolution;
- target and watchlist resolution;
- archive and local-capture discovery;
- source-specific acquisition adapters;
- URL, redirect, timestamp, and capture-identity validation;
- local artifact materialization and hashing;
- source-record normalization;
- deterministic cross-verification;
- conflict and gap reporting;
- restricted operational logging;
- optional receipt references;
- the boundary to the separate manual publication gate.

It applies to the Internet Archive Wayback Machine, separately governed archive.today-family services, Perma.cc, Memento aggregators, ArchiveBox, SingleFile, and future reviewed Evidence Sources.

## 3. Explicitly out of scope

This model does not authorize or cover:

- bypassing authentication, paywalls, robots controls, access restrictions, or technical protections;
- acquisition of non-public material;
- automatic Save Page Now or equivalent archive-write operations;
- browser execution of archived JavaScript, plugins, forms, trackers, or other active content;
- automatic truth scoring, guilt inference, identity inference, or legal-admissibility decisions;
- automatic status elevation from `HOLD` to `VERIFIED` or `PUBLISHED`;
- receipt creation, private-key custody, signing, or publication execution;
- unrestricted whole-domain crawling;
- production activation before all applicable GO gates are met.

Issue #30 governs only the receipt-bound publication transition. A bounded offline Phase 3 pilot may be designed and tested under `HOLD` before publication exists, but no Phase 3 output may be published through that pilot.

## 4. Protected assets

The system must protect:

1. **Source identity** — which archive or local tool produced each record.
2. **Primary provenance** — original URL, archive URL or local record ID, source timestamp, timestamp semantics, retrieval time, source metadata, and policy version.
3. **Artifact integrity** — exact bytes, byte length, SHA-256, and safe local path.
4. **Manifest integrity** — deterministic ordering, canonicalization, and hash binding.
5. **Comparison integrity** — exact inputs, normalization rules, windows, conflicts, gaps, and report hash.
6. **Trust boundaries** — source-specific hosts, redirects, credentials, terms, and allowed operations.
7. **Release state** — `HOLD`, internal `VERIFIED`, and unavailable `PUBLISHED` until the separate gate exists.
8. **Case confidentiality** — watchlists, sensitive query context, review packets, and personal-data decisions.
9. **Operator safety** — prevention of malicious active content, path attacks, resource exhaustion, and misleading output.
10. **Auditability** — reproducible evidence chains without secret or private-key material.

## 5. Trust boundaries

### 5.1 Target registry boundary

Only explicitly approved public HTTP(S) targets may enter acquisition. Raw operator input is untrusted until normalized and checked against target policy.

### 5.2 Source-policy boundary

Every Evidence Source has an independent versioned policy. A policy record is configuration, not authority. Disabled acquisition remains disabled even if the source appears in a manifest or comparison request.

### 5.3 Adapter boundary

Each source adapter is isolated. Adapters must not share implicit cookies, credentials, redirects, transport trust, host allowlists, timestamp assumptions, or response parsers.

### 5.4 External network boundary

Archive services and aggregators are untrusted external systems. Their status codes, headers, redirects, timestamps, content types, metadata, and bytes are evidence inputs, not trusted assertions.

### 5.5 Local bundle boundary

Returned bytes cross into controlled local storage only after bounded acquisition and capture-identity checks. Writes must resist traversal, symlink escapes, overwrite races, and partial-state ambiguity.

### 5.6 Normalization boundary

Source-native metadata may be copied into namespaced fields but must not overwrite the common provenance envelope or be translated silently into publication semantics.

### 5.7 Cross-verification boundary

The comparison engine consumes already acquired source records. It does not gain network authority from those records and must not fetch additional sources implicitly.

### 5.8 Release boundary

Cross-verification output remains `HOLD`. Internal review may later produce `VERIFIED`; publication remains impossible until Issue #30 is implemented and separately approved.

## 6. Adversaries and failure actors

Relevant actors include:

- a malicious or compromised archive service;
- an archive returning stale, substituted, wrapped, or source-confused content;
- a hostile public target attempting SSRF, redirect abuse, decompression bombs, malformed content, or parser exploitation;
- an operator accidentally selecting the wrong URL, timestamp, source, policy, or comparison window;
- a malicious insider attempting to remove limitations, relabel sources, weaken role thresholds, or force publication;
- a compromised dependency, CI action, adapter package, or local capture tool;
- an external observer learning sensitive investigative interests from archive queries;
- an attacker placing symlinks or filesystem objects in the reconstruction root;
- a reviewer overinterpreting multiple archive matches as factual corroboration;
- ordinary outages, schema changes, rate limiting, clock differences, and incomplete captures.

## 7. Security assumptions

The model assumes:

- cryptographic SHA-256 remains suitable for integrity binding;
- canonical JSON behavior is versioned and deterministic;
- approved public trust registries are obtained through an authenticated process;
- local restricted storage and access controls are correctly administered;
- source-specific terms and automation policies are reviewed before connector activation;
- operators do not supply credentials through URLs or manifests;
- publication and signing remain outside Phase 3 adapters and comparison code.

A failed assumption creates a blocker or explicit limitation; it is not silently accepted.

## 8. Threat catalogue and required controls

### T01 — SSRF and special-address access

**Threat:** A target URL resolves to loopback, private, link-local, multicast, reserved, cloud metadata, or other non-public infrastructure, including numeric IPv4 aliases or DNS rebinding.

**Controls:**

- HTTP(S) only;
- reject URL credentials and ambiguous host syntax;
- normalize hosts before policy comparison;
- reject private and special literal addresses, including inet_aton-style aliases;
- approved public target registry;
- validate each redirect target;
- production adapters must not accept caller-supplied arbitrary transports;
- where DNS is used, validate resolved addresses at connection time and after redirects.

**Failure state:** acquisition fails; no absence claim is emitted.

### T02 — Source-host and redirect confusion

**Threat:** A source redirects to an unapproved domain, CDN, login page, download host, or attacker-controlled endpoint.

**Controls:**

- exact source-specific host allowlist;
- redirect count and destination revalidation;
- no inherited Wayback allowlist for secondary archives;
- record the final approved source URL separately;
- reject credentials and cross-origin authentication forwarding.

**Failure state:** source path returns `SOURCE_POLICY_NOT_AUTHORIZED` or explicit acquisition failure.

### T03 — Replay or capture identity substitution

**Threat:** Returned bytes belong to a different original URL, timestamp, capture, or replay wrapper.

**Controls:**

- bind replay URL, embedded target, and selected source timestamp;
- preserve source-native identifiers;
- record status, MIME type, digest, and response metadata;
- reject soft identity mismatches rather than rewriting them;
- distinguish replay wrapper bytes from archived payload bytes.

**Failure state:** `TARGET_MISMATCH`, `CAPTURE_WINDOW_MISMATCH`, or acquisition failure.

### T04 — Malformed API response interpreted as absence

**Threat:** Rate limits, HTML error pages, changed JSON schemas, or partial responses are interpreted as “no snapshot.”

**Controls:**

- strict response shape and content-type checks;
- distinguish empty valid result from malformed response;
- honor `Retry-After` and bounded backoff;
- record archive-specific error class;
- never turn adapter errors into successful missing-source findings.

**Failure state:** source error with preserved uncertainty.

### T05 — Credential and secret leakage

**Threat:** Credentials, cookies, tokens, account identifiers, private query context, or signed URLs leak to archive services, logs, manifests, or CI.

**Controls:**

- no credentials in target URLs;
- source-specific authentication policy;
- no shared cookie jar across adapters;
- redact sensitive query components from logs;
- secret scanning and bounded fixtures;
- no private keys or authentication tokens in evidence bundles;
- Perma.cc account or creation workflows require separate policy and explicit operation approval.

**Failure state:** blocker; affected output is not retained as releasable evidence.

### T06 — Tracking and case-interest disclosure

**Threat:** External archives learn sensitive investigative interests from requested URLs, timing, source selection, or repeated watchlist access.

**Controls:**

- data minimization and approved case targets;
- do not transmit case labels, allegations, victim names, internal notes, or unrelated metadata;
- controlled schedules and bounded request patterns;
- restricted logs;
- privacy review before activating sensitive watchlists;
- source-specific risk decision for high-sensitivity cases.

**Residual risk:** a source necessarily observes the public URL and request time. This must be documented.

### T07 — Aggressive parallelism and service abuse

**Threat:** Orchestration violates archive policies, creates denial of service, triggers blocks, or produces inconsistent throttled results.

**Controls:**

- global and per-source concurrency limits;
- token-bucket or equivalent rate limiting;
- honor `Retry-After`;
- bounded retries with jitter;
- descriptive User-Agent where permitted;
- no automatic all-source fan-out merely because adapters exist;
- explicit source selection from an approved operation plan.

**Failure state:** partial source report; never increased confidence.

### T08 — Oversized, compressed, or malicious payload

**Threat:** Decompression bombs, huge responses, parser bombs, malformed encodings, or polyglot files exhaust resources or exploit tooling.

**Controls:**

- compressed and decompressed byte limits;
- streaming hash with bounded storage;
- content-type and magic-byte recording;
- no automatic execution or rich preview;
- parser isolation for optional extraction;
- time, memory, file-count, nesting, and archive-depth limits;
- quarantine unexpected executable or active formats.

**Failure state:** artifact blocked or retained only as restricted raw bytes with explicit limitation.

### T09 — Active-content execution

**Threat:** Archived JavaScript, forms, trackers, service workers, plugins, macros, or browser exploits execute during reconstruction or comparison.

**Controls:**

- acquire bytes without execution;
- offline reconstruction with active content disabled;
- no browser automation in core adapters;
- no network fallback;
- content security restrictions for any future viewer;
- separate sandbox threat model, approval, and implementation for active rendering.

**Clarification:** semantic comparison does not inherently require JavaScript. Safe offline text or structural extraction from already acquired bytes may be separately reviewed. Any active rendering remains disabled by default.

### T10 — Live-resource contamination

**Threat:** Missing archived assets are silently loaded from the current live web, producing a mixed historical/current page.

**Controls:**

- local-only resource resolution;
- block network in offline viewers;
- explicit missing-resource report;
- mixed-timestamp asset graph labeling;
- no repair from live content without a separate reviewed operation and new evidence record.

**Failure state:** incomplete reconstruction with limitations, never silent substitution.

### T11 — Filesystem traversal, symlink, and race attacks

**Threat:** Relative paths, symlinks, hard links, special files, or races write outside the approved bundle or replace evidence.

**Controls:**

- normalized relative paths only;
- resolved-root containment checks;
- reject symlink parents and targets;
- exclusive file creation and no overwrite;
- regular-file checks;
- temporary sibling directory plus atomic finalize where appropriate;
- rehash after materialization.

**Failure state:** no partial successful bundle claim.

### T12 — Provenance laundering

**Threat:** A secondary archive, Memento result, or local capture is represented as Internet Archive evidence or inherits another source's trust.

**Controls:**

- immutable `source_id`, `source_class`, and policy version;
- source-specific records and hashes;
- `acquisition_authority: separate_policy_required` until activation;
- Memento is discovery provenance only; underlying archive remains the capture source;
- local tools are labeled local captures;
- comparison reports never rewrite source origin.

**Failure state:** `SOURCE_PROVENANCE_INCOMPLETE` or validation failure.

### T13 — Timestamp semantic confusion

**Threat:** Capture, creation, preservation, retrieval, modification, and publication times are conflated.

**Controls:**

- mandatory `source_timestamp_semantics`;
- separate retrieval timestamp;
- no automatic publication-date inference;
- documented comparison windows;
- mixed-clock and missing-time limitations;
- human review for historical assertions.

**Failure state:** `TIMESTAMP_SEMANTICS_INCOMPATIBLE` or `TIMESTAMP_AMBIGUITY`.

### T14 — False confidence from redundancy

**Threat:** Multiple archives copied the same source or one another, and agreement is presented as independent proof of truth.

**Controls:**

- distinguish preservation agreement from factual corroboration;
- record known source-dependence limits;
- no truth score or majority vote;
- no state change from source count;
- substantive claims require separate primary-source and contextual review.

**Residual risk:** source independence may be unknowable. Reports must say so.

### T15 — Conflict suppression or “best version” synthesis

**Threat:** The engine hides disagreements, selects a preferred capture, or creates a composite representation without evidentiary traceability.

**Controls:**

- deterministic conflict taxonomy;
- preserve every compared source-record hash;
- no automatic reconciliation;
- no “best-of” page generation;
- separate human decision artifact if a representative version is chosen;
- a conflict cannot become agreement by majority vote.

**Failure state:** explicit conflict and continued HOLD.

### T16 — Canonicalization and comparison collision

**Threat:** URL normalization, text extraction, whitespace folding, encoding conversion, or canonical representation causes distinct evidence to compare equal.

**Controls:**

- raw-byte SHA-256 remains primary representation integrity;
- canonical representation algorithms are versioned and separately hashed;
- retain exact extraction tool and version;
- compare normalization output only within compatible profiles;
- never replace raw hashes with semantic hashes.

**Failure state:** comparison downgraded to a lower confidence level.

### T17 — Parser and extraction compromise

**Threat:** HTML, PDF, image, archive, or text parsers are exploited during optional offline extraction.

**Controls:**

- extraction disabled unless explicitly selected;
- isolated process or sandbox with no network and least privilege;
- pinned and scanned dependencies;
- CPU, memory, time, and output limits;
- raw bytes preserved independently;
- extraction output receives its own provenance and hash.

**Failure state:** extraction fails without invalidating preserved raw evidence.

### T18 — Local capture misclassification

**Threat:** ArchiveBox or SingleFile output is presented as an independent historical archive capture.

**Controls:**

- classify as `local_capture`;
- record tool version, capture environment, active-content behavior, operator, time, and input URL;
- do not claim historical existence before local capture time;
- local capture never inherits third-party archive status.

**Failure state:** validation error or explicit local-capture limitation.

### T19 — Status elevation and publication bypass

**Threat:** Code, CI, a manifest edit, cross-verification result, or empty blocker list elevates `HOLD` to `VERIFIED` or `PUBLISHED`.

**Controls:**

- Phase 3 acquisition and comparison always emit HOLD outputs;
- internal VERIFIED requires explicit review-aware validation;
- PUBLISHED remains rejected until Issue #30;
- no `is_publishable` shortcut;
- no automatic pipeline state mutation;
- exact predecessor and signed receipt checks in the future publication verifier;
- separate explicit GO for publication action.

**Failure state:** HOLD.

### T20 — Review-role collapse and insider manipulation

**Threat:** One person or compromised account controls acquisition, review, release roles, or trust configuration.

**Controls:**

- role-bound external keys;
- legal, privacy, and SENTINEL release separation;
- CODEOWNERS and independent review;
- immutable review-packet hash;
- protected branch and environment controls;
- no private signing keys in repository code;
- audit trail for policy and trust changes.

### T21 — Supply-chain compromise

**Threat:** A dependency, GitHub Action, adapter package, container, or local tool changes behavior or exfiltrates data.

**Controls:**

- immutable action pins;
- pinned reviewed dependencies;
- secret scans, CodeQL, vulnerability scans, and dependency review;
- minimal permissions and non-persisted checkout credentials;
- isolated adapters and reproducible fixtures;
- software bill of materials and provenance for production builds before activation.

### T22 — Retention and unauthorized disclosure

**Threat:** Sensitive historical bundles, personal data, or victim-identifying material are retained too long or accessed broadly.

**Controls:**

- case-specific retention and legal-hold decision;
- restricted storage and least privilege;
- immutable access audit;
- minimization and redaction as separate derived artifacts;
- deletion or preservation decisions documented;
- public availability at capture time does not waive privacy obligations.

### T23 — Misleading absence and coverage metrics

**Threat:** Missing snapshots, failed adapters, or incomplete watch windows are presented as evidence that information did not exist.

**Controls:**

- distinguish `NOT_FOUND`, `NOT_QUERIED`, `QUERY_FAILED`, `POLICY_BLOCKED`, and `UNKNOWN`;
- report exact query window and source policy;
- mandatory non-existence limitation;
- coverage metrics never become truth claims.

### T24 — Release destination substitution

**Threat:** Approved content is published to a different destination, scope, path, audience, or format.

**Controls:**

- future Class A receipt binds exact scope and destination;
- publication action is separate from verification;
- immutable artifact-set hash;
- no wildcard destination authorization;
- post-publication receipt and deployed-byte verification in any future implementation.

## 9. Cross-verification security levels

Phase 3 uses the levels defined in the architecture specification:

- **Level 0 — unrelated:** no defensible target identity relationship;
- **Level 1 — same target:** same normalized original URL only;
- **Level 2 — temporally comparable:** compatible source timestamps within a documented window;
- **Level 3 — representation agreement:** byte-identical or separately defined canonical representation agreement;
- **Level 4 — independently preserved claim fragment:** human-reviewed exact ranges preserved by multiple source records.

No level changes release status automatically.

A separate optional semantic-extraction profile may compare text or document structure without executing active content. It must record extraction tool, version, normalization profile, output hash, and limitations. Active JavaScript rendering is a different, currently disabled capability and must not be smuggled into semantic comparison.

## 10. Required conflict taxonomy

At minimum, implementations must preserve and report:

- `TARGET_MISMATCH`;
- `TIMESTAMP_SEMANTICS_INCOMPATIBLE`;
- `CAPTURE_WINDOW_MISMATCH`;
- `BYTE_HASH_MISMATCH`;
- `CANONICAL_REPRESENTATION_MISMATCH`;
- `MIME_TYPE_MISMATCH`;
- `STATUS_CODE_MISMATCH`;
- `MISSING_PRIMARY_RESOURCE`;
- `MISSING_SECONDARY_RESOURCE`;
- `QUERY_FAILED`;
- `POLICY_BLOCKED`;
- `MIXED_TIMESTAMP_ASSET_GRAPH`;
- `SOURCE_PROVENANCE_INCOMPLETE`;
- `SOURCE_POLICY_NOT_AUTHORIZED`;
- `ACTIVE_CONTENT_NOT_EVALUATED`;
- `PRIVACY_REVIEW_REQUIRED`;
- `SOURCE_INDEPENDENCE_UNKNOWN`.

Severity is operational triage metadata, not a truth score. A `BYTE_HASH_MISMATCH` requires review but does not by itself prove tampering; archives may capture different timestamps, encodings, wrappers, or representations.

## 11. Abuse cases that must be tested

A reviewed implementation must include negative evidence for at least:

1. numeric loopback and private-address targets;
2. DNS or redirect transition to a private or unapproved host;
3. credential-bearing target and archive URLs;
4. malformed archive API response not treated as absence;
5. mismatched replay target or timestamp;
6. oversized and compressed payload rejection;
7. no archived JavaScript execution;
8. no live-resource fallback;
9. traversal and symlink escape rejection;
10. source-origin substitution and Memento provenance laundering;
11. source-policy disabled but source listed in manifest;
12. rate-limit and `Retry-After` behavior;
13. one adapter failure while others complete, with no confidence increase;
14. byte-hash disagreement preserved as conflict;
15. extraction failure while raw artifact remains intact;
16. missing source distinguished from failed query;
17. local capture not classified as independent archive evidence;
18. cross-source agreement unable to elevate HOLD;
19. removed limitation or changed artifact invalidating prior review;
20. publication attempt rejected without Issue #30 gate.

## 12. Security acceptance evidence

Phase 3 remains HOLD until the scoped implementation provides:

- versioned source-policy schema;
- exact allowlists and redirect rules per enabled source;
- isolated adapter per source;
- public-target validation including DNS and numeric aliases;
- bounded time, memory, byte, file-count, concurrency, and retry behavior;
- deterministic source-record and comparison-report hashes;
- full conflict and gap fixtures;
- active-content non-execution evidence;
- local storage traversal and symlink tests;
- credential and sensitive-log tests;
- source-specific timestamp fixtures;
- privacy review for the bounded pilot;
- rights and terms review for each enabled source;
- supply-chain scan and immutable CI pins;
- independent review;
- documented GO/HOLD decision.

Production activation additionally requires Phase 1 to be independently reviewed and merged, Phase 2 boundaries to be stable, source-specific operational approval, and an explicit activation GO.

Publication additionally requires Issue #30 and a separate explicit publication GO.

## 13. Residual risks

Even after controls:

- archives can contain incomplete, altered, wrapped, or misleading material;
- source independence may be unknown;
- capture timestamps may not reveal publication time;
- public URL queries disclose some investigative interest to the queried service;
- historical context can be missing;
- rights and privacy decisions remain human and jurisdiction-specific;
- identical bytes prove representation identity, not factual truth;
- a signed release proves an approved decision chain, not legal admissibility in every forum.

Every residual risk relevant to a bundle must appear in its limitations or review packet.

## 14. Monitoring and incident response

Operational monitoring should record bounded metadata only:

- source ID and policy version;
- approved target registry ID;
- operation class;
- request result class;
- retry and rate-limit events;
- byte and artifact counts;
- source-record and comparison-report hashes;
- validation issue codes.

Do not log credentials, full sensitive query strings, case allegations, unnecessary personal data, or private review content.

A suspected adapter compromise, source-policy bypass, provenance substitution, secret leak, or unauthorized publication attempt requires:

1. immediate adapter and schedule disablement;
2. preservation of relevant audit logs and hashes;
3. affected-output HOLD classification;
4. trust and credential review;
5. scope analysis and notification under applicable policy;
6. corrected implementation through a separate reviewed change;
7. no silent repair of previously emitted evidence.

## 15. Change control

Any change that adds or widens:

- a trusted host;
- credentials or account use;
- archive writes;
- parallelism or recurring schedules;
- active rendering;
- extraction parsers;
- normalization semantics;
- comparison levels;
- source classes;
- release roles or thresholds;
- publication capability;

requires a separate issue, scoped pull request, updated threat analysis, dedicated negative tests, independent review, green required CI, and explicit SENTINEL GO.

Until all applicable controls are evidenced, the capability remains disabled and fails closed.
