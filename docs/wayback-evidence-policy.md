# SENTINEL Historical Web Evidence Policy

**Policy ID:** `sentinel.wayback.policy.v1`  
**Manifest:** `sentinel.wayback.evidence.v1`  
**Default state:** `HOLD`  
**Operating model:** evidence-first, fail-closed, local/offline first

## 1. Purpose and global scope

The SENTINEL Wayback Evidence Layer is a reusable core component for preserving,
reconstructing, comparing, and verifying publicly accessible historical web data.

It applies globally and identically across municipal, regional, national, and
international work. Initial use cases include Ilmenau, the Ilm-Kreis, Thüringen
authorities, Teich Am Ilmufer, the former Fischerhütte paint-factory site, the
Ilm-Rennsteig cycle route, engineering firms, public procurement, project pages,
historical maps, mineral-oil and tank installations, and missing project records.
The same controls apply to other authorities, critical infrastructure, research,
resilience work, and transparency initiatives.

An archive capture is evidence of what an archive returned for a requested capture.
It is not automatically proof that the content was true, complete, continuously
available, officially published at the archive timestamp, or legally reusable.

## 2. Immutable core rules

1. The Wayback acquisition component may communicate only with approved official
   Internet Archive endpoints on `archive.org` and `web.archive.org`.
2. Every acquired artifact must preserve:
   - original URL;
   - archive replay URL;
   - archive capture timestamp;
   - retrieval timestamp;
   - source identity and origin;
   - byte length;
   - SHA-256 digest;
   - safe local bundle path.
3. A Wayback capture timestamp must never be represented automatically as a
   publication date, creation date, or proof of continuous existence.
4. A missing capture must never be interpreted as proof that a page or statement
   never existed.
5. Reconstruction is local and offline first. A reconstructed bundle must not
   silently substitute live resources.
6. Archived JavaScript, forms, plugins, embedded applications, and active content
   must not be executed during acquisition or reconstruction.
7. Reconstructed or archived material must not be published or operationally reused
   without separate rights, privacy, provenance, and SENTINEL release reviews.
8. The default publication state is `HOLD`; `publish_restored_content` is `false`.
9. Every evidence bundle must have a deterministic versioned manifest and an
   independently verifiable manifest hash.
10. Known limitations and uncertainty must be recorded explicitly. No overclaims
    are permitted.
11. Automated access must use a descriptive User-Agent, bounded requests, restrained
    concurrency, response-size limits, timeouts, and compliant retry behavior.
    `Retry-After` must be respected.
12. Save Page Now is a separate controlled write process and is never triggered
    automatically by the read-only evidence layer.
13. Nothing leaves the system without an explicit, documented release decision.

## 3. Trust boundary

### 3.1 Primary Wayback source

The Phase 1 implementation trusts only these fixed Internet Archive functions:

- Availability API: `https://archive.org/wayback/available`
- CDX API: `https://web.archive.org/cdx/search/cdx`
- Replay origin: `https://web.archive.org`

Redirects outside the approved hosts fail closed. Credentials, private or local
network targets, unsafe numeric IP aliases, mismatched replay URLs, malformed
responses, oversized payloads, path traversal, and symlink escapes are rejected.

### 3.2 Separate historical evidence sources

Phase 3 may record evidence from other sources, including archive.today, Perma.cc,
Memento aggregators, ArchiveBox, and SingleFile. These are separate evidence
sources, not Internet Archive hosts.

Each source requires its own acquisition policy, provenance record, timestamp
semantics, SHA-256 digest, limitations, and trust classification. Merely recording
a Phase 3 cross-verification entry does not authorize network access to that source.
The Wayback trust boundary must not be widened implicitly.

## 4. Provenance and deterministic manifests

Each bundle uses `sentinel.wayback.evidence.v1` or a reviewed successor. The
manifest binds:

- schema version and state;
- fixed primary source identity;
- target URL;
- selected Wayback snapshot;
- acquisition observation time;
- artifact records and hashes;
- mandatory interpretation limits;
- release-gate state;
- optional separately governed cross-verification records;
- deterministic manifest hash.

SHA-256 values use the form `sha256:<64 lowercase hexadecimal characters>`.

The manifest hash covers the complete manifest except the `manifest_hash` field
itself. Changes to provenance, limitations, release state, or artifact metadata
invalidate the hash.

## 5. State and release model

### HOLD

`HOLD` is mandatory for newly acquired and reconstructed evidence.

- mode: `offline_preview_only`
- rights review: required
- privacy review: required
- provenance review: required
- SENTINEL release: HOLD
- publication: false

### VERIFIED

`VERIFIED` means internal review has passed. It does not authorize publication.

- mode: `offline_reviewed`
- rights, privacy, and provenance reviews: approved
- SENTINEL release: HOLD
- publication: false

The default validator rejects non-HOLD manifests unless the caller explicitly
selects release-aware validation.

### PUBLISHED

`PUBLISHED` is permitted only after a separate release workflow.

- mode: `released`
- rights, privacy, and provenance reviews: approved
- SENTINEL release: approved
- publication: true
- a release-receipt SHA-256 is required

Changing a JSON field is not a release decision. The release receipt and its
authorization chain must be verified independently.

## 6. Local reconstruction rules

1. Write only caller-supplied, already acquired bytes.
2. Resolve the destination root before writing.
3. Reject absolute paths, empty paths, `.` and `..` components, path traversal,
   symbolic-link targets, symbolic-link parent escapes, and pre-existing temporary
   files.
4. Create files atomically through an exclusive temporary file.
5. Recompute and verify byte length and SHA-256 from local files.
6. Produce missing-resource reports instead of loading live replacements.
7. Keep reconstructed pages visually and operationally distinguishable from current
   official pages.

## 7. Phased implementation

### Phase 1: secure acquisition and offline reconstruction

Implemented in Draft PR #27:

- fixed-host snapshot discovery;
- bounded read-only capture retrieval;
- deterministic artifact and manifest hashing;
- local-only reconstruction;
- schema and semantic validation;
- HOLD enforcement;
- offline tests and dedicated CI;
- no publication, active rendering, or Save Page Now automation.

Independent review and all required checks remain mandatory before merge.

### Phase 2: domain watchlists and verified site reconstruction

Tracked in Issue #28:

- versioned approved target registry;
- exact, prefix, and domain discovery with bounded pagination and caching;
- capture counts, first and last captures, digest changes, MIME types, and status;
- reports for deleted pages, altered statements, PDFs, images, tenders, project
  references, and named contractors;
- asset graphs and missing-resource reports;
- multi-timestamp comparison and mixed-timestamp disclosure;
- optional SENTINEL receipt linkage;
- georeferenced overlays where evidentially appropriate;
- documented GO/HOLD decision before recurring operation.

### Phase 3: Multi-Source Historical Evidence Engine

Phase 3 adds redundancy without weakening source separation.

- primary: Internet Archive Wayback Machine;
- secondary, independently governed sources: archive.today and Perma.cc;
- federated time discovery: Memento protocol and aggregators;
- optional local capture: ArchiveBox and SingleFile;
- source-specific provenance and SHA-256 for every artifact;
- cross-verification where capture identity and timestamp semantics permit it;
- disagreement reports rather than silent reconciliation;
- source availability and evidential-limit reporting.

No Phase 3 connector inherits the Wayback allowlist. Each requires a reviewed
source policy and tests before acquisition is enabled.

## 8. SENTINEL Receipt integration

A later reviewed integration may bind the manifest hash, artifact hashes, policy
version, reviewer decisions, and release state into SENTINEL Receipts.

Receipt linkage strengthens integrity and decision traceability; it does not by
itself prove factual truth, copyright permission, privacy compliance, or legal
admissibility.

## 9. Sensitive historical cases

The layer may preserve publicly accessible historical records connected to sensitive
events, investigations, or abuse, including deleted or modified pages from the
Epstein-files era and comparable cases.

Such work must remain victim-first and evidence-first:

- collect only lawfully accessible public material;
- minimize unnecessary personal and sensitive data;
- distinguish archived statements from verified facts;
- avoid speculation, identification by inference, and guilt by association;
- keep restored content on HOLD until dedicated legal, privacy, provenance, and
  release reviews are complete;
- preserve limitations and contradictory evidence.

## 10. Required interpretation limits

Every v1 manifest must state at least:

- archive timestamp is not automatically the publication timestamp;
- missing captures do not prove that content never existed;
- archived replay may omit dynamic or externally hosted resources.

Additional case-specific limits are encouraged and must never be removed merely to
make a finding appear stronger.

## 11. Non-goals

The core layer does not:

- certify the truth of archived content;
- certify legal admissibility;
- bypass authentication or access controls;
- collect non-public content;
- execute archived code;
- impersonate a current authority or website;
- publish restored material automatically;
- infer non-existence from archive gaps;
- merge distinct archive sources into a single undocumented provenance chain.

## 12. Change control

Changes that widen trusted hosts, enable write operations, execute active content,
allow live-resource fallback, relax HOLD, introduce publication, or automate
recurring acquisition require a separate reviewed change, dedicated tests, and an
explicit SENTINEL GO decision.

Until then, the system fails closed.
