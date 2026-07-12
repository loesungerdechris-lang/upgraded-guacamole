# SENTINEL Phase 3 Multi-Source Historical Evidence Engine

**Specification ID:** `sentinel.historical-web.multi-source.v1-draft`  
**Status:** DRAFT / HOLD  
**Authority:** architecture and validation design only  
**Primary dependency:** Draft PR #27  
**Planning issue:** #29

## 1. Purpose

Phase 3 extends the reviewed Wayback Evidence Layer into a redundant historical-web evidence engine. It increases coverage and comparison capability without widening the Internet Archive trust boundary or weakening provenance, privacy, rights, or release controls.

The engine records what independently governed sources returned. It does not certify factual truth, legal admissibility, continuous historical existence, or publication dates.

## 2. Immutable architectural rules

1. The Internet Archive Wayback Machine remains the primary source and keeps its fixed official-host allowlist.
2. Every additional archive, aggregator, or local capture tool is a separate Evidence Source.
3. No source inherits another source's trust, credentials, timestamp semantics, release status, or network allowlist.
4. Every source record has its own provenance, SHA-256, limitations, and acquisition authority.
5. Cross-verification reports agreement, disagreement, and gaps; it never silently merges incompatible captures.
6. Missing records from one or more sources do not prove non-existence.
7. Live resources are never substituted into an offline reconstruction without an explicit, separately reviewed operation.
8. Archived JavaScript and active content are not executed by the core engine.
9. New sources and recurring acquisition remain disabled until a source-specific policy, tests, and explicit GO decision exist.
10. Publication remains outside Phase 3 acquisition and comparison. The default state is HOLD.

## 3. Source classes

### 3.1 Primary archive

`internet-archive-wayback`

- official endpoints only;
- read-only acquisition;
- fixed replay binding;
- Internet Archive capture timestamp semantics;
- current implementation in Draft PR #27.

### 3.2 External archives

Examples include archive.today-family services and Perma.cc.

Each adapter requires:

- exact reviewed host list;
- terms and automated-access review;
- redirect and credential policy;
- source-specific timestamp interpretation;
- response-size and retry limits;
- dedicated fixtures and negative tests;
- `acquisition_authority: separate_policy_required` until activated.

### 3.3 Memento discovery sources

Memento aggregators may discover candidate captures across archives. A Memento response is not the provenance of the underlying capture. Every returned Memento must be attributed to its actual archive and then processed under that archive's source policy.

### 3.4 Local capture tools

ArchiveBox and SingleFile may be used only in controlled local infrastructure. Their outputs are local captures, not third-party archive captures. The record must identify tool version, capture environment, capture time, input URL, local artifact hashes, and active-content behavior.

## 4. Components

### 4.1 Source policy registry

A versioned registry defines source identity, class, approved hosts, allowed operations, rate limits, timestamp semantics, authentication rules, and HOLD gates.

The registry is configuration, not authority. An entry with disabled acquisition cannot be used to make a network request.

### 4.2 Acquisition adapters

One isolated adapter per approved source. Adapters expose a narrow interface and may not share implicit redirects, cookies, credentials, or host trust.

Conceptual interface:

```python
class HistoricalEvidenceAdapter:
    source_id: str

    def discover(self, target: ApprovedTarget, window: TimeWindow) -> tuple[Candidate, ...]: ...
    def acquire(self, candidate: Candidate) -> AcquiredArtifact: ...
```

Adapters return bytes and source metadata. They do not decide evidentiary meaning, release status, or publication.

### 4.3 Evidence normalizer

The normalizer creates a source-specific record with common envelope fields while preserving source-native metadata. It must never translate a source timestamp into a publication date.

### 4.4 Immutable local bundle store

Acquired bytes are written locally with traversal and symlink protection. Each file receives byte length and SHA-256. Bundle mutation creates a new manifest; it never rewrites an existing verified record silently.

### 4.5 Cross-verification engine

The engine compares normalized records and emits deterministic findings. It does not fetch new sources unless the acquisition layer has separate authority.

### 4.6 Conflict and gap reporter

The reporter produces machine-readable and human-readable reports for:

- capture presence and absence;
- timestamp differences;
- URL canonicalization differences;
- byte-identical and byte-different representations;
- mixed-timestamp asset graphs;
- missing resources;
- status-code and MIME-type differences;
- archive-specific errors and uncertainty.

### 4.7 Receipt binder

A later reviewed binder may reference manifest hashes and decision artifacts in SENTINEL Receipts. It remains verifier-oriented and does not hold private signing material.

## 5. Source evidence record

Every source record must include at least:

```text
source_id
source_class
source_policy_version
source_origin
original_url
archive_url_or_local_record_id
source_timestamp
source_timestamp_semantics
retrieval_timestamp
content_type
byte_length
sha256
local_relative_path
acquisition_authority
provenance_notes
limitations
```

Optional source-native fields are preserved in a namespaced metadata object. They must not overwrite common envelope fields.

## 6. Capture identity and comparison levels

Cross-verification results use explicit levels:

### Level 0: unrelated

Different normalized original URL or no defensible identity relationship.

### Level 1: same target

Same normalized original URL, but timestamps or representations are not sufficiently aligned.

### Level 2: temporally comparable

Same target and source timestamps fall within a documented comparison window. This does not imply byte identity.

### Level 3: representation agreement

Same target and byte-identical content hash, or a documented canonical representation hash, with compatible timestamp semantics.

### Level 4: independently corroborated claim fragment

A human-reviewed statement, file, or image is independently preserved by multiple sources and linked to exact artifact ranges. This strengthens preservation confidence only; it does not prove the statement is true.

No level changes HOLD, VERIFIED, or PUBLISHED status automatically.

## 7. Deterministic cross-verification output

A comparison report contains:

- report schema and version;
- target identity;
- ordered source record hashes;
- comparison window and normalization rules;
- agreement findings;
- disagreement findings;
- missing-source findings;
- timestamp-semantics notes;
- limitations;
- deterministic report hash.

Sources are sorted by stable source ID, archive URL or local record ID, source timestamp, and SHA-256 before hashing.

## 8. Conflict taxonomy

The engine must report, not conceal:

- `TARGET_MISMATCH`
- `TIMESTAMP_SEMANTICS_INCOMPATIBLE`
- `CAPTURE_WINDOW_MISMATCH`
- `BYTE_HASH_MISMATCH`
- `MIME_TYPE_MISMATCH`
- `STATUS_CODE_MISMATCH`
- `MISSING_PRIMARY_RESOURCE`
- `MISSING_SECONDARY_RESOURCE`
- `MIXED_TIMESTAMP_ASSET_GRAPH`
- `SOURCE_PROVENANCE_INCOMPLETE`
- `SOURCE_POLICY_NOT_AUTHORIZED`
- `ACTIVE_CONTENT_NOT_EVALUATED`
- `PRIVACY_REVIEW_REQUIRED`

A conflict cannot be converted into agreement by majority vote.

## 9. Acquisition flow

1. Resolve an approved target from the versioned target registry.
2. Resolve an enabled source policy.
3. Confirm the requested operation is allowed.
4. Perform bounded discovery with source-specific limits.
5. Validate candidate identity and URL safety.
6. Acquire bytes without executing archived active content.
7. Record source-native response metadata.
8. Write bytes to the local bundle safely.
9. Compute byte length and SHA-256 locally.
10. Create the source evidence record and deterministic hash.
11. Run offline comparison against selected existing records.
12. Emit conflict, gap, and limitation reports.
13. Keep all outputs on HOLD.

Any failed step stops the affected source path. Other source failures must not be rewritten as successful absence findings.

## 10. Threat model

### 10.1 SSRF and unsafe targets

Threats include private IPs, numeric loopback aliases, DNS rebinding, credential-bearing URLs, unsafe redirects, and protocol confusion.

Controls:

- approved public target registry;
- normalized HTTP(S) URLs only;
- private and special-address rejection;
- source-specific fixed host allowlists;
- redirect revalidation;
- no caller-supplied transport overrides in production paths.

### 10.2 Provenance confusion

Threat: representing a secondary source as Internet Archive evidence or merging source metadata.

Controls:

- immutable source IDs and classes;
- source-specific policy versions;
- separate records and hashes;
- no shared `source_origin` field mutation;
- explicit comparison reports.

### 10.3 Timestamp manipulation

Threat: treating capture timestamps as publication dates or aligning incompatible clocks.

Controls:

- mandatory timestamp-semantics field;
- no automatic publication-date inference;
- explicit comparison windows;
- mixed-timestamp disclosure.

### 10.4 Content substitution and archive ambiguity

Threat: redirects, soft-404s, replay wrappers, live-resource fallbacks, or mismatched embedded target URLs.

Controls:

- capture identity binding;
- local hashing of returned bytes;
- status and MIME recording;
- no live fallback;
- missing-resource reports.

### 10.5 Active content

Threat: archived JavaScript, forms, trackers, plugins, or malicious payloads.

Controls:

- byte acquisition without execution;
- offline reconstruction;
- content-type labeling;
- separate sandbox review for any future rendering;
- no browser automation in the core adapter.

### 10.6 Privacy and victim safety

Threat: unnecessary collection or release of personal, sensitive, or victim-identifying information.

Controls:

- public-source limitation;
- data minimization;
- case-specific access control;
- privacy review before VERIFIED;
- release review before publication;
- no inference-based identification.

### 10.7 False confidence from redundancy

Threat: multiple archives copying one another or independently preserving the same false statement.

Controls:

- distinguish preservation agreement from factual corroboration;
- record source independence limits;
- no truth score from source count;
- primary-source corroboration for substantive claims.

### 10.8 Supply-chain and adapter compromise

Controls:

- pinned dependencies and actions;
- isolated adapters;
- secret scanning;
- source-specific tests;
- least-privilege CI;
- no private signing material in the repository.

## 11. Privacy, retention, and access

Case owners define retention and access controls before acquisition. Sensitive bundles should use restricted storage, immutable audit logs, and documented deletion or preservation holds. Public availability at acquisition time does not remove privacy or rights obligations.

## 12. Observability

Operational logs record source ID, policy version, target registry ID, request class, result class, byte count, retry behavior, and evidence-record hash. Logs must not contain credentials, full sensitive query strings, or unnecessary personal data.

Metrics may include request counts, source failures, rate-limit events, capture counts, hash agreements, conflict counts, and missing-resource counts. Metrics do not change evidentiary status.

## 13. Acceptance evidence

Phase 3 cannot move beyond HOLD without:

- reviewed source-policy schema;
- one isolated adapter per approved source;
- exact host and redirect tests;
- SSRF and credential-leak tests;
- source-specific timestamp fixtures;
- deterministic record and report hashes;
- disagreement and missing-source tests;
- active-content non-execution tests;
- bounded offline pilot using approved public URLs;
- privacy and rights review of the pilot;
- documented GO/HOLD decision.

## 14. Explicit non-goals

Phase 3 does not:

- automate publication;
- assert legal admissibility;
- prove factual truth by source count;
- bypass authentication or access controls;
- collect non-public material;
- execute archived JavaScript;
- silently repair missing assets with live content;
- automatically submit Save Page Now or equivalent archive writes;
- grant authority to any source merely because it appears in a manifest.

## 15. Change control

Every new source, adapter, credential mode, write operation, recurring schedule, active renderer, or publication path requires a separate reviewed change, dedicated tests, and explicit SENTINEL GO. Until those conditions are met, the relevant capability remains disabled and fails closed.
