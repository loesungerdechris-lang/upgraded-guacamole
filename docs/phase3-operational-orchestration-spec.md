# SENTINEL Phase 3 Operational Multi-Source Orchestration Specification

**Specification ID:** `sentinel.historical-web.phase3.operational.v1-draft`  
**Status:** DRAFT / HOLD  
**Scope:** Operational contracts and orchestration design only  
**Parent issue:** #29  
**Stacked dependencies:** Draft PR #27 and Draft PR #31  
**Publication dependency:** Issue #30  
**Activation authority:** none

## 1. Purpose

This specification translates the Phase 3 architecture and threat model into an
implementable operational contract for a multi-source historical-web evidence
engine.

It defines how an approved operation may coordinate independently governed
adapters for:

- the Internet Archive Wayback Machine;
- Memento TimeMap discovery;
- future archive.today-family adapters;
- future Perma.cc adapters;
- future controlled local-capture adapters.

This document does not enable any source, endpoint, credential, schedule,
transport, acquisition, signing, publication, or production operation.

Every run and every output remains `HOLD`.

## 2. Normative precedence

Where documents differ, the following order applies:

1. signed SENTINEL release policy and verified trust registry;
2. reviewed schemas and verifier code on the exact approved commit;
3. `docs/wayback-evidence-policy.md`;
4. `docs/wayback-release-receipt-gate.md`;
5. source-specific policies and adapter boundaries;
6. `docs/phase3-multi-source-threat-model.md`;
7. `docs/phase3-multi-source-historical-evidence-spec.md`;
8. this operational specification;
9. implementation notes and summaries.

This document may narrow an operation. It may never widen authority granted by
a higher-precedence source.

Ambiguity fails closed.

## 3. Immutable operational rules

1. No source is queried merely because an adapter exists.
2. No target is queried merely because it appears in user input or a manifest.
3. A source-policy record is configuration, not activation authority.
4. A run requires an immutable operation plan with explicit targets and sources.
5. Every source uses its own policy, transport, host rules, parser, timestamp
   semantics, rate limits, and result classes.
6. Adapters never inherit Wayback trust, cookies, credentials, redirects, or
   allowlists.
7. Memento is discovery provenance only and never acquires candidate content.
8. Memento candidate archive identity and datetime remain unverified until a
   separately approved source adapter verifies them.
9. Cross-verification operates on already normalized local records and gains no
   network authority.
10. Adapter failure is not absence.
11. Source count is not truth.
12. No run changes `HOLD` to `VERIFIED` or `PUBLISHED`.
13. Active content, browser execution, live fallback, and archive writes are
    disabled.
14. The orchestrator does not hold private signing material.
15. Publication is outside Phase 3 and remains blocked by Issue #30.

## 4. Control plane and data plane

Phase 3 is split into two explicit trust domains.

### 4.1 Control plane

The control plane resolves and freezes:

- approved target registry version;
- source-policy registry version;
- operation-plan version and hash;
- adapter descriptor hashes;
- reviewed transport identifiers;
- privacy classification;
- per-source and global limits;
- code commit and CI evidence;
- operator or automation identity;
- output root and retention class.

The control plane may authorize a bounded run only through a separately
documented pilot gate.

It never acquires archive bytes directly.

### 4.2 Data plane

The data plane executes only the already frozen operation plan.

It performs:

- adapter preflight;
- bounded discovery;
- separately authorized acquisition;
- source-record normalization;
- safe local materialization;
- deterministic comparison;
- conflict and gap reporting;
- audit-event emission.

The data plane cannot add sources, targets, transports, credentials, or
capabilities during a run.

## 5. Required registries

### 5.1 Approved target registry

Every target record contains at least:

```text
target_id
normalized_url
target_class
case_or_project_id
approval_status
privacy_classification
approved_operations
approved_source_ids
query_window
retention_class
registry_version
record_hash
```

Raw operator input is never an approved target.

A target with `approval_status != APPROVED` returns `POLICY_BLOCKED`.

### 5.2 Source-policy registry

Every source policy contains at least:

```text
source_id
source_class
policy_version
status
enabled
approved_operations
approved_hosts
redirect_policy
authentication_mode
transport_id
timestamp_semantics
request_limits
response_limits
logging_policy
retention_policy
required_reviews
policy_hash
```

`enabled: false` is authoritative.

The presence of a host, endpoint, or adapter in configuration does not enable
network use.

### 5.3 Adapter registry

The adapter registry maps one exact `source_id` and `policy_version` to one
reviewed adapter descriptor.

An adapter descriptor includes:

```text
adapter_id
source_id
source_class
adapter_version
implementation_commit
capabilities
transport_requirements
input_contract_version
output_contract_version
supported_result_classes
active_content_execution = false
publication_capability = false
descriptor_hash
```

Dynamic plugin discovery is prohibited in the first operational profile.

## 6. Operation plan

A Phase 3 run requires a deterministic operation plan.

Minimum fields:

```text
plan_schema
plan_id
plan_version
created_at
created_by
target_registry_version
source_policy_registry_version
target_ids
source_ids
operation_classes
comparison_profile
comparison_window
global_concurrency
per_source_concurrency
max_total_requests
max_total_bytes
max_run_seconds
offline_only
active_content_execution
live_fallback
archive_writes
publication
privacy_classification
output_root_id
retention_class
pilot_authorization_reference
plan_hash
```

Required fixed values for the first operational profile:

```text
offline_only: true
active_content_execution: false
live_fallback: false
archive_writes: false
publication: false
global_concurrency: 1
per_source_concurrency: 1
```

A plan with missing or contradictory controls is rejected before adapter
construction.

The plan is immutable after execution begins.

## 7. Run context and audit identity

Each run receives a unique `run_id` and a frozen run context.

Minimum fields:

```text
run_id
plan_hash
source_commit
ci_run_reference
started_at
operator_identity
execution_environment_id
network_mode
output_root_id
audit_log_id
status = HOLD
```

The run context never contains private signing keys.

A resumed run creates a new `run_id` and references the prior run. It does not
silently continue an incomplete audit chain.

## 8. Adapter interface contracts

### 8.1 Base descriptor contract

Conceptual interface:

```python
from typing import Protocol

class HistoricalEvidenceAdapter(Protocol):
    descriptor: AdapterDescriptor

    def preflight(
        self,
        request: AdapterPreflightRequest,
    ) -> AdapterPreflightResult:
        ...

    def discover(
        self,
        request: DiscoveryRequest,
    ) -> DiscoveryResult:
        ...

    def acquire(
        self,
        request: AcquisitionRequest,
    ) -> AcquisitionResult:
        ...
```

An adapter may implement only a subset of capabilities.

Calling an unsupported capability returns `CAPABILITY_NOT_SUPPORTED`. It does
not fall back to another adapter automatically.

### 8.2 Preflight contract

Preflight must verify, without performing the requested acquisition:

- exact source ID and policy version;
- adapter descriptor hash;
- target approval;
- operation approval;
- transport approval;
- endpoint and host constraints;
- authentication mode;
- request and response limits;
- logging and privacy constraints;
- output storage availability;
- current HOLD invariants.

Preflight result classes:

```text
READY
POLICY_BLOCKED
TARGET_NOT_APPROVED
SOURCE_NOT_ENABLED
TRANSPORT_NOT_APPROVED
CAPABILITY_NOT_SUPPORTED
CONFIGURATION_INVALID
```

Only `READY` permits that adapter path to continue.

### 8.3 Discovery contract

Discovery returns source-native candidate metadata without changing evidence
status.

Minimum discovery envelope:

```text
source_id
source_class
policy_version
target_id
original_url
request_url
retrieved_at
result_class
candidates
linked_discovery_records
response_sha256
response_byte_length
http_status
content_type
limitations
error_code
error_message
status = HOLD
```

Common result classes:

```text
SUCCESS
PARTIAL
PAGINATION_REQUIRED
NOT_FOUND
QUERY_FAILED
POLICY_BLOCKED
```

`NOT_FOUND` is valid only for a complete, valid source response that expresses
absence under documented source semantics.

### 8.4 Acquisition contract

Acquisition is a separate capability from discovery.

Minimum acquisition envelope:

```text
source_id
source_class
policy_version
candidate_id
target_id
original_url
source_url
source_timestamp
source_timestamp_semantics
retrieved_at
http_status
content_type
byte_length
sha256
local_relative_path
source_native_metadata
limitations
result_class
status = HOLD
```

Acquisition result classes:

```text
ACQUIRED
ACQUISITION_FAILED
POLICY_BLOCKED
TARGET_MISMATCH
SOURCE_IDENTITY_UNVERIFIED
CONTENT_REJECTED
```

An adapter must never report `ACQUIRED` before local byte length, SHA-256, and
safe-path materialization succeed.

## 9. Source-specific operational roles

### 9.1 Internet Archive Wayback Machine

Role:

- primary historical-web source;
- discovery and read-only acquisition;
- fixed official Internet Archive hosts;
- replay URL, timestamp, and original URL binding;
- existing Phase 1 schema and validator.

Operational restrictions:

- no inherited secondary-archive trust;
- no Save Page Now;
- no archived active-content execution;
- no publication;
- no live-resource fallback.

### 9.2 Memento protocol

Role:

- discovery-only aggregator interface;
- candidate enumeration through TimeMaps;
- preservation of declared candidate archive host and datetime;
- response hashing and explicit pagination state.

Operational restrictions:

- no candidate-content acquisition;
- no recursive TimeMap traversal;
- no automatic adapter routing;
- no candidate host or datetime treated as verified;
- no source-policy activation by discovery.

A Memento candidate may become an input to a separately approved archive
adapter only through a new acquisition request bound to:

```text
memento_discovery_result_hash
candidate_id
declared_source_archive
source_policy_version
operation_plan_hash
```

### 9.3 archive.today-family services

Status: planned and disabled.

Before implementation, a separate source policy and adapter boundary must
define:

- exact service domains and aliases;
- terms and automated-access constraints;
- response and redirect behavior;
- archive URL identity rules;
- timestamp semantics;
- CAPTCHA and challenge handling;
- parser and payload limits;
- source-specific fixtures.

The adapter must not bypass CAPTCHAs, challenges, access restrictions, or
technical protections.

### 9.4 Perma.cc

Status: planned and disabled.

Public-link discovery or read-only retrieval and permanent-link creation are
different operation classes.

Creation is an archive write and requires:

- separate account and collection policy;
- credential custody outside the repository;
- explicit write authority;
- idempotency and duplicate handling;
- legal, privacy, terms, and retention review;
- a separate reviewed implementation and GO.

No Perma.cc creation path is part of the initial Phase 3 operational profile.

### 9.5 Local capture tools

ArchiveBox, SingleFile, and future local tools are classified as
`local_capture`.

They do not establish historical existence before their local capture time.

Each local record must bind tool version, environment, operator, capture time,
input URL, network behavior, active-content behavior, output hashes, and
limitations.

## 10. Orchestrator state machine

The orchestrator uses the following states:

```text
CREATED
  -> PLAN_VALIDATED
  -> PREFLIGHT
  -> READY
  -> DISCOVERY
  -> ACQUISITION
  -> NORMALIZATION
  -> OFFLINE_COMPARISON
  -> REPORTING
  -> COMPLETE_HOLD
```

Terminal failure or limitation states:

```text
BLOCKED_HOLD
PARTIAL_HOLD
FAILED_HOLD
CANCELLED_HOLD
COMPLETE_HOLD
```

There is no transition to `VERIFIED` or `PUBLISHED`.

### 10.1 State rules

- `CREATED` performs no network action.
- `PLAN_VALIDATED` means only that the plan is structurally and semantically
  valid.
- `PREFLIGHT` evaluates every selected adapter independently.
- One blocked adapter does not authorize another.
- `READY` includes only explicitly ready adapter paths.
- `DISCOVERY` executes in deterministic source order in the first profile.
- `ACQUISITION` runs only for candidates explicitly selected by the plan.
- `NORMALIZATION` preserves source-native metadata and provenance.
- `OFFLINE_COMPARISON` has no network capability.
- `REPORTING` emits conflicts, gaps, limitations, and hashes.
- Every terminal state remains HOLD.

## 11. Deterministic execution order

The first operational profile is sequential.

Sources are processed by ascending `source_id`.

Targets are processed by ascending `target_id`.

Candidates are ordered by:

```text
source_id
normalized_original_url
source_timestamp
source_url_or_record_id
candidate_hash
```

Parallel execution requires a separate reviewed profile and explicit pilot
approval.

Determinism does not imply source independence or factual truth.

## 12. Rate limiting and retry behavior

The orchestrator enforces both global and source-specific limits.

The effective value is always the stricter limit.

Required rules:

- no automatic all-source fan-out;
- global concurrency defaults to one;
- per-source concurrency defaults to one;
- bounded total requests and bytes;
- bounded run duration;
- source-specific retry count;
- finite, nonnegative retry delays only;
- honor valid `Retry-After` within a reviewed maximum;
- bounded exponential fallback for invalid retry metadata;
- no infinite pagination;
- no hidden background retries.

A rate-limited or failed source yields a partial or failed source result. It
never increases confidence.

## 13. Normalization contract

The normalizer creates a common envelope while preserving source-native
metadata in a namespaced object.

It must not:

- rewrite `source_id`;
- translate capture time into publication time;
- remove uncertainty flags;
- change declared provenance into verified provenance;
- replace raw hashes with semantic hashes;
- merge records from different sources;
- infer missing metadata.

Every normalized record receives its own deterministic hash.

## 14. Local bundle contract

The local bundle writer must:

- use an approved root identified by `output_root_id`;
- accept normalized relative paths only;
- reject traversal, symlinks, hard-link ambiguity, and special files;
- create files exclusively without overwrite;
- hash exact bytes during or immediately after writing;
- record byte length and content type;
- preserve partial failures without claiming a successful bundle;
- finalize atomically where supported;
- emit a deterministic bundle manifest.

No offline viewer may fetch live network resources.

## 15. Cross-verification engine

The cross-verification engine accepts only already normalized local records.

It has no adapter registry and no transport.

Inputs:

```text
comparison_profile
comparison_window
ordered_record_hashes
normalization_profile_versions
extraction_profile_versions
```

Outputs:

```text
agreement_findings
conflict_findings
gap_findings
coverage_findings
limitations
report_hash
status = HOLD
```

### 15.1 Comparison eligibility

Memento discovery metadata alone is not eligible for byte-level agreement.

Eligible representation comparison requires acquired source records with:

- verified source adapter path;
- exact artifact SHA-256;
- documented timestamp semantics;
- compatible comparison profile;
- retained source provenance.

### 15.2 No truth score

The engine does not produce:

- majority votes;
- factual truth scores;
- legal-admissibility scores;
- guilt or identity inference;
- automatic representative-version selection.

## 16. Unified conflict and gap taxonomy

Minimum operational codes:

```text
TARGET_MISMATCH
TIMESTAMP_SEMANTICS_INCOMPATIBLE
CAPTURE_WINDOW_MISMATCH
BYTE_HASH_MISMATCH
CANONICAL_REPRESENTATION_MISMATCH
MIME_TYPE_MISMATCH
STATUS_CODE_MISMATCH
MISSING_PRIMARY_RESOURCE
MISSING_SECONDARY_RESOURCE
NOT_QUERIED
QUERY_FAILED
POLICY_BLOCKED
PAGINATION_REQUIRED
MIXED_TIMESTAMP_ASSET_GRAPH
SOURCE_PROVENANCE_INCOMPLETE
SOURCE_POLICY_NOT_AUTHORIZED
SOURCE_IDENTITY_UNVERIFIED
ACTIVE_CONTENT_NOT_EVALUATED
PRIVACY_REVIEW_REQUIRED
SOURCE_INDEPENDENCE_UNKNOWN
```

Severity is operational triage metadata, not a truth score.

`BYTE_HASH_MISMATCH` does not by itself prove tampering.

## 17. Failure isolation

Each adapter path has an independent result envelope.

Rules:

- one adapter crash cannot erase completed source results;
- one source failure cannot become another source's success;
- a failed query is not `NOT_FOUND`;
- a disabled source is `POLICY_BLOCKED`;
- an unselected source is `NOT_QUERIED`;
- pagination not followed is `PAGINATION_REQUIRED`;
- partial results remain visibly partial;
- run-level completion may be `PARTIAL_HOLD`.

No orchestrator exception may silently discard an already hashed audit record.

## 18. Privacy and logging

External services necessarily observe requested public URLs and request times.

Before a pilot, the operation plan must classify that disclosure risk.

Logs may contain:

- run ID;
- plan hash;
- target ID;
- source ID and policy version;
- request class;
- result class;
- retry and rate-limit events;
- byte counts;
- record and report hashes;
- error codes.

Logs must not contain:

- credentials;
- cookies;
- authorization headers;
- case allegations;
- victim names;
- unnecessary query strings;
- private review content;
- full sensitive payloads.

## 19. Monitoring and circuit breakers

The first operational profile requires circuit breakers for:

- repeated source failures;
- repeated parser failures;
- rate-limit responses;
- unexpected content types;
- response-size rejections;
- policy mismatches;
- provenance validation failures;
- storage failures;
- total request, byte, or time exhaustion.

A tripped circuit breaker disables only the affected run or source path and
emits `BLOCKED_HOLD` or `PARTIAL_HOLD`.

It does not activate a fallback source automatically.

## 20. Idempotency and reruns

A run key is derived from:

```text
plan_hash
target_registry_version
source_policy_registry_version
implementation_commit
comparison_profile_version
```

A repeated run creates a new observation record and retrieval timestamp.

It never overwrites prior evidence.

Identical returned bytes may share a content-addressed storage object only if
the evidence records remain distinct and preserve each retrieval event.

## 21. Implementation sequence

### Stage O1 — Contracts only

- operation-plan schema;
- target and source-policy registry contracts;
- adapter descriptor contract;
- run-context contract;
- no network execution.

### Stage O2 — Offline orchestrator

- deterministic state machine;
- injected fixture adapters only;
- failure isolation;
- audit records;
- offline comparison;
- no live endpoints.

### Stage O3 — Wayback integration

- reuse reviewed Phase 1 client and manifest validation;
- no widening of official hosts;
- bounded pilot profile remains disabled.

### Stage O4 — Memento integration

- consume PR #31 discovery results;
- no recursive TimeMap following;
- no content acquisition;
- candidate-routing records only.

### Stage O5 — Secondary archive research

- source-specific policy and threat analysis;
- fixtures before transport;
- no activation in this stage.

### Stage O6 — Bounded pilot proposal

- separate activation framework;
- approved public targets;
- reviewed transports;
- privacy and terms review;
- explicit GO/HOLD decision.

No stage includes publication.

## 22. Required negative tests

An implementation must prove at least:

1. raw target input cannot bypass the approved target registry;
2. a disabled source never receives a network request;
3. an unapproved transport cannot be constructed;
4. an adapter cannot add an unplanned source;
5. Memento cannot acquire candidate content;
6. Memento candidate provenance remains unverified;
7. a Memento candidate cannot route to an unapproved adapter;
8. adapter failure remains `QUERY_FAILED`;
9. a disabled source remains `POLICY_BLOCKED`;
10. an unselected source remains `NOT_QUERIED`;
11. indexed TimeMaps remain `PAGINATION_REQUIRED`;
12. one source failure does not erase other source results;
13. no adapter shares cookies, credentials, or implicit redirects;
14. response-size and total-byte limits stop the affected path;
15. no active content executes;
16. no live-resource fallback occurs;
17. traversal and symlink writes are rejected;
18. normalization cannot rewrite source identity;
19. cross-verification has no transport capability;
20. source count cannot elevate HOLD;
21. changed artifacts invalidate comparison hashes;
22. logs exclude credentials and restricted context;
23. no run emits VERIFIED or PUBLISHED;
24. publication remains rejected without Issue #30.

## 23. Acceptance evidence

This specification is implemented only when a scoped successor provides:

- versioned contracts for plans, registries, descriptors, requests, and results;
- deterministic plan and run hashing;
- an offline orchestrator with injected fixtures;
- independent adapter preflight;
- failure-isolated result envelopes;
- deterministic normalization and comparison reports;
- all required negative tests;
- immutable CI action pins;
- updated threat analysis;
- independent review;
- a documented GO/HOLD decision.

Live pilot activation additionally requires the separate Phase 3 activation
framework.

Production activation requires Phase 1 review and merge, stable Phase 2
boundaries, source-specific approval, and an explicit production GO.

Publication additionally requires Issue #30 and a separate publication GO.

## 24. Explicit non-goals

This operational specification does not authorize:

- endpoint activation;
- credential use;
- archive writes;
- whole-domain crawling;
- background monitoring;
- aggressive parallelism;
- recursive Memento traversal;
- archive.today challenge bypass;
- Perma.cc link creation;
- active rendering;
- semantic extraction by default;
- automatic status elevation;
- receipt signing;
- publication.

## 25. Change control

Any change that adds or widens:

- sources or hosts;
- transports;
- credentials;
- operation classes;
- concurrency;
- schedules;
- pagination;
- acquisition;
- archive writes;
- active rendering;
- extraction profiles;
- comparison semantics;
- release roles;
- publication capability;

requires a separate issue, scoped pull request, updated threat analysis,
dedicated negative tests, independent review, green required CI, and explicit
SENTINEL GO.

Until all applicable controls are evidenced, the capability remains disabled
and fails closed.
