# SENTINEL Phase 3 Pilot Activation Framework

**Framework ID:** `sentinel.historical-web.phase3.pilot-activation.v1-draft`  
**Status:** DRAFT / HOLD  
**Scope:** Preconditions and manual gates for bounded non-production pilots  
**Parent issue:** #29  
**Stacked dependencies:** Draft PR #27, Draft PR #31, Draft PR #32  
**Publication dependency:** Issue #30  
**Activation authority:** none

## 1. Purpose

This framework defines the formal, technical, privacy, security, and operational
conditions that must be satisfied before a bounded Phase 3 pilot may query any
real historical-web source.

It does not activate an endpoint, transport, source, credential, schedule,
runner, environment, or adapter.

A pilot remains a non-production evidence-acquisition exercise. Every run and
every output remains `HOLD`.

Issue #30 is not a prerequisite for a strictly internal HOLD-only pilot. It is
the separate prerequisite for any future publication transition. No pilot may
publish, externally release, or represent an output as `PUBLISHED` before Issue
#30 is implemented, independently reviewed, and separately approved.

## 2. Normative precedence

Where documents differ, the following order applies:

1. signed SENTINEL release policy and verified trust registry;
2. reviewed schemas and verifier code on the exact approved commit;
3. `docs/wayback-evidence-policy.md`;
4. `docs/wayback-release-receipt-gate.md`;
5. source-specific policies and adapter boundaries;
6. `docs/phase3-multi-source-threat-model.md`;
7. `docs/phase3-multi-source-historical-evidence-spec.md`;
8. `docs/phase3-operational-orchestration-spec.md`;
9. this pilot activation framework;
10. implementation notes and summaries.

This framework may narrow a pilot. It may never widen a higher-precedence
source. Ambiguity fails closed.

## 3. Immutable pilot principles

1. `HOLD` remains the only pilot evidence status.
2. A pilot has no transition to `VERIFIED` or `PUBLISHED`.
3. Source identity, policy, transport, timestamps, and provenance remain
   isolated.
4. No source is queried merely because an adapter or endpoint exists.
5. No raw operator URL is an approved target.
6. No adapter may inherit another source's allowlist, redirects, credentials,
   cookies, parser, or timestamp semantics.
7. Memento remains discovery-only and never acquires candidate content.
8. Memento candidate source identity and datetime remain unverified until a
   separately approved source adapter verifies them.
9. Active content, browser execution, live fallback, archive writes, recursive
   Memento traversal, and automatic publication remain disabled.
10. Cross-verification uses already normalized local records and has no network
    authority.
11. Every run is manually authorized, bounded, uniquely identified, and
    independently reviewable.
12. Aborted or failed runs preserve the minimum immutable audit record required
    for security, incident response, and evidentiary integrity.
13. Raw pilot data is retained or destroyed only under a pre-approved retention
    and disposition decision. It is never deleted automatically merely because
    a run was aborted.

## 4. Pilot authorization model

Pilot authorization is a separate decision from:

- code review;
- merge approval;
- source-policy approval;
- transport approval;
- environment creation;
- publication approval;
- production activation.

No one approval implies another.

The pilot decision must bind an exact:

```text
pilot_authorization_id
pilot_version
operation_plan_hash
target_registry_version
source_policy_registry_version
adapter_descriptor_hashes
reviewed_transport_ids
source_commit
ci_run_reference
pilot_environment_id
privacy_classification
retention_class
start_not_before
expires_at
maximum_runs
maximum_targets
maximum_requests
maximum_bytes
maximum_run_seconds
approved_roles
approval_record_hash
status = HOLD
```

Any change to a bound field invalidates the authorization and returns the pilot
to `BLOCKED_HOLD`.

## 5. Mandatory prerequisites

A live-source pilot cannot begin until all applicable prerequisites are
recorded as evidence.

### 5.1 Parent architecture and review

Required:

- PR #27 independently reviewed and merged;
- PR #31 independently reviewed and merged after PR #27;
- PR #32 independently reviewed and merged after PR #31;
- no unresolved security review finding affecting the pilot path;
- exact implementation commit recorded;
- all required CI checks green on that exact commit.

A documentation-only or fixture-only P0 exercise may be prepared before these
merges, but it must perform no external network request.

### 5.2 Pilot-specific threat and privacy review

Required:

- a versioned pilot threat-model addendum;
- a DPIA-equivalent privacy assessment for the exact source and target set;
- source-terms and automated-access review;
- case-sensitivity classification;
- documented residual risk for disclosure of requested public URLs and request
  times to external services;
- incident-response and evidence-preservation decision;
- retention and disposition decision.

A privacy or terms uncertainty is a blocker, not a limitation that may be
silently accepted.

### 5.3 Registries and operation plan

Required:

- approved target registry with exact URLs and no wildcards;
- source-policy registry with every pilot source defaulting to `enabled: false`;
- adapter registry with exact descriptor hashes and implementation commits;
- reviewed transport registry;
- deterministic operation plan under PR #32;
- plan hash and registry versions frozen before approval;
- exact operation classes and source paths listed;
- no dynamic plugin discovery.

### 5.4 Environment and execution boundary

Required:

- isolated non-production environment named or identified as `phase3-pilot`;
- required human reviewers on the environment gate;
- branch or tag restrictions tied to the reviewed commit;
- manual trigger only;
- no cron, background monitor, or automatic retry schedule;
- least-privilege read-only repository permissions;
- outbound network destinations restricted to the exact approved source hosts;
- no access to production credentials, production data, or signing keys;
- separate approved evidence output root;
- storage encryption and access control appropriate to the privacy class;
- explicit emergency stop and transport revocation mechanism.

Creating the environment does not activate it.

### 5.5 Test and rollback evidence

Required:

- all operational negative tests from PR #32;
- source-specific adapter negative tests;
- fixture-only dry run with no external network;
- tested stop switch;
- tested circuit breakers;
- tested request, byte, time, and storage limits;
- tested audit-record preservation after failure;
- tested absence of secrets and restricted data from logs;
- rollback and containment procedure;
- named incident owner and review owner.

## 6. Manual gate roles

At least the following independent roles must approve the exact pilot
authorization record:

- `architecture_owner`;
- `security_reviewer`;
- `privacy_reviewer`;
- `source_policy_owner`;
- `pilot_operations_owner`.

The same person must not satisfy all roles alone.

The approval record must state:

- exact scope;
- exact source paths;
- exact target count;
- expiry;
- residual risks;
- storage and retention decision;
- stop conditions;
- whether the next pilot phase is permitted.

CI success is not approval.

## 7. First-pilot hard limits

The first live-source profile is intentionally smaller than the maximum
framework ceiling.

### 7.1 Absolute framework ceilings

```text
maximum_sources: 3
maximum_targets: 50
maximum_runs_per_day: 1
manual_trigger_only: true
background_monitoring: false
global_concurrency: 1
per_source_concurrency: 1
active_content_execution: false
live_fallback: false
archive_writes: false
publication: false
recursive_memento_traversal: false
```

These are ceilings, not default permissions.

### 7.2 Initial live phase limits

The first Wayback live phase is limited to five approved URLs.

The first Wayback plus Memento discovery phase is limited to ten approved URLs.

Later increases require a new phase approval and may never exceed the framework
ceiling without a new version of this framework and explicit review.

### 7.3 Rate limits

The effective request rate is always the stricter of:

- the source-specific reviewed policy;
- the transport policy;
- the operation plan;
- the pilot authorization.

The default pilot limit is no faster than one request every five seconds per
source. No pilot source may exceed one request per second.

Valid `Retry-After` values are honored within reviewed maximums. Invalid,
negative, or non-finite values use bounded fallback. Hidden background retries
are prohibited.

## 8. Source-specific pilot roles

### 8.1 Wayback Machine

Permitted role after all gates:

- primary-source discovery and read-only acquisition through the reviewed PR
  #27 boundary;
- official Internet Archive hosts only;
- bounded exact-URL operation;
- local hashing and offline reconstruction.

Still prohibited:

- Save Page Now;
- whole-domain crawling;
- active-content execution;
- live-resource fallback;
- publication.

### 8.2 Memento

Permitted role after all gates:

- TimeMap discovery only;
- exact response hashing;
- candidate enumeration;
- explicit `PARTIAL` and `PAGINATION_REQUIRED` reporting.

Still prohibited:

- candidate-content acquisition;
- recursive TimeMap traversal;
- automatic routing to another adapter;
- treating declared archive identity or datetime as verified;
- status elevation.

There is no pilot phase in which the Memento adapter itself retrieves archived
content.

### 8.3 archive.today-family services

Status: excluded from the initial live pilot.

A future read-only pilot path requires its own:

- source policy;
- terms review;
- exact domain and alias analysis;
- adapter boundary;
- redirect and challenge handling rules;
- parser limits;
- fixtures and negative tests;
- explicit phase authorization.

CAPTCHA, challenge, paywall, access-control, or technical-protection bypass is
prohibited.

### 8.4 Perma.cc

Status: excluded from the initial live pilot.

Public read-only retrieval and link creation are separate operation classes.
Link creation is an archive write and is not allowed by this framework version.

### 8.5 Local capture tools

Local captures may be tested only in fixture or separately approved local
capture profiles. They do not establish historical existence before their
capture time and must remain labeled `local_capture`.

## 9. Phased pilot sequence

### P0 — Fixture-only cold start

Scope:

- no external network;
- fixture adapters only;
- validate registries, plan hashing, run context, audit events, limits, stop
  switch, failure isolation, and report generation.

Exit evidence:

- all tests green;
- frozen P1 proposal;
- no external request occurred.

### P1 — Wayback-only bounded run

Scope:

- maximum five approved public URLs;
- one manual run;
- official Internet Archive hosts only;
- compare results with the reviewed Phase 1 behavior;
- no secondary source.

Exit evidence:

- no trust-boundary deviation;
- deterministic bundle and manifest hashes;
- complete request and error accounting;
- manual review decision.

### P2 — Wayback plus Memento discovery-only

Scope:

- maximum ten approved public URLs;
- Wayback acquisition under PR #27;
- Memento TimeMap discovery under PR #31;
- no Memento content acquisition;
- no recursive pagination;
- no automatic candidate routing.

Exit evidence:

- declared and verified provenance remain separate;
- TimeMap bytes and results are hashed;
- `PAGINATION_REQUIRED` remains visible;
- no source status elevation;
- manual review decision.

### P3 — Candidate-routing dry run

Scope:

- offline only;
- consume already captured P2 Memento records;
- create candidate-routing proposals for separately governed archive adapters;
- perform no candidate network request;
- prove that unapproved source adapters return `POLICY_BLOCKED`.

Exit evidence:

- deterministic routing records;
- no network authority gained from discovery metadata;
- no source identity treated as verified.

### P4 — Separately approved secondary archive

Scope:

- unavailable until a separate source-specific adapter PR, policy, threat
  review, tests, transport approval, and phase authorization exist;
- read-only only;
- no archive writes;
- no publication.

P4 is not granted by this framework document.

Each phase requires a separate manual GO/HOLD decision. Approval for one phase
does not authorize the next.

## 10. Pilot run state machine

```text
PROPOSED_HOLD
  -> PREREQUISITES_REVIEW
  -> AUTHORIZATION_REVIEW
  -> AUTHORIZED_HOLD
  -> ENVIRONMENT_PREFLIGHT
  -> READY_HOLD
  -> MANUAL_START
  -> RUNNING_HOLD
  -> REVIEW_HOLD
  -> COMPLETE_HOLD
```

Failure and stop states:

```text
BLOCKED_HOLD
FAILED_HOLD
ABORTED_HOLD
EXPIRED_HOLD
INCIDENT_HOLD
PARTIAL_HOLD
```

There is no transition to `VERIFIED` or `PUBLISHED`.

## 11. Runtime monitoring and stop conditions

The pilot must monitor at least:

- actual outbound destinations;
- request count and rate;
- response bytes and content types;
- retry and `Retry-After` behavior;
- parser and provenance failures;
- `POLICY_BLOCKED`, `QUERY_FAILED`, `NOT_FOUND`, `NOT_QUERIED`,
  `PAGINATION_REQUIRED`, and partial states;
- storage usage and write failures;
- log-redaction failures;
- run-time and total-budget exhaustion;
- unexpected credential or secret access;
- unexpected active-content or live-resource attempt.

Immediate stop is required when:

- an unapproved host is contacted or attempted;
- a credential, cookie, token, or signing key is exposed;
- restricted personal data is collected outside the approved scope;
- active content executes or live fallback occurs;
- an archive write is attempted;
- a source-policy, adapter, plan, or transport hash differs;
- a request, byte, time, or storage ceiling is exceeded;
- logs contain prohibited sensitive context;
- the stop switch or circuit breaker fails;
- a reviewer withdraws authorization;
- the authorization expires.

A source conflict does not automatically stop the pilot. It remains a HOLD
finding unless it exposes a security, privacy, provenance, or scope breach.

## 12. Pilot evidence package

Each run produces a restricted evidence package containing at least:

```text
pilot_authorization_record
operation_plan
operation_plan_hash
target_registry_version_and_hash
source_policy_registry_version_and_hash
adapter_descriptor_hashes
reviewed_transport_ids
source_commit
ci_run_reference
run_id
run_context
network_destination_report
request_and_retry_report
source_result_envelopes
wayback_manifests_if_created
memento_discovery_records_if_created
local_bundle_manifest
conflict_and_gap_report
limitations
manual_review_record
incident_record_if_any
retention_and_disposition_record
```

Wayback artifacts use the reviewed Wayback schema. Memento and future secondary
sources retain their own source-specific evidence records and common normalized
envelopes. They must not be forced into Wayback provenance fields.

## 13. Storage and artifact policy

Raw reconstructed content and sensitive evidence must not be uploaded to GitHub
Actions artifacts by default.

Raw evidence is written only to an approved encrypted restricted pilot store
identified by `output_root_id` and governed by the retention class.

GitHub Actions artifacts may contain only approved non-sensitive material such
as:

- hashes;
- schema-valid manifests without restricted payloads;
- redacted result summaries;
- CI and audit references;
- signed or hashed review records where allowed.

An Actions artifact is not the authoritative evidence store.

Repository commits must not contain captured raw evidence, sensitive target
lists, credentials, cookies, private review records, or signing keys.

## 14. Retention, abort, and incident disposition

An abort performs immediate containment:

1. stop new requests;
2. disable the affected transport or environment authorization;
3. block further source paths;
4. preserve the immutable minimum audit record;
5. preserve incident-relevant evidence under restricted access;
6. classify raw pilot artifacts under the pre-approved retention decision;
7. record the final state and reason.

Raw data is not automatically deleted on abort. Deletion may destroy audit or
incident evidence and may conflict with preservation obligations.

Disposition options must be selected in advance:

```text
RETAIN_UNTIL_REVIEW_COMPLETE
RETAIN_UNDER_INCIDENT_HOLD
RETAIN_UNDER_LEGAL_OR_EVIDENCE_HOLD
DESTROY_AFTER_APPROVED_REVIEW
DESTROY_AT_RETENTION_EXPIRY
```

Every destruction action requires a separate authorized record and must retain
hashes, disposition evidence, and the non-sensitive audit minimum.

## 15. Exit criteria

A phase may complete only when:

- all planned paths have a terminal result;
- no unexplained outbound destination exists;
- request, byte, time, and storage reports reconcile;
- all evidence records and reports hash deterministically;
- no HOLD invariant was weakened;
- security and privacy reviewers complete the phase review;
- incidents and conflicts are classified;
- retention and disposition are confirmed;
- the next phase receives a separate decision or remains blocked.

Pilot completion does not imply production readiness, VERIFIED status,
publication authority, or source trust.

## 16. Acceptance evidence for this framework

This framework is ready for later implementation only when a scoped successor
provides:

- a versioned pilot-authorization schema;
- registry and operation-plan validators;
- environment-preflight checks;
- exact commit and CI binding;
- role-separated approval records;
- fixture-only P0 tests;
- egress and rate-limit tests;
- stop-switch and circuit-breaker tests;
- logging and privacy-redaction tests;
- storage-boundary and retention tests;
- abort and incident-preservation tests;
- independent review;
- a documented GO/HOLD decision.

No live pilot is authorized by satisfying documentation tests alone.

## 17. Explicit non-goals

This framework does not authorize:

- source activation;
- endpoint activation;
- transport approval;
- credential use;
- archive writes;
- Save Page Now;
- Perma.cc link creation;
- whole-domain crawling;
- wildcard targets;
- background monitoring;
- cron schedules;
- aggressive parallelism;
- recursive Memento traversal;
- Memento content acquisition;
- archive.today challenge bypass;
- active rendering;
- archived JavaScript execution;
- live-resource fallback;
- semantic extraction by default;
- automatic status elevation;
- receipt signing;
- publication;
- production use.

## 18. Change control

Any change that widens:

- source or target scope;
- URL count;
- request rate;
- concurrency;
- time or byte ceilings;
- transport or egress destinations;
- credentials;
- data retention;
- environment privileges;
- pagination;
- acquisition;
- archive writes;
- active rendering;
- extraction profiles;
- status transitions;
- publication capability;

requires a separate issue, scoped pull request, updated threat and privacy
analysis, dedicated negative tests, independent review, green required CI, and
explicit SENTINEL GO.

Until all applicable controls are evidenced, the capability remains disabled
and fails closed.
