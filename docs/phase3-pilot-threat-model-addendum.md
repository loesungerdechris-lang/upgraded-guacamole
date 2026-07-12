# SENTINEL Phase 3 Pilot Threat Model Addendum

**Threat model ID:** `sentinel.historical-web.phase3.pilot-threat.v1-draft`  
**Status:** DRAFT / HOLD  
**Scope:** Pilot-specific threats, controls, stop conditions, and evidence only  
**Parent issue:** #29  
**Stacked dependencies:** Draft PR #27, Draft PR #31, Draft PR #32, Draft PR #33  
**Publication dependency:** Issue #30  
**Activation authority:** none

## 1. Purpose

This addendum extends the Phase 3 multi-source threat model with threats that
exist only when a bounded pilot is proposed, approved, prepared, or executed.

It does not authorize a pilot, endpoint, transport, environment, credential,
source, schedule, acquisition, production operation, signing action, or
publication.

Every modeled pilot state and every resulting evidence record remains `HOLD`.

Issue #30 remains the separate publication dependency. It does not grant pilot,
network, adapter, acquisition, or environment authority.

## 2. Relationship to the base threat model

The base Phase 3 threat model remains authoritative for:

- source isolation;
- SSRF, DNS rebinding, and redirect attacks;
- parser and payload compromise;
- provenance laundering;
- timestamp-semantic confusion;
- false confidence from archive redundancy;
- path, storage, and active-content risks;
- status elevation and publication risks.

This addendum focuses on pilot-only attack surfaces:

- authorization lifecycle;
- human approval and role separation;
- registry and operation-plan integrity;
- environment and egress configuration;
- runner and workflow execution;
- pilot data handling;
- monitoring and stop controls;
- abort, incident, retention, and evidence disposition;
- stacked-PR and exact-commit drift.

Where controls differ, the stricter higher-precedence control applies.
Ambiguity fails closed.

## 3. Protected assets

The pilot must protect at least:

1. pilot authorization records and approval evidence;
2. approved target, source-policy, adapter, and transport registries;
3. immutable operation plans and plan hashes;
4. exact source commits and CI evidence;
5. environment configuration and reviewer rules;
6. egress host allowlists and transport identities;
7. request, byte, time, concurrency, and storage limits;
8. source-native discovery and acquisition records;
9. Wayback manifests and local bundle hashes;
10. Memento TimeMap bytes and discovery metadata;
11. sensitive target lists and investigative-interest metadata;
12. restricted raw evidence and encrypted evidence stores;
13. audit logs, incident records, and retention decisions;
14. stop switches, circuit breakers, and revocation paths;
15. the continued absence of signing and publication authority.

## 4. Trust boundaries

### 4.1 Human approval boundary

Approvers may authorize only the exact record they reviewed. Approval must not
be inferred from team membership, prior approval, CI success, or environment
existence.

### 4.2 Control-plane boundary

The control plane freezes plans, registries, adapters, transports, code, CI,
limits, roles, expiry, storage, and retention decisions.

It must not perform archive acquisition.

### 4.3 Data-plane boundary

The data plane executes only the frozen plan. It cannot add targets, sources,
credentials, transports, privileges, or capabilities during a run.

### 4.4 Environment boundary

The pilot environment is non-production and least-privilege. Creating it does
not activate it. Environment approval is not source, transport, or pilot
approval.

### 4.5 External-source boundary

External archives observe request URLs and request times. They are untrusted
for local policy, authorization, identity, status, and publication decisions.

### 4.6 Evidence-store boundary

The authoritative restricted evidence store is separate from GitHub Actions
artifacts and repository commits.

### 4.7 Publication boundary

No pilot component has a transition to `VERIFIED` or `PUBLISHED`. Publication
remains outside the pilot and depends on Issue #30 plus a separate release GO.

## 5. Threat actors and failure sources

The model considers:

- an external attacker controlling DNS, redirects, or archive responses;
- a compromised or malicious archive service;
- a compromised dependency, GitHub Action, runner, or transport;
- a repository collaborator with excessive permissions;
- an authorized operator making an unsafe or mistaken change;
- an approver acting on stale, incomplete, or misleading evidence;
- colluding or insufficiently independent approvers;
- a malicious pull request or branch attempting secret access;
- configuration drift between review and execution;
- accidental disclosure through logs, caches, artifacts, or notifications;
- resource exhaustion, retry storms, and pagination expansion;
- incident pressure causing evidence deletion or review bypass;
- normal software defects and ambiguous source responses.

## 6. Severity and decision model

Threats are classified by impact:

```text
CRITICAL  may cause unauthorized network activity, secret exposure,
          provenance corruption, evidence destruction, status elevation,
          production impact, or publication
HIGH      may exceed approved scope, disclose sensitive pilot interests,
          invalidate auditability, or bypass a mandatory review
MEDIUM    may cause bounded availability loss, incomplete evidence, or
          misleading operational reporting without authority elevation
LOW       may reduce usability while remaining contained and auditable
```

No numerical risk score grants activation.

An unresolved `CRITICAL` or `HIGH` pilot threat is `BLOCKED_HOLD`.

## 7. Authorization and approval threats

### P-01 — Stale authorization replay

**Scenario:** A previously valid pilot authorization is reused after expiry,
code change, registry change, adapter change, or phase completion.

**Impact:** Unreviewed execution under obsolete controls.

**Controls:**

- bind `start_not_before` and `expires_at`;
- bind exact commit, CI run, plan hash, registry versions, adapter hashes,
  transport IDs, environment ID, limits, and phase;
- reject any changed or missing binding;
- one authorization cannot approve the next phase;
- resumed work receives a new authorization ID.

**Stop condition:** Any binding mismatch or expired authorization.

**Required evidence:** Authorization-verifier result and mismatch fixture.

### P-02 — Approval substitution

**Scenario:** CI success, issue comments, labels, team membership, or an existing
GitHub Environment is treated as pilot approval.

**Impact:** Pilot activation without the required human decision.

**Controls:**

- dedicated pilot-authorization record;
- role-bound approvals;
- environment approval checked separately;
- explicit statement that CI success is not approval;
- no implicit activation from configuration.

**Stop condition:** Missing role approval or substituted evidence.

### P-03 — Role collapse or collusion

**Scenario:** One person satisfies all approval roles, or approvers are not
independent enough to challenge unsafe scope.

**Impact:** Single-point approval failure.

**Controls:**

- separate architecture, security, privacy, source-policy, and operations roles;
- prohibit one person from satisfying all roles;
- record reviewer identities and conflicts of interest;
- require an independent reviewer for security-critical changes.

**Residual risk:** Organizational collusion cannot be eliminated technically.

### P-04 — Approval coercion or social engineering

**Scenario:** An operator pressures reviewers to approve an urgent run or
presents incomplete evidence.

**Controls:**

- no emergency bypass path;
- complete evidence checklist;
- reviewers may withdraw authorization;
- withdrawal immediately blocks future requests;
- record the decision basis and residual risks.

## 8. Exact-commit and stacked-PR threats

### P-05 — Review-to-run TOCTOU

**Scenario:** Code, policy, workflow, plan, or registry changes after approval
but before execution.

**Impact:** Reviewed evidence no longer matches executed behavior.

**Controls:**

- bind all immutable hashes in the authorization record;
- verify bindings immediately before environment approval and manual start;
- use exact commit SHA, not a mutable branch name;
- reject dirty, rebased, retargeted, or different merge refs;
- regenerate authorization after any change.

### P-06 — Stacked dependency drift

**Scenario:** PR #31, #32, or #33 is rebased, retargeted, or changed while a
child pilot PR still references the old boundary.

**Controls:**

- bind parent PR head SHAs and base branches;
- verify the expected stack before every review and run;
- prohibit merging or activating a child ahead of its parent;
- require fresh CI and review after stack changes.

### P-07 — CI checks the wrong revision

**Scenario:** A successful merge-ref or previous-head run is cited for a
different pilot commit.

**Controls:**

- record the exact checked-out commit and workflow run;
- compare CI evidence to `source_commit`;
- reject stale or unrelated workflow evidence;
- require all relevant gates on the exact head.

## 9. Registry and operation-plan threats

### P-08 — Target-registry poisoning

**Scenario:** A wildcard, redirected target, sensitive query parameter, private
host, or unapproved URL is inserted into the approved target registry.

**Controls:**

- exact normalized public URLs only;
- no wildcards;
- no credentials or fragments;
- URL and DNS safety validation;
- privacy classification and case binding;
- target-record hash and independent review;
- raw operator input never becomes approved automatically.

### P-09 — Source-policy widening

**Scenario:** `enabled`, hosts, redirects, authentication, limits, or operation
classes are widened without a new review.

**Controls:**

- `enabled: false` is the default and authoritative;
- source-policy hash bound to authorization;
- separate policy per source;
- no trust inheritance;
- widening requires a separate PR, threat review, tests, and GO.

### P-10 — Adapter descriptor substitution

**Scenario:** A different implementation is loaded under an approved adapter ID.

**Controls:**

- bind implementation commit and descriptor hash;
- prohibit dynamic plugin discovery;
- preflight verifies exact descriptor and capability set;
- unsupported capability returns `CAPABILITY_NOT_SUPPORTED`.

### P-11 — Operation-plan scope expansion

**Scenario:** Targets, sources, operations, pagination, retries, or limits are
added after approval.

**Controls:**

- immutable deterministic plan;
- plan hash bound to authorization;
- reject contradictory or missing controls before adapter construction;
- data plane cannot add plan entries;
- any change creates a new plan and authorization.

## 10. Environment and workflow threats

### P-12 — Environment bypass

**Scenario:** A workflow runs outside the approved `phase3-pilot` environment or
without required reviewers.

**Controls:**

- exact environment ID bound to authorization;
- environment preflight;
- required reviewer enforcement;
- branch and tag restrictions;
- manual trigger only;
- no fallback environment.

### P-13 — Fork or pull-request secret exposure

**Scenario:** A workflow triggered from untrusted code gains pilot credentials,
network authority, or evidence-store access.

**Controls:**

- no pilot secrets on untrusted pull-request events;
- no `pull_request_target` execution of untrusted code;
- least-privilege tokens;
- environment secrets only after manual approval of an exact commit;
- pilot credentials have no production or signing privileges.

### P-14 — Workflow or Action supply-chain compromise

**Scenario:** A mutable action tag or compromised dependency changes behavior.

**Controls:**

- immutable action SHA pins;
- dependency lock and review;
- software bill of materials where applicable;
- exact workflow hash in the authorization evidence;
- no unreviewed runtime package installation;
- egress limits remain authoritative even if a process is compromised.

### P-15 — Runner residue or cross-run contamination

**Scenario:** Prior files, caches, credentials, or network state affect a pilot.

**Controls:**

- ephemeral clean runner or verified clean environment;
- no shared writable cache for sensitive data;
- explicit workspace cleanup;
- unique output root and run ID;
- post-run revocation and cleanup with audit evidence.

### P-16 — Environment privilege escalation

**Scenario:** Repository write, organization access, production secrets, or
signing material becomes available to the pilot.

**Controls:**

- repository contents read-only;
- no production credentials or signing keys;
- environment-specific minimal identities;
- privilege inventory and preflight;
- immediate stop on unexpected credential access.

## 11. Network and transport threats

### P-17 — Egress allowlist bypass

**Scenario:** A process contacts an unapproved host through redirects, DNS
changes, proxies, alternate ports, or secondary resource loading.

**Controls:**

- exact approved host and scheme set;
- no implicit redirects;
- DNS and IP validation at request time;
- no private, loopback, link-local, or reserved targets;
- no ports unless explicitly approved;
- actual destination monitoring;
- no browser or active-content resource loading.

**Stop condition:** Any unapproved destination attempt.

### P-18 — Transport substitution

**Scenario:** An approved adapter receives an unreviewed transport or proxy.

**Controls:**

- transport ID and implementation hash bound to authorization;
- transport preflight;
- no default transport activation;
- adapter cannot construct an alternate transport;
- separate transport revocation mechanism.

### P-19 — Retry storm

**Scenario:** Invalid `Retry-After`, repeated timeouts, or server errors cause
unbounded retries or extended execution.

**Controls:**

- finite nonnegative retry delays only;
- bounded retries and total run time;
- stricter source, transport, plan, and pilot limit wins;
- circuit breaker after repeated failures;
- no hidden background retries.

### P-20 — Pagination or candidate explosion

**Scenario:** TimeMaps or archive indexes expand into unbounded pages or
candidate sets.

**Controls:**

- no recursive Memento traversal;
- `PAGINATION_REQUIRED` remains terminal for the approved request;
- candidate and response limits;
- explicit later-page approval required;
- no automatic all-source fan-out.

### P-21 — Rate-limit or terms violation

**Scenario:** The pilot exceeds source policy or automated-access constraints.

**Controls:**

- source-terms review;
- conservative default of one request every five seconds per source;
- absolute ceiling of one request per second;
- one manual run per day;
- honor valid `Retry-After` within reviewed limits;
- stop on repeated rate-limit responses.

## 12. Source-specific pilot threats

### P-22 — Wayback boundary widening

**Scenario:** The pilot uses unofficial hosts, Save Page Now, live fallback, or
active content.

**Controls:** Reuse the reviewed PR #27 boundary without widening.

### P-23 — Memento authority laundering

**Scenario:** A TimeMap candidate is treated as verified archive identity,
verified timestamp, acquired evidence, or permission to query another archive.

**Controls:**

- Memento remains discovery-only;
- `source_archive_verified: false` and `datetime_verified: false` by default;
- no candidate-content acquisition;
- no automatic routing;
- offline P3 routing proposals only;
- a separate approved source adapter and request are required.

### P-24 — Secondary-archive premature inclusion

**Scenario:** archive.today or Perma.cc is added because it appears in the
architecture rather than because its policy and adapter are approved.

**Controls:**

- both excluded from the initial live pilot;
- source-specific PR, policy, terms review, threat model, fixtures, tests,
  transport approval, and phase authorization required;
- no CAPTCHA, challenge, access-control, or technical-protection bypass;
- no archive writes.

## 13. Data-protection and confidentiality threats

### P-25 — Investigative-interest disclosure

**Scenario:** External archives infer a sensitive case or target set from
requested URLs and timing.

**Controls:**

- DPIA-equivalent assessment for exact targets;
- minimal exact-URL set;
- no unnecessary query strings;
- no victim names or allegations in requests or logs;
- source-specific disclosure-risk decision;
- sensitive cases may be `POLICY_BLOCKED` from external pilots.

### P-26 — Sensitive logging

**Scenario:** Logs capture credentials, cookies, full URLs with sensitive query
parameters, allegations, victim identities, or raw payloads.

**Controls:**

- approved logging schema;
- target IDs instead of sensitive URLs where possible;
- secrets and restricted fields redacted before emission;
- logging-negative tests;
- immediate stop on redaction failure.

### P-27 — GitHub Actions artifact leakage

**Scenario:** Raw reconstructed content, target lists, or private review records
are uploaded as workflow artifacts.

**Controls:**

- raw sensitive evidence prohibited from Actions artifacts by default;
- allow only approved hashes, redacted summaries, manifests without restricted
  payloads, and CI references;
- artifact inventory and classification check;
- Actions artifacts are never authoritative evidence storage.

### P-28 — Evidence-store access failure

**Scenario:** Raw evidence is written to an unencrypted, shared, or wrong output
root.

**Controls:**

- approved `output_root_id` bound to authorization;
- encryption and access-control preflight;
- no fallback path;
- safe relative paths and exclusive writes;
- storage failure produces `FAILED_HOLD` or `PARTIAL_HOLD`.

### P-29 — Notification leakage

**Scenario:** Workflow notifications expose target URLs, errors, or evidence
metadata to unauthorized recipients.

**Controls:**

- notification content classification;
- IDs and redacted summaries only;
- restricted recipient list;
- no raw evidence or sensitive target data in notifications.

## 14. Evidence integrity and audit threats

### P-30 — Partial-result laundering

**Scenario:** `QUERY_FAILED`, `POLICY_BLOCKED`, `NOT_QUERIED`, or
`PAGINATION_REQUIRED` is presented as `NOT_FOUND` or successful coverage.

**Controls:**

- distinct result classes;
- no adapter failure interpreted as absence;
- source and run completion may remain `PARTIAL_HOLD`;
- reconciliation tests and mandatory gap reporting.

### P-31 — Cross-source provenance mixing

**Scenario:** Memento or another archive record is forced into Wayback fields or
inherits Wayback trust.

**Controls:**

- source-specific records;
- common normalized envelope preserves source-native metadata;
- no rewriting source identity;
- no secondary source inherits Wayback policy or trust.

### P-32 — Hash or audit-record omission

**Scenario:** A partial or failed record is discarded before hashing or logging.

**Controls:**

- hash response and result records where available;
- preserve completed audit events after adapter failure;
- no exception silently erases prior records;
- deterministic report and bundle manifests.

### P-33 — Evidence overwrite

**Scenario:** A rerun overwrites a previous retrieval or incident record.

**Controls:**

- unique run IDs;
- exclusive writes;
- append-only or immutable evidence records;
- reruns create new observations and reference prior runs;
- content-addressed storage may deduplicate bytes only while records remain
  separate.

## 15. Availability and resource threats

### P-34 — Response or decompression exhaustion

**Scenario:** A source returns oversized or highly compressed data.

**Controls:**

- strict response, decompression, byte, memory, and time limits;
- content-type validation;
- streaming hash with bounded storage;
- circuit breaker and partial-state evidence.

### P-35 — Storage exhaustion

**Scenario:** Raw or partial data consumes the evidence store or runner disk.

**Controls:**

- plan and pilot byte ceilings;
- storage preflight and runtime monitoring;
- no overwrite or uncontrolled cache;
- stop before crossing the limit;
- preserve a minimum audit record.

### P-36 — Stop-switch failure

**Scenario:** Requests continue after authorization withdrawal, incident, or
limit breach.

**Controls:**

- tested stop switch and transport revocation;
- request-bound authorization check;
- no background workers;
- short-lived environment authorization;
- immediate incident escalation.

An unproven stop switch blocks live execution.

## 16. Abort, retention, and incident threats

### P-37 — Automatic evidence deletion

**Scenario:** A failed or aborted run deletes evidence needed for audit,
incident response, legal preservation, or root-cause analysis.

**Controls:**

- preserve immutable audit minimum;
- preserve incident-relevant evidence under restricted access;
- pre-approved retention and disposition class;
- no automatic deletion merely because a run aborted;
- separate authorized destruction record.

### P-38 — Indefinite over-retention

**Scenario:** Pilot evidence is retained without a lawful or documented basis.

**Controls:**

- retention class and expiry bound to authorization;
- review at phase exit;
- approved destruction process;
- retain only hashes and minimum audit evidence after approved destruction where
  appropriate.

### P-39 — Incident concealment

**Scenario:** An operator classifies a security or privacy incident as a normal
source conflict or parser error.

**Controls:**

- explicit incident criteria;
- independent security and privacy review;
- automatic stop for unapproved egress, secret exposure, restricted-data scope
  breach, active content, archive writes, hash drift, or failed stop controls;
- immutable incident record.

## 17. Pilot-phase threat mapping

### P0 — Fixture-only

Dominant threats:

- misleading fixture coverage;
- test paths that accidentally retain network access;
- incomplete stop, limit, and redaction tests.

Required controls:

- network disabled or denied;
- injected fixtures only;
- negative evidence that no external request occurred.

### P1 — Wayback-only

Dominant threats:

- trust-boundary widening;
- target and egress misconfiguration;
- unexpected redirects or live-resource access;
- storage and logging leakage.

### P2 — Wayback plus Memento discovery

Dominant threats:

- Memento authority laundering;
- candidate explosion;
- pagination expansion;
- source-identity confusion;
- investigative-interest disclosure to an additional service.

### P3 — Offline candidate-routing dry run

Dominant threats:

- offline routing records treated as network authority;
- unapproved source adapter selected;
- source identity treated as verified.

P3 must have no network transport.

### P4 — Separately approved secondary archive

P4 is outside the authority of this addendum alone. It requires a separate
source-specific threat model and activation decision.

## 18. Mandatory stop conditions

The pilot immediately enters `INCIDENT_HOLD`, `BLOCKED_HOLD`, or `FAILED_HOLD`
when any of the following occurs:

- authorization missing, expired, withdrawn, or mismatched;
- parent stack, commit, workflow, policy, registry, adapter, plan, transport, or
  environment binding differs;
- an unapproved destination is contacted or attempted;
- a credential, cookie, token, production secret, or signing key is exposed;
- active content executes or live fallback occurs;
- an archive write is attempted;
- Memento attempts candidate-content acquisition or automatic routing;
- request, rate, byte, time, memory, or storage limit is exceeded;
- logs or notifications contain prohibited sensitive data;
- raw sensitive evidence is directed to GitHub Actions artifacts or a repository
  commit;
- stop switch, circuit breaker, redaction, or evidence-store control fails;
- restricted personal data is collected outside approved scope;
- a reviewer withdraws approval;
- incident evidence cannot be preserved.

A source-content conflict alone remains a HOLD finding and is not automatically
a security incident.

## 19. Required pilot security evidence

Before a live pilot, the evidence package must include:

- exact threat-model and addendum versions and hashes;
- exact pilot framework version and hash;
- pilot authorization record and role approvals;
- parent PR head and base bindings;
- exact source commit and all required CI runs;
- target, source-policy, adapter, and transport registry hashes;
- operation plan and plan hash;
- environment and egress configuration evidence;
- privacy and source-terms reviews;
- fixture-only P0 report;
- stop-switch, circuit-breaker, limit, and revocation test results;
- logging, artifact, notification, and redaction test results;
- storage encryption and access-control evidence;
- retention and incident-preservation decision;
- unresolved-risk register;
- explicit manual GO/HOLD decision.

Documentation presence alone is insufficient. Controls must be tested against
the exact pilot implementation.

## 20. Required negative tests

A successor implementation must prove at least:

1. expired authorization is rejected;
2. changed commit, plan, registry, adapter, transport, or environment is rejected;
3. missing role approval blocks execution;
4. CI success cannot substitute for pilot approval;
5. mutable branch names cannot substitute for exact commit binding;
6. changed stacked-parent head invalidates the child authorization;
7. unapproved target or wildcard target is blocked;
8. disabled source performs no request;
9. unapproved transport cannot be constructed;
10. workflow from untrusted code receives no pilot secret;
11. unapproved egress and redirects are blocked;
12. invalid retry metadata cannot create unbounded delay;
13. pagination cannot expand automatically;
14. Memento cannot acquire content or route automatically;
15. Memento identity and datetime remain unverified;
16. source failure remains distinct from absence;
17. raw evidence cannot be uploaded as an Actions artifact by default;
18. restricted data is absent from logs and notifications;
19. storage-root mismatch and unencrypted storage are blocked;
20. abort preserves audit and incident evidence;
21. deletion requires a separate authorized disposition record;
22. stop-switch failure blocks live execution;
23. no pilot state becomes `VERIFIED` or `PUBLISHED`;
24. publication remains rejected without Issue #30 and separate release GO.

## 21. Residual risks

Even with all controls, residual risks remain:

- external services can observe approved URL requests and timing;
- independent human reviewers may make correlated mistakes;
- public archives may provide incomplete, inconsistent, or manipulated records;
- source independence may be unknown;
- a zero-day in the runtime, runner, parser, or dependency may remain;
- legal, privacy, and source-terms interpretations may change;
- encrypted storage and access control reduce but do not eliminate insider risk.

Residual risk must be accepted for the exact pilot scope by the designated
roles. Acceptance does not authorize later phases, production, or publication.

## 22. Acceptance criteria for this addendum

This addendum is ready for later implementation only when:

- it is independently reviewed;
- the pilot framework references it explicitly;
- governance tests protect its HOLD and authority boundaries;
- the dedicated CI gate is green on the exact head;
- Issue #29 records the addendum;
- no live pilot, source, transport, or environment is activated;
- a future implementation supplies every required negative test and evidence
  item before requesting pilot GO.

## 23. Explicit non-goals

This addendum does not authorize:

- pilot approval;
- environment activation;
- endpoint or source activation;
- transport approval;
- credentials or secrets;
- external network execution;
- Memento content acquisition;
- recursive TimeMap traversal;
- automatic candidate routing;
- archive.today challenge bypass;
- Perma.cc link creation;
- archive writes;
- active rendering;
- archived JavaScript execution;
- live-resource fallback;
- background monitoring;
- cron schedules;
- automatic status elevation;
- receipt signing;
- production use;
- publication.

## 24. Change control

Any change that weakens or widens:

- approval roles or independence;
- authorization bindings or expiry;
- parent-stack verification;
- target, source, adapter, or transport scope;
- environment privileges or secret access;
- egress destinations or redirects;
- request, retry, pagination, concurrency, time, byte, memory, or storage limits;
- logging, notification, artifact, or retention rules;
- stop, incident, preservation, or destruction controls;
- Memento discovery-only status;
- evidence status or publication capability;

requires a separate issue, scoped PR, updated threat and privacy analysis,
dedicated negative tests, independent review, green required CI, and explicit
SENTINEL GO.

Until all applicable controls are evidenced, the capability remains disabled
and fails closed.
