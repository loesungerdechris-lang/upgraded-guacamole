# SENTINEL Historical Web Evidence — Consolidated Reference

**Reference ID:** `sentinel.historical-web.reference.v1-draft`  
**Status:** DRAFT / HOLD  
**Date:** 2026-07-12  
**Scope:** Global SENTINEL historical-web evidence architecture

## 1. Purpose

This document is the single navigation and control reference for the SENTINEL Wayback Evidence Layer, Phase 2 domain reconstruction, Phase 3 multi-source historical evidence, and the manual receipt-bound publication gate.

It consolidates the architecture without replacing the normative schema, policy, verifier code, source policies, threat models, or signed release decisions.

## 2. Document hierarchy and precedence

Where documents differ, the following order applies:

1. applicable signed SENTINEL release policy and verified trust registry;
2. versioned JSON Schema and verifier code on the reviewed commit;
3. `docs/wayback-evidence-policy.md`;
4. `docs/wayback-release-receipt-gate.md`;
5. source-specific acquisition policies;
6. `docs/phase3-multi-source-historical-evidence-spec.md`;
7. implementation checklists and consistency reviews;
8. executive summaries and this navigation reference.

A summary cannot relax a gate defined by a higher-precedence source. Ambiguity fails closed.

## 3. Core position

The Internet Archive Wayback Machine is a global, reusable SENTINEL Evidence Layer for public historical web data.

The immutable operating principles are:

- evidence-first;
- fail-closed;
- complete source-specific provenance;
- deterministic local hashing;
- local and offline reconstruction first;
- no hidden live-resource substitution;
- no archived active-content execution;
- explicit interpretation limits;
- no inference of non-existence from archive gaps;
- no automatic publication;
- no overclaims;
- nothing leaves the system without a separate documented release decision.

## 4. Phase model

### Phase 1 — Wayback acquisition and offline reconstruction

Tracked in Draft PR #27.

Capabilities:

- fixed official Internet Archive endpoints;
- bounded, read-only snapshot discovery and capture retrieval;
- replay URL, timestamp, and original URL binding;
- numeric loopback and unsafe-target rejection;
- malformed-response and response-size failure controls;
- SHA-256 artifact records;
- deterministic `sentinel.wayback.evidence.v1` manifests;
- traversal and symlink-safe local reconstruction;
- schema, semantic, bundle, and manifest-hash validation;
- default `HOLD` enforcement.

Excluded:

- Save Page Now automation;
- whole-site aggressive crawling;
- archived JavaScript execution;
- third-party archive acquisition;
- publication;
- signing-key custody;
- production activation.

### Phase 2 — Domain watchlists and verified site reconstruction

Tracked in Issue #28.

Planned capabilities include approved target registries, bounded domain discovery, change reports, asset graphs, missing-resource reports, multi-timestamp comparison, optional receipt linkage, and georeferenced overlays where evidentially appropriate.

Recurring operation requires an explicit GO/HOLD decision after a bounded reviewed pilot.

### Phase 3 — Multi-Source Historical Evidence Engine

Tracked in Issue #29 and specified in `docs/phase3-multi-source-historical-evidence-spec.md`.

The Wayback Machine remains the primary source. archive.today-family services, Perma.cc, Memento discovery, ArchiveBox, and SingleFile are separate Evidence Sources. Each needs its own policy, host boundary, timestamp semantics, provenance, hash, tests, and acquisition authority.

No secondary source inherits Internet Archive trust. Cross-verification records agreement, disagreement, and gaps; it does not merge incompatible captures or establish factual truth by source count.

## 5. Manifest and provenance model

Each Phase 1 manifest binds:

- schema version and status;
- fixed Wayback source identity;
- normalized target URL;
- selected capture metadata;
- observation time;
- artifact original URL, archive URL, capture timestamp, retrieval time, content type, byte length, SHA-256, and safe relative path;
- mandatory interpretation limits;
- release-gate state;
- optional separately governed cross-verification source records;
- deterministic manifest hash.

The required interpretation limits include:

- the archive timestamp is not automatically the publication timestamp;
- missing captures do not prove that content never existed;
- archived replay may omit dynamic or externally hosted resources.

## 6. State model

### HOLD

Normal state for acquisition and reconstruction.

- offline preview only;
- rights, privacy, and provenance reviews required;
- SENTINEL release remains HOLD;
- publication is false.

### VERIFIED

Internal reviewed state only.

- technical, provenance, rights, and privacy checks approved;
- publication remains false;
- SENTINEL release remains HOLD;
- accepted only through explicit release-aware internal validation.

### PUBLISHED

A signed release state, not a manually edited JSON label.

Draft PR #27 rejects `PUBLISHED`. The state remains unavailable until Issue #30 implements and independently verifies the receipt-bound publication transition.

## 7. Non-circular manual release chain

```text
VERIFIED manifest H_verified
    -> externally produced and signed Class A receipt
    -> receipt verifier produces H_receipt and verified role result
    -> PUBLISHED envelope references H_verified and H_receipt
    -> final envelope receives H_published
```

The receipt must bind the VERIFIED predecessor, not a final envelope containing the same receipt hash.

Minimum roles:

- legal officer;
- privacy officer;
- SENTINEL release officer.

Minimum valid signatures: three, with externally managed role-bound keys.

The future publication verifier remains verifier-only. It performs no archive access, key generation, receipt signing, content publication, or rights determination.

## 8. Security controls

The current and planned architecture addresses:

- SSRF and private-address access;
- numeric loopback aliases;
- unsafe redirects and credential-bearing URLs;
- replay/capture mismatch;
- malformed CDX or availability responses;
- response-size abuse;
- path traversal and symlink escapes;
- artifact and manifest tampering;
- active-content execution;
- live-resource substitution;
- provenance laundering between archives;
- timestamp-semantic confusion;
- false confidence from archive redundancy;
- privacy and victim-safety risk;
- signing-key leakage and role spoofing;
- automatic status elevation.

Any unsupported or ambiguous condition returns HOLD or an explicit failure. It is never converted into a successful absence or approval finding.

## 9. Sensitive historical cases

The architecture may be used for Ilmenau, Ilm-Kreis, Thüringen authorities, Teich Am Ilmufer, the former Fischerhütte paint-factory site, the Ilm-Rennsteig cycle route, engineering firms, public procurement, historical maps, mineral-oil and tank installations, missing project records, and comparable global cases.

It may also preserve lawful public historical web records connected to sensitive events and abuse-related investigations. Such work remains victim-first, minimizes personal data, distinguishes archived statements from verified facts, avoids inference-based identification and guilt by association, and keeps all reconstructed content on HOLD until dedicated review is complete.

## 10. Current repository status

- Draft PR #27: open, mergeable, DRAFT / HOLD;
- Issue #28: Phase 2 planning;
- Issue #29: Phase 3 planning;
- Issue #30: receipt-bound publication verifier planning;
- publication verifier: not implemented;
- publication authority: not granted;
- recurring acquisition: not authorized;
- external archive connectors: not authorized;
- merge and production activation: require explicit separate GO.

## 11. Normative file map

```text
schemas/sentinel.wayback.evidence.v1.json
src/sentinel_core/wayback.py
src/sentinel_core/wayback_manifest.py
config/wayback-source-policy.json
docs/wayback-evidence-policy.md
docs/wayback-policy-schema-consistency.md
docs/phase3-multi-source-historical-evidence-spec.md
docs/wayback-release-receipt-gate.md
docs/wayback-release-gate-executive-summary.md
docs/wayback-release-verifier-implementation-checklist.md
tests/test_wayback.py
tests/test_wayback_manifest.py
.github/workflows/sentinel-wayback-evidence.yml
```

## 12. Change-control rule

Any change that widens trusted hosts, enables credentials, adds recurring acquisition, performs archive writes, executes active content, allows live fallback, weakens HOLD, changes release roles or thresholds, adds signing capability, or enables publication requires:

- a separate scoped change;
- updated threat and policy analysis;
- dedicated negative tests;
- independent review;
- green required CI;
- explicit SENTINEL GO for merge;
- a separate explicit GO for operational activation or publication.

Until every applicable condition is met, the relevant capability remains disabled and fails closed.
