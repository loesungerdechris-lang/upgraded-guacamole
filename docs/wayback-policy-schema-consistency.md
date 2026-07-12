# SENTINEL Wayback Policy and Schema Consistency Review

**Review ID:** `sentinel.wayback.consistency.2026-07-12`  
**Status:** DRAFT / HOLD  
**Scope:** Draft PR #27 after release-boundary hardening

## Result

The normative policy, JSON Schema, manifest builder, semantic validator, and tests are materially consistent for Phase 1.

The review identified one important boundary that required explicit clarification: the schema can describe a future `PUBLISHED` record, but Phase 1 must not accept that state until a separate receipt-bound verifier exists. The validator now rejects `PUBLISHED` unconditionally and accepts `VERIFIED` only through explicit release-aware internal validation.

The dedicated Wayback test selection contains 29 test cases after parameter expansion and passes in GitHub Actions.

## Mapping

| Policy requirement | Schema or code enforcement | Result |
|---|---|---|
| Default state is HOLD | builder emits HOLD; schema constrains HOLD release gate | aligned |
| Publication false by default | schema and source policy require false for HOLD | aligned |
| Official Internet Archive hosts only | fixed endpoints, host checks, redirect checks | aligned |
| Full primary provenance | source, target, snapshot, artifact records | aligned |
| Capture timestamp is not publication date | mandatory interpretation limit | aligned |
| Missing capture is not non-existence proof | mandatory interpretation limit | aligned |
| No live fallback or archived JavaScript execution | policy, source gates, implementation non-goals | aligned |
| Deterministic manifest hash | canonical manifest hash and tamper test | aligned |
| Local file hashes and paths verified | bundle verifier, traversal and symlink controls | aligned |
| Cross sources remain separate | separate source records and acquisition authority marker | aligned |
| VERIFIED is internal only | explicit `allow_non_hold=True`; publication remains false | aligned |
| PUBLISHED requires receipt gate | schema describes state; Phase 1 validator rejects it | fail-closed pending implementation |
| Phase 3 sources need separate policies | Phase 3 specification and Issue #29 | aligned |

## Deliberately rejected alternative implementation patterns

The following patterns were not adopted because they weaken the current architecture:

1. A flat manifest model that mixes archive.today, Perma.cc, or Memento into the Wayback `source_origin`.
2. `is_publishable()` returning true merely because `hold_reasons` is empty.
3. Extracting local file paths from free-text reconstruction notes.
4. Direct tests of private helper methods as the primary security evidence.
5. Importing the package through `src.sentinel_core` instead of the installed `sentinel_core` package.
6. Case-insensitive acceptance of SHA-256 strings when the schema requires deterministic lowercase values.
7. Hypothesis or coverage commands without declaring and pinning the required development dependencies.
8. A release receipt that signs a final manifest hash containing the same receipt hash.

## Non-circular release binding

The accepted model is:

```text
VERIFIED manifest hash
    -> signed external release receipt
    -> final PUBLISHED envelope referencing predecessor and receipt
```

The final PUBLISHED manifest is hashed after the receipt reference is attached. The receipt does not attempt to sign a circular final state.

## Remaining HOLD items

- independent review of the latest PR head;
- formal resolution or response for Codex review threads;
- implementation and tests for the receipt-bound publication verifier;
- source-specific policies before any Phase 3 acquisition adapter is enabled;
- explicit GO before merge, recurring operation, or publication.

## Referenced normative documents

```text
docs/wayback-evidence-policy.md
docs/phase3-multi-source-historical-evidence-spec.md
docs/wayback-release-receipt-gate.md
schemas/sentinel.wayback.evidence.v1.json
```
