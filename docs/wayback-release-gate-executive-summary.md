# SENTINEL Wayback Release Gate — Executive Summary

**Document ID:** `sentinel.wayback.release-gate.executive.v1-draft`  
**Status:** DRAFT / HOLD  
**Scope:** Decision summary for Issue #30  
**Normative source:** `docs/wayback-release-receipt-gate.md`

## Decision position

Technical validity is not publication authority.

A Wayback evidence bundle begins in `HOLD`. It may become `VERIFIED` only after explicit internal technical, provenance, rights, and privacy review. `VERIFIED` remains non-public. A transition to `PUBLISHED` requires a separately produced, independently signed, cryptographically verified Class A SENTINEL release receipt and a separate manual publication action.

Draft PR #27 does not implement publication authority. Its Phase 1 validator rejects `PUBLISHED` even when internal release-aware validation is explicitly requested.

## Directed release chain

```text
VERIFIED manifest H_verified
    -> external Class A release receipt binds H_verified
    -> verified receipt hash H_receipt
    -> PUBLISHED envelope references H_verified and H_receipt
    -> final PUBLISHED manifest hash H_published
```

The receipt must not sign a final manifest that already contains the same receipt hash. The directional chain prevents circular hash dependencies.

## Required independent approvals

The minimum release policy requires three independently role-bound valid signatures:

- `legal_officer` — rights and legal release basis;
- `privacy_officer` — personal and sensitive data review;
- `sentinel_release_officer` — final SENTINEL release decision.

The reconstruction preparer must not satisfy all release roles alone. The repository and verifier contain no private signing material.

## Mandatory receipt bindings

The release receipt must bind at least:

- VERIFIED manifest hash;
- deterministic artifact-set hash;
- approved policy-document hash;
- immutable manual-review-packet hash;
- reviewed source commit;
- green validation pipeline run;
- exact release scope;
- exact release destination.

Any change to content, source, snapshot, artifacts, provenance, or interpretation limits creates a new `HOLD` manifest and requires a fresh review cycle.

## Publication gate result

The future verifier may return only a machine-readable verified gate result or `HOLD`. It must never repair missing fields, generate signatures, hold private keys, publish content, or infer approval from CI success.

## Current status

- Draft PR #27: DRAFT / HOLD;
- Issue #30: implementation planning only;
- `PUBLISHED`: technically blocked;
- receipt signing: not implemented in this PR;
- publication: not authorized;
- merge and production activation: require separate explicit GO decisions.

This summary is explanatory. In any conflict, the normative release-gate specification, evidence policy, schema, validator, and signed release policy take precedence. Until those gates are implemented and independently approved, the release path remains fail-closed.
