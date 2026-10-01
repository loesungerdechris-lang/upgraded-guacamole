# SENTINEL Wayback Release Receipt Gate

**Specification ID:** `sentinel.wayback.release-gate.v1-draft`  
**Status:** DRAFT / HOLD  
**Applies to:** `sentinel.wayback.evidence.v1` and reviewed successors  
**Authority:** verifier and manual decision design only

## 1. Purpose

This document defines the strictly manual transition from `HOLD` to `VERIFIED` and, only after a separate signed decision, to `PUBLISHED`.

The gate does not create signing keys, hold private signing material, publish content, or grant rights. It verifies evidence and externally produced SENTINEL Receipts.

## 2. Hard rule

```text
Technical validity is not release authority.
VERIFIED is not publication.
PUBLISHED requires an independently signed and verified release receipt.
No state transition is automatic.
```

The default validator accepts only `HOLD`. Release-aware validation must be invoked explicitly.

## 3. Directed non-circular chain

A release receipt must not sign a final manifest hash that already contains the receipt hash. That would create a circular dependency.

The binding is therefore directional:

```text
HOLD manifest
    -> human reviews
VERIFIED manifest H_verified
    -> external signed release receipt R binding H_verified
release receipt hash H_receipt
    -> PUBLISHED envelope references H_verified and H_receipt
PUBLISHED manifest hash H_published
```

The signed receipt authorizes a reviewed immutable evidence state. The final published manifest records that decision and can be hashed afterward.

A future successor schema should include an explicit `previous_manifest_hash` or state-transition object. Until then, the release verifier must receive both the VERIFIED and proposed PUBLISHED manifests and compare their immutable evidence fields.

## 4. State model

### 4.1 HOLD

Required state for acquisition and reconstruction.

```text
status: HOLD
mode: offline_preview_only
rights_review_status: required
privacy_review_status: required
provenance_review_status: required
sentinel_release_status: HOLD
publish_restored_content: false
```

Allowed actions:

- local validation;
- offline reconstruction;
- internal evidence review;
- preparation of review records.

Forbidden actions:

- public release;
- status elevation by CI;
- receipt self-signing;
- active rendering or live fallback without separate approval.

### 4.2 VERIFIED

`VERIFIED` records that the selected evidence bundle passed internal technical, provenance, rights, and privacy review. It remains non-public.

Required conditions:

- schema validation passes;
- manifest hash passes;
- snapshot and replay identity binding passes;
- every local artifact byte length and SHA-256 pass;
- mandatory limitations remain present;
- rights review is approved;
- privacy review is approved;
- provenance review is approved;
- release status remains HOLD;
- publication remains false;
- no unresolved blocker is recorded in the review packet.

The transition is a manual decision recorded outside the manifest before the manifest is rehashed as VERIFIED.

### 4.3 PUBLISHED

`PUBLISHED` is a release record, not merely a JSON value.

Required conditions:

- a valid VERIFIED predecessor manifest exists;
- immutable evidence fields match the predecessor;
- a Class A SENTINEL release receipt binds the VERIFIED manifest hash;
- the receipt passes the production receipt verifier against a public trust registry;
- all required signer roles and signature thresholds are met;
- the receipt hash matches `release_gate.release_receipt_sha256`;
- release scope and destination match the approved release packet;
- publication is performed as a separate explicit action;
- the final PUBLISHED manifest is generated and hashed after the receipt is attached.

## 5. Immutable evidence comparison

The proposed PUBLISHED manifest must preserve these fields exactly from the VERIFIED predecessor:

- `schema_version` unless a reviewed migration is used;
- `source`;
- `target_url`;
- `snapshot`;
- `observed_at`;
- `artifacts`;
- `interpretation_limits`;
- `cross_verification_sources`, if present.

Only these fields may change during a direct VERIFIED-to-PUBLISHED transition:

- `status`;
- `release_gate`;
- `manifest_hash`.

Any content, provenance, artifact, limitation, or source change creates a new HOLD evidence manifest and requires new review.

## 6. Release receipt profile

The receipt uses the existing verifier-only `sentinel.receipt.v1` envelope.

Recommended profile:

```json
{
  "schema_version": "sentinel.receipt.v1",
  "receipt_type": "wayback_publication_release",
  "subject": {
    "entity_type": "historical_web_evidence_manifest",
    "entity_id": "<H_verified>"
  },
  "release_class": "A",
  "policy": {
    "policy_id": "sentinel.wayback.publication-release",
    "policy_version": "1.0.0",
    "required_roles": [
      "legal_officer",
      "privacy_officer",
      "sentinel_release_officer"
    ],
    "min_signatures": 3
  },
  "evidence": {
    "verified_manifest_hash": "<H_verified>",
    "artifact_set_hash": "<deterministic aggregate hash>",
    "policy_document_hash": "<hash of approved policy version>",
    "review_packet_hash": "<hash of complete manual review packet>",
    "source_commit": "<reviewed commit SHA>",
    "pipeline_run_id": "<green validation run>",
    "release_scope": "<exact approved files or pages>",
    "release_destination": "<exact approved destination>"
  }
}
```

This profile is normative for the design but does not authorize signing or publication.

## 7. Signer separation

The recommended minimum is three independently role-bound valid signatures:

- `legal_officer`: rights and legal release basis;
- `privacy_officer`: personal and sensitive data review;
- `sentinel_release_officer`: final operational release decision.

The person or system that prepared the reconstruction must not satisfy all release roles alone. Trust keys are externally managed and role-bound. The repository and verifier must never contain private keys.

Higher-risk cases may require additional roles, for example case owner, records officer, victim-safety reviewer, or public-authority liaison.

## 8. Deterministic artifact-set hash

The release receipt should bind a deterministic aggregate of all artifact records in addition to the VERIFIED manifest hash.

Recommended construction:

1. select each artifact's `relative_path`, `byte_length`, and `sha256`;
2. sort by `relative_path` using bytewise UTF-8 order;
3. canonicalize the ordered array with the SENTINEL canonical JSON function;
4. compute `sha256:<hex>`.

This is defense in depth. The VERIFIED manifest hash remains the primary evidence-state binding.

## 9. Manual review packet

The review packet is immutable and hashed. It should contain:

- manifest and bundle validation output;
- rights decision and basis;
- privacy decision and minimization actions;
- provenance decision;
- interpretation limitations;
- release scope;
- release destination;
- responsible reviewers and decision timestamps;
- unresolved risks or explicit statement that none remain;
- source commit and CI run references;
- policy and schema versions.

Attachments are referenced by SHA-256, not trusted by filename alone.

## 10. Gate algorithm

Conceptual verifier sequence:

```text
validate VERIFIED predecessor with release-aware internal validation
validate proposed PUBLISHED manifest schema and manifest hash
compare immutable evidence fields exactly
verify release receipt with public trust registry
require receipt_type = wayback_publication_release
require release_class = A
require policy ID and minimum role set
require receipt subject and evidence bind H_verified
require release_gate.release_receipt_sha256 = verified receipt hash
require approved release scope and destination
return RELEASE_GATE_VERIFIED
```

Any failure returns HOLD. The verifier never repairs, guesses, or auto-approves fields.

## 11. Required negative tests

The implementation must reject:

- `PUBLISHED` with no receipt;
- structurally valid but cryptographically invalid receipt;
- receipt signed by revoked or expired key;
- missing required role;
- insufficient signatures;
- role spoofing;
- receipt binding a different VERIFIED manifest;
- changed artifact list or hash after VERIFIED;
- removed limitation after VERIFIED;
- changed target or snapshot after VERIFIED;
- mismatched receipt hash in release gate;
- changed release destination;
- circular final-manifest-hash binding;
- receipt generated or signed inside verifier code;
- publication request while any review remains required, rejected, or HOLD.

## 12. Phase 1 enforcement

Draft PR #27 does not implement the publication verifier. Therefore:

- `HOLD` remains the normal accepted state;
- `VERIFIED` may be evaluated only through explicit release-aware internal validation;
- `PUBLISHED` must remain rejected until the separate receipt-bound gate is implemented and reviewed;
- no CI success can elevate state;
- no merge of PR #27 grants publication authority.

## 13. Future implementation boundary

A later reviewed change may add a verifier function similar to:

```python
def verify_wayback_publication_transition(
    verified_manifest,
    proposed_published_manifest,
    release_receipt,
    *,
    trust_registry,
    bundle_root=None,
): ...
```

The function must remain verifier-only. Receipt creation, signing, key custody, and publication execution stay outside this module.

## 14. Audit output

A gate result should be machine-readable and include:

- decision: verified or hold;
- verified predecessor hash;
- proposed published manifest hash;
- receipt hash;
- valid signature count;
- matched roles;
- policy version;
- issue codes;
- timestamp of verification;
- no secret or private-key material.

## 15. Non-goals

This gate does not:

- decide copyright law automatically;
- decide privacy compliance automatically;
- certify truth or legal admissibility;
- sign receipts;
- store private keys;
- publish content;
- allow CI to replace human decisions;
- turn cross-archive agreement into release authority.

Until the complete receipt-bound verifier and manual process are independently reviewed, the release path fails closed.
