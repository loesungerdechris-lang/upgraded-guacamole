# SENTINEL End-to-End Evidence Artifact Specification

**Specification ID:** `sentinel.evidence.artifact.spec.v1-draft`  
**Status:** DRAFT / HOLD  
**Prototype schema:** `sentinel.evidence.artifact.v1`  
**Prototype profile:** `sentinel-e2e-evidence-v1`  
**Activation authority:** none  
**Signing authority:** none  
**Publication authority:** none

## 1. Purpose

The SENTINEL Evidence Artifact is the cryptographic lifecycle bridge between
source discovery, acquisition, normalization, comparison, conflict review,
governance, human review, release authorization, and independently verifiable
publication.

It does not claim that archived content is true. It proves which exact bytes,
provenance claims, policies, registries, code, CI evidence, conflicts, and
lifecycle events were bound together in one immutable evidence state.

The v1 prototype implements only a `HOLD` core artifact and an offline,
verifier-only implementation. It performs no archive request, signing,
publication, receipt creation, or trusted-time assertion.

## 2. Source-native evidence remains authoritative

Wayback manifests retain Wayback replay and timestamp semantics. Memento records
remain discovery records with declared but unverified archive identity and
datetime. Future archive adapters retain their own source policies and formats.
Local captures remain explicitly labelled local captures.

The Evidence Artifact never rewrites these records into one invented
provenance. It binds their byte hashes and source-specific descriptor hashes
into a higher-level object.

## 3. Directional, non-circular artifact family

```text
HOLD Core Artifact
    H_core
      -> Internal Review Envelope binds H_core and review decisions
    H_verified
      -> external Class-A Release Receipt signs H_verified
    H_receipt
      -> Published Envelope binds H_verified, H_receipt, scope and destination
    H_published
```

The receipt never signs a final envelope that already contains the same receipt
hash. Issue #30 remains the only publication-gate implementation path.

The prototype accepts only:

```text
status = HOLD
publication = false
verified_envelope_hash = null
release_receipt_hash = null
temporal anchor status = UNANCHORED_HOLD
```

## 4. Root-of-roots integrity model

The core artifact exposes four independently recomputable roots:

1. `evidence_root` — ordered Merkle root of source-member descriptor hashes;
2. `conflict_root` — ordered Merkle root of conflict descriptor hashes;
3. `governance_root` — canonical hash of policies, registries, operation plan,
   code, CI and environment bindings;
4. `lifecycle_root` — terminal hash of an ordered, previous-hash-linked event
   chain.

The final `artifact_hash = H_core` is the SHA-256 of the canonical artifact with
only `artifact_hash` removed. It therefore binds all four roots, counts,
subjects, interpretation limits, HOLD status, temporal non-claim, and the
explicit absence of release authority.

## 5. Canonicalization profile

The prototype profile is `sentinel-canonical-json-v1`.

Permitted values are null, booleans, Unicode strings, integers in the range
`-(2^53-1)` through `2^53-1`, arrays, and objects with ASCII keys.
Floating-point values, NaN, infinity, duplicate JSON keys, non-string keys and
unknown schema fields are rejected.

Canonical bytes are UTF-8 JSON with lexicographically sorted object keys, no
insignificant whitespace, and no floating-point serialization. Production
promotion requires published cross-language conformance vectors and a formal
mapping to RFC 8785 JCS.

## 6. Evidence members

Each member binds exact bytes to evidentiary context:

```text
member_id
kind
source_id
path
media_type
byte_length
sha256
observed_at
provenance
member_hash
```

`sha256` hashes the exact stored payload bytes. `member_hash` hashes the
canonical member descriptor with only `member_hash` omitted. A metadata,
provenance, path, byte-length or payload-hash change therefore invalidates the
member descriptor.

Provenance distinguishes declared identity from verified identity. In
particular, Memento discovery records must retain unverified archive and
datetime status until a separately approved archive adapter verifies them.

Members are sorted by `member_id`; duplicate identifiers and bundle paths are
rejected.

## 7. Merkle commitment and selective disclosure

Member and conflict hashes use domain-separated binary Merkle trees:

```text
leaf = SHA256("SENTINEL-EVIDENCE-LEAF-v1\0" || digest)
node = SHA256("SENTINEL-EVIDENCE-NODE-v1\0" || left || right)
```

An odd terminal node is duplicated. The leaf count is separately bound in the
artifact. Inclusion proofs bind the member hash, leaf index, leaf count,
sibling direction and expected root. Proof verification does not imply source
truth, rights clearance, trusted time, or publication authority.

## 8. Conflict commitment

Conflicts are first-class evidence, not free-text notes. Each conflict binds:

```text
conflict_id
type
severity
member_hashes
description_hash
resolution_status
resolution_record_hash
conflict_hash
```

Referenced member hashes must exist. Unresolved conflicts remain visible and
cannot be removed merely to improve a verification outcome.

## 9. Governance commitment

`governance_root` binds the exact versions and hashes of:

- evidence and source policies;
- approved target, source-policy, adapter, transport and trust registries;
- operation plan;
- source commit and parent-stack heads;
- CI workflow and run evidence;
- optional non-production environment descriptor;
- privacy, terms, threat-model and retention decisions.

The verifier checks the root, but does not infer that a policy was legally
sufficient or that CI success granted approval.

## 10. Lifecycle chain

Each lifecycle event contains:

```text
sequence
event_type
occurred_at
actor
input_hashes
output_hashes
policy_hashes
decision
previous_event_hash
event_hash
```

The sequence starts at zero and is consecutive. Hash arrays are sorted and
unique. Every referenced hash must already be known when the event is recorded.
Events are time-ordered and may not occur after artifact creation. Human actors
are represented by a hashed identifier, not plaintext personal data.

The terminal event must be `INTEGRITY_SEAL` or `BLOCKED`, and its decision must
remain `HOLD` or `BLOCKED`. The terminal event hash is `lifecycle_root`.

## 11. Temporal honesty

A JSON `created_at` field is a claim, not cryptographic proof that the artifact
existed at that wall-clock time. The prototype therefore requires:

```text
claimed_created_at = artifact.created_at
anchor_status = UNANCHORED_HOLD
anchor_hashes = []
```

The verifier always reports `temporal_anchor_verified = false` for v1.
A future temporal-anchor envelope may bind `H_core` to an independently
verified RFC 3161 timestamp or transparency log receipt. That envelope requires
its own schema, trust policy, verifier, threat model and review.

## 12. Release and Issue #30

The core artifact contains no signatures and grants no release authority.

A future Internal Review Envelope may bind `H_core`, review-packet hashes,
role-bound decisions and immutable fields to produce `H_verified`. Issue #30
may then verify a separately signed Class-A release receipt that binds
`H_verified`. A Published Envelope may finally bind the verified receipt hash,
release scope and destination.

No step is automatic. Technical integrity is not legal, privacy or publication
approval.

## 13. Verification levels

```text
Level 0  PARSE      bounded JSON, duplicate-key and schema checks
Level 1  STRUCTURE  deterministic ordering, identifiers and safe paths
Level 2  BINDINGS   member, conflict, governance, lifecycle and artifact hashes
Level 3  BYTES      local bundle byte lengths and SHA-256 values
Level 4  SOURCE     source-native verifier results, implemented separately
Level 5  REVIEW     future Internal Review Envelope and role decisions
Level 6  RELEASE    Issue #30 receipt and Published Envelope verification
```

The prototype implements Levels 0–3 only. A successful result is
`SEA_INTEGRITY_OK`, not `VERIFIED`, not `PUBLISHED`, and not a truth judgment.

## 14. Verifier requirements

The verifier must:

- work fully offline;
- contain no private key or signing helper;
- perform no network request or archive acquisition;
- reject unsafe paths, symlinks and bundle-root escapes;
- recompute all descriptor hashes, Merkle roots and lifecycle links;
- reject unknown lifecycle hash references;
- return machine-readable failure without silently repairing the artifact;
- report `release_authorized = false` and
  `temporal_anchor_verified = false` for v1.

## 15. Privacy and selective disclosure

Raw evidence may remain in an approved encrypted evidence store. An artifact may
bind bytes without embedding them. Merkle proofs permit later disclosure of a
specific member while preserving the original root.

Selective disclosure does not permit hiding conflicts or interpretation limits
that materially affect the disclosed member. Redacted derivatives are new
members with their own hashes and transformation events.

## 16. Threat coverage

The artifact design addresses payload tampering, metadata substitution,
provenance laundering, conflict deletion, policy drift, review-to-run drift,
record reordering, lifecycle omission, bundle traversal, symlink substitution,
unsafe numeric canonicalization, duplicate JSON keys, release-status editing,
and false temporal claims.

It does not prove source truth, source independence, completeness of an archive,
legal admissibility, rights clearance, or wall-clock existence without an
external anchor.

## 17. Acceptance evidence

The v1 prototype is complete only when it provides:

- strict JSON Schema 2020-12;
- verifier-only implementation;
- deterministic root and artifact-hash calculation;
- Merkle inclusion proof generation and verification;
- local bundle byte verification;
- adversarial tests for every integrity boundary;
- dedicated read-only CI gate;
- independent review on the exact commit;
- no live acquisition, signing, production or publication capability.

## 18. Non-goals and change control

This specification does not authorize archive access, a pilot, credentials,
signing, trusted-time anchoring, automatic review, receipt creation,
publication, production use, or merging any parent Draft PR.

Any new hash algorithm, canonicalization profile, source type, transformation,
temporal anchor, review envelope, signature, release role, storage path or
publication capability requires a separate issue, scoped PR, threat analysis,
negative tests, independent review, green CI and explicit SENTINEL GO.
