# M3 — Governance Realization

Status: Planned; no governance engine is implemented by this change.
M2 remains the architecture baseline with a labelled Governance-Mock and
Demo-Provenance. This plan does not authorize production use.

## Deliverable

Evaluate explicit policy input deterministically, produce a versioned governance
predicate, attest it against the verified image digest, and independently check
that predicate and its evidence. Start with a small agreed policy contract.

| Provisional item | Required rule / output | Acceptance evidence |
|---|---|---|
| GOV-001 | Replace mock values with an evaluated decision | Positive and negative decisions derived from input, policy and engine version |
| GOV-010 | Evaluate an explicit versioned rule set | Rule IDs, per-rule results, input and policy hashes, deterministic evaluation tests |
| GOV-011 | Define and approve a risk model before calculating scores | Agreed bounds, arithmetic and test vectors; no inherited static score of 12 |
| GOV-012 | Validate approval evidence independently | Authorized approver, signed scope, expiry and binding to the release/policy; missing or invalid approval rejected |

These IDs are local planning references. The canonical specification and its
requirement text must be supplied, versioned and reviewed before assigning
canonical references. Risk scoring and CAB semantics remain design decisions.

## Contract to agree before implementation

- Input: image digest, validated evidence references and explicit facts needed by
  named controls. Reject unknown schema versions, missing facts and malformed
  values; do not silently substitute a successful default.
- Evaluation: fixed rule version, deterministic ordering and numeric semantics.
  For any time-dependent rule, use an explicit evaluation instant; identical
  input, policy, engine version and evaluation instant must yield the same decision.
- Output: engine and policy versions/hashes, input hashes, image subject, per-rule
  outcomes and an overall decision. Keep mock and production profiles distinct.
- Approval: a policy result cannot synthesize human/CAB authorization. Validate
  independently supplied approval evidence against its own trust policy.
- Attestation: sign the produced predicate; independently verify signature,
  subject, evidence hashes, allowed predicate version and decision rules.

## Implementation sequence and acceptance

1. Review the canonical requirement source and approved policy examples; update
   the crosswalk with exact source references and retain unmapped items as open.
2. Implement a pure evaluator for the smallest agreed rule set and schema.
   Test passing input, failing controls, missing/unknown input, type errors and
   deterministic re-evaluation. Add risk and approval checks only after their
   contracts are accepted.
3. Emit and attest evaluated predicates in the existing pipeline. Retain the M2
   fixture profile for regression tests; never silently relabel it as production.
4. Extend mutations with validly signed policy failures so semantic rejection is
   exercised after integrity and signature checks. Bind every new case to its
   requirement and stable exit-code contract.
5. Record a reviewed CI observation for the new source, update generated views,
   and obtain human acceptance. A PASS must not imply compliance beyond the
   explicitly approved rule set or production trust anchors.

M4 validates PKCS#11 and Azure Key Vault paths and their independent trust policy.
M5 completes the canonical v2.2 acceptance suite once its full requirement inventory
is available. Neither milestone is included in M2's coverage denominator.
