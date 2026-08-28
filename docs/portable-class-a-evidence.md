# SENTINEL portable Class A evidence bundle

## Purpose

The portable evidence builder produces a five-file public bundle for customer browsers, tablets, rugged handhelds and mobile phones. It does not own private keys. Every signature is obtained through the existing external SHA-256 digest signer contract and the complete receipt is independently verified before any public file set is returned.

This profile is intended for release receipts that require multiple independent roles, including strategic campaign approvals.

## Public files

A successful build emits exactly:

1. `subject-manifest.json`
2. `signed-receipt.json`
3. `public-trust-registry.json`
4. `verification-report.json`
5. `evidence-manifest.json`

Every file is canonical UTF-8 JSON with one trailing newline. The evidence manifest records the exact SHA-256 bytes of the first four files.

## Portable subject profile

`subject-manifest.json` uses `sentinel.portable-subject.v1` and binds:

- repository;
- exact source commit;
- workflow name;
- run ID and attempt;
- UTC creation time;
- receipt entity type;
- receipt entity ID.

The receipt `evidence.artifact_hash` is the SHA-256 hash of the exact subject-manifest bytes, including the trailing newline.

## Multi-signature trust profile

`public-trust-registry.json` uses `sentinel.public-trust-registry.v1` and contains up to sixteen public entries. Each entry is limited to:

- canonical versioned Azure Key Vault key ID;
- signer role;
- `ES256`;
- active or revoked status;
- RFC3339 UTC validity interval;
- public-only EC P-256 JWK containing exactly `kty`, `crv`, `x`, `y` and `ext`.

Private JWK fields and unknown metadata are rejected before any signer is called. Public coordinates must form a valid P-256 point.

## Class A policy

The portable builder requires Class A to have:

- at least two required roles;
- at least two required signatures;
- distinct versioned key IDs;
- public trust entries covering every required role;
- a complete canonical receipt payload shared by every signature.

Signers are processed in sorted key-ID order. Required roles are sorted before signing so repeated runs with the same inputs produce the same unsigned receipt bytes.

## `REC-MRESFOEY` correction boundary

The earlier compact JWS strings for `REC-MRESFOEY` signed a payload that omitted policy, evidence and chain fields. They cannot be transferred into the corrected receipt because the corrected receipt has different canonical bytes.

The safe production sequence is:

1. build the complete Class A receipt with explicit policy, evidence and chain fields;
2. compute its canonical receipt hash;
3. send only each frozen digest request to the authorized external signer;
4. attach separated `protected`, `payload` and raw ES256 `signature` values;
5. verify both signatures against the public trust registry;
6. require `RC_VERIFIED`, two valid signatures, both required roles and no issues;
7. publish the five-file portable bundle atomically;
8. let the public UI independently repeat the byte, trust, policy and signature checks on the customer device.

No existing signature value is reused and no private key material enters the repository or bundle builder.

## Example builder shape

```python
bundle = build_portable_evidence_bundle(
    context=context,
    receipt_id="REC-MRESFOEY",
    entity_type="strategic_campaign",
    entity_id="NIS2_Q3_ULTIMATE_LAUNCH",
    release_class="A",
    policy_id="sentinel.strategic-campaign-release",
    policy_version="1.0.0",
    required_roles=["marketing_lead", "legal_officer"],
    min_signatures=2,
    signer_bindings=[marketing_binding, legal_binding],
)
```

The bindings contain public trust metadata and an implementation of the existing `ExternalDigestSigner` protocol. They contain no private key field.

## Gate

- Repository tests and review: required before merge.
- Actual signer bindings and public trust metadata: supplied only by authorized deployment configuration.
- Live signing: remains protected by the relevant Entra, GitHub environment and Azure Key Vault controls.
- Public deployment: remains `HOLD` until an authentic bundle passes both the independent backend verifier and the customer-device public verifier.
