# SENTINEL Protected Live Sign-and-Verify Evidence

## Purpose

This workflow is the final repository-side bridge between the protected GitHub OIDC environment, the non-exportable Azure Key Vault key, the external digest signer contract and the existing independent receipt verifier.

```text
protected main workflow
  -> public versioned Key Vault metadata
  -> deterministic public subject manifest
  -> canonical SENTINEL receipt
  -> SHA-256 digest only to Key Vault
  -> raw ES256 result
  -> structural signature attachment
  -> independent public-key verification
  -> public evidence bundle
```

The workflow is not a replacement for tenant authorization. It remains unusable until issue #14 provisions the authorized Azure resources and protects the `sentinel-production` GitHub environment.

## Public evidence bundle

A successful run emits exactly five JSON files:

1. `subject-manifest.json`
2. `signed-receipt.json`
3. `public-trust-entry.json`
4. `verification-report.json`
5. `evidence-manifest.json`

All files are canonical UTF-8 JSON with a trailing newline. The evidence manifest records the exact SHA-256 digest of the first four files. It is intentionally not self-hashed.

The bundle contains only public or operationally non-secret evidence:

- repository and commit identifier;
- workflow run and attempt identifier;
- public versioned Key Vault `kid`;
- public P-256 JWK coordinates;
- public trust validity interval and status;
- signed receipt and receipt hash;
- independent verification result;
- file hashes.

It must never contain Azure tokens, client secrets, private certificates, private JWK members, exported keys, CLI caches or raw Azure account context.

## Public key profile

The builder accepts only:

- canonical public Azure Key Vault versioned key ID;
- `kty=EC`;
- `crv=P-256`;
- exactly `sign` and `verify` key operations;
- canonical unpadded base64url `x` and `y` coordinates, each encoding exactly 32 bytes.

The JWK emitted to the trust file contains only:

```json
{"crv":"P-256","ext":true,"kty":"EC","x":"...","y":"..."}
```

No `d` member or any private value is accepted or emitted.

## Trust policy

The protected environment supplies public trust-policy timestamps:

- `SENTINEL_KEY_NOT_BEFORE`
- `SENTINEL_KEY_NOT_AFTER`

Both must be RFC3339 UTC timestamps. The receipt timestamp must fall inside the interval and the key status must be `active`. Revoked, expired, not-yet-valid or reversed trust windows fail before signing.

The trust role is frozen to `release_signer`, the algorithm to `ES256`, and the release receipt requires one valid signature from that role.

## Deterministic subject and receipt

The subject manifest binds:

- repository;
- exact lowercase 40-character commit SHA;
- workflow name;
- GitHub run ID;
- run attempt;
- UTC creation timestamp.

Its canonical hash becomes the receipt evidence `artifact_hash`. The receipt also binds the commit, pipeline run, sequence and zero previous hash. Any post-preparation mutation fails before signature attachment.

## Independent verification gate

The evidence builder signs through the `ExternalDigestSigner` protocol and then calls the existing `verify_receipt` function with the public trust entry.

No bundle is returned or written unless the result is exactly:

```text
status = RC_VERIFIED
verified = true
```

A wrong key, malformed signature, revoked trust entry, expired trust interval, metadata mismatch or verification issue aborts the process.

## Atomic output

The CLI writes all files into a temporary sibling directory, flushes each file, and publishes the bundle through one same-filesystem directory rename. An existing output directory is never overwritten. Failed runs remove the temporary directory and leave no partial public evidence bundle.

## Protected workflow requirements

The live workflow is:

- manual dispatch only;
- restricted to `refs/heads/main`;
- bound to environment `sentinel-production`;
- limited to `contents: read` and `id-token: write`;
- pinned to immutable third-party action SHAs;
- configured with `persist-credentials: false`;
- authenticated only through GitHub OIDC;
- required to verify tenant and subscription binding;
- required to inspect only public versioned key metadata;
- required to scan the output for secret/private-key markers;
- allowed to upload only the five public JSON files;
- required to remove transient metadata and log out in `always()` cleanup steps.

## Required protected environment values

```text
AZURE_CLIENT_ID
AZURE_TENANT_ID
AZURE_SUBSCRIPTION_ID
SENTINEL_KEY_VAULT_NAME
SENTINEL_KEY_NAME
SENTINEL_KEY_NOT_BEFORE
SENTINEL_KEY_NOT_AFTER
```

These are identifiers and public trust-policy values, not private credentials.

## Activation sequence

1. Complete issue #14 with an authorized Azure administrator.
2. Protect `sentinel-production` with deliberate deployment review.
3. Configure only the approved environment values.
4. Run the existing metadata-only OIDC smoke from `main`.
5. Register and review the public versioned key/JWK trust metadata.
6. Run `SENTINEL Azure Live Sign Verify` from `main`.
7. Review the public artifact, workflow logs and independent verification report.
8. Record rotation/revocation policy before any production-signing claim.

## Gate

- Repository implementation and offline tests: may merge before Azure activation.
- Live workflow execution: **HOLD** until #14 is complete.
- Production signing claim: **HOLD** until a protected live run succeeds and its public bundle is independently reviewed.

Related: #11, #14 and #22.