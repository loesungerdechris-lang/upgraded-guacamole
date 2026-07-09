# SENTINEL Receipt Verifier Production Gate

## Position

The receipt verifier is a production-boundary component. It verifies signed release receipts, but it does not create trust.

The hard rule is:

```text
Frontend or verifier code may verify receipts.
Frontend or verifier code must not generate signing keys.
Frontend or verifier code must not hold private signing material.
Frontend or verifier code must not self-sign the object it later declares verified.
```

## Verification scope

A receipt is accepted only when all required checks pass:

1. Receipt schema marker is `sentinel.receipt.v1`.
2. `created_at` is RFC3339 UTC with trailing `Z`.
3. `release_class` is one of `A`, `B`, `C`.
4. `chain.sequence` is an integer.
5. `chain.previous_hash` is a `sha256:` URN.
6. `chain.receipt_hash` matches the canonical unsigned receipt payload.
7. Each signature has complete JWS-style parts.
8. The protected header binds `alg=ES256` and the expected `kid`.
9. The signature payload matches the canonical unsigned receipt payload.
10. The ES256 signature verifies against the public JWK in the trust registry.
11. The trust key is active and valid at `created_at`.
12. The signer role matches the role bound to the trust key.
13. All required roles are present.
14. The minimum valid-signature threshold is met.
15. Class A releases require at least two valid signatures.

## Red-team fixtures

`tests/test_receipt_verifier.py` covers the mandatory failure modes:

- subject tampering after signing
- evidence artifact hash tampering after signing
- missing required role
- revoked key
- role spoofing
- corrupted signature bytes
- malformed previous hash
- weak Class A policy
- empty trust registry configuration error

## GitHub Actions gate

The dedicated workflow is:

```text
.github/workflows/sentinel-receipt-verifier.yml
```

It runs on every pull request to `main`, every push to `main`, and manual dispatch.

The workflow performs:

1. checkout
2. Python setup
3. package install with dev tools
4. private signing material guard
5. demo/browser key-generation guard
6. ruff lint
7. receipt verifier red-team tests

## GitHub governance guardrails

This branch also adds repository-level collaboration guardrails:

- `.github/pull_request_template.md` requires an explicit SENTINEL safety-boundary checklist.
- `.github/CODEOWNERS` maps core verifier, policy, trust, schema, workflow and security files to the repository owner.
- `SECURITY.md` states the forbidden trust direction and the receipt-verifier negative-test floor.
- `.gitignore` blocks private JWK files and local `.sentinel/private/` signing workspaces.
- `docs/github-main-protection-checklist.md` defines the required `main` protection checklist after merge.

The CODEOWNERS-covered verifier governance surface includes:

```text
src/sentinel_core/receipt.py
tests/test_receipt_verifier.py
docs/receipt-verifier-production-gate.md
docs/github-main-protection-checklist.md
.github/workflows/
.github/pull_request_template.md
SECURITY.md
README.md
```

Recommended repository settings after merge:

```text
Require pull request before merging: on
Require approvals: at least 1
Require review from Code Owners: on
Require status checks before merge: on
Required checks:
  - CI
  - SENTINEL Receipt Verifier Gate
  - SENTINEL Core Secret Scan
  - SENTINEL Core Security
Do not allow bypassing the above settings: on, where available
```

## Merge-readiness checklist

Before merging a receipt-verifier PR, verify:

```text
- PR is not draft.
- PR is mergeable.
- CI is green.
- SENTINEL Receipt Verifier Gate is green.
- Secret scan is green.
- CODEOWNERS includes every touched verifier/security surface.
- PR body documents the verifier-only boundary.
- No private signing material appears in the diff.
```

## Non-goals

This PR does not add production private-key custody. That belongs outside this repository surface, for example in a controlled signer backed by Key Vault, HSM, TPM, or CI-protected secret storage.

This PR also does not assert that all historical evidence records are production-signed. It adds a hardened receipt-verifier path and the CI gate that prevents the verifier from drifting back into demo mode.
