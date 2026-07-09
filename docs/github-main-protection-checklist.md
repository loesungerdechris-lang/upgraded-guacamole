# GitHub Main Branch Protection Checklist

Use this checklist after merging the receipt-verifier gate.

## Required branch protection for `main`

Configure GitHub branch protection or a repository ruleset for `main`:

```text
Require a pull request before merging: on
Require approvals: at least 1
Dismiss stale approvals when new commits are pushed: on
Require review from Code Owners: on
Require status checks to pass before merging: on
Require branches to be up to date before merging: preferred/on when practical
Restrict who can push to matching branches: on where practical
Do not allow bypassing the above settings: on where available
```

## Required status checks

At minimum, require these checks before merge:

```text
CI
SENTINEL Receipt Verifier Gate
SENTINEL Core Secret Scan
SENTINEL Core Security
```

If additional language-specific workflows remain active, keep them required as well.

## Required human review focus

For changes touching verifier, trust, policy, schema, CI or security docs, review must check:

- no private signing material
- no browser or verifier-side key generation
- no self-signing verifier flow
- deterministic hash and payload construction
- explicit trust registry binding
- required negative tests
- no public overclaims

## CODEOWNERS-covered governance surface

The receipt-verifier governance surface should remain covered by `.github/CODEOWNERS`, including:

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

## Receipt-specific merge blockers

Do not merge if any of these are true:

- `SENTINEL Receipt Verifier Gate` is not green
- `CI` is not green
- secret/security scan is not green
- PR is still draft
- PR is not mergeable
- PR removes or narrows negative receipt tests without replacement
- PR weakens Class A policy behavior
- PR introduces private signing material or signer-side key generation into verifier code

## Incident response trigger

Treat any of the following as a security incident until disproven:

- committed private key, token or `.env` file
- verifier accepts tampered payload
- Class A receipt verifies with fewer than two valid signatures
- revoked key verifies successfully
- signer role can be spoofed
- CI guard is disabled, bypassed or narrowed without review
