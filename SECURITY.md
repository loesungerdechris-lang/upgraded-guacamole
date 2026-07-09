# Security Policy

## Supported scope

This repository contains the SENTINEL core bootstrap. Security-sensitive areas include evidence hashing, chain verification, policy decisions, receipt validation and trust registry logic.

## Reporting security issues

Please do not publish security vulnerabilities, exposed credentials or sensitive evidence data in public issues.

For now, report security-sensitive findings directly to the repository owner.

Include:

- affected commit or branch
- impacted package or file
- reproduction steps
- expected and observed behavior
- suggested fix if known

## Data handling rules

- Do not commit secrets, API keys, private keys, certificates, tokens, passwords, personal data, health data or raw incident evidence.
- Use synthetic fixtures for tests.
- Store only hashes, schemas and non-sensitive examples in this repository.
- Treat real evidence bundles as confidential unless explicitly cleared for publication.

## Commit hygiene

Before pushing changes, check for:

- accidental `.env` files
- private keys or certificates
- raw logs containing names, addresses, tokens or identifiers
- generated artifacts that should not be versioned
- private JWK files such as `*.private.jwk`
- local signing workspaces such as `.sentinel/private/`

## Hard rules

- Do not weaken validation in evidence, policy, receipt or registry code without explicit review.
- Do not introduce network side effects into core validation packages.
- Do not use floating production artifacts.
- Releases must document commit SHA and immutable image digest where applicable.
- Verifier code must not generate signing keys.
- Verifier code must not contain private signing material.
- Verifier code must not self-sign the object it later declares verified.
- Trust registries committed to this repository may contain public verification material only.

## Receipt verifier boundary

SENTINEL receipt verification is verifier-only. The accepted trust direction is:

```text
external signer / controlled key custody
        -> signed receipt JSON
        -> public trust registry
        -> verifier
        -> RC_VERIFIED or NOT_VERIFIED
```

The forbidden trust direction is:

```text
verifier generates key
        -> verifier signs receipt
        -> verifier declares own receipt verified
```

Any receipt-verifier change must include or preserve negative tests for tampering, missing required roles, revoked keys, role spoofing, corrupted signatures and weak Class A policy.

## Recommended GitHub security settings

After merging the receipt-verifier gate, configure branch protection or rulesets for `main`:

- require a pull request before merging
- require at least one approval
- require review from Code Owners
- require status checks before merge
- require the `CI` workflow
- require the `SENTINEL Receipt Verifier Gate` workflow
- require existing secret/security scan workflows
- disallow bypassing the above protections where available

## Design principle

Security-relevant decisions must be deterministic, auditable and reproducible. Manual overrides must be explicit, documented and reviewed.
