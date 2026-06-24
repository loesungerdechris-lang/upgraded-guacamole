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

## Hard rules

- Do not weaken validation in evidence, policy, receipt or registry code without explicit review.
- Do not introduce network side effects into core validation packages.
- Do not use floating production artifacts.
- Releases must document commit SHA and immutable image digest where applicable.

## Design principle

Security-relevant decisions must be deterministic, auditable and reproducible. Manual overrides must be explicit, documented and reviewed.
