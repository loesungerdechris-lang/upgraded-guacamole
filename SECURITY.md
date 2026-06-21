# Security Policy

## Reporting security issues

Please do not publish security vulnerabilities, exposed credentials, or sensitive evidence data in public issues.

For now, report security-sensitive findings directly to the repository owner.

## Data handling rules

- Do not commit secrets, API keys, private keys, certificates, tokens, passwords, personal data, health data, or raw incident evidence.
- Use synthetic fixtures for tests.
- Store only hashes, schemas, and non-sensitive examples in this repository.
- Treat real evidence bundles as confidential unless explicitly cleared for publication.

## Commit hygiene

Before pushing changes, check for:

- accidental `.env` files
- private keys or certificates
- raw logs containing names, addresses, tokens, or identifiers
- generated artifacts that should not be versioned

## Design principle

Security-relevant decisions should be deterministic, auditable, and reproducible. Manual overrides must be explicit and documented.
