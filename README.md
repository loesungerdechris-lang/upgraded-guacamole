# LoesungErde / Akira SENTINEL Workspace

This repository is the clean starting point for the SENTINEL governance and evidence-chain work.

## Purpose

SENTINEL is designed as a governance and verification layer for high-risk technical and organisational decisions. The repository should remain focused on evidence integrity, policy enforcement, auditability, and safe operational tooling.

## Repository status

- Status: bootstrap
- Owner: Christian Meyer / LoesungErde / Akira
- Default branch: `main`
- Change model: branch + pull request, no direct production changes

## Planned modules

```text
docs/          Architecture, governance, compliance mapping
schemas/       JSON schemas for evidence and receipts
src/           Implementation code
scripts/       Local helper scripts
tests/         Verifier and red-team tests
.github/       CI, security and issue templates
```

## Ground rules

1. No secrets, tokens, credentials, private keys, or medical/personal data in Git.
2. Evidence formats must be deterministic and verifiable.
3. Security-relevant changes require review.
4. Claims must be testable, documented, and reproducible.
5. Public communication must avoid overclaims.

## Next step

The next development step is to add the first minimal evidence schema, verifier skeleton, and CI checks.
