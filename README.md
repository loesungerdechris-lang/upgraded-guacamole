# SENTINEL Core

This repository is the active bootstrap implementation for the LoesungErde / Akira SENTINEL core.

## Purpose

SENTINEL is designed as a governance and verification layer for high-risk technical and organisational decisions. The repository remains focused on evidence integrity, policy enforcement, auditability, and safe operational tooling.

## Repository status

- Status: active bootstrap core
- Current GitHub repository name: `upgraded-guacamole`
- Intended repository name: `sentinel-core`
- Owner: Christian Meyer / LoesungErde / Akira
- Default branch: `main`
- Change model: branch + pull request for security-relevant changes

## Current modules

```text
docs/          Architecture, governance, rename plan
schemas/       JSON schemas for evidence and receipts
src/           Python implementation code
tests/         Verifier, fixtures, and red-team style tests
.github/       CI and repository hygiene checks
```

## Implemented bootstrap checks

- JSON Schema validation for evidence records
- deterministic JSON hashing helper
- `sha256:`-prefixed digest format
- previous-hash continuity check
- explicit verifier warning that cryptographic signature verification is not active yet
- CI checks for JSON validity, forbidden secret-like files, linting, and tests

## Ground rules

1. No secrets, tokens, credentials, private keys, or medical/personal data in Git.
2. Evidence formats must be deterministic and verifiable.
3. Security-relevant changes require review.
4. Claims must be testable, documented, and reproducible.
5. Public communication must avoid overclaims.

## Local development

```bash
python -m pip install --upgrade pip
python -m pip install -e .[dev]
ruff check src tests
pytest -q
```

## Verifier stage

Stage 1 verifies structure and hash-chain integrity. Ed25519/ES256 signature verification is intentionally deferred until trust anchors, key identifiers, canonicalization and rotation rules are specified.
