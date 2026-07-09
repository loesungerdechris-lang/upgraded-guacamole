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
- Ed25519 evidence-record signature verification through explicit trust registry
- policy authorization derived from verified TrustKey role
- key validity-window checks against record timestamps
- ES256/JWS-style release receipt verification through public trust registry
- release receipt policy checks for required roles and minimum signatures
- receipt tamper tests for subject, evidence, signature, key status, role binding and chain data
- CI checks for JSON validity, forbidden secret-like files, linting, and tests

## Ground rules

1. No secrets, tokens, credentials, private keys, or medical/personal data in Git.
2. Evidence formats must be deterministic and verifiable.
3. Security-relevant changes require review.
4. Claims must be testable, documented, and reproducible.
5. Public communication must avoid overclaims.
6. Frontend surfaces may verify receipts, but must never create trust, generate signing keys, or hold private signing material.

## Local development

```bash
python -m pip install --upgrade pip
python -m pip install -e .[dev]
ruff check src tests
pytest -q
```

## Receipt verifier gate

The production-oriented receipt verifier is implemented as verifier-only code. It accepts signed SENTINEL receipts and a public trust registry, then checks:

- canonical unsigned receipt payload
- `chain.receipt_hash`
- ES256 JWS-style signatures
- `kid`, algorithm and protected-header binding
- trust-key active/revoked state
- key validity windows
- signer role binding
- required roles and minimum signature policy
- class-A release policy floor

Run the receipt-specific red-team tests locally:

```bash
pytest -q tests/test_receipt_verifier.py
```

Run the full local gate:

```bash
ruff check src tests
pytest -q
```

GitHub guardrails for this verifier path are documented in:

```text
docs/receipt-verifier-production-gate.md
.github/pull_request_template.md
.github/CODEOWNERS
SECURITY.md
```

## Verifier stage

Stage 1 verifies structure and hash-chain integrity. Stages 2-5 add trusted public-key verification, policy authorization, TrustKey role binding and key validity windows. The receipt verifier extends this line with ES256/JWS-style release receipt verification and explicit production boundaries: verifier code only, public trust registry only, no private keys in repository code.
