# SENTINEL Core Go Threat Model v0.1

## Security objective

The core must make evidence integrity, policy decisions and receipt structure deterministic and independently verifiable.

## Primary threats

- Evidence reordering
- Previous-hash manipulation
- Digest spoofing
- Policy bypass
- Receipt structure downgrade
- Revoked trust key reuse
- Accidental introduction of network side effects into core validation

## Required controls

- Strict digest format validation
- Sequence monotonicity checks
- Genesis previous-hash sentinel
- Policy gate allowlist
- Trust key active-status check
- Tests for every verifier path
- No secrets or real evidence in repository fixtures

## Current state

This baseline provides structural controls only. Signature verification, trust-anchor rotation and hardware attestation remain explicit future gates.
