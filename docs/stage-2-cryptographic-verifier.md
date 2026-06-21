# Stage 2: Cryptographic Verifier

## Scope

Stage 2 adds explicit public-key signature verification on top of Stage 1.

The verifier now separates four checks:

1. Schema validity
2. Hash-chain continuity
3. Trusted signature validity
4. Future policy validity

## Implemented

- `src/sentinel_core/trust.py`
  - in-memory trust registry
  - active / revoked / expired key status model
  - unknown-key rejection
  - algorithm mismatch rejection

- `src/sentinel_core/crypto.py`
  - EdDSA / Ed25519 public-key verification
  - URL-safe base64 decoding for public key and signature material
  - canonical signing payload derived from the evidence record

- `src/sentinel_core/verifier.py`
  - optional trusted signature verification through `TrustRegistry`
  - explicit failure when trusted verification is requested without a registry
  - rejection of unknown, revoked, expired or mismatched keys

- `tests/test_trust_and_signature.py`
  - accepts a synthetically signed record
  - rejects unknown key IDs
  - rejects revoked keys
  - rejects tampered signed records

## Safety boundary

No production private keys, real evidence records, customer data, health data, or live trust anchors are committed to this repository.

The tests generate synthetic keys at runtime and store only transient in-memory material.

## Not yet implemented

- persistent trust registry file format
- key rotation windows
- revocation list import
- time-aware validation against `issued_at`
- ES256 support
- policy authorization layer
