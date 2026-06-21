# Stage 4: TrustKey Role Binding

## Scope

Stage 4 removes the conceptual spoofing vector created by manually supplied roles.

The verifier now treats the role embedded in the resolved `TrustKey` as authoritative whenever trusted signature verification is active.

## Rule

> Authorization follows the verified key, not a caller-supplied claim.

## Implemented

- `src/sentinel_core/trust.py`
  - `TrustKey.role` is now required
  - role values: `sensor`, `auditor`, `authority`, `admin`

- `src/sentinel_core/verifier.py`
  - resolves the active key from `signature.key_id`
  - verifies the signature with the resolved public key
  - derives `actor_role` from `TrustKey.role`
  - exposes resolved `actor_role` and `key_id` in `VerificationResult`
  - ignores manual `actor_role` for policy authorization when a TrustKey was resolved

- `tests/test_stage4_role_binding.py`
  - auditor key can issue `allow`
  - sensor key cannot issue `allow`, even when caller claims `actor_role="auditor"`
  - sensor key keeps sensor permissions even when caller claims `actor_role="admin"`

## Security impact

Before Stage 4, an integration could verify a sensor signature and then accidentally or maliciously pass `actor_role="auditor"` into the policy layer.

After Stage 4, this no longer works. If the key is known and active, the role comes from the Trust Registry.

## Remaining work

- role binding must be persisted in a signed trust-registry file
- key rotation windows must be time-aware
- policy IDs should be hash-anchored
- CI must stay green before further feature expansion
