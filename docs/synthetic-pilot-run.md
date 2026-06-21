# Synthetic Pilot Run

## Purpose

The synthetic pilot verifies the full SENTINEL Core path without using real evidence, real private keys, customer data, health data or production trust anchors.

## Verified chain

1. Build synthetic evidence record
2. Generate runtime-only Ed25519 key
3. Sign canonical record payload
4. Register public key as `TrustKey`
5. Bind role to `TrustKey.role`
6. Validate schema
7. Validate hash-chain continuity
8. Verify signature
9. Resolve trust key
10. Authorize decision through policy

## Command

```bash
python scripts/run_pilot_evidence.py
```

Expected result:

```json
{
  "ok": true,
  "actor_role": "auditor",
  "key_id": "synthetic-pilot-key"
}
```

## Negative tests

The test suite also verifies that:

- a sensor key cannot issue `allow`
- a sensor key can issue `review`
- authorization follows the TrustKey role, not external caller claims

## Safety boundary

The pilot is synthetic only. It must not be mistaken for a production trust-registry design or a real evidence bundle format.
