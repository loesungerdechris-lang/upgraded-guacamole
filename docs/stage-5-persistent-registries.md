# Stage 5: Persistent Registries

## Scope

Stage 5 moves SENTINEL Core from in-memory registry objects to deterministic, local JSON registry files.

The verifier no longer has to trust code-created state. It can operate on explicit registry truth loaded from disk.

## Implemented

- `registries/trust-registry.bootstrap.json`
  - public key metadata only
  - `key_id`
  - algorithm
  - public key
  - role
  - status
  - validity window

- `registries/policy-registry.bootstrap.json`
  - policy versions
  - role-to-decision rules

- `src/sentinel_core/registry_loader.py`
  - loads trust registry JSON
  - loads policy registry JSON
  - rejects unsupported roles
  - rejects unsupported decisions
  - rejects unsupported key algorithms
  - validates optional RFC3339 trust windows

- `src/sentinel_core/trust.py`
  - adds RFC3339 timestamp parsing
  - adds `resolve_active_key_at(...)`
  - validates `issued_at` against `not_before` and `not_after`

- `src/sentinel_core/verifier.py`
  - uses time-aware trust resolution during trusted verification

- `tests/test_registry_loader.py`
  - validates bootstrap registry loading
  - rejects malformed roles and decisions

- `tests/test_time_aware_trust.py`
  - accepts a key valid at `issued_at`
  - rejects records before `not_before`
  - rejects records after `not_after`

## Security boundary

The registry files must never contain private keys, secrets, customer records, medical data or real incident evidence.

Stage 5 remains local-file only: no database, no network, no cloud dependency.

## Stage 5 rule

> The verifier trusts versioned registry truth, not ad-hoc runtime assumptions.

## Next stage

Stage 6 should hash-anchor the exact trust and policy registry versions used by an Evidence Record.
