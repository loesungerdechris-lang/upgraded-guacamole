# Stage 3: Policy Authorization

## Scope

Stage 3 adds authorization on top of schema, chain and signature verification.

The central rule is:

> A valid key does not imply unlimited authority.

## Implemented

- `src/sentinel_core/policy.py`
  - role model: `sensor`, `auditor`, `authority`, `admin`
  - decision model: `allow`, `deny`, `review`, `quarantine`
  - immutable `PolicyVersion`
  - `PolicyRegistry` keyed by `policy_id`
  - deterministic bootstrap policy

- `src/sentinel_core/verifier.py`
  - optional policy authorization through `policy_registry`
  - explicit failure when policy authorization is required but no registry is supplied
  - explicit failure when `actor_role` is missing
  - rejection of unknown policy IDs
  - rejection of unknown roles
  - rejection of validly signed but unauthorized decisions

- `tests/test_policy_authorization.py`
  - sensor can request review
  - sensor cannot issue allow
  - auditor can issue allow
  - unknown policy is rejected
  - unknown role is rejected
  - missing policy registry is rejected when policy is required

## Bootstrap policy

| Role | Allowed decisions |
|---|---|
| sensor | review, quarantine |
| auditor | review, allow, deny |
| authority | review, allow, deny, quarantine |
| admin | review, allow, deny, quarantine |

## Historical verification

Each record declares its `policy_id`. The verifier resolves that exact policy from the registry. This keeps old records verifiable against the policy version that was active when the record was created.

## Not yet implemented

- persistent policy registry files
- time-window validation against `issued_at`
- role binding directly to trusted keys
- source-specific allowlists per deployment
- policy hash anchoring inside evidence records
