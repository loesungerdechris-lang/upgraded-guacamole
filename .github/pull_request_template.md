## Summary

Describe what changed and why.

## SENTINEL safety boundary

Confirm every applicable item before requesting review:

- [ ] This change does not add secrets, tokens, credentials, private keys, private JWKs, PEM files or real evidence material.
- [ ] This change does not move signing or private-key custody into frontend, verifier, docs examples or tests.
- [ ] Any verification behavior is deterministic and covered by tests.
- [ ] Any policy, role, trust-registry or receipt change has a negative/tamper test.
- [ ] Any Class A release-control change preserves the two-signature floor or explicitly documents why it does not apply.
- [ ] Public-facing wording avoids overclaims such as impossible, unbreakable, tamper-proof or fully guaranteed.

## Validation

Paste the exact commands or GitHub checks used:

```bash
ruff check src tests
pytest -q
```

## Risk notes

Call out any remaining risks, deferred work or assumptions.
