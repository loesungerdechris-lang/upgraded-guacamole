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

## GitHub merge gate

Confirm before merge:

- [ ] PR is not draft.
- [ ] PR is mergeable.
- [ ] Required GitHub Actions checks are green.
- [ ] `SENTINEL Receipt Verifier Gate` is green when verifier, trust, policy, schema, workflow, security or documentation surfaces are touched.
- [ ] CODEOWNERS coverage is correct for touched security-sensitive files.
- [ ] No private signing material appears in the diff.

## Validation

Paste the exact commands or GitHub checks used:

```bash
ruff check src tests
pytest -q
pytest -q tests/test_receipt_verifier.py
```

## Risk notes

Call out any remaining risks, deferred work or assumptions.
