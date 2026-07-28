# PR #42 remediation plan

This plan is executable only through the protected pull-request path.

## Required code changes

### Ruff findings

- `src/sentinel_core/azure_cli_signing.py`
  - import `Callable` from `collections.abc`;
  - use `TypeError` for invalid `timeout_seconds` and invalid `runner` types.
- `src/sentinel_core/policy.py`
  - return the boolean authorization expression directly.
- `src/sentinel_core/receipt.py`
  - use `datetime.UTC`.
- `src/sentinel_core/trust.py`
  - use `datetime.UTC`.
- `src/sentinel_core/verifier.py`
  - preserve the defensive fail-closed boundary with a narrowly documented `BLE001` suppression.
- `tests/test_hashchain.py`
  - format the import block.
- `tests/test_receipt_verifier.py`
  - remove the unnecessary UTF-8 argument from `encode()`.

### Workflow hardening

- Replace duplicated line-only action-pin checks with one repository-owned validator script and tests.
- Fail closed on unsupported or ambiguous YAML forms involving `uses` or `persist-credentials`.
- Permit local actions only through `./...` paths.
- Require every remote action to use an exact 40-character hexadecimal commit SHA.
- Require `actions/checkout` to set `persist-credentials: false` exactly once.
- Pass `--` before tracked filenames supplied to `sha256sum`.
- Replace the non-authoritative `RC_VERIFIED` release-gate output with `CANDIDATE_VALIDATED`.

## Verification

Run:

```text
ruff check src tests
pytest -q
go test ./...
gofmt check
govulncheck ./...
secret scan
receipt-verifier red-team suite
```

Do not merge until all required GitHub checks and review threads are green or resolved.
