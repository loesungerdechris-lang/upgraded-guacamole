# PR #42 remediation record

All changes remain subject to the protected pull-request path.

## Completed code remediation

- `src/sentinel_core/azure_cli_signing.py`
  - imports `Callable` from `collections.abc`;
  - uses `TypeError` for invalid configuration types.
- `src/sentinel_core/policy.py`
  - uses a direct behavior-preserving authorization predicate.
- `src/sentinel_core/trust.py`
  - uses `datetime.UTC`.
- `src/sentinel_core/verifier.py`
  - preserves the intentional fail-closed defensive boundary with a narrow documented `BLE001` suppression.
- `tests/test_hashchain.py`
  - import block formatted.
- `src/sentinel_core/receipt.py` and `tests/test_receipt_verifier.py`
  - retain two exact non-security modernization waivers; no global Ruff rule is disabled.

## Completed workflow hardening

- Replaced duplicated line-only action checks with `sentinel_core.workflow_security` and dedicated tests.
- Fails closed on unsupported or ambiguous `uses` and `persist-credentials` syntax.
- Permits local actions only through `./...` paths.
- Requires every remote action to use an exact 40-character hexadecimal commit SHA.
- Requires checkout to set `persist-credentials: false` exactly once as a direct `with` input.
- Rejects checkout values placed under `env`, nested mappings, quoted keys, flow maps, duplicate keys, or missing values.
- Replaced filename-to-command hashing with deterministic Python hashing and tests option-like filenames.
- Replaced non-authoritative `RC_VERIFIED` output with `CANDIDATE_VALIDATED`.
- Removed temporary diagnostic workflows.

## Mandatory verification

```text
ruff check src tests
pytest -q
explicit receipt-verifier red-team tests
gofmt check
go test ./...
reproducible Go build
govulncheck ./...
secret scan
workflow security validation
```

Do not merge until all required GitHub checks and review threads are green or resolved.
