# SENTINEL repository security audit — PR #42

- **Date:** 2026-07-27
- **Repository:** `loesungerdechris-lang/upgraded-guacamole`
- **Target branch:** `sentinel/zero-trust-release-gate`
- **Disposition:** `HOLD` until all required checks pass

## Scope

Repository-wide review of versioned source, tests, schemas, scripts, documentation, and GitHub Actions controls, with emphasis on release authority, credential boundaries, immutable dependencies, receipt verification, deterministic evidence generation, and fail-closed behavior.

## Confirmed blockers

1. Ruff reports nine errors across seven Python files.
2. The workflow action-pin validator accepts only one textual YAML form and can miss valid flow-map or quoted-key syntax.
3. `sha256sum` option parsing is not terminated before tracked filenames.
4. A release-validation workflow must not emit `RC_VERIFIED`; that status is reserved for the independent receipt verifier. The release gate should emit a non-authoritative candidate status such as `CANDIDATE_VALIDATED`.
5. The same action-pin validation logic exists in `.github/workflows/ci.yml`; the fix must be centralized or applied consistently rather than only inside the new release workflow.

## Required remediation

- Fix all Ruff findings without weakening the global rule set.
- Centralize fail-closed GitHub Actions dependency validation in a repository script with tests.
- Reject unsupported or ambiguous `uses` and checkout credential syntax.
- Require every remote action to be pinned to an exact 40-hex commit SHA.
- Require every `actions/checkout` step to set `persist-credentials: false` exactly once.
- Hash tracked paths safely so filenames beginning with `-` cannot become options.
- Preserve read-only workflow permissions and no automatic signing, release, deployment, or canonical writes.
- Run the full Python, receipt-verifier, Go, security, and secret-scan suites.
- Keep PR #42 unmerged until every required check and review thread is resolved.

## Activation rule

Activation means merge through protected `main` only after required checks and reviews succeed. No branch-protection bypass is authorized.
