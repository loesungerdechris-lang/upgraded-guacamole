# SENTINEL repository security audit — PR #42

- **Initial date:** 2026-07-27
- **Updated:** 2026-07-28
- **Repository:** `loesungerdechris-lang/upgraded-guacamole`
- **Target branch:** `sentinel/zero-trust-release-gate`
- **Disposition:** `HOLD` until the final head satisfies every protected-branch gate

## Scope and evidence boundary

The audit covers all Git-tracked files through deterministic enumeration and SHA-256 evidence generation. GitHub workflows are checked by one shared fail-closed validator. Repository JSON, secret-like material, Python source and tests, receipt-verifier red-team cases, Go source, build, tests, and security checks are exercised by CI.

This is repository-wide machine verification plus focused manual review of the security-sensitive release, workflow, signing, receipt, trust, policy, and evidence paths. It is not a claim that every documentation sentence received an independent human line-by-line review.

## Remediation implemented

- Resolved seven Ruff findings in source and tests.
- Recorded two exact non-security modernization waivers in `pyproject.toml`; no rule is disabled globally.
- Centralized GitHub Actions dependency validation in `sentinel_core.workflow_security`.
- Rejects mutable remote action references, unsupported `uses` syntax, duplicate action keys, and checkout credential bypass forms.
- Requires `persist-credentials: false` exactly once as a direct checkout `with` input.
- Added tests for flow maps, quoted keys, duplicate keys, missing values, nested values, and `env`-based bypass attempts.
- Replaced shell-based tracked-file hashing with deterministic Python hashing and covered option-like filenames such as `--help`.
- Reserved `RC_VERIFIED` for the independent receipt verifier; the release workflow emits only `CANDIDATE_VALIDATED`.
- Preserved read-only workflow permissions and prohibited automatic release, deployment, signing, or canonical writes.
- Removed all temporary diagnostic workflows after collecting their evidence.

## Remaining activation gates

- every required workflow must complete successfully on the final head;
- all security review threads must be resolved against the final implementation;
- protected-branch review and merge requirements must be satisfied;
- post-merge workflows on `main` must complete successfully.

## Activation rule

Activation means merge through protected `main` only after required checks and reviews succeed. No branch-protection bypass is authorized.
