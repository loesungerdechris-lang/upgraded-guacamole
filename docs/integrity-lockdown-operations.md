# Integrity Guard: controlled ruleset activation

## Observed state, not a deployment claim

The read-only observation on **2026-11-11 UTC** is recorded in
[`evidence/integrity-lockdown-observation-2026-11-11.json`](evidence/integrity-lockdown-observation-2026-11-11.json).
It describes the state before the second hardening commit:

| Item | Observed state |
| --- | --- |
| Repository | `loesungerdechris-lang/upgraded-guacamole` |
| Bootstrap PR | [#86](https://github.com/loesungerdechris-lang/upgraded-guacamole/pull/86), open, draft, not merged, no reviews |
| Bootstrap head at observation | `50ae8bf82bd3d4e54b77923199f0657cbf153d4d` |
| Protected `main` | `35c2623c1f01164f8361c0d6fdb2e50e854d46a1` |
| Existing ruleset | `27074079`, `Pre-Merge Integrity Protection (main)`, active |
| Existing review rule | One approval, stale approvals dismissed, review threads resolved |
| Existing ref rules | Deletion and non-fast-forward updates prohibited; no bypass actors |
| Required checks in that ruleset | None yet |
| Classic branch protection | Seven required checks, all App 15368 |
| New guard check | Not yet observed on a post-bootstrap PR |
| Review capacity | CODEOWNERS names only the bootstrap author |
| Administration access | Full protection read returned 403; local `gh` was not authenticated |

The prior CI results prove that checks ran on the bootstrap branch. They do not
prove that the trusted-base controller is deployed on `main`, that a human has
approved the latest PR, or that the new checks are required. A local guard result
of **40** for this PR is the expected protected-change decision, not a live
GitHub enforcement receipt.

The current activation decision is **HOLD**. A chat statement that a PR was
merged is not substituted for GitHub's current PR and ref state.
The reproducible offline result is recorded in
[`evidence/integrity-lockdown-readiness-2026-11-11.json`](evidence/integrity-lockdown-readiness-2026-11-11.json).

## What is implemented

`integrity_guard.protection` is a pure planner. It preserves the existing ruleset
name, conditions, additional rules, stronger approval counts, and existing
required-check sources. It rejects ambiguous duplicate checks and conflicting
known publishers. It does not access the network.

`integrity_guard.lockdown` is the separate operator entry point. Offline JSON can
produce a reviewable plan only. Live activation collects fresh evidence, binds a
reviewed plan digest, checks again for changes, updates the existing ruleset ID,
and reads the result back. It never merges a PR, submits a review, installs a
bypass, or runs PR code. No workflow automatically invokes its write mode.

The scanner also protects all of `tests/`, its fixtures, conventional Python
test files and Go `_test.go` files outside that tree. A real regression deletes
a failing security test while leaving another passing test. Pytest then exits
0, but the guard rejects the deletion with `INT-010` and exit 40. Weakening an
assertion or adding executable test code is a protected change as well.

## Proposed protection

[`sentinel_lockdown.json`](../sentinel_lockdown.json) is the generated API body
for the observed configuration. Its `enforcement: active` describes the intended
server state; the existence of the file does not activate anything.

The operation is **PUT**, targeting the existing resource:

```text
/repos/loesungerdechris-lang/upgraded-guacamole/rulesets/27074079
```

It preserves seven required contexts and adds two:

| Required context | Intended source App ID | Origin |
| --- | ---: | --- |
| `codeql` | 15368 | Existing classic protection |
| `gitleaks` | 15368 | Existing classic protection |
| `govulncheck` | 15368 | Existing classic protection |
| `python-tests` | 15368 | Existing classic protection |
| `receipt-verifier` | 15368 | Existing classic protection |
| `repository-hygiene` | 15368 | Existing classic protection |
| `test` | 15368 | Existing classic protection |
| `Pre-Merge Integrity Guard` | 15368 | New, requires an observed successful deployed controller |
| `SENTINEL Required CI` | 15368 | New, requires an observed successful CI aggregate |

The API field is `integration_id`, the GitHub App ID, not an installation ID.
The observed Actions checks use 15368. Live preflight must independently verify
the two new check publishers and their workflow-run provenance.

The payload also requires codeowner review and approval of the last reviewable
push, keeps stale-review dismissal, and uses the correct API parameter
**`required_review_thread_resolution`**. The similar spelling
`require_review_thread_resolution` is rejected by the planner. Strict checks are
enabled, branch-creation exemption is disabled, and `bypass_actors` is explicitly
empty. Existing stronger or unrelated constraints are retained.

The original sample used a different repository and would POST a second
ruleset. The operator uses the verified repository and updates the existing ID.
It leaves classic branch protection in place and verifies that it is unchanged.

## Reviewable offline plan

Use an installed checkout of this implementation. The following command reads
only the captured observation and writes local review files:

```sh
python -m integrity_guard.lockdown \
  --snapshot docs/evidence/integrity-lockdown-observation-2026-11-11.json \
  --output /tmp/sentinel-lockdown-review
```

Outputs are `sentinel_lockdown.json` and `readiness.json`. This captured state
must produce `HOLD`, a nonzero exit, and no write. Even changing every supplied
boolean to `true` cannot authorize a live mutation. Offline success means only
`PLAN_ONLY`; `--snapshot` cannot be combined with `--apply`.

Do not blindly send the checked-in payload to the API. New protection rules or
checks may have been added since the observation; the live planner preserves
the current server configuration instead of overwriting it with an old copy.

## Activation prerequisites

1. An eligible person other than the author independently reviews the current
   bootstrap revision and records the approval on GitHub. PR #86 is then merged
   through the existing protected process. A chat approval or an approval from
   an alternate account belonging to the same person is not an independent review.
   The operator requires the eligible owner's latest submitted review to be
   `APPROVED`, bound to the exact bootstrap head, and submitted no later than
   the recorded merge time. A retrospective approval is insufficient.
2. Add an actual eligible independent codeowner through a reviewed change.
   Requiring codeowner approval while only the PR author is an owner would
   strand that author's future changes. No reviewer identity is invented here.
3. Verify that `main` contains the reviewed guard, schema, runtime lock and
   workflows. The live operator compares committed file identities with its
   local reviewed checkout, and requires a clean local worktree before applying.
4. Open a separate harmless ordinary validation PR after deployment. Both new
   checks must explicitly finish with `success` on its current head. Check
   identity, source, workflow execution, and current base must agree.
   The guard run must identify exactly that validation PR and its head/base.
   The CI job must also match the server's check-run URL and check suite.
   Missing or ambiguous run-to-PR associations cause HOLD, including API cases
   where GitHub supplies an empty association list. There is no name-only fallback.
5. Use an already authenticated `gh` with the necessary administration access.
   The operator suppresses prompts and does not run `gh auth login` or acquire
   credentials. Missing access produces HOLD rather than a weaker plan.

The conservative CODEOWNERS validator supports individual usernames and requires
an eligible common owner across operative entries, including explicit coverage
of the guard and workflow directories. It verifies repository write, maintain
or admin permission, and excludes both PR authors. Unsupported syntax, teams,
or missing permission evidence produces HOLD. Distinct eligible accounts are
observable; the tool cannot establish that two accounts belong to different
natural persons. That remains part of the independent review process.

## Live plan and controlled apply

Run from a clean, reviewed checkout after the prerequisites are met. Replace
the example PR number with the actual separate validation PR number:

```sh
python -m integrity_guard.lockdown \
  --live --validation-pr VALIDATION_PR_NUMBER \
  --output /tmp/sentinel-lockdown-live-plan
```

Inspect both output files. Only a live plan with no blockers can be considered
for activation. Use the exact `plan_sha256` from that plan in the final command:

```sh
python -m integrity_guard.lockdown \
  --live --validation-pr VALIDATION_PR_NUMBER \
  --apply --expected-plan-sha256 REVIEWED_PLAN_SHA256 \
  --output /tmp/sentinel-lockdown-live-receipt
```

The apply invocation repeats the authenticated collection. Before writing it
collects again and rejects a different plan, ruleset, main revision, PR,
check result, deployed implementation or owner evidence. If already configured
identically, it reports `UNCHANGED` without another PUT. Otherwise it performs
one PUT to the same ruleset and verifies the resulting configuration and
unchanged classic protection through fresh reads.

If a write was attempted but confirmation fails, its outcome is **unverified**.
`write_performed: null` means that the PUT acknowledgement was not obtained;
it does not mean the server made no change. Inspect fresh server state before
retrying. There is no automatic rollback that
could remove protections added by someone else. The REST update does not provide
an atomic compare-and-swap guarantee; prewrite checks and readback reduce drift
risk but cannot make concurrent administrator actions impossible.

## What the controls do and do not establish

- GitHub accepts `neutral` and `skipped` for required checks. `strict` does not
  change this. The guard publishes success only for a validated exit 0, and the
  `always()` CI aggregate explicitly requires `success` from its two dependencies,
  repository hygiene and Python tests. The other seven contexts remain separate
  requirements; the aggregate is not a cross-workflow result verifier.
- Strict status checks require the PR to be current with its base. They do not
  erase historical successful runs or rule out every possible race.
- Empty bypass actors prohibit the configured bypass route while the ruleset
  remains in force. Administrators with rule-management rights can still change
  or delete it. Stronger separation requires independently administered
  organization controls and restricted administrator access.
- App binding reduces publisher ambiguity, but the Actions App is shared by
  many workflows. The deployed controller, protected workflow files and live
  run-provenance checks remain essential. A separate narrowly scoped publisher
  App would provide a stronger boundary and is not silently provisioned here.
- SHA-256 policy and plan digests detect mismatches. They are not signatures or
  attestations of honest execution. The payload adds no commit-signing mandate.
- The scanner covers explicit credential patterns and configured integrity
  rules. It is not a universal backdoor, PII, vulnerability or ethics detector.
- Protected guard and test maintenance intentionally yields exit 40. Ordinary
  approvals cannot override a required failing check. A future upgrade requires
  a documented maintenance procedure or an independently designed authorizer.

The regression suite uses synthetic fixtures and fake API transports. It checks
rejection and state transitions without forcing a real push, inserting a real
backdoor or changing production rules. Live enforcement is only established by
observing actual post-activation test PR behavior, including missing, failed,
cancelled and stale checks.

## Authoritative references

- [Repository ruleset REST API, including update parameters and permissions](https://docs.github.com/en/rest/repos/rules?apiVersion=2022-11-28#update-a-repository-ruleset)
- [Ruleset layering and rule-administration rights](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- [Available rules, source binding, strict checks and review conditions](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [Required checks, skipped jobs and dependency gates](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)
- [CODEOWNERS and permissions](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [Required reviews and prohibition on approving one's own PR](https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/approving-a-pull-request-with-required-reviews)
