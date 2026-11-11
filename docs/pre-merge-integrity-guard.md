# Pre-Merge Integrity Guard v1

## Purpose and evidence boundary

The guard makes a deterministic decision about its **configured static checks**.
It does not prove that software is free of vulnerabilities, that a credential is
active, or that legal, ethical or architectural requirements are satisfied.

This implementation replaces the placeholder on `feat/pre-merge-integrity-guard`.
At the inspected starting revision `5bf4769d9161c858616b8da0dc564f6246925d12`,
the workflow returned success for an empty placeholder analysis and contained a
missing-conclusion fallback to success. The proposed Python modules and tests
did not exist in that revision.

Source evidence is the Git revision and executable tests, not a previous chat's
claims. The baseline `main` revision was
`35c2623c1f01164f8361c0d6fdb2e50e854d46a1`.

## What runs

| Layer | Source of authority | Behavior |
| --- | --- | --- |
| Finding policy | Immutable registry in the protected base | Mandatory findings cannot be downgraded; advisory findings cannot be promoted |
| Git data scanner | Trusted base Python code | Reads committed PR objects without executing them |
| Result validation | Schema, semantic checks and expected context | Requires exactly the four configured checks, consistent outcomes and the observed OS exit |
| Publisher | Trusted `pull_request_target` controller | Posts a check on the inspected head SHA only after validation and freshness checks |
| Existing build/test CI | Read-only `pull_request` jobs | Runs repository hygiene, lint and Python tests; the final `SENTINEL Required CI` job requires each dependency to succeed |
| Repository rules | GitHub ruleset, configured independently | Must require the guard and the CI gate before the checks become a merge barrier |

The four static checks are `diff`, `guard`, `secrets` and `workflows`. The scanner
examines the complete new blobs of files changed from the merge base, not just
patch snippets. It limits file counts, object sizes, total bytes and command
runtime. Missing history, unsupported blobs, invalid paths and partial analysis
produce an incomplete result. Binary files, symlinks, submodules and Git LFS
pointers are not silently treated as inspected source.

Known pytest, packaging and Python startup controls are protected too, including
`conftest.py` at any depth. A regression demonstrates an otherwise failing pytest
session being terminated with exit 0 by a new conftest, and requires that change
to be rejected by the guard. This prevents that concrete bypass. The CI aggregate
confirms observed job outcomes; it is not an independent proof of test coverage
or a guarantee against arbitrary behavior of all executed PR code.

Credential detection intentionally covers a small explicit set of recognizable
token and private-key patterns. It is not comprehensive secret detection and
does not replace the existing Gitleaks workflow. It does not decode arbitrary
encodings, prove that an AWS access-key ID has a matching secret, or perform
general semantic SAST. Detection patterns and protected paths are visible in
`src/integrity_guard/scanner.py`.

## Result contract

`src/integrity_guard/result.schema.json` is included in built Python wheels.
The version is `1.0`; there was no deployed Python v1 contract to preserve. The
result includes:

- `status`, `exit_code`, `complete`, and individual `findings`;
- exactly one outcome for each of the four static checks;
- repository, base SHA, head SHA and the policy digest.

The caller supplies the expected context independently and compares the report
with the actual scanner process return code. A schema-valid report alone is
not proof that anything ran. Reports from untrusted PR code are never accepted
as execution evidence by the controller.

| Exit | Meaning | Required behavior |
| ---: | --- | --- |
| 0 | PASS | All mandatory static checks completed, all passed, no blocker |
| 10 | POLICY_VIOLATION | Completed run with at least one mandatory policy finding |
| 20 | SCAN_INCOMPLETE | Missing coverage, unsupported input or stale revision |
| 21 | SCAN_ERROR | A mandatory check could not execute correctly |
| 22 | SCAN_TIMEOUT | Time limit exceeded |
| 30 | INVALID_RESULT | Malformed, inconsistent, mismatched or missing report |
| 40 | GUARD_INTEGRITY_FAILURE | A protected component changed or was removed |
| 50 | DEPENDENCY_FAILURE | Required runtime, Git or API operation unavailable |
| 99 | INTERNAL_ERROR | Unexpected internal failure |

Only 0 can produce a successful Check Run. A detected guard modification may
produce 40 even when another check could not complete: the positive evidence
of a protected change is retained. Diagnostic findings do not override the
incomplete state. `INT-000` is an overall decision, not an accepted finding.

The registry includes all 15 finding IDs in the proposed matrix. Registering
`INT-020`, `INT-021` or `INT-040` does **not** mean the static scanner runs a build,
all tests or a critical-vulnerability scanner. Build/test evidence is supplied
by the separate CI gate. Additional scanners need implementation and tests.

The policy digest is SHA-256 over an explicitly serialized local registry and
required-check list. It is not JCS, a digital signature, a trusted timestamp,
or a hash of the entire toolchain. The base Git SHA identifies the executing
guard, schema, patterns and dependency lock together.

## Trusted execution

The privileged workflow checks out `pull_request.base.sha` into `trusted/`, with
full history and `persist-credentials: false`. It installs hash-pinned wheels
for CPython 3.12 on Linux x86_64. It never installs the PR's project or executes
its scripts. Actions are pinned to the repository's existing immutable pins.

The adapter fetches `refs/pull/<number>/head` from the base repository using
ephemeral Git authentication. It verifies `FETCH_HEAD` against the event SHA.
No fork-provided URL or arbitrary ref is executed. The scan runs in a separate
process with isolated Python imports, a minimal environment, no GitHub token
and a newly allocated temporary result path. Git and scanner timeouts kill
their process groups. The installed base source remains the import source;
the PR working tree is never checked out.

The token has only `contents: read`, `checks: write`, and `pull-requests: write`
for the controller job. There is no global `write-all` or `statuses: write`.
The independent CI jobs stay read-only. The base workflow runs on drafts too;
there is no draft skip that can masquerade as a successful integrity check.

Before publishing success the adapter verifies that the PR is still open,
still targets the expected repository/main, and still has the same base and
head. Branch rules must additionally require an up-to-date branch, because a
base branch can advance after any individual API read. A dedicated GitHub App
with the required-check source restricted to that App provides a stronger
publisher boundary than the shared GitHub Actions App. Binding to the Actions
App alone does not identify one immutable workflow. Repository administrators,
the protected base and GitHub/runner infrastructure remain trusted.

## Safe reporting and labels

All public descriptions come from fixed templates. Scanner free text, matched
source lines, raw keys, Git stderr, API response bodies and tracebacks are not
published. Source location and rule ID remain available for review. Annotations
are sent in batches of at most 50; the adapter does not drop findings after the
first batch and does not finalize success before reporting completes.

`Integrität: Bestätigt` and `Integrität: Blockiert` are advisory UI labels. The
SHA-bound check is authoritative. Label updates check freshness, but labels
have no atomic SHA binding in GitHub and can transiently lag a new push. A
label failure never becomes evidence of a successful scan. Only a 404 when
removing an absent label is ignored; other API failures are surfaced safely.

If GitHub's API is unavailable, the system cannot promise that a failure was
recorded. It returns a nonzero exit and does not deliberately publish success;
an absent or unfinished **required** check then keeps merging closed.

## Local use

From the repository root, install the existing development dependencies:

```sh
python -m pip install -e '.[dev]'
pytest -q
ruff check src tests
```

Run a scan on existing full commit SHAs, using a fresh result filename:

```sh
PYTHONPATH=src python -m integrity_guard.cli scan \
  --repo . --repository loesungerdechris-lang/upgraded-guacamole \
  --base FULL_BASE_COMMIT_SHA --head FULL_HEAD_COMMIT_SHA \
  --output /tmp/new-integrity-result.json
```

The command returns the actual decision as its OS exit code. Validation requires
the independently observed code and the expected repository/base/head:

```sh
PYTHONPATH=src python -m integrity_guard.cli validate /tmp/new-integrity-result.json \
  --repository loesungerdechris-lang/upgraded-guacamole \
  --base FULL_BASE_COMMIT_SHA --head FULL_HEAD_COMMIT_SHA \
  --process-exit-code OBSERVED_SCANNER_EXIT
```

The transport rejects duplicate JSON keys, non-finite numbers, oversized or
excessively nested JSON, non-regular files and symlinks. The schema rejects
unknown fields. Schema and semantic validation reject contradictory outcomes,
unknown rules, missing checks, unsafe paths, invalid line ranges and downgraded
mandatory findings. The CLI refuses to reuse an existing report path.

## Bootstrap and protected updates

This PR cannot prove its own trustworthiness. The trusted controller is loaded
from the protected base and will only be installed there after independent
review and merge. The first implementation PR is therefore a bootstrap change.
Its actual CI and local negative tests must be reviewed before deployment.

Once active, changes to the guard, workflow controls, dependency lock or guard
tests intentionally return 40. Ordinary PR approvals or a green label do not
override that decision. A future maintenance release needs an explicit,
audited administrator procedure or a separately designed, independent upgrade
authorizer. This implementation deliberately has no PR-controlled exception
list. Do not enable this strict policy without accepting this maintenance cost.

## Required-check rollout

At inspection, ruleset `27074079` (`Pre-Merge Integrity Protection (main)`) was
active, required one approval, dismissed stale approvals, required resolved
review discussions, prohibited force pushes/deletion and had no bypass actors.
It did **not** contain required status checks. This implementation does not
silently claim that this has changed.

After reviewing and merging the bootstrap change:

1. Verify the actual Actions event policy allows this trusted
   `pull_request_target` controller. GitHub's current documentation announces
   enforcement of a default block for affected public repositories on
   **2026-12-02**. Do not assume the trigger remains available by default.
2. Run a clean ordinary PR and prove the custom check is attached to the correct
   PR-head SHA. Test a draft and a real external fork separately.
3. Demonstrate failure for a synthetic credential, a protected-path change,
   an incomplete scan and an injected scanner/reporting failure. Do not use real
   credentials. Confirm new pushes invalidate old results.
4. Require the exact check contexts `Pre-Merge Integrity Guard` and
   `SENTINEL Required CI`, with an expected publisher App, strict up-to-date
   requirements and no bypass. Preserve approvals and resolved discussions.
5. Keep the existing secret scan, receipt verifier and Go/security checks
   required as appropriate to the repository's approved policy; confirm their
   actual emitted job names before adding them. This implementation does not
   invent required-check names or claim that they are already enforced.
6. Verify missing, failing, cancelled and stale outcomes block a real test PR.
   A successful local test suite is not evidence of live ruleset enforcement.

GitHub considers `neutral` and `skipped` successful for required checks. This
controller only publishes `success` after validated exit 0, and otherwise
`failure`. The separate CI aggregate uses `always()` and requires every named
dependency's result to equal `success`. Its own workflow must remain protected.
Merge queues are not supported by this v1 controller: add and test a trusted
`merge_group` flow before enabling a merge queue; never omit a required guard
check to make a queue proceed.

## Official references

- [Required status checks, skipped jobs, latest SHA and merge groups](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [Trusted use and event policy for pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [Check Run API and annotation limits](https://docs.github.com/en/rest/checks/runs)
- [Protected branches and expected check sources](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
