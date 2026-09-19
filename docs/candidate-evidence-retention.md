# Candidate evidence retention and verification

The release gate validates candidates. It has no signing or release authority.
PR #71 changed the Azure login pin in the separate manual OIDC smoke workflow;
ordinary pull-request checks do not execute that login.

## Retained artifact

After all validation succeeds, the release gate checks and packages exactly:

- `sentinel`
- `sentinel.sha256`
- `tracked-files.sha256.json`
- `release-evidence.json`

The artifact is named
`sentinel-candidate-<commit-sha>-<run-id>-<run-attempt>`. It contains
`sentinel-candidate.tar`, preserving the binary's executable mode. Uploads use
the reviewed `actions/upload-artifact` v7.0.1 commit, reject missing files,
and do not overwrite previous attempts.

The job summary records the artifact ID, URL and artifact ZIP SHA-256.
The inner `sentinel.sha256` contains a relative `sentinel` filename so it can
be checked after download. No tokens, signing keys or Azure account context
belong in this artifact.

**GitHub retention is 90 days, not permanent archival.** Repository policy or
deleting a run can also affect availability. Before expiry, export each reviewed
artifact to the authorized durable evidence archive with its original bytes,
GitHub artifact digest, repository, commit, run ID, attempt and retrieval date.
Verify the copy before recording archival completion. This workflow does not
claim to provision that archive or to make GitHub storage permanent.

## Verify after download

Obtain the expected repository, commit, run ID, attempt and artifact digest from
the trusted GitHub run. Do not take the expected values solely from the bundle
being checked. Compare the downloaded ZIP's SHA-256 to the artifact digest, then
unpack the ZIP and its `sentinel-candidate.tar` in a fresh directory. Inspect
archive member paths before extracting and never execute an unreviewed binary.

Using a reviewed checkout of this verifier:

```bash
PYTHONPATH=src python -m sentinel_core.candidate_bundle \
  --bundle /path/to/extracted-candidate \
  --expected-sha <full-run-commit-sha> \
  --expected-repository loesungerdechris-lang/upgraded-guacamole \
  --expected-run-id <run-id> \
  --expected-run-attempt <attempt>
```

Use `--repo-root /path/to/clean-source-checkout` to also compare the complete
tracked-file set and every source-file hash against the expected Git commit.
The verifier rejects changes to the index or tracked working-tree files before
comparing source hashes, even if the bundle was updated to match those changes.
Untracked files are outside this source comparison.
For pull-request runs, GitHub may use a synthetic merge commit; use the
`GITHUB_SHA` recorded by that run, not merely the pull-request branch head.

The check rejects missing/extra files, symlinks, duplicate JSON members,
binary or subordinate-manifest hash mismatches, wrong commit/repository/run/attempt,
non-relative checksum filenames, unsafe tracked paths and any elevation of
the candidate's release authority. It does not execute the candidate.
The inner verifier does not validate `ref` or `created_utc`. The separate check
against the trusted artifact ZIP digest detects changes to any archived bytes,
including these fields; do not omit that check.

Success is `CANDIDATE_BUNDLE_CONSISTENT`. This proves the checked bindings and
hash consistency, not a cryptographic signature, trusted origin by itself,
production authorization, or full SLSA provenance.

## Existing integration work

Snapshot checked on 2026-09-19 against main
`35c2623c1f01164f8361c0d6fdb2e50e854d46a1`:

- [PR #23](https://github.com/loesungerdechris-lang/upgraded-guacamole/pull/23)
  contains the protected live sign/verify workflow on a Draft branch,
  head `b92d82a70b177648b24507177da5a2deaf00b99b`.
  It is absent from main because it has not been merged. The live key
  exportability recheck remains an unresolved review finding. Its login pin
  also still points to v2.3.0. Refresh and independently review that branch
  before considering integration; do not infer readiness from the issue text.
- [Issue #14](https://github.com/loesungerdechris-lang/upgraded-guacamole/issues/14)
  tracks protected Azure activation. Actual Environment, Entra and RBAC settings,
  metadata smoke, public trust registration and independently verified live
  signing remain separate evidence requirements.
- [PR #61](https://github.com/loesungerdechris-lang/upgraded-guacamole/pull/61)
  is an older Draft for azure/login v3.0.1. Its runtime-verification requirement
  is still relevant, but its dependency proposal is older than merged #71.
- [PR #69](https://github.com/loesungerdechris-lang/upgraded-guacamole/pull/69)
  and [PR #70](https://github.com/loesungerdechris-lang/upgraded-guacamole/pull/70)
  hold the v2.2 demonstrator and mutation-test work on Draft branches.
  This candidate-retention change does not merge or supersede those contracts.

The Azure OIDC smoke remains manual, main-only, and bound to
`sentinel-production`. No approval, branch-protection, federation or deployment
rule is weakened by candidate artifact retention.
