# M2 artifact retention and recovery

Status: historical archive gap OPEN; new-run retention remediation prepared.

On 2026-09-24 the GitHub API returned `expired: true` for all 16 artifacts
of run **35225083250**, PR #70 head
`63f8875c27ba29ac6ba87da5ed0cf1b6b9040194`.
The successful run metadata remains evidence of the recorded execution.
It does not replace the original artifact bytes or enable an offline replay.
No independently verified byte archive of that run has been located in the
scoped Library/Drive search. This is a search limit, not proof that no copy exists.
The owner's workstation was offline during this review.

This change requests **90 days** of retention for all seven artifact upload
steps in `sentinel-demo.yml`, covering all 16 generated artifacts. It does not
change verification, mutation cases, permissions, action pins or approval gates.
It neither extends expired artifacts retroactively nor provides permanent storage.

A new successful workflow run is a new observation, with its own commit,
run ID, attempt, golden pin and artifact digests. Never label it as recovery
of the old bytes. The frozen crosswalk baseline remains unchanged.

## Closure requirements

1. Read the trusted run metadata, jobs and complete artifact inventory.
   Record repository, source head, actual checkout/merge commit, run ID and attempt.
2. Download every original ZIP while available. Verify each SHA-256 against
   its GitHub artifact digest; missing, expired or mismatched files keep the
   archive incomplete. Preserve the original ZIP without recompression.
3. Store those ZIPs, their byte counts, artifact IDs/digests and retrieval time
   in the authorized durable archive outside the temporary Actions retention.
4. Read the stored copy back. Compare hashes and sizes, check ZIP CRCs and safe
   member paths before extraction, and retain a file inventory.
5. Check the golden export against its independently exported pin and execute
   the reviewed verifier/mutation procedure for that exact source version.
   Record actual results; do not infer semantic validity from hashes alone.
6. Record `STORED_RECEIPT`, `READBACK_HASH_VERIFIED` and `RESTORE_CHECKED`
   separately. Mark missing components explicitly. Schedule an expiry review
   and periodic restore check; a retention setting alone closes no archive gate.

The archive contains only the public demo outputs selected by this workflow.
Never add ephemeral private signing keys, credentials or unrelated private files.

## Release boundary

M2 remains a demonstrator: governance fixture, custom demo provenance and
`productionAcceptance: false`. Restored artifacts do not grant production
authorization, canonical v2.2 completeness, an HSM trust anchor or SLSA status.
PR #72 retains a separate unsigned release candidate; it is not the M2 golden
bundle and cannot fill this historical gap.
