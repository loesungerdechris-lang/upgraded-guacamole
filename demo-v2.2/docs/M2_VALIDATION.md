# M2 validation

These are executed local results, not a compliance or production approval.
Hosted evidence will be attached to the stacked Draft PR against M1 #69.

## Observed results

- Native registry build, push, Syft scan, four Cosign attestations and live verify: PASS.
- Golden live/offline/repeated decisions: identical PASS.
- Golden index pin: `sha256:6dac9112195c0aac35075bcd4983abc51929fe54d2f44aaa2fc5075d03f6642b`.
- Ten mutation cases: all expected process exit codes matched.
- Every mutation generated twice: byte-identical work-file inventories.
- Golden verification before/after: exit 0; index/file inventory unchanged.
- Demo unittest suite: 32 tests passed in a fresh complete run, including the existing 13 M1/CI tests.
- M1 full registry pipeline rerun: all six acceptance scenarios passed.
- Existing core: 172 pytest tests passed; `ruff check src tests` passed.
- Workflow: actionlint 1.7.12 passed.
- Verifier task and whole-branch reviews: spec compliance and code quality approved; no open findings.

| Scenario | Expected | Actual |
|---|---:|---:|
| missing-manifest | 10 | 10 |
| missing-sbom | 11 | 11 |
| missing-governance | 12 | 12 |
| missing-provenance | 13 | 13 |
| missing-attestation | 14 | 14 |
| digest-mismatch | 20 | 20 |
| invalid-signature | 30 | 30 |
| subject-mismatch | 40 | 40 |
| governance-fail | 50 | 50 |
| unknown-predicate | 60 | 60 |

The preserved golden bundle is generated at runtime, not committed. A fresh
build has new test keys/signatures/time fields and thus a different index pin.
Only mutation application and verification of the same bytes are claimed
reproducible. Registry deletion behavior and remote registry compatibility are
not tested by offline mutations. See M2_PROFILE.md for the exact trust boundary.
