# SENTINEL demo verifier test report

Date: 2026-09-17

Scope: `sentinel-demo-mvp/v0.1` technical demo verification only. The
governance predicate used by these tests is explicitly a non-production mock:
`fixture` is `true`, `productionApproval` is `false`, and every verifier result
sets `productionAcceptance` to `false`. This report is not CN-EVIDENCE-001
conformance evidence, production approval, a SLSA claim, or an SBOM
completeness/vulnerability claim.

## Test setup

- Cosign: 3.1.3, selected by `COSIGN_BIN`, project `.tools/cosign`, or `PATH`
- Python: standard-library `unittest`
- Signing: fresh password-protected temporary ECDSA key per test
- Attestation command: Cosign-generated in-toto Statement v0.1 through
  `attest-blob --predicate --type`, with
  `--use-signing-config=false --tlog-upload=false`
- Verification: `verify-blob-attestation` with the independently pinned public
  key, exact predicate URI, image digest, SHA-256 digest algorithm, and
  `--insecure-ignore-tlog`
- Network/public services: none used; test attestations are not uploaded to a
  transparency log or registry
- Key lifecycle: private and public test keys are held in a
  `TemporaryDirectory` and deleted by test teardown; no test secret is part of
  the repository

## Red run

The six required behavioural tests were first run against an `ERROR /
NOT_IMPLEMENTED` verifier stub:

```console
$ COSIGN_BIN=/workspace/scratch/cb41117e24a7/toolchain/cosign python3 -m unittest tests.test_verify -v
...
Ran 6 tests in 15.578s

FAILED (failures=6)
```

Each failure was the intended literal exit-code assertion: `0`, `2`, `2`, `3`,
`3`, and `2` were expected, while the stub returned `4`.

## Green run

After implementing the verifier and adding four focused regression tests:

```console
$ COSIGN_BIN=/workspace/scratch/cb41117e24a7/toolchain/cosign python3 -m unittest discover -s tests -p 'test_verify.py' -v
test_bad_signature_is_blocked_after_outer_descriptors_are_repinned ... ok
test_cosign_name_is_resolved_from_callers_path ... ok
test_digest_mismatch_is_blocked ... ok
test_happy_path_passes ... ok
test_missing_governance_holds ... ok
test_missing_manifest_holds ... ok
test_missing_sbom_holds ... ok
test_non_finite_json_policy_values_are_malformed ... ok
test_numeric_governance_check_cannot_equal_json_true ... ok
test_public_key_path_swap_after_pin_cannot_change_verification_key ... ok

Ran 10 tests in 31.754s

OK
```

The six primary outcomes and reason codes are:

| Scenario | Status | Exit | Reason code |
| --- | --- | ---: | --- |
| Valid bundle | PASS | 0 | `VERIFIED` |
| Referenced SBOM object unavailable | HOLD | 2 | `MISSING_SBOM` |
| Referenced governance object unavailable | HOLD | 2 | `MISSING_GOVERNANCE` |
| Pinned content digest mismatch | BLOCKED | 3 | `DIGEST_MISMATCH` |
| Cryptographically invalid DSSE signature | BLOCKED | 3 | `INVALID_SIGNATURE` |
| Referenced root manifest object unavailable | HOLD | 2 | `MISSING_MANIFEST` |

The bad-signature fixture changes the DSSE signature and then recomputes the
bundle descriptor, outer OCI artifact manifest, and trusted request
descriptors. It therefore reaches Cosign signature verification rather than
being rejected by an outer hash check. The two missing-role fixtures remove
the actual OCI artifact manifest referenced by the signed inventory.

## Security review

The verifier rejects duplicate JSON keys; unknown profiles, policy fields,
roles, and predicate types; OCI indexes; malformed descriptors; unpinned or
wrong-sized content; extra or duplicate mandatory roles; context mismatches;
invalid mock-governance markers; and Cosign failures. Reads are capped at 64
MiB per object and 128 MiB total. Evidence content supplies no URL or executable
path, and verification uses no content-selected key or certificate fallback.

Review found one concrete false-PASS risk: Python considers integer `1` equal
to boolean `True`. A fully signed governance predicate with numeric check data
initially passed. The added regression test demonstrated the flaw, and the
validator now requires literal JSON booleans. The same identity check protects
the boolean policy fields. Strict parsing also rejects `NaN` and infinities,
and a bare Cosign command name is resolved from the caller's `PATH` before the
verification subprocess receives its restricted environment.

The independent review also identified a public-key time-of-check/time-of-use
flaw. The verifier hashed the trusted key file, but Cosign later reopened the
same path. A malicious store callback could replace key A with attacker key B
after the pin check and make B-signed evidence pass. The focused regression
demonstrated the false PASS before the fix:

```console
$ PYTHONPATH=tests COSIGN_BIN=/workspace/scratch/cb41117e24a7/toolchain/cosign python3 -m unittest test_verify.VerifyBundleAcceptanceTests.test_public_key_path_swap_after_pin_cannot_change_verification_key -v
FAIL: test_public_key_path_swap_after_pin_cannot_change_verification_key
AssertionError: 3 != 0

Ran 1 test in 5.766s
FAILED (failures=1)
```

The verifier now passes only the already hashed key bytes through the evidence
walk, writes those bytes to a private temporary `public.pem`, and gives that
snapshot to every Cosign invocation. It never reopens the caller's original key
path after pinning. The same regression then returned `BLOCKED /
INVALID_SIGNATURE`, and the final ten-test run shown above passed.
