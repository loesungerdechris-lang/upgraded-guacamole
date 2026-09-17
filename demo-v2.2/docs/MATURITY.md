# Evidence Bundle v2.2 — M1 maturity

**Architecture Demonstrator — DRAFT.** CI/CD and the verification framework are
implemented. This is not a Compliance Demonstrator, a production release, a SLSA
level claim, or canonical Evidence v2.2 conformance. The executable profile is
`sentinel-demo-mvp/v0.1`; `v2.2` in the directory and milestone title is the project
working label.

## Implemented and locally observed

| Capability | Local evidence | Hosted GitHub evidence |
|---|---|---|
| One Rust binary, build and test | Passed | PR checks required |
| Native loopback OCI registry and immutable image digest | Passed | PR checks required |
| Real Syft CycloneDX SBOM for that digest | Passed | PR checks required |
| Cosign SBOM, governance and manifest attestation round-trip | Passed | PR checks required |
| verify-bundle reading real OCI manifests and blobs | Passed | PR checks required |
| Online/offline/repeat decision equality | Passed | PR checks required |
| Six positive/negative acceptance scenarios | 6/6 passed | All six matrix jobs required |
| Verifier and CI gate tests | 13/13 passed before import | Rerun in PR |
| Workflow syntax | actionlint passed before import | Adapted path validation and PR checks required |

The local registry, attestation upload, download and signature verification were
actually executed. They are not unimplemented placeholders. A successful local
run is not a substitute for the corresponding hosted run.

## Mock and signing boundaries

Governance is explicitly synthetic: `fixture:true`, `productionApproval:false`,
and every result has `productionAcceptance:false`. Build/test/SBOM checks follow
actual completed steps. There is no static `cabApproved:true`, no fabricated risk
score and no human/CAB approval claim.

The demo producer and test-fixture generator create ephemeral synthetic signing
keys in temporary directories. No key bytes, certificates, generated bundles or
raw logs are committed. The verifier only accepts a separately supplied public
key and pinned request; it never generates keys or signs evidence. The demo's
self-generated trust inputs demonstrate a technical chain, not independent
release authorization.

The repository PR-template statement excluding signing from *tests* cannot be
checked without qualification for these fixtures. The isolated temporary test-key
scope must be explicitly accepted at review. No existing core/receipt validation
or Class A signature floor is modified, and no security rule is weakened.

## Merge blockers

- [ ] Real GitHub Actions run completed successfully for the reviewed revision.
- [ ] OCI registry integration validated on GitHub's runner.
- [ ] Cosign attestation round-trip validated on GitHub's runner.
- [ ] verify-bundle against live OCI artifacts validated on GitHub's runner.
- [ ] Governance mock replaced or formally accepted for this architecture-only M1.
- [ ] Required Evidence v2.2 acceptance suite completed. This PR implements only
      the six-case MVP; the canonical 24-case suite is not claimed complete.
- [ ] Temporary synthetic signing fixtures and isolated demo scope accepted by
      the human reviewer; applicable CODEOWNERS/repository checks satisfied.

These checkboxes are review decisions, not automatic conclusions from this file.
GitHub check URLs and the reviewed commit identify hosted evidence. Keep the PR
draft until the applicable blockers have been resolved explicitly.

## Deferred milestones

Real governance engine, independent production trust, SLSA provenance, Trivy,
HSM signing validation, Azure Key Vault validation, ORAS migration, broader OCI
registry compatibility and the complete 24-case suite are future work. HSM/Azure
are not silently represented as passing by the software-key demonstration.
