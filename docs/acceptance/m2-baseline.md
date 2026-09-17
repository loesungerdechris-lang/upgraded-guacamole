# Evidence Bundle v2.2 — Milestone M2 Baseline

<!-- Generated from the reviewed m2-observation.json snapshot. -->

Baseline ID: **M2-2026-09-17-66732c7**. Architecture Demonstrator; technical M2 reference, human acceptance pending.

| Field | Frozen value |
|---|---|
| Date | 2026-09-17 (UTC) |
| Commit | [`66732c7bfddd7812222827763336c732cf05461a`](https://github.com/loesungerdechris-lang/upgraded-guacamole/commit/66732c7bfddd7812222827763336c732cf05461a) |
| Source tree | `1a68a5ec409b154de289aa07baf6a3900c5c81ac` |
| PR | [#69 M1](https://github.com/loesungerdechris-lang/upgraded-guacamole/pull/69), [#70 M2](https://github.com/loesungerdechris-lang/upgraded-guacamole/pull/70), both separate from merge approval |
| Workflow Run | [35221177108](https://github.com/loesungerdechris-lang/upgraded-guacamole/actions/runs/35221177108) |
| Tests | 32/32 PASS |
| Jobs | 12/12 PASS |
| Mutations | 10/10 expected rejection codes observed; all tests PASS |
| Coverage | COMPLETE (M2 Scope); overall v2.2 INCOMPLETE |
| Golden | PASS; `sha256:e30b263cd7f4a833f6080e8b3da0e64e46fe324329384bee8bd3231d7151163f` |

## Versioned observation

[m2-observation.json](../evidence-bundle-v2.2/evidence/m2-observation.json) preserves job identities, selected public log observations, artifact digests and 35 source-file pins. These pins must match the current demo before this baseline can support its crosswalk. New runtime/code/catalog changes need a new reviewed run and observation; documentation-only changes do not inherit a green CI result automatically.

This is a versioned reference, not WORM storage or a signed independent CI receipt. The full raw artifact ZIPs and logs are not committed. GitHub artifact expiry starts at 2026-09-24T12:27:38Z; their digests and references remain here, but do not preserve their bytes. A durable external archive remains open. No release or Git tag was created.

## Artifact inventory

| Artifact | ID | SHA-256 archive digest | Expires (UTC) |
|---|---:|---|---|
| sentinel-demo-gate | 10497546184 | `sha256:ed51b70a2d0354963b89b6a7f89adaf05d53faf8d9d7cd4e02b9e7ab55bda8dd` | 2026-09-24T12:28:08Z |
| sentinel-m2-digest-mismatch | 10497676087 | `sha256:53b7ccbe4a2b5bde0d2399729a00ef1ebb0867455d7f2b329921935559b3684a` | 2026-09-24T12:27:53Z |
| sentinel-m2-golden | 10496897557 | `sha256:a03fb015f7862b5dbf9814f370024ad84b4cfc58a1e91f69bbe74bbeb9415b36` | 2026-09-24T12:27:38Z |
| sentinel-m2-governance-fail | 10496932574 | `sha256:cb33edeebcc371b277a52dbb0b802091c74b09cf881bfafa4a43f57f933ecec7` | 2026-09-24T12:27:52Z |
| sentinel-m2-invalid-signature | 10497546125 | `sha256:b74c01dc8a34917e9115922b70bd386a824ca7985f1934b365fe7449e6903dcc` | 2026-09-24T12:27:51Z |
| sentinel-m2-missing-attestation | 10496862570 | `sha256:68eb74f93fe47aa5e4629eb251978d8de2acfd7b18ae82d43f993738d467b47a` | 2026-09-24T12:27:53Z |
| sentinel-m2-missing-governance | 10497575960 | `sha256:28a7feb1441f3033e8e40fe5d1b16b4d886c730097a56ed7261f1a8b8feda2f2` | 2026-09-24T12:27:52Z |
| sentinel-m2-missing-manifest | 10496927558 | `sha256:4d5b5023fd648c46a14bffea11b4503038046be48dec105eb5a270716d453187` | 2026-09-24T12:27:52Z |
| sentinel-m2-missing-provenance | 10497541145 | `sha256:7683e122c551f5f3f3b9af488fdd6faa8c9bd2d96ec6b75cc34f6b6635dfc0cb` | 2026-09-24T12:27:54Z |
| sentinel-m2-missing-sbom | 10497171449 | `sha256:37fdc0c714c82d638bb9c4f2ae1c4725ae9cade37c11da66442392c9e05d978c` | 2026-09-24T12:27:53Z |
| sentinel-m2-pin | 10496557858 | `sha256:25ed69e33b5d500e792fe1316928ca63eedca1f0dc5f2fca97eaed7893d5b3df` | 2026-09-24T12:27:40Z |
| sentinel-m2-subject-mismatch | 10497396249 | `sha256:7ad3f324ae96183c9072f8b184235d167bafa260e05bdb7acff6dabf7c40a130` | 2026-09-24T12:27:51Z |
| sentinel-m2-unknown-predicate | 10496997631 | `sha256:5ec8b74d93b62eef9f843a699a75f6241216db4b606ac10a4584799f2411e730` | 2026-09-24T12:27:54Z |

## Remaining limits

Governance Mock; Demo-Provenance; missing canonical v2.2 crosswalk; no HSM, Azure Key Vault or production trust validation. `productionAcceptance:false`. M3 Governance Realization, M4 trust paths and M5 full v2.2 acceptance remain open.
