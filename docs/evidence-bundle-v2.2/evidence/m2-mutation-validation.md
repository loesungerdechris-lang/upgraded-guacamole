# M2 evidence reference

- [Draft PR #70](https://github.com/loesungerdechris-lang/upgraded-guacamole/pull/70)
- [Frozen baseline and artifact inventory](../../acceptance/m2-baseline.md)
- [Machine-readable observation](m2-observation.json)
- [Requirement / test / exit / CI crosswalk](../crosswalk.md)
- [Original mutation contract](../../mutation-coverage-matrix.md)

The baseline records successful rejection tests: the mutated bundles were rejected
with the expected codes, while the tests themselves passed. It does not record
ten accepted bundles. The original mutation matrix cites the earlier implementation
run; the frozen baseline cites the later documentation run. These references are
intentionally tied to their respective commits.

Current CI validates the crosswalk and re-runs the live golden/mutation suite.
Its job counts and results are separate from the frozen baseline. Artifact hashes
and job references are preserved; full raw artifact bytes are not archived here.
