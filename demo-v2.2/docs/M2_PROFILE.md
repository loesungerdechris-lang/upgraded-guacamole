# M2 — Golden Bundle and mutation contract

Status: Architecture Demonstrator, draft. Profile `sentinel-demo-m2/v0.1`.
M1 `sentinel-demo-mvp/v0.1` remains supported with its original status codes.
This extension is not canonical v2.2 conformance or a SLSA level claim.

## One golden bundle

`build_golden.py` calls the existing build/registry/Syft/Cosign runner with the
M2 policy. It creates one image, SBOM, governance predicate, custom demo
provenance, and signed inventory. All four attestations are uploaded to and read
from the native loopback registry. Live, offline and repeated decisions must
agree and PASS before the export is accepted.

The provenance records source and binary SHA-256 values from this build, builder
`sentinel-demo`, run ID, image digest and policy digest. It is a signed producer
assertion with `fixture:true`, not an independently protected build attestation.
The verifier checks its schema and binding, not an independent rebuild.

After registry shutdown and log closure, `golden-index.json` lists the exact
public file set with sizes and SHA-256 hashes. Its digest is exported separately
as the CI job output `golden-pin`. Mutation jobs download the same artifact and
require this pin before and after mutation. No private signing key is retained.
The pin detects changes to the exported fixture; it is not independent production
release authorization. Its trust comes from the reviewed workflow and source.

## Declarative mutations

`tests/mutations/*.yaml` uses the JSON subset of YAML. The interpreter accepts a
closed set of logical operations and roles, with no shell commands, arbitrary
paths or YAML object constructors. `sentinel mutate` copies bytes into its own
work directory and never uses hard links to golden evidence. Repeated invocation
replaces only a directory carrying the runner's ownership marker. Overlapping
paths, symbolic links and unrelated existing output directories are rejected.
The tool assumes a user-owned workspace, not a hostile concurrently modified
filesystem. Each CI job has an isolated work directory.

The signed inventory and CAS layout are authoritative; deleting a convenience
copy such as `sbom.json` would not remove the actual signed SBOM. Accordingly:

The normative scenario/requirement/exit mapping is defined in the
[Mutation Coverage Matrix](../../docs/mutation-coverage-matrix.md), revision 1.0.
It includes the golden control (exit 0), ten negative cases, requirement IDs,
observed results for a pinned commit and links to the executable catalog.
Changes to this contract require the matrix and catalog to be reviewed together.

M2 other verification/input errors return 90. Before an M2 request can be read,
legacy CLI input errors return 4; argument syntax errors return 2. Mutation setup
errors return 99. The suite returns 0 only when golden verification is successful
and every selected verifier process returns its exact declared code. A nonzero
mutator exit or operational exception fails the suite; it cannot count as the
expected verifier rejection. Log strings are diagnostic only.

Presence errors here distinguish the referenced OCI wrapper from its signed
payload. A malformed inventory, absent role declaration, unsupported profile or
wrongly shaped predicate fails closed with the applicable generic reason; these
ten cases do not exhaust every malformed-input classification.

## Isolated semantic failures

Changing signed JSON alone usually tests a digest or signature failure. During
golden generation, while the temporary key exists, the producer creates three
public signed deltas for subject, governance and predicate faults. Each includes
its changed governance artifact and a newly signed inventory referencing it.
The golden graph is never overwritten. These are a few shared CAS objects, not
three independently built full bundles. Mutation jobs receive no signing key.

For M2, Cosign authenticates the DSSE signature with the pinned public-key
snapshot and `--check-claims=false`. The Python verifier then **mandatorily**
checks the statement format, expected predicate URI, exactly one subject and its
exact image digest. OCI subject descriptors are also bound to the image. This
separation allows authenticated wrong-subject/type cases to return 40/60 rather
than masquerading as signature failures. No signature-only result produces PASS.
The demo transparency-log exception remains explicit and unchanged in scope.

## Local execution

From `demo-v2.2`:

```bash
python3 scripts/bootstrap.py --directory .tools
COSIGN_BIN="$PWD/.tools/cosign" python3 -m unittest discover -s tests -v
python3 scripts/build_golden.py --tools .tools \
  --output release-golden --pin-output release-pin.json
PIN=$(python3 -c 'import json; print(json.load(open("release-pin.json"))["goldenPin"])')
python3 scripts/run_mutation_suite.py --golden release-golden \
  --golden-pin "$PIN" --cosign .tools/cosign --output release-mutations
```

For an individual mutation, use `python3 sentinel mutate --golden release-golden
--golden-pin "$PIN" --scenario missing-sbom --output release-case` then the usual
`verify-bundle` command with the request/policy/key/bundle from `release-case`.
Keep reports outside the sealed golden directory. Do not regenerate the index
merely to accept modified evidence. New builds require fresh output directories.

The suite verifies golden before and after each selected run, generates every
mutation twice and compares work-file hashes to demonstrate idempotence. Matrix
jobs run this same script. Mutation verification is offline against an export
retrieved from the live registry; it does not mutate a running registry server.

## Boundaries

Governance remains a marked mock; the new failure test proves rejection of a
failed technical check, not a complete policy engine. HSM, Azure Key Vault,
independent trust provisioning, revocation/time validation, real governance,
SLSA provenance and the complete canonical v2.2 suite remain open. There is no
measured percentage claim about real-world attack coverage.
