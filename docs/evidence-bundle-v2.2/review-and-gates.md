# Crosswalk review and gate contract

Status: Draft. This contract covers the local M2 demonstrator. A green check is
technical evidence; production acceptance and human merge approval remain open.

## Sources and authority

| Source | Responsibility |
|---|---|
| `requirements.yaml` | Reviewed local requirement inventory, maturity and traceability |
| `crosswalk.schema.json` | Strict structure and permitted M2 maturity claims |
| `../../tests/exit-codes.yaml` | Symbolic and numeric M2 exit-code contract |
| `../../demo-v2.2/tests/mutations/*.yaml` | Executable mutation definitions |
| `../../tests/crosswalk/expected-requirements.txt` | Separately reviewed expected ID inventory |
| `evidence/m2-observation.json` | Frozen, reviewed CI observation and source-file hashes |
| `crosswalk.md`, `crosswalk.mmd`, `../acceptance/m2-baseline.md` | Deterministically generated review views |

Paths in this table are relative to this document. Both YAML inputs use the strict
JSON subset, matching the existing demo: no `yq` variant, YAML tags, aliases, merge
keys, duplicate keys or implicit type conversion. The validator rejects remote
schema references and does not download schemas.

The authoritative v2.2 specification has not been established in this repository.
`M2-MUT-*` retains the reviewed mutation contract; `GOV-*` and `TR-*` are provisional
planning IDs. All canonical references are explicitly unassigned. The local
inventory has 16 entries, not an asserted canonical total of 24. Production
Governance evaluation is partial only because a related mock rejection exists;
it has no accepted implementation or acceptance test.

## Local and CI commands

From the repository root, using Python 3.10 or newer:

```bash
python3 -m venv .crosswalk-venv
.crosswalk-venv/bin/python -m pip install jsonschema==4.26.0
.crosswalk-venv/bin/python scripts/crosswalk.py generate
.crosswalk-venv/bin/python scripts/crosswalk.py validate --output .crosswalk-results/validation.json
.crosswalk-venv/bin/python -m unittest discover -s tests/crosswalk -v
```

`tests/crosswalk/validate-crosswalk.sh` is a wrapper using the active `python3`;
activate the same environment before invoking it. `generate` validates first,
then writes only the three named views. `validate` writes no source files and
compares generated content byte for byte. The JSON report is persisted atomically.

The validator checks schema, unique IDs, the expected inventory, bidirectional
requirement/mutation mappings, symbolic and numeric exit codes against the actual
verifier, existing rule functions, predicate types and roles, source pins,
observed CI rejection codes, maturity boundaries and generated views.
It cannot prove that a prose title correctly describes a function; review must
establish that semantic relationship.

| Validator exit | Meaning |
|---|---|
| 0 | All checks passed and any requested report was persisted |
| 1 | Contract, evidence-reference or generated-view inconsistency |
| 2 | Infrastructure, missing input, parser/runtime or report-persistence error |

These are validator process codes, separate from the bundle-verifier contract
(0, 10–60, generic 90). Neither an error nor an expected bundle rejection grants
production approval.

## Frozen baseline and changes

The [M2 baseline](../acceptance/m2-baseline.md) records commit `66732c7` and run
`35221177108`. Its 12 evidence jobs were all jobs in that historical workflow.
The updated workflow adds three crosswalk/aggregate jobs, making 15 in the current
configuration. Historical counts remain historical.

The observation pins the demo verifier, runner, mutation catalog, tests, policy,
source and toolchain. Editing any pinned file invalidates reuse of that observation.
Workflow and documentation files are reviewed separately; a prior green baseline
does not prove a new workflow revision works.

For a runtime change, first push the candidate and let `verify-golden`, the ten
mutations and `SENTINEL demo gate` produce fresh evidence. They run independently
of crosswalk validation, so a stale baseline can block the crosswalk without
preventing evidence collection. After reviewing their logs, artifact metadata and
the exact candidate source, record a new observation and hashes, regenerate the
views, and run the complete workflow again. Keep only those 12 evidence jobs in
the observation; the current crosswalk and total-gate result must be cited
separately. Never describe a failed aggregate run as a passing complete workflow.
Preserve the earlier baseline in Git history and explain the replacement in the PR.

The committed observation is an auditable reference, not a signed independent CI
receipt or an archive of artifact bytes. Retention expiry and the open archival
task are disclosed in the baseline. A coordinated edit of data, schema, validator
and tests can redefine the contract; human review remains necessary.

## Workflow gates

The existing [demo workflow](../../.github/workflows/sentinel-demo.yml) runs on
every PR, pushes to `main`, merge-queue events, dispatch and `workflow_call`, without
path filters that could omit a required check. Permissions are read-only.

| Check | Required predecessor results |
|---|---|
| `crosswalk-validation` | Contract validation and all crosswalk regression tests succeed |
| `crosswalk-gate` | `crosswalk-validation` equals `success` |
| `SENTINEL demo gate` | Golden job and complete mutation matrix equal `success` |
| `evidence-total-gate` | `crosswalk-gate` and `SENTINEL demo gate` both equal `success` |

Gate jobs use `always()` and compare exact result values. Failure, cancellation,
skip, unknown or missing values cannot pass. Runner cancellation can prevent a
final check from completing; the server must require that check before merging.
Gate reports always carry `productionAcceptance: false`.

## Review and server-side enforcement

`.github/CODEOWNERS` covers the crosswalk, baseline, schema, validator, tests and
ruleset proposal. The PR template requires affected IDs, scope changes and CI
proof. CODEOWNERS on its own does not make a review mandatory; the base branch
must contain the applicable file and GitHub must enforce the review rule.
Draft PR #70 stays draft. Automatic code-owner review requests start when a draft
becomes ready; no request or human approval is claimed here.

The existing owner is also the PR author. An author cannot approve their own PR.
Before activation, assign an actual independent, eligible code owner with write
access; no reviewer identity or approval is invented in this change.

[`evidence-review.proposed.json`](../../.github/rulesets/evidence-review.proposed.json)
is an **inactive additive proposal**, not an applied server setting. It adds the
two uniquely named crosswalk/total checks, one approval, stale-review dismissal,
code-owner review, approval after the last push and resolved conversations for
`main`. Existing core, security, receipt and release protections must be retained.
The proposal has no bypass actors. Before activation, inspect effective existing
rules, confirm the actual check names and GitHub Actions App identity from a live
run, and set the status-check `integration_id` accordingly. Then activate the new
rule with repository administration access and read back the effective settings.
No repository-administration tool is available in this session; server-side
activation and verification remain open.

PR #70 is stacked on the M1 branch. Its green demo workflow does not substitute
for the existing core/security workflows that run on PRs targeting `main`.
Re-run those required checks after retargeting; do not remove their requirements.

Official references: [workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax),
[code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners),
[ruleset API](https://docs.github.com/en/rest/repos/rules#create-a-repository-ruleset).
