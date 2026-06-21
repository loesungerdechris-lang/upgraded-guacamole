# Repository Architecture

## Current repository role

`upgraded-guacamole` is currently used as the clean bootstrap repository for the LoesungErde / Akira SENTINEL workspace.

## Recommended target repositories

The project should be split into focused repositories once repository creation is available:

| Repository | Purpose | Visibility recommendation |
|---|---|---|
| `sentinel-core` | Evidence chain, verifier, policy engine, deterministic decision logic | private during development |
| `sentinel-schemas` | Public JSON schemas, receipt profiles, compliance mappings | public after review |
| `sentinel-labs` | Synthetic demos, red-team fixtures, test cases | public or private depending on data |
| `akira-security-playbooks` | B2B playbooks, audit checklists, customer-neutral templates | private |
| `loesungerde-docs` | Public project documents, website copy, whitepapers | public after legal/compliance review |

## What should not live in GitHub

- Real incident evidence
- raw health, personal, or customer data
- secrets and credentials
- private keys or certificates
- unreviewed allegations or claims about third parties

## Migration plan

1. Use this repository as the bootstrap workspace.
2. Add schemas, verifier skeleton, CI checks and documentation.
3. Rename or split the repository once the project boundaries are stable.
4. Keep large upstream forks such as `azure-sdk-for-net` separate from SENTINEL code.
