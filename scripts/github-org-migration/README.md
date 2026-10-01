# SENTINEL GitHub Organization Migration Toolkit

Status: **DRAFT / HOLD**

This toolkit automates evidence-first preparation for moving SENTINEL repositories from a personal GitHub account into a dedicated organization. It is designed for PowerShell 7 and the GitHub CLI (`gh`).

## Safety model

The default mode is non-mutating. Inventory, backup, team plans, OIDC subject plans, transfer preflight, and post-transfer verification can run without changing GitHub or Azure.

Mutating actions require separate gates:

- `-Apply` on the exact script;
- an exact confirmation string;
- an explicit environment authorization value;
- repository- or organization-specific checks;
- no automatic merge, deployment, signing, publication, or production activation.

The toolkit never creates a GitHub organization, changes billing, purchases credits, creates Azure resources by default, reads secret values, deletes repositories, rewrites Git history, prunes unreachable objects, or transfers more than one repository per invocation.

## Files

- `00-master-migration.ps1` — plan and orchestrate safe phases.
- `01-inventory-repos.ps1` — repository metadata inventory, optional mirror backup, and SHA-256 manifest.
- `02-create-teams.ps1` — organization and team plan; optional guarded team creation.
- `03-plan-oidc-and-controls.ps1` — environment and OIDC-subject plan; optional guarded GitHub environment creation.
- `04-migrate-repo.ps1` — one-repository transfer preflight and separately authorized transfer.
- `05-verify-after-transfer.ps1` — exact-head, repository-ID, configuration, and OIDC subject verification.
- `migration-config.example.json` — reviewed configuration template.

## Prerequisites

```powershell
pwsh --version
gh --version
git --version
gh auth status
```

Do not request broad scopes pre-emptively. Authenticate only with the permissions required for the current phase. Organization administration and repository transfer normally require elevated owner permissions and should be used only during the controlled migration window.

## Recommended sequence

### 1. Create the organization manually

GitHub does not expose organization creation through the normal public API. Create the organization in the GitHub UI. Do not transfer repositories yet.

### 2. Run the plan

```powershell
pwsh ./scripts/github-org-migration/00-master-migration.ps1 `
  -ConfigPath ./scripts/github-org-migration/migration-config.json `
  -Mode Plan
```

### 3. Inventory and mirror backup

```powershell
pwsh ./scripts/github-org-migration/01-inventory-repos.ps1 `
  -ConfigPath ./scripts/github-org-migration/migration-config.json `
  -CreateMirrorBackup
```

The output contains metadata only, backup paths, and SHA-256 hashes. Secret values are never requested or written.

### 4. Create teams only after review

```powershell
$env:SENTINEL_GITHUB_ORG_APPLY = 'AUTHORIZED-TEAM-SETUP'
pwsh ./scripts/github-org-migration/02-create-teams.ps1 `
  -ConfigPath ./scripts/github-org-migration/migration-config.json `
  -Apply `
  -Confirmation 'CREATE TEAMS IN akira-security-technologies'
```

Team creation alone does not establish separation of duties. Independent humans must be assigned before security or release approval claims are made.

### 5. Generate OIDC and environment plan

```powershell
pwsh ./scripts/github-org-migration/03-plan-oidc-and-controls.ps1 `
  -ConfigPath ./scripts/github-org-migration/migration-config.json
```

This emits the exact future GitHub OIDC subjects. It does not modify Microsoft Entra. GitHub environments can be created only through the script's separate guarded apply mode.

### 6. Transfer one repository

The transfer script refuses bulk transfer, denies legacy repositories by default, and requires an approval record bound to the exact source head and verified mirror backup.

```powershell
$env:SENTINEL_GITHUB_TRANSFER_AUTHORIZED = 'YES'
pwsh ./scripts/github-org-migration/04-migrate-repo.ps1 `
  -ConfigPath ./scripts/github-org-migration/migration-config.json `
  -RepositoryName sentinel-docs `
  -ApprovalFile ./migration-evidence/sentinel-docs/transfer-approval.json `
  -Apply `
  -Confirmation 'TRANSFER loesungerdechris-lang/sentinel-docs TO akira-security-technologies'
```

### 7. Verify before proceeding

```powershell
pwsh ./scripts/github-org-migration/05-verify-after-transfer.ps1 `
  -ConfigPath ./scripts/github-org-migration/migration-config.json `
  -RepositoryName sentinel-docs `
  -PreflightInventory ./migration-evidence/sentinel-docs/repository-inventory.json
```

A failed or incomplete verification produces `HOLD`. Do not transfer the next repository until the current transfer has an independently reviewed result.

## Explicit non-claims

A successful script run does not prove independent review, legal ownership, production authorization, evidentiary admissibility, correct Azure federation, or safe deployment. It proves only the checks and mutations explicitly recorded by that run.
