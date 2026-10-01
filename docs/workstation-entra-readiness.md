# SENTINEL workstation, Codex and Entra readiness audit

## Purpose

This runbook checks whether an administrator workstation is ready to inspect or apply the SENTINEL Microsoft Entra OIDC and Azure Key Vault bootstrap.

The audit is intentionally non-mutating. It does not:

- install or upgrade software;
- authenticate to Azure or GitHub;
- create or change Microsoft Entra, Azure, GitHub or Codex resources;
- request an Azure access token;
- run the bootstrap with `-Apply`;
- expose full tenant or subscription identifiers in its report.

## What it checks

`scripts/azure/test-sentinel-workstation-readiness.ps1` checks:

- PowerShell 7 runtime and installation path;
- whether WinGet reports a PowerShell update;
- Azure CLI availability and the reviewed repository baseline;
- current Azure tenant and subscription context;
- optional exact tenant and subscription binding;
- GitHub CLI availability and authentication;
- local Codex executable availability;
- PowerShell parser acceptance of the Entra bootstrap script.

A local Codex executable and the GitHub Codex review integration are separate surfaces. A missing local executable does not prove that GitHub review is disconnected. Likewise, a GitHub message that the code-review usage limit is reached proves that the integration answered; reconnecting does not reset quota.

## Current reviewed toolchain baseline

As of 10 July 2026:

- PowerShell 7.4 or later is accepted for the repository scripts. Use the same installation channel that installed PowerShell when upgrading.
- Azure CLI 2.88.0 is the reviewed command-line baseline.
- GitHub Actions authentication remains OIDC-only through a protected environment and immutable action pins.
- The runtime signer application must have exactly one expected federated credential and no password or certificate credential.

These values are an audit baseline, not permission to mutate Azure resources automatically.

## Run the audit

From the repository root:

```powershell
pwsh ./scripts/azure/test-sentinel-workstation-readiness.ps1
```

For exact tenant and subscription binding:

```powershell
pwsh ./scripts/azure/test-sentinel-workstation-readiness.ps1 `
  -ExpectedTenantId '<TENANT-ID>' `
  -ExpectedSubscriptionId '<SUBSCRIPTION-ID>'
```

For machine-readable output:

```powershell
pwsh ./scripts/azure/test-sentinel-workstation-readiness.ps1 -AsJson
```

## Status meaning

- `GO`: the observed condition satisfies the local readiness check.
- `INFO`: optional context; not a blocker by itself.
- `UPDATE`: an update should be reviewed before Azure administration.
- `HOLD`: authentication, context or optional tooling must be corrected before proceeding.
- `BLOCKER`: a required runtime, CLI or parser condition is missing or broken.

## Safe update commands

Review the detected installation method before updating PowerShell:

```powershell
$PSVersionTable.PSVersion
$PSHOME
winget list --id Microsoft.PowerShell --exact --upgrade-available
```

When WinGet owns the installation and reports an update:

```powershell
winget upgrade --id Microsoft.PowerShell
```

Review Azure CLI before applying its in-tool update:

```powershell
az --version
az upgrade
```

After any update, open a new PowerShell session and re-run the readiness audit.

## Codex result interpretation

For GitHub reviews, distinguish these states:

1. **Connected and working:** Codex submits a review or reaction on the current PR head.
2. **Connected but quota-limited:** the Codex bot replies that the code-review usage limit has been reached.
3. **Repository environment missing:** the bot asks for a Codex environment to be created for the repository.
4. **Disconnected or unauthorized:** no app response appears and repository installation or workspace access is absent.

Only states 3 and 4 require connection or environment repair. State 2 requires a usage reset, credits or plan change; reconnecting is not a technical fix.

## Azure apply boundary

A successful workstation audit does not authorize the bootstrap. Continue with the existing runbook:

1. run `bootstrap-sentinel-oidc.ps1` without `-Apply`;
2. review tenant, subscription, resource group, vault, subject and role values;
3. confirm the protected `sentinel-production` GitHub environment and deployment reviewer;
4. apply only under an authorized administrator identity;
5. run the manual OIDC smoke workflow from `main`;
6. preserve HOLD until public trust registration and independent receipt verification succeed.
