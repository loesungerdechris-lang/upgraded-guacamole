[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [ValidateSet('Plan', 'Inventory', 'PrepareOrganization', 'TransferRepository', 'VerifyRepository')]
    [string]$Mode = 'Plan',
    [string]$RepositoryName,
    [string]$ApprovalFile,
    [string]$PreflightInventory,
    [switch]$CreateMirrorBackup,
    [switch]$ApplyTeams,
    [switch]$ApplyEnvironments,
    [switch]$ApplyTransfer,
    [string]$AssignmentsPath,
    [string]$TeamConfirmation,
    [string]$EnvironmentConfirmation,
    [string]$TransferConfirmation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Migration.Common.psm1') -Force

$config = Read-SentinelMigrationConfig -Path $ConfigPath
$sourceOwner = [string]$config.source_owner
$targetOrg = [string]$config.target_organization

Write-Host '=== SENTINEL GitHub Organization Migration Orchestrator ===' -ForegroundColor Cyan
Write-Host "Mode: $Mode" -ForegroundColor Cyan
Write-Host "Source: $sourceOwner" -ForegroundColor Cyan
Write-Host "Target: $targetOrg" -ForegroundColor Cyan
Write-Host 'Global state: HOLD' -ForegroundColor Yellow

$inventoryScript = Join-Path $PSScriptRoot '01-inventory-repos.ps1'
$teamScript = Join-Path $PSScriptRoot '02-create-teams.ps1'
$oidcScript = Join-Path $PSScriptRoot '03-plan-oidc-and-controls.ps1'
$transferScript = Join-Path $PSScriptRoot '04-migrate-repo.ps1'
$verifyScript = Join-Path $PSScriptRoot '05-verify-after-transfer.ps1'

switch ($Mode) {
    'Plan' {
        Write-Host '[1/3] Repository inventory plan' -ForegroundColor Cyan
        & $inventoryScript -ConfigPath $ConfigPath
        if (-not $?) { throw 'Inventory planning failed.' }

        Write-Host '[2/3] Organization team plan' -ForegroundColor Cyan
        $teamArgs = @{ ConfigPath = $ConfigPath }
        if ($AssignmentsPath) { $teamArgs.AssignmentsPath = $AssignmentsPath }
        & $teamScript @teamArgs
        if (-not $?) { throw 'Team planning failed.' }

        Write-Host '[3/3] OIDC and controls plan' -ForegroundColor Cyan
        & $oidcScript -ConfigPath $ConfigPath
        if (-not $?) { throw 'OIDC planning failed.' }
    }

    'Inventory' {
        $args = @{ ConfigPath = $ConfigPath }
        if ($RepositoryName) { $args.RepositoryName = @($RepositoryName) }
        if ($CreateMirrorBackup) { $args.CreateMirrorBackup = $true }
        & $inventoryScript @args
        if (-not $?) { throw 'Inventory or backup failed.' }
    }

    'PrepareOrganization' {
        $teamArgs = @{ ConfigPath = $ConfigPath }
        if ($AssignmentsPath) { $teamArgs.AssignmentsPath = $AssignmentsPath }
        if ($ApplyTeams) {
            if (-not $TeamConfirmation) { throw 'TeamConfirmation is required with ApplyTeams.' }
            $teamArgs.Apply = $true
            $teamArgs.Confirmation = $TeamConfirmation
        }
        & $teamScript @teamArgs
        if (-not $?) { throw 'Team setup failed.' }

        $oidcArgs = @{ ConfigPath = $ConfigPath }
        if ($ApplyEnvironments) {
            if (-not $EnvironmentConfirmation) { throw 'EnvironmentConfirmation is required with ApplyEnvironments.' }
            $oidcArgs.ApplyGitHubEnvironments = $true
            $oidcArgs.Confirmation = $EnvironmentConfirmation
        }
        & $oidcScript @oidcArgs
        if (-not $?) { throw 'Environment/OIDC planning failed.' }
    }

    'TransferRepository' {
        if (-not $RepositoryName) { throw 'RepositoryName is required for TransferRepository.' }
        $transferArgs = @{ ConfigPath = $ConfigPath; RepositoryName = $RepositoryName }
        if ($ApprovalFile) { $transferArgs.ApprovalFile = $ApprovalFile }
        if ($ApplyTransfer) {
            if (-not $ApprovalFile) { throw 'ApprovalFile is required with ApplyTransfer.' }
            if (-not $TransferConfirmation) { throw 'TransferConfirmation is required with ApplyTransfer.' }
            $transferArgs.Apply = $true
            $transferArgs.Confirmation = $TransferConfirmation
        }
        & $transferScript @transferArgs
        if (-not $?) { throw 'Repository transfer preflight or apply failed.' }
    }

    'VerifyRepository' {
        if (-not $RepositoryName) { throw 'RepositoryName is required for VerifyRepository.' }
        if (-not $PreflightInventory) { throw 'PreflightInventory is required for VerifyRepository.' }
        & $verifyScript -ConfigPath $ConfigPath -RepositoryName $RepositoryName -PreflightInventory $PreflightInventory
        if (-not $?) { throw 'Post-transfer verification failed.' }
    }
}

Write-Host 'Orchestrator completed. No merge, deployment, signing, Azure mutation, or publication was authorized.' -ForegroundColor Green
