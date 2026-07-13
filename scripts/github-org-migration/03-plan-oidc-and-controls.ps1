[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [switch]$ApplyGitHubEnvironments,
    [string]$Confirmation,
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Migration.Common.psm1') -Force

$config = Read-SentinelMigrationConfig -Path $ConfigPath
$sourceOwner = [string]$config.source_owner
$targetOrg = [string]$config.target_organization
$evidenceRoot = if ($OutputDirectory) { $OutputDirectory } else { [string]$config.evidence_root }

$records = [System.Collections.Generic.List[object]]::new()
foreach ($repository in @($config.repositories)) {
    foreach ($environment in @($config.environments)) {
        Assert-SafeGitHubName -Value ([string]$environment) -FieldName 'environment'
        $records.Add([ordered]@{
            repository = [string]$repository
            environment = [string]$environment
            current_subject = "repo:$sourceOwner/$repository:environment:$environment"
            proposed_subject = "repo:$targetOrg/$repository:environment:$environment"
            entra_change_required = $true
            old_federation_removal_authorized = $false
        })
    }
}

$plan = [ordered]@{
    schema_version = 'sentinel.github-oidc-control-plan.v1'
    status = 'HOLD'
    source_owner = $sourceOwner
    target_organization = $targetOrg
    created_at = (Get-Date).ToUniversalTime().ToString('o')
    github_environment_apply_requested = [bool]$ApplyGitHubEnvironments
    oidc_subjects = @($records)
    required_repository_controls = [ordered]@{
        pull_request_required = $true
        independent_approval_required = $true
        code_owner_review_required = $true
        conversation_resolution_required = $true
        required_status_checks = @(
            'CI',
            'SENTINEL Receipt Verifier Gate',
            'SENTINEL Core Secret Scan',
            'SENTINEL Core Security'
        )
        bypass_default = 'DENY'
        signed_commits = 'REVIEW_SEPARATELY'
    }
    required_environment_controls = [ordered]@{
        'sentinel-staging' = 'non-production validation only'
        'sentinel-production' = 'independent deployment approval and exact OIDC subject'
        'evidence-release' = 'separate release authority; no production signer sharing'
        'archive-pilot' = 'HOLD-only bounded pilot; no publication authority'
    }
    prohibitions = @(
        'this script does not create or modify Microsoft Entra federated credentials',
        'this script does not create secrets or variables',
        'this script does not add deployment reviewers',
        'old OIDC federation must not be removed until new federation is independently verified',
        'no environment creation implies production authorization'
    )
}

$evidenceDirectory = New-EvidenceDirectory -Root $evidenceRoot -Name 'oidc-control-plan'
$planPath = Join-Path $evidenceDirectory 'oidc-control-plan.json'
Write-StableJson -InputObject $plan -Path $planPath

if (-not $ApplyGitHubEnvironments) {
    Write-Host "OIDC and control plan created without mutation: $planPath" -ForegroundColor Green
    return
}

$expectedConfirmation = "CREATE GITHUB ENVIRONMENTS IN $targetOrg"
if ($Confirmation -cne $expectedConfirmation) {
    throw "Apply denied. Confirmation must be exactly: $expectedConfirmation"
}
if ($env:SENTINEL_GITHUB_ENVIRONMENT_APPLY -cne 'AUTHORIZED-ENVIRONMENT-SETUP') {
    throw 'Apply denied. SENTINEL_GITHUB_ENVIRONMENT_APPLY must equal AUTHORIZED-ENVIRONMENT-SETUP.'
}
if ([bool]$config.allow_azure_mutation) {
    throw 'Configuration unexpectedly permits Azure mutation. This script requires allow_azure_mutation=false.'
}

$orgResult = Invoke-GhOptionalJson -Endpoint "orgs/$targetOrg"
if (-not $orgResult.available) { throw "Target organization '$targetOrg' is unavailable." }
$currentUser = Invoke-GhJson -Endpoint 'user'
$membership = Invoke-GhOptionalJson -Endpoint "orgs/$targetOrg/memberships/$($currentUser.login)"
if (-not $membership.available -or $membership.value.role -ne 'admin') {
    throw "Authenticated GitHub user '$($currentUser.login)' is not confirmed as an organization owner."
}

$actions = [System.Collections.Generic.List[object]]::new()
foreach ($repository in @($config.repositories)) {
    $targetRepo = Invoke-GhOptionalJson -Endpoint "repos/$targetOrg/$repository"
    if (-not $targetRepo.available) {
        $actions.Add([ordered]@{ repository = $repository; action = 'create_environments'; result = 'HOLD_REPOSITORY_NOT_IN_ORG' })
        continue
    }

    foreach ($environment in @($config.environments)) {
        $payload = [ordered]@{
            wait_timer = 0
            prevent_self_review = $true
            deployment_branch_policy = [ordered]@{
                protected_branches = $true
                custom_branch_policies = $false
            }
        }
        $temp = New-TemporaryFile
        try {
            Write-StableJson -InputObject $payload -Path $temp
            Invoke-GhJson -Endpoint "repos/$targetOrg/$repository/environments/$environment" -Arguments @('--method', 'PUT', '--input', $temp) | Out-Null
        }
        finally {
            Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        }
        $actions.Add([ordered]@{ repository = $repository; environment = $environment; action = 'create_or_update_environment'; result = 'APPLIED_BASELINE_ONLY' })
    }
}

$result = [ordered]@{
    schema_version = 'sentinel.github-environment-setup-result.v1'
    status = 'HOLD'
    target_organization = $targetOrg
    actor = $currentUser.login
    completed_at = (Get-Date).ToUniversalTime().ToString('o')
    actions = @($actions)
    entra_federation_modified = $false
    secrets_modified = $false
    deployment_reviewers_configured = $false
    note = 'Base environments alone do not authorize deployment. Reviewer IDs and Entra federation require separate reviewed actions.'
}
$resultPath = Join-Path $evidenceDirectory 'github-environment-setup-result.json'
Write-StableJson -InputObject $result -Path $resultPath
Write-Host "GitHub environment baseline completed under HOLD: $resultPath" -ForegroundColor Green
