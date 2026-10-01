[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$RepositoryName,
    [string]$ApprovalFile,
    [switch]$Apply,
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
Assert-SafeGitHubName -Value $RepositoryName -FieldName 'RepositoryName'

if ([bool]$config.allow_bulk_transfer) { throw 'Configuration must keep allow_bulk_transfer=false.' }
if ([bool]$config.allow_paid_plan_changes) { throw 'Configuration must keep allow_paid_plan_changes=false.' }
if ($RepositoryName -notin @($config.repositories)) { throw "Repository '$RepositoryName' is not in the approved migration inventory." }
if ($RepositoryName -in @($config.denied_repositories)) { throw "Repository '$RepositoryName' is explicitly denied for automated transfer." }

$transferIndex = [Array]::IndexOf(@($config.transfer_order), $RepositoryName)
if ($transferIndex -lt 0) { throw "Repository '$RepositoryName' is absent from transfer_order." }

$sourceRepoResult = Invoke-GhOptionalJson -Endpoint "repos/$sourceOwner/$RepositoryName"
if (-not $sourceRepoResult.available) { throw "Source repository '$sourceOwner/$RepositoryName' is unavailable." }
$sourceRepo = $sourceRepoResult.value
$defaultBranch = [string]$sourceRepo.default_branch
$headSha = Get-RepositoryHead -Owner $sourceOwner -Repository $RepositoryName -DefaultBranch $defaultBranch
$targetOrgResult = Invoke-GhOptionalJson -Endpoint "orgs/$targetOrg"
$targetRepoResult = Invoke-GhOptionalJson -Endpoint "repos/$targetOrg/$RepositoryName"
$openPulls = Invoke-GhPaginatedArray -Endpoint "repos/$sourceOwner/$RepositoryName/pulls?state=open&per_page=100"

$blockers = [System.Collections.Generic.List[string]]::new()
if (-not $targetOrgResult.available) { $blockers.Add("Target organization '$targetOrg' does not exist or is inaccessible.") }
if ($targetRepoResult.available) { $blockers.Add("Target repository '$targetOrg/$RepositoryName' already exists.") }
if ($sourceRepo.archived) { $blockers.Add('Source repository is archived and must be reviewed separately.') }
if ($sourceRepo.permissions -and -not [bool]$sourceRepo.permissions.admin) { $blockers.Add('Authenticated user is not confirmed as source repository administrator.') }
if ([bool]$config.require_zero_open_pull_requests_for_transfer -and @($openPulls).Count -gt 0) {
    $blockers.Add("Repository has $(@($openPulls).Count) open pull request(s); configuration requires zero.")
}

$approval = $null
$resolvedApprovalPath = $null
$inventoryRecord = $null
$bundleRecord = $null
if (-not $ApprovalFile) {
    $blockers.Add('A transfer approval file is required for Apply mode and recommended for final preflight.')
}
else {
    try {
        $resolvedApprovalPath = (Resolve-Path -LiteralPath $ApprovalFile).Path
        $approval = Get-Content -LiteralPath $resolvedApprovalPath -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
        if ($approval.schema_version -ne 'sentinel.github-repository-transfer-approval.v1') { $blockers.Add('Approval file schema is invalid.') }
        if ($approval.status -ne 'APPROVED_FOR_SINGLE_TRANSFER') { $blockers.Add('Approval status is not APPROVED_FOR_SINGLE_TRANSFER.') }
        if ($approval.source_full_name -ne "$sourceOwner/$RepositoryName") { $blockers.Add('Approval source_full_name does not match.') }
        if ($approval.target_organization -ne $targetOrg) { $blockers.Add('Approval target_organization does not match.') }
        if ([string]$approval.repository_id -ne [string]$sourceRepo.id) { $blockers.Add('Approval repository_id does not match the source repository.') }
        if ($approval.exact_head_sha -ne $headSha) { $blockers.Add('Approval exact_head_sha is stale or does not match.') }
        if (-not $approval.coordination_issue_url) { $blockers.Add('Approval lacks coordination_issue_url.') }

        $approvers = @($approval.approvers | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        if ($approvers.Count -lt 2) { $blockers.Add('At least two distinct named approvers are required for transfer Apply mode.') }
        foreach ($approver in $approvers) { Assert-SafeGitHubName -Value $approver -FieldName 'approver login' }

        if ($RepositoryName -eq 'upgraded-guacamole' -and $approval.authority_consolidation_complete -ne $true) {
            $blockers.Add('upgraded-guacamole requires authority_consolidation_complete=true in the approval record.')
        }

        if (-not $approval.inventory_path -or -not (Test-Path -LiteralPath $approval.inventory_path -PathType Leaf)) {
            $blockers.Add('Approval inventory_path is missing or unavailable.')
        }
        else {
            $inventoryRecord = Get-Sha256Record -Path ([string]$approval.inventory_path)
            if ($inventoryRecord.sha256 -ne [string]$approval.inventory_sha256) { $blockers.Add('Inventory SHA-256 does not match the approval.') }
            $inventory = Get-Content -LiteralPath $approval.inventory_path -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
            if ([string]$inventory.repository.id -ne [string]$sourceRepo.id) { $blockers.Add('Inventory repository ID does not match.') }
            if ($inventory.repository.default_branch_head_sha -ne $headSha) { $blockers.Add('Inventory exact head is stale.') }
        }

        if ([bool]$config.require_verified_mirror_backup) {
            if (-not $approval.bundle_path -or -not (Test-Path -LiteralPath $approval.bundle_path -PathType Leaf)) {
                $blockers.Add('Verified Git bundle is required but bundle_path is missing or unavailable.')
            }
            else {
                Assert-ExternalCommand -Name 'git'
                $bundleRecord = Get-Sha256Record -Path ([string]$approval.bundle_path)
                if ($bundleRecord.sha256 -ne [string]$approval.bundle_sha256) { $blockers.Add('Bundle SHA-256 does not match the approval.') }
                $bundleHeads = & git bundle list-heads ([string]$approval.bundle_path) 2>&1
                if ($LASTEXITCODE -ne 0 -or @($bundleHeads).Count -eq 0) { $blockers.Add('Git bundle format or reference listing validation failed.') }
            }
        }
    }
    catch {
        $blockers.Add("Approval validation failed: $($_.Exception.Message)")
    }
}

for ($i = 0; $i -lt $transferIndex; $i++) {
    $priorRepo = [string](@($config.transfer_order)[$i])
    $priorTarget = Invoke-GhOptionalJson -Endpoint "repos/$targetOrg/$priorRepo"
    if (-not $priorTarget.available) {
        $blockers.Add("Earlier transfer-order repository '$priorRepo' is not present in the target organization.")
    }
}

$preflight = [ordered]@{
    schema_version = 'sentinel.github-repository-transfer-preflight.v1'
    status = if ($blockers.Count -eq 0) { 'READY_FOR_SEPARATE_APPLY_DECISION' } else { 'HOLD' }
    created_at = (Get-Date).ToUniversalTime().ToString('o')
    source_full_name = "$sourceOwner/$RepositoryName"
    target_full_name = "$targetOrg/$RepositoryName"
    repository_id = $sourceRepo.id
    visibility = $sourceRepo.visibility
    default_branch = $defaultBranch
    exact_head_sha = $headSha
    open_pull_request_count = @($openPulls).Count
    approval_file = $resolvedApprovalPath
    inventory_record = $inventoryRecord
    bundle_record = $bundleRecord
    blockers = @($blockers)
    apply_requested = [bool]$Apply
    oidc_subject_change_required = $true
    production_authorized = $false
}

$evidenceDirectory = New-EvidenceDirectory -Root $evidenceRoot -Name "$RepositoryName-transfer"
$preflightPath = Join-Path $evidenceDirectory 'transfer-preflight.json'
Write-StableJson -InputObject $preflight -Path $preflightPath

if (-not $Apply) {
    Write-Host "Transfer preflight completed with status $($preflight.status): $preflightPath" -ForegroundColor Green
    return
}
if ($blockers.Count -gt 0) { throw "Transfer denied by preflight blockers. See $preflightPath" }

$expectedConfirmation = "TRANSFER $sourceOwner/$RepositoryName TO $targetOrg"
if ($Confirmation -cne $expectedConfirmation) { throw "Transfer denied. Confirmation must be exactly: $expectedConfirmation" }
if ($env:SENTINEL_GITHUB_TRANSFER_AUTHORIZED -cne 'YES') { throw 'Transfer denied. SENTINEL_GITHUB_TRANSFER_AUTHORIZED must equal YES.' }

$currentUser = Invoke-GhJson -Endpoint 'user'
$orgMembership = Invoke-GhOptionalJson -Endpoint "orgs/$targetOrg/memberships/$($currentUser.login)"
if (-not $orgMembership.available -or $orgMembership.value.role -ne 'admin') {
    throw "Authenticated user '$($currentUser.login)' is not confirmed as an owner of '$targetOrg'."
}

$transferResponse = Invoke-GhJson -Endpoint "repos/$sourceOwner/$RepositoryName/transfer" -Arguments @('--method', 'POST', '-f', "new_owner=$targetOrg")

$targetRepo = $null
for ($attempt = 1; $attempt -le 24; $attempt++) {
    Start-Sleep -Seconds 5
    $candidate = Invoke-GhOptionalJson -Endpoint "repos/$targetOrg/$RepositoryName"
    if ($candidate.available) { $targetRepo = $candidate.value; break }
}
if ($null -eq $targetRepo) {
    throw 'GitHub accepted the transfer request, but the target repository was not observable within the verification window. Manual HOLD review is required.'
}

$targetHead = Get-RepositoryHead -Owner $targetOrg -Repository $RepositoryName -DefaultBranch ([string]$targetRepo.default_branch)
$verificationBlockers = [System.Collections.Generic.List[string]]::new()
if ([string]$targetRepo.id -ne [string]$sourceRepo.id) { $verificationBlockers.Add('Repository ID changed unexpectedly.') }
if ($targetHead -ne $headSha) { $verificationBlockers.Add('Default-branch exact head changed during transfer.') }
if ($targetRepo.visibility -ne $sourceRepo.visibility) { $verificationBlockers.Add('Repository visibility changed during transfer.') }

$result = [ordered]@{
    schema_version = 'sentinel.github-repository-transfer-result.v1'
    status = if ($verificationBlockers.Count -eq 0) { 'TRANSFERRED_PENDING_FULL_VERIFICATION' } else { 'HOLD' }
    completed_at = (Get-Date).ToUniversalTime().ToString('o')
    actor = $currentUser.login
    source_full_name = "$sourceOwner/$RepositoryName"
    target_full_name = "$targetOrg/$RepositoryName"
    repository_id_before = $sourceRepo.id
    repository_id_after = $targetRepo.id
    exact_head_before = $headSha
    exact_head_after = $targetHead
    visibility_before = $sourceRepo.visibility
    visibility_after = $targetRepo.visibility
    transfer_api_response = [ordered]@{ id = $transferResponse.id; full_name = $transferResponse.full_name }
    verification_blockers = @($verificationBlockers)
    oidc_updated = $false
    git_remote_updates_completed = $false
    full_post_transfer_verification_completed = $false
    production_authorized = $false
}
$resultPath = Join-Path $evidenceDirectory 'transfer-result.json'
Write-StableJson -InputObject $result -Path $resultPath
Write-Host "Single-repository transfer request completed under HOLD: $resultPath" -ForegroundColor Yellow
