[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$RepositoryName,
    [Parameter(Mandatory)][string]$PreflightInventory,
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

$inventoryPath = (Resolve-Path -LiteralPath $PreflightInventory).Path
$before = Get-Content -LiteralPath $inventoryPath -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
if ($before.schema_version -ne 'sentinel.github-repository-inventory.v1') {
    throw 'Preflight inventory schema is invalid.'
}
if ($before.repository.full_name -ne "$sourceOwner/$RepositoryName") {
    throw 'Preflight inventory does not match the configured source repository.'
}

$targetResult = Invoke-GhOptionalJson -Endpoint "repos/$targetOrg/$RepositoryName"
if (-not $targetResult.available) { throw "Target repository '$targetOrg/$RepositoryName' is unavailable." }
$afterRepo = $targetResult.value
$afterHead = Get-RepositoryHead -Owner $targetOrg -Repository $RepositoryName -DefaultBranch ([string]$afterRepo.default_branch)

$afterBranches = Invoke-GhPaginatedArray -Endpoint "repos/$targetOrg/$RepositoryName/branches?per_page=100"
$afterTags = Invoke-GhPaginatedArray -Endpoint "repos/$targetOrg/$RepositoryName/tags?per_page=100"
$afterPulls = Invoke-GhPaginatedArray -Endpoint "repos/$targetOrg/$RepositoryName/pulls?state=open&per_page=100"
$afterIssues = Invoke-GhPaginatedArray -Endpoint "repos/$targetOrg/$RepositoryName/issues?state=open&per_page=100"
$afterWorkflows = Invoke-GhOptionalJson -Endpoint "repos/$targetOrg/$RepositoryName/actions/workflows?per_page=100"
$afterEnvironments = Invoke-GhOptionalJson -Endpoint "repos/$targetOrg/$RepositoryName/environments?per_page=100"
$afterRulesets = Invoke-GhOptionalJson -Endpoint "repos/$targetOrg/$RepositoryName/rulesets?per_page=100"
$afterProtection = Invoke-GhOptionalJson -Endpoint "repos/$targetOrg/$RepositoryName/branches/$($afterRepo.default_branch)/protection"
$afterHooks = Invoke-GhOptionalJson -Endpoint "repos/$targetOrg/$RepositoryName/hooks?per_page=100"
$afterKeys = Invoke-GhOptionalJson -Endpoint "repos/$targetOrg/$RepositoryName/keys?per_page=100"
$afterPages = Invoke-GhOptionalJson -Endpoint "repos/$targetOrg/$RepositoryName/pages"
$sourceRedirect = Invoke-GhOptionalJson -Endpoint "repos/$sourceOwner/$RepositoryName"

$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check {
    param([string]$Name, [bool]$Passed, [object]$BeforeValue, [object]$AfterValue, [string]$Severity = 'BLOCKER')
    $checks.Add([ordered]@{
        name = $Name
        passed = $Passed
        severity = $Severity
        before = $BeforeValue
        after = $AfterValue
    })
}

Add-Check -Name 'repository_id_preserved' -Passed ([string]$before.repository.id -eq [string]$afterRepo.id) -BeforeValue $before.repository.id -AfterValue $afterRepo.id
Add-Check -Name 'visibility_preserved' -Passed ($before.repository.visibility -eq $afterRepo.visibility) -BeforeValue $before.repository.visibility -AfterValue $afterRepo.visibility
Add-Check -Name 'default_branch_preserved' -Passed ($before.repository.default_branch -eq $afterRepo.default_branch) -BeforeValue $before.repository.default_branch -AfterValue $afterRepo.default_branch
Add-Check -Name 'exact_head_preserved' -Passed ($before.repository.default_branch_head_sha -eq $afterHead) -BeforeValue $before.repository.default_branch_head_sha -AfterValue $afterHead
Add-Check -Name 'archived_state_preserved' -Passed ([bool]$before.repository.archived -eq [bool]$afterRepo.archived) -BeforeValue $before.repository.archived -AfterValue $afterRepo.archived

$beforeBranchMap = @{}
foreach ($branch in @($before.branches)) { $beforeBranchMap[[string]$branch.name] = [string]$branch.sha }
$afterBranchMap = @{}
foreach ($branch in @($afterBranches)) { $afterBranchMap[[string]$branch.name] = [string]$branch.commit.sha }
$branchMismatch = @($beforeBranchMap.Keys | Where-Object { -not $afterBranchMap.ContainsKey($_) -or $afterBranchMap[$_] -ne $beforeBranchMap[$_] })
Add-Check -Name 'branch_refs_preserved' -Passed ($branchMismatch.Count -eq 0 -and $beforeBranchMap.Count -eq $afterBranchMap.Count) -BeforeValue $beforeBranchMap -AfterValue $afterBranchMap

$beforeTagMap = @{}
foreach ($tag in @($before.tags)) { $beforeTagMap[[string]$tag.name] = [string]$tag.sha }
$afterTagMap = @{}
foreach ($tag in @($afterTags)) { $afterTagMap[[string]$tag.name] = [string]$tag.commit.sha }
$tagMismatch = @($beforeTagMap.Keys | Where-Object { -not $afterTagMap.ContainsKey($_) -or $afterTagMap[$_] -ne $beforeTagMap[$_] })
Add-Check -Name 'tag_refs_preserved' -Passed ($tagMismatch.Count -eq 0 -and $beforeTagMap.Count -eq $afterTagMap.Count) -BeforeValue $beforeTagMap -AfterValue $afterTagMap

$beforePullNumbers = @($before.open_pull_requests | ForEach-Object { [int]$_.number } | Sort-Object)
$afterPullNumbers = @($afterPulls | ForEach-Object { [int]$_.number } | Sort-Object)
Add-Check -Name 'open_pull_requests_preserved' -Passed ((ConvertTo-Json $beforePullNumbers -Compress) -eq (ConvertTo-Json $afterPullNumbers -Compress)) -BeforeValue $beforePullNumbers -AfterValue $afterPullNumbers

$beforeIssueNumbers = @($before.open_issues | ForEach-Object { [int]$_.number } | Sort-Object)
$afterIssueNumbers = @($afterIssues | Where-Object { -not $_.pull_request } | ForEach-Object { [int]$_.number } | Sort-Object)
Add-Check -Name 'open_issues_preserved' -Passed ((ConvertTo-Json $beforeIssueNumbers -Compress) -eq (ConvertTo-Json $afterIssueNumbers -Compress)) -BeforeValue $beforeIssueNumbers -AfterValue $afterIssueNumbers

$beforeWorkflowNames = if ($before.workflows.available -and $before.workflows.value.workflows) { @($before.workflows.value.workflows | ForEach-Object { [string]$_.name } | Sort-Object) } else { @() }
$afterWorkflowNames = if ($afterWorkflows.available -and $afterWorkflows.value.workflows) { @($afterWorkflows.value.workflows | ForEach-Object { [string]$_.name } | Sort-Object) } else { @() }
Add-Check -Name 'workflow_definitions_visible' -Passed ((ConvertTo-Json $beforeWorkflowNames -Compress) -eq (ConvertTo-Json $afterWorkflowNames -Compress)) -BeforeValue $beforeWorkflowNames -AfterValue $afterWorkflowNames

$expectedEnvironments = @($config.environments | Sort-Object)
$actualEnvironments = if ($afterEnvironments.available -and $afterEnvironments.value.environments) { @($afterEnvironments.value.environments | ForEach-Object { [string]$_.name } | Sort-Object) } else { @() }
$environmentMissing = @($expectedEnvironments | Where-Object { $_ -notin $actualEnvironments })
Add-Check -Name 'required_environments_present' -Passed ($environmentMissing.Count -eq 0) -BeforeValue $expectedEnvironments -AfterValue $actualEnvironments

Add-Check -Name 'rulesets_endpoint_available' -Passed ([bool]$afterRulesets.available) -BeforeValue $before.rulesets.available -AfterValue $afterRulesets.available
Add-Check -Name 'default_branch_protection_available' -Passed ([bool]$afterProtection.available) -BeforeValue $before.default_branch_protection.available -AfterValue $afterProtection.available
Add-Check -Name 'hooks_inventory_available' -Passed ([bool]$afterHooks.available) -BeforeValue $before.hooks.Count -AfterValue (if ($afterHooks.available) { @($afterHooks.value).Count } else { $null }) -Severity 'REVIEW'
Add-Check -Name 'deploy_keys_inventory_available' -Passed ([bool]$afterKeys.available) -BeforeValue $before.deploy_keys.Count -AfterValue (if ($afterKeys.available) { @($afterKeys.value).Count } else { $null }) -Severity 'REVIEW'
Add-Check -Name 'pages_state_observable' -Passed ([bool]$afterPages.available -eq [bool]$before.pages.available) -BeforeValue $before.pages.available -AfterValue $afterPages.available -Severity 'REVIEW'
Add-Check -Name 'source_path_redirect_or_resolution_observable' -Passed ([bool]$sourceRedirect.available) -BeforeValue "$sourceOwner/$RepositoryName" -AfterValue (if ($sourceRedirect.available) { $sourceRedirect.value.full_name } else { $sourceRedirect.error }) -Severity 'REVIEW'

$blockingFailures = @($checks | Where-Object { -not $_.passed -and $_.severity -eq 'BLOCKER' })
$reviewFailures = @($checks | Where-Object { -not $_.passed -and $_.severity -eq 'REVIEW' })
$oidcSubjects = @($config.environments | ForEach-Object {
    [ordered]@{
        environment = [string]$_
        expected_subject = "repo:$targetOrg/$RepositoryName:environment:$_"
        entra_verification_status = 'NOT_VERIFIED_BY_THIS_SCRIPT'
    }
})

$result = [ordered]@{
    schema_version = 'sentinel.github-post-transfer-verification.v1'
    status = if ($blockingFailures.Count -eq 0) { 'TRANSFER_INTEGRITY_OK_REVIEW_REQUIRED' } else { 'HOLD' }
    verified_at = (Get-Date).ToUniversalTime().ToString('o')
    repository = "$targetOrg/$RepositoryName"
    repository_id = $afterRepo.id
    exact_head_sha = $afterHead
    checks = @($checks)
    blocking_failure_count = $blockingFailures.Count
    review_failure_count = $reviewFailures.Count
    expected_oidc_subjects = $oidcSubjects
    azure_entra_verified = $false
    github_app_access_verified = $false
    local_remote_updates_verified = $false
    ci_rerun_verified = $false
    independent_review_complete = $false
    production_authorized = $false
    limitations = @(
        'this script does not inspect secret values',
        'this script does not modify Azure or GitHub',
        'a successful result still requires GitHub App, OIDC, CI, local remote, and independent review evidence'
    )
}

$evidenceDirectory = New-EvidenceDirectory -Root $evidenceRoot -Name "$RepositoryName-post-transfer"
$resultPath = Join-Path $evidenceDirectory 'post-transfer-verification.json'
Write-StableJson -InputObject $result -Path $resultPath
Write-Host "Post-transfer verification status $($result.status): $resultPath" -ForegroundColor $(if ($result.status -eq 'HOLD') { 'Yellow' } else { 'Green' })
