[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [string]$AssignmentsPath,
    [switch]$Apply,
    [string]$Confirmation,
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Migration.Common.psm1') -Force

$config = Read-SentinelMigrationConfig -Path $ConfigPath
$org = [string]$config.target_organization
$evidenceRoot = if ($OutputDirectory) { $OutputDirectory } else { [string]$config.evidence_root }

$orgResult = Invoke-GhOptionalJson -Endpoint "orgs/$org"
if (-not $orgResult.available) {
    throw "Target organization '$org' does not exist or is not accessible. Create it manually before running this script."
}

$assignments = $null
if ($AssignmentsPath) {
    $assignments = Get-Content -LiteralPath (Resolve-Path -LiteralPath $AssignmentsPath) -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100
}

$plan = [ordered]@{
    schema_version = 'sentinel.github-team-setup-plan.v1'
    status = 'HOLD'
    target_organization = $org
    created_at = (Get-Date).ToUniversalTime().ToString('o')
    apply_requested = [bool]$Apply
    teams = @()
    warnings = @(
        'team creation alone does not establish independent review',
        'do not assign invented or unverified identities',
        'repository permissions apply only after the repository exists in the target organization'
    )
}

foreach ($team in @($config.teams)) {
    $name = [string]$team.name
    $privacy = if ($team.privacy) { [string]$team.privacy } else { 'closed' }
    Assert-SafeGitHubName -Value $name -FieldName 'team name'
    if ($privacy -notin @('closed', 'secret')) { throw "Unsupported team privacy '$privacy'." }

    $teamAssignment = $null
    if ($assignments -and $assignments.teams) {
        $teamAssignment = $assignments.teams.PSObject.Properties[$name].Value
    }

    $plan.teams += [ordered]@{
        name = $name
        privacy = $privacy
        members = if ($teamAssignment -and $teamAssignment.members) { @($teamAssignment.members) } else { @() }
        repositories = if ($teamAssignment -and $teamAssignment.repositories) { $teamAssignment.repositories } else { [ordered]@{} }
    }
}

$evidenceDirectory = New-EvidenceDirectory -Root $evidenceRoot -Name 'organization-team-setup'
$planPath = Join-Path $evidenceDirectory 'team-setup-plan.json'
Write-StableJson -InputObject $plan -Path $planPath

if (-not $Apply) {
    Write-Host "Team plan created without mutation: $planPath" -ForegroundColor Green
    return
}

$expectedConfirmation = "CREATE TEAMS IN $org"
if ($Confirmation -cne $expectedConfirmation) {
    throw "Apply denied. Confirmation must be exactly: $expectedConfirmation"
}
if ($env:SENTINEL_GITHUB_ORG_APPLY -cne 'AUTHORIZED-TEAM-SETUP') {
    throw 'Apply denied. SENTINEL_GITHUB_ORG_APPLY must equal AUTHORIZED-TEAM-SETUP.'
}
if ([bool]$config.allow_paid_plan_changes) {
    throw 'Configuration unexpectedly permits paid plan changes. Team setup requires allow_paid_plan_changes=false.'
}

$currentUser = Invoke-GhJson -Endpoint 'user'
$membership = Invoke-GhOptionalJson -Endpoint "orgs/$org/memberships/$($currentUser.login)"
if (-not $membership.available -or $membership.value.role -ne 'admin') {
    throw "Authenticated GitHub user '$($currentUser.login)' is not confirmed as an organization owner."
}

$actions = [System.Collections.Generic.List[object]]::new()
$existingTeams = Invoke-GhPaginatedArray -Endpoint "orgs/$org/teams?per_page=100"

foreach ($teamPlan in @($plan.teams)) {
    $existing = @($existingTeams | Where-Object { $_.name -eq $teamPlan.name } | Select-Object -First 1)
    if ($existing.Count -eq 0) {
        $created = Invoke-GhJson -Endpoint "orgs/$org/teams" -Arguments @(
            '--method', 'POST',
            '-f', "name=$($teamPlan.name)",
            '-f', "privacy=$($teamPlan.privacy)"
        )
        $slug = [string]$created.slug
        $actions.Add([ordered]@{ action = 'create_team'; team = $teamPlan.name; slug = $slug; result = 'CREATED' })
    }
    else {
        $slug = [string]$existing[0].slug
        $actions.Add([ordered]@{ action = 'create_team'; team = $teamPlan.name; slug = $slug; result = 'ALREADY_EXISTS' })
    }

    foreach ($member in @($teamPlan.members)) {
        $login = [string]$member.login
        $role = if ($member.role) { [string]$member.role } else { 'member' }
        Assert-SafeGitHubName -Value $login -FieldName 'member login'
        if ($role -notin @('member', 'maintainer')) { throw "Unsupported team role '$role'." }
        Invoke-GhJson -Endpoint "orgs/$org/teams/$slug/memberships/$login" -Arguments @('--method', 'PUT', '-f', "role=$role") | Out-Null
        $actions.Add([ordered]@{ action = 'set_team_membership'; team = $teamPlan.name; login = $login; role = $role; result = 'APPLIED' })
    }

    foreach ($repoProperty in @($teamPlan.repositories.PSObject.Properties)) {
        $repository = [string]$repoProperty.Name
        $permission = [string]$repoProperty.Value
        Assert-SafeGitHubName -Value $repository -FieldName 'repository'
        if ($permission -notin @('pull', 'triage', 'push', 'maintain', 'admin')) {
            throw "Unsupported repository permission '$permission'."
        }
        $targetRepo = Invoke-GhOptionalJson -Endpoint "repos/$org/$repository"
        if (-not $targetRepo.available) {
            $actions.Add([ordered]@{ action = 'set_repository_permission'; team = $teamPlan.name; repository = $repository; permission = $permission; result = 'HOLD_REPOSITORY_NOT_IN_ORG' })
            continue
        }
        Invoke-GhJson -Endpoint "orgs/$org/teams/$slug/repos/$org/$repository" -Arguments @('--method', 'PUT', '-f', "permission=$permission") | Out-Null
        $actions.Add([ordered]@{ action = 'set_repository_permission'; team = $teamPlan.name; repository = $repository; permission = $permission; result = 'APPLIED' })
    }
}

$result = [ordered]@{
    schema_version = 'sentinel.github-team-setup-result.v1'
    status = 'HOLD'
    target_organization = $org
    authenticated_actor = $currentUser.login
    completed_at = (Get-Date).ToUniversalTime().ToString('o')
    actions = @($actions)
    independent_review_established = $false
    note = 'Independent review remains false until separate verified humans occupy security-review and release-approval roles.'
}
$resultPath = Join-Path $evidenceDirectory 'team-setup-result.json'
Write-StableJson -InputObject $result -Path $resultPath
Write-Host "Guarded team setup completed under HOLD: $resultPath" -ForegroundColor Green
