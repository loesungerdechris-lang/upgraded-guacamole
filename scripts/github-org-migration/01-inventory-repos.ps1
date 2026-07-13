[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [string[]]$RepositoryName,
    [string]$OutputDirectory,
    [string]$BackupDirectory,
    [switch]$CreateMirrorBackup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Migration.Common.psm1') -Force

Assert-ExternalCommand -Name 'gh'
$config = Read-SentinelMigrationConfig -Path $ConfigPath
$sourceOwner = [string]$config.source_owner
$repositories = if ($RepositoryName) { @($RepositoryName) } else { @($config.repositories) }
$evidenceRoot = if ($OutputDirectory) { $OutputDirectory } else { [string]$config.evidence_root }
$backupRoot = if ($BackupDirectory) { $BackupDirectory } else { [string]$config.backup_root }

if ($CreateMirrorBackup) {
    Assert-ExternalCommand -Name 'git'
}

$run = [ordered]@{
    schema_version = 'sentinel.github-repository-inventory-run.v1'
    status = 'HOLD'
    source_owner = $sourceOwner
    created_at = (Get-Date).ToUniversalTime().ToString('o')
    mirror_backup_requested = [bool]$CreateMirrorBackup
    repositories = @()
}

foreach ($repository in $repositories) {
    Assert-SafeGitHubName -Value ([string]$repository) -FieldName 'repository'
    Write-Host "[INVENTORY] $sourceOwner/$repository" -ForegroundColor Cyan

    $repo = Invoke-GhJson -Endpoint "repos/$sourceOwner/$repository"
    $defaultBranch = [string]$repo.default_branch
    $headSha = Get-RepositoryHead -Owner $sourceOwner -Repository $repository -DefaultBranch $defaultBranch

    $branches = Invoke-GhPaginatedArray -Endpoint "repos/$sourceOwner/$repository/branches?per_page=100"
    $tags = Invoke-GhPaginatedArray -Endpoint "repos/$sourceOwner/$repository/tags?per_page=100"
    $releases = Invoke-GhPaginatedArray -Endpoint "repos/$sourceOwner/$repository/releases?per_page=100"
    $pulls = Invoke-GhPaginatedArray -Endpoint "repos/$sourceOwner/$repository/pulls?state=open&per_page=100"
    $issues = Invoke-GhPaginatedArray -Endpoint "repos/$sourceOwner/$repository/issues?state=open&per_page=100"

    $workflows = Invoke-GhOptionalJson -Endpoint "repos/$sourceOwner/$repository/actions/workflows?per_page=100"
    $environments = Invoke-GhOptionalJson -Endpoint "repos/$sourceOwner/$repository/environments?per_page=100"
    $rulesets = Invoke-GhOptionalJson -Endpoint "repos/$sourceOwner/$repository/rulesets?per_page=100"
    $protection = Invoke-GhOptionalJson -Endpoint "repos/$sourceOwner/$repository/branches/$defaultBranch/protection"
    $variables = Invoke-GhOptionalJson -Endpoint "repos/$sourceOwner/$repository/actions/variables?per_page=100"
    $secrets = Invoke-GhOptionalJson -Endpoint "repos/$sourceOwner/$repository/actions/secrets?per_page=100"
    $hooks = Invoke-GhOptionalJson -Endpoint "repos/$sourceOwner/$repository/hooks?per_page=100"
    $deployKeys = Invoke-GhOptionalJson -Endpoint "repos/$sourceOwner/$repository/keys?per_page=100"
    $collaborators = Invoke-GhOptionalJson -Endpoint "repos/$sourceOwner/$repository/collaborators?affiliation=all&per_page=100"
    $pages = Invoke-GhOptionalJson -Endpoint "repos/$sourceOwner/$repository/pages"

    $safeHooks = if ($hooks.available) {
        @($hooks.value) | ForEach-Object {
            [ordered]@{ id = $_.id; name = $_.name; active = $_.active; events = @($_.events); updated_at = $_.updated_at }
        }
    } else { @() }
    $safeDeployKeys = if ($deployKeys.available) {
        @($deployKeys.value) | ForEach-Object {
            [ordered]@{ id = $_.id; title = $_.title; verified = $_.verified; read_only = $_.read_only; created_at = $_.created_at }
        }
    } else { @() }
    $safeCollaborators = if ($collaborators.available) {
        @($collaborators.value) | ForEach-Object {
            [ordered]@{ login = $_.login; type = $_.type; permissions = $_.permissions; role_name = $_.role_name }
        }
    } else { @() }
    $safeSecrets = if ($secrets.available -and $secrets.value.secrets) {
        @($secrets.value.secrets) | ForEach-Object { [ordered]@{ name = $_.name; created_at = $_.created_at; updated_at = $_.updated_at } }
    } else { @() }
    $safeVariables = if ($variables.available -and $variables.value.variables) {
        @($variables.value.variables) | ForEach-Object { [ordered]@{ name = $_.name; created_at = $_.created_at; updated_at = $_.updated_at } }
    } else { @() }

    $inventory = [ordered]@{
        schema_version = 'sentinel.github-repository-inventory.v1'
        status = 'HOLD'
        captured_at = (Get-Date).ToUniversalTime().ToString('o')
        repository = [ordered]@{
            id = $repo.id
            node_id = $repo.node_id
            full_name = $repo.full_name
            visibility = $repo.visibility
            private = $repo.private
            archived = $repo.archived
            disabled = $repo.disabled
            fork = $repo.fork
            default_branch = $defaultBranch
            default_branch_head_sha = $headSha
            size_kb = $repo.size
            topics = @($repo.topics)
            created_at = $repo.created_at
            updated_at = $repo.updated_at
            pushed_at = $repo.pushed_at
            has_issues = $repo.has_issues
            has_projects = $repo.has_projects
            has_wiki = $repo.has_wiki
            has_pages = $repo.has_pages
            allow_auto_merge = $repo.allow_auto_merge
            allow_merge_commit = $repo.allow_merge_commit
            allow_squash_merge = $repo.allow_squash_merge
            allow_rebase_merge = $repo.allow_rebase_merge
            delete_branch_on_merge = $repo.delete_branch_on_merge
            authenticated_permissions = $repo.permissions
        }
        branches = @($branches | ForEach-Object { [ordered]@{ name = $_.name; sha = $_.commit.sha; protected = $_.protected } })
        tags = @($tags | ForEach-Object { [ordered]@{ name = $_.name; sha = $_.commit.sha } })
        releases = @($releases | ForEach-Object { [ordered]@{ id = $_.id; tag_name = $_.tag_name; draft = $_.draft; prerelease = $_.prerelease; published_at = $_.published_at } })
        open_pull_requests = @($pulls | ForEach-Object { [ordered]@{ number = $_.number; title = $_.title; draft = $_.draft; head_sha = $_.head.sha; base = $_.base.ref; updated_at = $_.updated_at } })
        open_issues = @($issues | Where-Object { -not $_.pull_request } | ForEach-Object { [ordered]@{ number = $_.number; title = $_.title; state = $_.state; updated_at = $_.updated_at } })
        workflows = $workflows
        environments = $environments
        rulesets = $rulesets
        default_branch_protection = $protection
        action_variable_names = $safeVariables
        action_secret_names = $safeSecrets
        hooks = $safeHooks
        deploy_keys = $safeDeployKeys
        collaborators = $safeCollaborators
        pages = $pages
        limitations = @(
            'secret values are never requested or recorded',
            'optional endpoints may be unavailable because of plan or permission boundaries',
            'local uncommitted work is outside the GitHub API inventory and must be checked separately'
        )
    }

    $repoEvidence = New-EvidenceDirectory -Root $evidenceRoot -Name $repository
    $inventoryPath = Join-Path $repoEvidence 'repository-inventory.json'
    Write-StableJson -InputObject $inventory -Path $inventoryPath

    $backup = [ordered]@{ requested = [bool]$CreateMirrorBackup; verified = $false; mirror_path = $null; bundle_path = $null; refs_path = $null; fsck = $null; bundle_verify = $null }
    $evidenceFiles = [System.Collections.Generic.List[object]]::new()
    $evidenceFiles.Add((Get-Sha256Record -Path $inventoryPath))

    if ($CreateMirrorBackup) {
        $backupStamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
        $repoBackupRoot = Join-Path $backupRoot "$repository-$backupStamp"
        $mirrorPath = Join-Path $repoBackupRoot "$repository.git"
        $bundlePath = Join-Path $repoBackupRoot "$repository.bundle"
        $refsPath = Join-Path $repoBackupRoot 'refs.txt'
        New-Item -ItemType Directory -Path $repoBackupRoot -Force | Out-Null

        & gh repo clone "$sourceOwner/$repository" $mirrorPath -- --mirror
        if ($LASTEXITCODE -ne 0) { throw "Mirror clone failed for $sourceOwner/$repository." }

        $fsckOutput = & git -C $mirrorPath fsck --full 2>&1
        if ($LASTEXITCODE -ne 0) { throw "git fsck failed for $sourceOwner/$repository: $fsckOutput" }

        $refsOutput = & git -C $mirrorPath for-each-ref '--format=%(refname) %(objectname)' 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Reference inventory failed for $sourceOwner/$repository: $refsOutput" }
        $refsOutput | Set-Content -LiteralPath $refsPath -Encoding UTF8

        & git -C $mirrorPath bundle create $bundlePath --all
        if ($LASTEXITCODE -ne 0) { throw "Git bundle creation failed for $sourceOwner/$repository." }

        $bundleVerifyOutput = & git -C $mirrorPath bundle verify $bundlePath 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Git bundle verification failed for $sourceOwner/$repository: $bundleVerifyOutput" }

        $backup.requested = $true
        $backup.verified = $true
        $backup.mirror_path = (Resolve-Path -LiteralPath $mirrorPath).Path
        $backup.bundle_path = (Resolve-Path -LiteralPath $bundlePath).Path
        $backup.refs_path = (Resolve-Path -LiteralPath $refsPath).Path
        $backup.fsck = 'PASS'
        $backup.bundle_verify = 'PASS'
        $evidenceFiles.Add((Get-Sha256Record -Path $bundlePath))
        $evidenceFiles.Add((Get-Sha256Record -Path $refsPath))
    }

    $manifest = [ordered]@{
        schema_version = 'sentinel.github-migration-evidence-manifest.v1'
        status = 'HOLD'
        repository_id = $repo.id
        repository_full_name = $repo.full_name
        exact_head_sha = $headSha
        created_at = (Get-Date).ToUniversalTime().ToString('o')
        backup = $backup
        files = @($evidenceFiles)
    }
    $manifestPath = Join-Path $repoEvidence 'evidence-manifest.json'
    Write-StableJson -InputObject $manifest -Path $manifestPath

    $run.repositories += [ordered]@{
        repository = $repo.full_name
        repository_id = $repo.id
        exact_head_sha = $headSha
        evidence_directory = $repoEvidence
        inventory_path = $inventoryPath
        manifest_path = $manifestPath
        backup_verified = $backup.verified
    }
}

$runPath = Join-Path $evidenceRoot ("inventory-run-{0}.json" -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ'))
Write-StableJson -InputObject $run -Path $runPath
Write-Host "Inventory completed under HOLD. Run record: $runPath" -ForegroundColor Green
