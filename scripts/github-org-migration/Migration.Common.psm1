Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-ExternalCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found in PATH."
    }
}

function Assert-SafeGitHubName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$FieldName
    )

    if ($Value -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}[A-Za-z0-9])?$') {
        throw "$FieldName contains an unsafe or unsupported GitHub name: '$Value'."
    }
}

function Read-SentinelMigrationConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $config = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 100

    if ($config.schema_version -ne 'sentinel.github-org-migration.v1') { throw 'Unsupported migration configuration schema.' }
    if ($config.status -ne 'HOLD') { throw 'Migration configuration must remain HOLD.' }

    Assert-SafeGitHubName -Value ([string]$config.source_owner) -FieldName 'source_owner'
    Assert-SafeGitHubName -Value ([string]$config.target_organization) -FieldName 'target_organization'

    $repositories = @($config.repositories)
    $deniedRepositories = @($config.denied_repositories | Where-Object { $null -ne $_ -and [string]$_ -ne '' })
    $transferOrder = @($config.transfer_order)
    if ($repositories.Count -eq 0) { throw 'At least one repository must be configured.' }
    if ($transferOrder.Count -eq 0) { throw 'transfer_order must contain at least one repository.' }

    foreach ($repo in $repositories + $deniedRepositories + $transferOrder) {
        Assert-SafeGitHubName -Value ([string]$repo) -FieldName 'repository'
    }
    foreach ($repo in $transferOrder) {
        if ($repo -notin $repositories) { throw "transfer_order contains repository '$repo' outside repositories." }
        if ($repo -in $deniedRepositories) { throw "transfer_order contains denied repository '$repo'." }
    }
    if (@($transferOrder | Sort-Object -Unique).Count -ne $transferOrder.Count) { throw 'transfer_order contains duplicate repositories.' }

    foreach ($team in @($config.teams)) {
        Assert-SafeGitHubName -Value ([string]$team.name) -FieldName 'team name'
    }
    foreach ($environment in @($config.environments)) {
        Assert-SafeGitHubName -Value ([string]$environment) -FieldName 'environment name'
    }

    if ([bool]$config.allow_bulk_transfer) { throw 'allow_bulk_transfer must remain false.' }
    if ([bool]$config.allow_paid_plan_changes) { throw 'allow_paid_plan_changes must remain false.' }
    if ([bool]$config.allow_azure_mutation) { throw 'allow_azure_mutation must remain false for this toolkit.' }

    return $config
}

function Invoke-GhJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Endpoint,
        [string[]]$Arguments = @()
    )

    Assert-ExternalCommand -Name 'gh'
    $stdout = New-TemporaryFile
    $stderr = New-TemporaryFile
    try {
        & gh api $Endpoint @Arguments 1> $stdout 2> $stderr
        if ($LASTEXITCODE -ne 0) {
            $message = (Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue).Trim()
            throw "GitHub API request failed for '$Endpoint': $message"
        }
        $raw = Get-Content -LiteralPath $stdout -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return $raw | ConvertFrom-Json -Depth 100
    }
    finally {
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-GhOptionalJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Endpoint,
        [string[]]$Arguments = @()
    )

    Assert-ExternalCommand -Name 'gh'
    $stdout = New-TemporaryFile
    $stderr = New-TemporaryFile
    try {
        & gh api $Endpoint @Arguments 1> $stdout 2> $stderr
        if ($LASTEXITCODE -ne 0) {
            return [ordered]@{
                available = $false
                value = $null
                error = (Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue).Trim()
            }
        }
        $raw = Get-Content -LiteralPath $stdout -Raw -Encoding UTF8
        $value = if ([string]::IsNullOrWhiteSpace($raw)) { $null } else { $raw | ConvertFrom-Json -Depth 100 }
        return [ordered]@{ available = $true; value = $value; error = $null }
    }
    finally {
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-GhPaginatedArray {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Endpoint)

    $pages = Invoke-GhJson -Endpoint $Endpoint -Arguments @('--paginate', '--slurp')
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($page in @($pages)) {
        if ($null -eq $page) { continue }
        if ($page -is [System.Array]) {
            foreach ($item in $page) { $items.Add($item) }
        }
        else {
            $items.Add($page)
        }
    }
    return @($items)
}

function Write-StableJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Path
    )

    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $json = $InputObject | ConvertTo-Json -Depth 100
    [System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($Path), $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}

function Get-Sha256Record {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path
    if (-not $item.PSIsContainer) {
        return [ordered]@{
            path = $item.FullName
            byte_length = $item.Length
            sha256 = 'sha256:' + (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    throw "SHA-256 record requires a regular file: $Path"
}

function Get-RepositoryHead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Owner,
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$DefaultBranch
    )

    $commit = Invoke-GhJson -Endpoint "repos/$Owner/$Repository/commits/$DefaultBranch"
    return [string]$commit.sha
}

function New-EvidenceDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Name
    )

    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
    $nonce = [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $path = Join-Path $Root "$Name-$stamp-$nonce"
    New-Item -ItemType Directory -Path $path -ErrorAction Stop | Out-Null
    return (Resolve-Path -LiteralPath $path).Path
}

Export-ModuleMember -Function @(
    'Assert-ExternalCommand',
    'Assert-SafeGitHubName',
    'Read-SentinelMigrationConfig',
    'Invoke-GhJson',
    'Invoke-GhOptionalJson',
    'Invoke-GhPaginatedArray',
    'Write-StableJson',
    'Get-Sha256Record',
    'Get-RepositoryHead',
    'New-EvidenceDirectory'
)
