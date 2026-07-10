[CmdletBinding()]
param(
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ExpectedTenantId,

    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ExpectedSubscriptionId,

    [string]$RepositoryPath = (Get-Location).Path,

    [version]$MinimumPowerShellVersion = '7.4.0',

    [version]$ReviewedAzureCliVersion = '2.88.0',

    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('GO', 'INFO', 'UPDATE', 'HOLD', 'BLOCKER')][string]$Status,
        [Parameter(Mandatory)][string]$Observed,
        [Parameter(Mandatory)][string]$NextAction
    )

    $results.Add([pscustomobject][ordered]@{
        area        = $Area
        check       = $Check
        status      = $Status
        observed    = $Observed
        next_action = $NextAction
    })
}

function Get-MaskedGuid {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return '<not-set>'
    }

    if ($Value.Length -lt 8) {
        return '<invalid>'
    }

    return "...$($Value.Substring($Value.Length - 8))"
}

function Test-ExternalCommand {
    param([Parameter(Mandatory)][string]$Name)

    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

$currentPowerShell = [version]$PSVersionTable.PSVersion
if ($currentPowerShell -ge $MinimumPowerShellVersion) {
    Add-Result -Area 'PowerShell' -Check 'Runtime version' -Status 'GO' \
        -Observed "$currentPowerShell at $PSHOME" \
        -NextAction 'No mandatory runtime update for the SENTINEL scripts.'
}
else {
    Add-Result -Area 'PowerShell' -Check 'Runtime version' -Status 'BLOCKER' \
        -Observed "$currentPowerShell at $PSHOME" \
        -NextAction "Upgrade PowerShell to at least $MinimumPowerShellVersion before running Entra bootstrap scripts."
}

if (Test-ExternalCommand -Name 'winget') {
    $wingetOutput = & winget list --id Microsoft.PowerShell --exact --upgrade-available 2>&1
    $wingetExit = $LASTEXITCODE
    $wingetText = (($wingetOutput | ForEach-Object { [string]$_ }) -join ' ').Trim()

    if ($wingetExit -eq 0 -and -not [string]::IsNullOrWhiteSpace($wingetText)) {
        Add-Result -Area 'PowerShell' -Check 'WinGet update probe' -Status 'INFO' \
            -Observed $wingetText \
            -NextAction 'If an upgrade is listed, run: winget upgrade --id Microsoft.PowerShell'
    }
    else {
        Add-Result -Area 'PowerShell' -Check 'WinGet update probe' -Status 'INFO' \
            -Observed 'No upgrade result was returned.' \
            -NextAction 'Use the same installation method that originally installed PowerShell.'
    }
}
else {
    Add-Result -Area 'PowerShell' -Check 'WinGet update probe' -Status 'INFO' \
        -Observed 'winget is not available in PATH.' \
        -NextAction 'Use Microsoft Update or the original PowerShell installation method.'
}

if (-not (Test-ExternalCommand -Name 'az')) {
    Add-Result -Area 'Azure CLI' -Check 'CLI availability' -Status 'BLOCKER' \
        -Observed 'az was not found in PATH.' \
        -NextAction 'Install the 64-bit Azure CLI before running the SENTINEL bootstrap.'
}
else {
    try {
        $azureVersionDocument = (& az version --output json 2>$null | Out-String) | ConvertFrom-Json
        $azureCliVersion = [version]([string]$azureVersionDocument.'azure-cli')

        if ($azureCliVersion -ge $ReviewedAzureCliVersion) {
            Add-Result -Area 'Azure CLI' -Check 'Reviewed version baseline' -Status 'GO' \
                -Observed "$azureCliVersion" \
                -NextAction 'No Azure CLI update is required against the reviewed baseline.'
        }
        else {
            Add-Result -Area 'Azure CLI' -Check 'Reviewed version baseline' -Status 'UPDATE' \
                -Observed "$azureCliVersion" \
                -NextAction "Review and run 'az upgrade'; the repository baseline was checked against Azure CLI $ReviewedAzureCliVersion."
        }
    }
    catch {
        Add-Result -Area 'Azure CLI' -Check 'Version probe' -Status 'HOLD' \
            -Observed 'Azure CLI exists but its version output could not be parsed.' \
            -NextAction 'Run az --version manually and repair the Azure CLI installation before applying changes.'
    }

    try {
        $account = (& az account show --only-show-errors --output json 2>$null | Out-String) | ConvertFrom-Json
        $actualTenantId = [string]$account.tenantId
        $actualSubscriptionId = [string]$account.id

        $tenantStatus = if ($ExpectedTenantId -and $actualTenantId -ne $ExpectedTenantId) { 'HOLD' } else { 'GO' }
        $tenantAction = if ($tenantStatus -eq 'GO') {
            'Tenant context is available and matches the expected value when supplied.'
        }
        else {
            'Run az login --tenant <TENANT-ID> and reselect the intended subscription.'
        }
        Add-Result -Area 'Microsoft Entra' -Check 'Tenant context' -Status $tenantStatus \
            -Observed (Get-MaskedGuid -Value $actualTenantId) \
            -NextAction $tenantAction

        $subscriptionStatus = if ($ExpectedSubscriptionId -and $actualSubscriptionId -ne $ExpectedSubscriptionId) { 'HOLD' } else { 'GO' }
        $subscriptionAction = if ($subscriptionStatus -eq 'GO') {
            'Subscription context is available and matches the expected value when supplied.'
        }
        else {
            'Run az account set --subscription <SUBSCRIPTION-ID> and re-run this audit.'
        }
        Add-Result -Area 'Azure' -Check 'Subscription context' -Status $subscriptionStatus \
            -Observed (Get-MaskedGuid -Value $actualSubscriptionId) \
            -NextAction $subscriptionAction
    }
    catch {
        Add-Result -Area 'Microsoft Entra' -Check 'Authenticated Azure context' -Status 'HOLD' \
            -Observed 'No usable Azure CLI account context was found.' \
            -NextAction 'Run az login --tenant <TENANT-ID>, select the intended subscription, then re-run this audit.'
    }
}

if (-not (Test-ExternalCommand -Name 'gh')) {
    Add-Result -Area 'GitHub' -Check 'GitHub CLI availability' -Status 'HOLD' \
        -Observed 'gh was not found in PATH.' \
        -NextAction 'Install GitHub CLI if local repository administration is required.'
}
else {
    $null = & gh auth status 2>&1
    if ($LASTEXITCODE -eq 0) {
        Add-Result -Area 'GitHub' -Check 'CLI authentication' -Status 'GO' \
            -Observed 'An authenticated GitHub CLI session is present.' \
            -NextAction 'No GitHub CLI reconnection is required.'
    }
    else {
        Add-Result -Area 'GitHub' -Check 'CLI authentication' -Status 'HOLD' \
            -Observed 'GitHub CLI is installed but not authenticated.' \
            -NextAction 'Run gh auth login, then verify with gh auth status.'
    }
}

if (Test-ExternalCommand -Name 'codex') {
    try {
        $codexVersion = ((& codex --version 2>&1 | Out-String).Trim())
        Add-Result -Area 'Codex' -Check 'Local client availability' -Status 'GO' \
            -Observed $codexVersion \
            -NextAction 'The local Codex client is callable. GitHub review quota is checked separately in PR activity.'
    }
    catch {
        Add-Result -Area 'Codex' -Check 'Local client availability' -Status 'HOLD' \
            -Observed 'The Codex command exists but did not return a version.' \
            -NextAction 'Open the Codex client and sign in again if local tasks fail.'
    }
}
else {
    Add-Result -Area 'Codex' -Check 'Local client availability' -Status 'INFO' \
        -Observed 'No codex executable was found in PATH.' \
        -NextAction 'This does not break GitHub review integration; install or reconnect the local client only if local Codex work is needed.'
}

$resolvedRepositoryPath = Resolve-Path -LiteralPath $RepositoryPath -ErrorAction SilentlyContinue
if ($null -eq $resolvedRepositoryPath) {
    Add-Result -Area 'Repository' -Check 'Repository path' -Status 'HOLD' \
        -Observed $RepositoryPath \
        -NextAction 'Run the audit from the upgraded-guacamole checkout or pass -RepositoryPath explicitly.'
}
else {
    $bootstrapPath = Join-Path $resolvedRepositoryPath.Path 'scripts/azure/bootstrap-sentinel-oidc.ps1'
    if (-not (Test-Path -LiteralPath $bootstrapPath -PathType Leaf)) {
        Add-Result -Area 'Repository' -Check 'Bootstrap script' -Status 'HOLD' \
            -Observed $bootstrapPath \
            -NextAction 'Use a current upgraded-guacamole checkout containing the Entra bootstrap script.'
    }
    else {
        $tokens = $null
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            $bootstrapPath,
            [ref]$tokens,
            [ref]$parseErrors
        ) | Out-Null

        if ($parseErrors.Count -eq 0) {
            Add-Result -Area 'Repository' -Check 'Bootstrap parser gate' -Status 'GO' \
                -Observed 'PowerShell parser accepted bootstrap-sentinel-oidc.ps1.' \
                -NextAction 'Proceed only with the documented dry-run; do not add -Apply until the plan is reviewed.'
        }
        else {
            Add-Result -Area 'Repository' -Check 'Bootstrap parser gate' -Status 'BLOCKER' \
                -Observed (($parseErrors | ForEach-Object { $_.Message }) -join '; ') \
                -NextAction 'Repair the script or update the checkout before any Azure operation.'
        }
    }
}

$priority = @{
    BLOCKER = 5
    HOLD    = 4
    UPDATE  = 3
    INFO    = 2
    GO      = 1
}
$overall = ($results | Sort-Object { $priority[$_.status] } -Descending | Select-Object -First 1).status

$report = [pscustomobject][ordered]@{
    generated_at_utc = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    overall_status   = $overall
    mutation_free    = $true
    results          = $results
}

if ($AsJson) {
    $report | ConvertTo-Json -Depth 6
}
else {
    $results | Format-Table -AutoSize -Wrap
    Write-Host "Overall status: $overall"
    Write-Host 'This audit performs no Azure, Entra, GitHub, Codex or package mutation.'
}

if ($overall -eq 'BLOCKER') {
    exit 2
}

exit 0
