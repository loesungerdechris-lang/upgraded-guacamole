[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Location,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9-]{3,24}$')]
    [string]$VaultName,

    [ValidatePattern('^[A-Za-z0-9._()-]{1,90}$')]
    [string]$ResourceGroupName = 'rg-sentinel-signing-prod',

    [ValidatePattern('^[A-Za-z0-9-]{1,127}$')]
    [string]$KeyName = 'sentinel-receipt-es256',

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._ -]{2,119}$')]
    [string]$AppDisplayName = 'sentinel-github-oidc-prod',

    [ValidatePattern('^[A-Za-z0-9-]+$')]
    [string]$GitHubOwner = 'loesungerdechris-lang',

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$GitHubRepository = 'upgraded-guacamole',

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$GitHubEnvironment = 'sentinel-production',

    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SignerRoleDefinitionId = '6dc31abc-4652-4751-8e2d-e749fe4c7db5'
$SignerRoleName = 'SENTINEL Key Vault Signer'
$SignerDataActions = @(
    'Microsoft.KeyVault/vaults/keys/read',
    'Microsoft.KeyVault/vaults/keys/sign/action',
    'Microsoft.KeyVault/vaults/keys/verify/action'
)
$FederatedCredentialName = "github-$GitHubEnvironment"
$FederatedSubject = "repo:${GitHubOwner}/${GitHubRepository}:environment:${GitHubEnvironment}"

function Assert-Command {
    param([Parameter(Mandatory)][string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found. Install Azure CLI before running this script."
    }
}

function Invoke-AzJson {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $output = & az @Arguments --only-show-errors --output json
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed: az $($Arguments -join ' ')"
    }

    if ([string]::IsNullOrWhiteSpace(($output -join "`n"))) {
        return $null
    }

    return (($output -join "`n") | ConvertFrom-Json)
}

function Invoke-AzText {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $output = & az @Arguments --only-show-errors --output tsv
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI command failed: az $($Arguments -join ' ')"
    }

    return (($output -join "`n").Trim())
}

function Test-ExactStringSet {
    param(
        [Parameter(Mandatory)][object[]]$Actual,
        [Parameter(Mandatory)][object[]]$Expected
    )

    $actualStrings = @($Actual | ForEach-Object { [string]$_ })
    $expectedStrings = @($Expected | ForEach-Object { [string]$_ })

    if ($actualStrings.Count -ne $expectedStrings.Count) {
        return $false
    }

    foreach ($value in $expectedStrings) {
        if ($value -notin $actualStrings) {
            return $false
        }
    }

    return $true
}

function Assert-NoApplicationCredentials {
    param(
        [Parameter(Mandatory)]
        [object]$DirectoryObject,

        [Parameter(Mandatory)]
        [string]$ObjectLabel
    )

    $passwordCredentials = @($DirectoryObject.passwordCredentials)
    $keyCredentials = @($DirectoryObject.keyCredentials)

    if ($passwordCredentials.Count -gt 0 -or $keyCredentials.Count -gt 0) {
        throw "$ObjectLabel contains password or certificate credentials. Refusing to weaken the GitHub OIDC-only boundary."
    }
}

function Assert-SignerRoleDefinition {
    param(
        [Parameter(Mandatory)]
        [object]$RoleDefinition,

        [Parameter(Mandatory)]
        [string]$AssignableScope
    )

    if ($RoleDefinition.roleName -ne $SignerRoleName -or $RoleDefinition.roleType -ne 'CustomRole') {
        throw "Role definition '$SignerRoleDefinitionId' does not match the frozen SENTINEL custom role identity."
    }

    $permissions = @($RoleDefinition.permissions)
    if ($permissions.Count -ne 1) {
        throw "SENTINEL signer role must contain exactly one permission block."
    }

    $permission = $permissions[0]
    if (
        @($permission.actions).Count -ne 0 -or
        @($permission.notActions).Count -ne 0 -or
        @($permission.notDataActions).Count -ne 0 -or
        -not (Test-ExactStringSet -Actual @($permission.dataActions) -Expected $SignerDataActions)
    ) {
        throw "SENTINEL signer role contains broader permissions than key read, sign and verify."
    }

    if (-not (Test-ExactStringSet -Actual @($RoleDefinition.assignableScopes) -Expected @($AssignableScope))) {
        throw "SENTINEL signer role assignable scope does not exactly match '$AssignableScope'."
    }
}

function Write-Plan {
    $plan = [ordered]@{
        mode                       = if ($Apply) { 'apply' } else { 'dry-run' }
        tenant_id                  = $TenantId
        subscription_id            = $SubscriptionId
        location                   = $Location
        resource_group             = $ResourceGroupName
        key_vault                  = $VaultName
        key_name                   = $KeyName
        entra_app_display_name     = $AppDisplayName
        github_repository          = "$GitHubOwner/$GitHubRepository"
        github_environment         = $GitHubEnvironment
        federated_subject          = $FederatedSubject
        signer_role_definition_id  = $SignerRoleDefinitionId
        signer_role_name           = $SignerRoleName
        signer_data_actions        = $SignerDataActions
    }

    $plan | ConvertTo-Json -Depth 6
}

Assert-Command -Name 'az'
Write-Host 'SENTINEL Entra/OIDC + Key Vault bootstrap plan:'
Write-Plan

if (-not $Apply) {
    Write-Host 'Dry-run only. Re-run with -Apply after reviewing the plan.'
    exit 0
}

$account = Invoke-AzJson -Arguments @('account', 'show')
if ($account.tenantId -ne $TenantId) {
    throw "Azure CLI is signed into tenant '$($account.tenantId)', expected '$TenantId'. Run: az login --tenant $TenantId"
}

& az account set --subscription $SubscriptionId --only-show-errors
if ($LASTEXITCODE -ne 0) {
    throw "Unable to select subscription '$SubscriptionId'."
}

$selectedSubscription = Invoke-AzJson -Arguments @('account', 'show')
if ($selectedSubscription.id -ne $SubscriptionId) {
    throw "Selected subscription mismatch. Expected '$SubscriptionId', got '$($selectedSubscription.id)'."
}

$resourceGroupExists = Invoke-AzText -Arguments @('group', 'exists', '--name', $ResourceGroupName)
if ($resourceGroupExists -ne 'true') {
    Write-Host "Creating resource group '$ResourceGroupName' in '$Location'."
    $null = Invoke-AzJson -Arguments @(
        'group', 'create',
        '--name', $ResourceGroupName,
        '--location', $Location,
        '--tags',
        'system=SENTINEL',
        'purpose=receipt-signing',
        'environment=production'
    )
}
else {
    Write-Host "Using existing resource group '$ResourceGroupName'."
}

$resourceGroup = Invoke-AzJson -Arguments @('group', 'show', '--name', $ResourceGroupName)
if ([string]::IsNullOrWhiteSpace([string]$resourceGroup.id)) {
    throw "Azure did not return a resource-group identifier for '$ResourceGroupName'."
}
$roleAssignableScope = [string]$resourceGroup.id

$roleDefinitions = @(Invoke-AzJson -Arguments @('role', 'definition', 'list', '--name', $SignerRoleDefinitionId))
if ($roleDefinitions.Count -gt 1) {
    throw "More than one role definition matched '$SignerRoleDefinitionId'."
}

if ($roleDefinitions.Count -eq 0) {
    Write-Host "Creating least-privilege custom role '$SignerRoleName'."
    $roleDocument = [ordered]@{
        Name             = $SignerRoleName
        Id               = $SignerRoleDefinitionId
        IsCustom         = $true
        Description      = 'SENTINEL workload signer: read public key metadata and sign/verify digests only.'
        Actions          = @()
        NotActions       = @()
        DataActions      = $SignerDataActions
        NotDataActions   = @()
        AssignableScopes = @($roleAssignableScope)
    } | ConvertTo-Json -Depth 6

    $roleTempFile = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText(
            $roleTempFile,
            $roleDocument,
            [System.Text.UTF8Encoding]::new($false)
        )

        $null = Invoke-AzJson -Arguments @(
            'role', 'definition', 'create',
            '--role-definition', $roleTempFile
        )
    }
    finally {
        Remove-Item -LiteralPath $roleTempFile -Force -ErrorAction SilentlyContinue
    }
}

$roleDefinitions = @(Invoke-AzJson -Arguments @('role', 'definition', 'list', '--name', $SignerRoleDefinitionId))
if ($roleDefinitions.Count -ne 1) {
    throw "Azure did not return exactly one SENTINEL signer role definition."
}
Assert-SignerRoleDefinition -RoleDefinition $roleDefinitions[0] -AssignableScope $roleAssignableScope

$appFilter = "displayName eq '$AppDisplayName'"
$apps = @(Invoke-AzJson -Arguments @('ad', 'app', 'list', '--filter', $appFilter))
if ($apps.Count -gt 1) {
    throw "More than one Entra application uses exact display name '$AppDisplayName'. Refusing ambiguous selection."
}

if ($apps.Count -eq 0) {
    Write-Host "Creating single-tenant Entra application '$AppDisplayName'."
    $app = Invoke-AzJson -Arguments @(
        'ad', 'app', 'create',
        '--display-name', $AppDisplayName,
        '--sign-in-audience', 'AzureADMyOrg'
    )
}
else {
    $app = $apps[0]
    Write-Host "Using existing Entra application '$AppDisplayName' ($($app.appId))."
}

$app = Invoke-AzJson -Arguments @('ad', 'app', 'show', '--id', $app.appId)
if ($app.displayName -ne $AppDisplayName) {
    throw "Resolved Entra application display name '$($app.displayName)' does not exactly match '$AppDisplayName'."
}
if ($app.signInAudience -ne 'AzureADMyOrg') {
    throw "Existing Entra application '$AppDisplayName' is not single-tenant."
}
Assert-NoApplicationCredentials -DirectoryObject $app -ObjectLabel "Entra application '$AppDisplayName'"

$servicePrincipals = @(Invoke-AzJson -Arguments @('ad', 'sp', 'list', '--filter', "appId eq '$($app.appId)'"))
if ($servicePrincipals.Count -gt 1) {
    throw "More than one service principal was returned for application '$($app.appId)'."
}

if ($servicePrincipals.Count -eq 0) {
    Write-Host "Creating service principal for application '$($app.appId)'."
    $servicePrincipal = Invoke-AzJson -Arguments @('ad', 'sp', 'create', '--id', $app.appId)
}
else {
    $servicePrincipal = $servicePrincipals[0]
    Write-Host "Using existing service principal '$($servicePrincipal.id)'."
}

$servicePrincipal = Invoke-AzJson -Arguments @('ad', 'sp', 'show', '--id', $app.appId)
if ($servicePrincipal.appId -ne $app.appId) {
    throw "Resolved service principal does not match application '$($app.appId)'."
}
Assert-NoApplicationCredentials -DirectoryObject $servicePrincipal -ObjectLabel "Service principal '$($servicePrincipal.id)'"

$federatedCredentials = @(Invoke-AzJson -Arguments @('ad', 'app', 'federated-credential', 'list', '--id', $app.id))
$unexpectedCredentials = @($federatedCredentials | Where-Object { $_.name -ne $FederatedCredentialName })
if ($unexpectedCredentials.Count -gt 0) {
    $unexpectedNames = ($unexpectedCredentials | ForEach-Object { $_.name }) -join ', '
    throw "Unexpected federated credentials exist on '$AppDisplayName': $unexpectedNames. Refusing alternate OIDC subjects."
}

$matchingCredentials = @($federatedCredentials | Where-Object { $_.name -eq $FederatedCredentialName })
if ($matchingCredentials.Count -gt 1) {
    throw "More than one federated credential uses name '$FederatedCredentialName'."
}

if ($matchingCredentials.Count -eq 1) {
    $existing = $matchingCredentials[0]
    $existingAudience = @($existing.audiences)
    if (
        $existing.issuer -ne 'https://token.actions.githubusercontent.com' -or
        $existing.subject -ne $FederatedSubject -or
        $existingAudience.Count -ne 1 -or
        $existingAudience[0] -ne 'api://AzureADTokenExchange'
    ) {
        throw "Federated credential '$FederatedCredentialName' exists but does not match the frozen GitHub subject/audience. Refusing mutation."
    }

    Write-Host "Using existing federated credential '$FederatedCredentialName'."
}
else {
    Write-Host "Creating federated credential '$FederatedCredentialName'."
    $credentialDocument = [ordered]@{
        name        = $FederatedCredentialName
        issuer      = 'https://token.actions.githubusercontent.com'
        subject     = $FederatedSubject
        description = 'SENTINEL production GitHub Actions workload identity'
        audiences   = @('api://AzureADTokenExchange')
    } | ConvertTo-Json -Depth 4

    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText(
            $tempFile,
            $credentialDocument,
            [System.Text.UTF8Encoding]::new($false)
        )

        $null = Invoke-AzJson -Arguments @(
            'ad', 'app', 'federated-credential', 'create',
            '--id', $app.id,
            '--parameters', $tempFile
        )
    }
    finally {
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
}

$federatedCredentials = @(Invoke-AzJson -Arguments @('ad', 'app', 'federated-credential', 'list', '--id', $app.id))
if ($federatedCredentials.Count -ne 1 -or $federatedCredentials[0].name -ne $FederatedCredentialName) {
    throw "Entra application '$AppDisplayName' must contain exactly the expected federated credential."
}

$finalCredential = $federatedCredentials[0]
$finalAudience = @($finalCredential.audiences)
if (
    $finalCredential.issuer -ne 'https://token.actions.githubusercontent.com' -or
    $finalCredential.subject -ne $FederatedSubject -or
    $finalAudience.Count -ne 1 -or
    $finalAudience[0] -ne 'api://AzureADTokenExchange'
) {
    throw "Final federated credential state does not match the frozen GitHub subject/audience."
}

$vaults = @(Invoke-AzJson -Arguments @(
    'keyvault', 'list',
    '--resource-group', $ResourceGroupName
))
$matchingVaults = @($vaults | Where-Object { $_.name -eq $VaultName })

if ($matchingVaults.Count -gt 1) {
    throw "More than one Key Vault named '$VaultName' was returned."
}

if ($matchingVaults.Count -eq 0) {
    Write-Host "Creating RBAC-enabled Key Vault '$VaultName'."
    $vault = Invoke-AzJson -Arguments @(
        'keyvault', 'create',
        '--name', $VaultName,
        '--resource-group', $ResourceGroupName,
        '--location', $Location,
        '--enable-rbac-authorization', 'true',
        '--enable-purge-protection', 'true',
        '--retention-days', '90',
        '--tags',
        'system=SENTINEL',
        'purpose=receipt-signing',
        'environment=production'
    )
}
else {
    $vault = Invoke-AzJson -Arguments @('keyvault', 'show', '--name', $VaultName)
    if (-not $vault.properties.enableRbacAuthorization) {
        throw "Existing Key Vault '$VaultName' does not use Azure RBAC. Refusing to change its permission model automatically."
    }
    if (-not $vault.properties.enablePurgeProtection) {
        throw "Existing Key Vault '$VaultName' does not have purge protection enabled. Refusing production use."
    }

    Write-Host "Using existing protected Key Vault '$VaultName'."
}

$keys = @(Invoke-AzJson -Arguments @('keyvault', 'key', 'list', '--vault-name', $VaultName))
$matchingKeys = @($keys | Where-Object { $_.kid -match "/keys/$([regex]::Escape($KeyName))(/|$)" })

if ($matchingKeys.Count -gt 1) {
    throw "More than one active key entry matched '$KeyName'."
}

if ($matchingKeys.Count -eq 0) {
    Write-Host "Creating non-exportable P-256 key '$KeyName'."
    $key = Invoke-AzJson -Arguments @(
        'keyvault', 'key', 'create',
        '--vault-name', $VaultName,
        '--name', $KeyName,
        '--kty', 'EC',
        '--curve', 'P-256',
        '--ops', 'sign', 'verify',
        '--exportable', 'false',
        '--tags',
        'system=SENTINEL',
        'purpose=receipt-signing',
        'algorithm=ES256'
    )
}
else {
    $key = Invoke-AzJson -Arguments @('keyvault', 'key', 'show', '--vault-name', $VaultName, '--name', $KeyName)
    if ($key.key.kty -ne 'EC' -or $key.key.crv -ne 'P-256') {
        throw "Existing key '$KeyName' is not an EC P-256 key."
    }

    $keyOperations = @($key.key.keyOps | ForEach-Object { [string]$_ })
    $unexpectedKeyOperations = @($keyOperations | Where-Object { $_ -notin @('sign', 'verify') })
    if (
        $keyOperations.Count -ne 2 -or
        'sign' -notin $keyOperations -or
        'verify' -notin $keyOperations -or
        $unexpectedKeyOperations.Count -gt 0
    ) {
        throw "Existing key '$KeyName' must permit exactly sign and verify operations."
    }

    $exportableProperty = $key.attributes.PSObject.Properties['exportable']
    if ($null -ne $exportableProperty -and [bool]$exportableProperty.Value) {
        throw "Existing key '$KeyName' is marked exportable. Refusing production use."
    }

    Write-Host "Using existing non-exportable P-256 key '$KeyName'."
}

$key = Invoke-AzJson -Arguments @('keyvault', 'key', 'show', '--vault-name', $VaultName, '--name', $KeyName)
$keyOperations = @($key.key.keyOps | ForEach-Object { [string]$_ })
$unexpectedKeyOperations = @($keyOperations | Where-Object { $_ -notin @('sign', 'verify') })
if (
    $key.key.kty -ne 'EC' -or
    $key.key.crv -ne 'P-256' -or
    $keyOperations.Count -ne 2 -or
    'sign' -notin $keyOperations -or
    'verify' -notin $keyOperations -or
    $unexpectedKeyOperations.Count -gt 0
) {
    throw "Final key state is not the frozen EC P-256 sign+verify-only profile."
}

$exportableProperty = $key.attributes.PSObject.Properties['exportable']
if ($null -ne $exportableProperty -and [bool]$exportableProperty.Value) {
    throw "Final key state is exportable. Refusing production use."
}

$expectedRoleDefinitionResourceId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$SignerRoleDefinitionId"
$existingAssignments = @(Invoke-AzJson -Arguments @(
    'role', 'assignment', 'list',
    '--assignee', $servicePrincipal.id,
    '--scope', $vault.id,
    '--include-inherited',
    '--all'
))
$unexpectedAssignments = @(
    $existingAssignments |
        Where-Object { ([string]$_.roleDefinitionId).ToLowerInvariant() -ne $expectedRoleDefinitionResourceId.ToLowerInvariant() }
)
if ($unexpectedAssignments.Count -gt 0) {
    $unexpectedRoleIds = ($unexpectedAssignments | ForEach-Object { $_.roleDefinitionId }) -join ', '
    throw "Signer service principal has unexpected direct or inherited Azure roles at the vault scope: $unexpectedRoleIds"
}

$matchingAssignments = @(
    $existingAssignments |
        Where-Object { ([string]$_.roleDefinitionId).ToLowerInvariant() -eq $expectedRoleDefinitionResourceId.ToLowerInvariant() }
)
if ($matchingAssignments.Count -gt 1) {
    throw "More than one SENTINEL signer-role assignment exists at the vault scope."
}

if ($matchingAssignments.Count -eq 0) {
    Write-Host "Granting least-privilege '$SignerRoleName' at the dedicated vault scope."
    $null = Invoke-AzJson -Arguments @(
        'role', 'assignment', 'create',
        '--assignee-object-id', $servicePrincipal.id,
        '--assignee-principal-type', 'ServicePrincipal',
        '--role', $SignerRoleDefinitionId,
        '--scope', $vault.id
    )
}
else {
    Write-Host "Required least-privilege signer-role assignment already exists."
}

$finalAssignments = @(Invoke-AzJson -Arguments @(
    'role', 'assignment', 'list',
    '--assignee', $servicePrincipal.id,
    '--scope', $vault.id,
    '--include-inherited',
    '--all'
))
$unexpectedAssignments = @(
    $finalAssignments |
        Where-Object { ([string]$_.roleDefinitionId).ToLowerInvariant() -ne $expectedRoleDefinitionResourceId.ToLowerInvariant() }
)
$matchingAssignments = @(
    $finalAssignments |
        Where-Object { ([string]$_.roleDefinitionId).ToLowerInvariant() -eq $expectedRoleDefinitionResourceId.ToLowerInvariant() }
)
if ($unexpectedAssignments.Count -gt 0 -or $matchingAssignments.Count -ne 1) {
    throw "Final signer-role state is not exactly one least-privilege vault-scoped assignment."
}

$result = [ordered]@{
    tenant_id                    = $TenantId
    subscription_id              = $SubscriptionId
    client_id                    = $app.appId
    application_object_id        = $app.id
    service_principal_object_id  = $servicePrincipal.id
    federated_subject            = $FederatedSubject
    resource_group               = $ResourceGroupName
    key_vault_name               = $VaultName
    key_vault_resource_id        = $vault.id
    key_name                     = $KeyName
    key_id                       = $key.key.kid
    signer_role_definition_id    = $expectedRoleDefinitionResourceId
    signer_role_assignment_scope = $vault.id
}

Write-Host 'Bootstrap completed. Store the following identifiers as protected GitHub environment variables:'
$result | ConvertTo-Json -Depth 6
