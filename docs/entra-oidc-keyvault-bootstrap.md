# SENTINEL Entra OIDC and Azure Key Vault Bootstrap

## Purpose

This runbook establishes the first production-grade external signing dependency for SENTINEL:

```text
GitHub Actions OIDC
  -> Microsoft Entra workload identity
  -> least-privilege Azure custom data-plane role
  -> dedicated Azure Key Vault
  -> non-exportable P-256 signing key
```

This change does **not** add private signing material to the repository and does not make the verifier a signer.

## Safety boundary

The bootstrap follows these mandatory rules:

- no Azure client secret
- no application or service-principal certificate credential
- no alternate federated identity subject on the signer application
- no private key export
- no private JWK
- no signing material in GitHub variables, secrets, logs, or artifacts
- dedicated vault for the production SENTINEL signing workload
- GitHub federation restricted to a protected environment subject
- Azure RBAC enabled for the vault data plane
- custom signer role limited to key metadata read, sign and verify
- no additional direct or inherited Azure role for the runtime signer at the vault scope
- purge protection required
- existing ambiguous or weaker resources fail closed
- dry-run is the default

The federated subject is:

```text
repo:loesungerdechris-lang/upgraded-guacamole:environment:sentinel-production
```

A workflow from another repository, branch-only subject, pull request, or unprotected environment must not satisfy this trust binding.

## Prerequisites

Run the bootstrap from a controlled administrator workstation with:

- PowerShell 7 or later
- Azure CLI
- access to the intended Microsoft Entra tenant
- an Azure subscription
- permission to create an Entra application and service principal
- permission to create the resource group and Key Vault
- permission to create a custom Azure role definition at the dedicated resource-group scope
- permission to create Azure role assignments at the dedicated vault scope

Confirm the active tenant and subscription before applying:

```powershell
az login --tenant <TENANT-ID>
az account set --subscription <SUBSCRIPTION-ID>
az account show
```

Do not paste access tokens or Azure CLI credential-cache contents into GitHub, issue comments, or chat transcripts.

## 1. Review the dry-run plan

The script makes no Azure changes unless `-Apply` is supplied.

```powershell
pwsh ./scripts/azure/bootstrap-sentinel-oidc.ps1 `
  -TenantId '<TENANT-ID>' `
  -SubscriptionId '<SUBSCRIPTION-ID>' `
  -Location 'germanywestcentral' `
  -VaultName '<GLOBALLY-UNIQUE-VAULT-NAME>'
```

Review every value in the JSON plan, especially:

- tenant ID
- subscription ID
- location
- resource group
- vault name
- GitHub repository
- GitHub environment
- federated subject
- custom role name
- exact signer data actions

## 2. Apply the bootstrap

After the dry-run has been reviewed:

```powershell
pwsh ./scripts/azure/bootstrap-sentinel-oidc.ps1 `
  -TenantId '<TENANT-ID>' `
  -SubscriptionId '<SUBSCRIPTION-ID>' `
  -Location 'germanywestcentral' `
  -VaultName '<GLOBALLY-UNIQUE-VAULT-NAME>' `
  -Apply
```

The script creates or safely reuses:

1. resource group `rg-sentinel-signing-prod`
2. custom role `SENTINEL Key Vault Signer`
3. single-tenant Entra application `sentinel-github-oidc-prod`
4. corresponding service principal without password or certificate credentials
5. exactly one GitHub Actions federated identity credential
6. RBAC-enabled, purge-protected Key Vault
7. non-exportable EC P-256 key `sentinel-receipt-es256`
8. one vault-scoped custom signer-role assignment for the workload identity

Azure assigns the custom role-definition GUID. The script retrieves that GUID from the Azure CLI response and uses the returned value for role assignment and verification.

The custom role contains no management-plane actions and exactly these data actions:

```text
Microsoft.KeyVault/vaults/keys/read
Microsoft.KeyVault/vaults/keys/sign/action
Microsoft.KeyVault/vaults/keys/verify/action
```

The script is idempotent for matching resources. It stops instead of silently rewriting resources when it finds:

- duplicate or non-exact application display names
- a multi-tenant application
- an application or service principal with password or certificate credentials
- duplicate or additional federated credentials
- a federated subject, issuer or audience mismatch
- an existing vault without Azure RBAC
- an existing vault without purge protection
- a key with the wrong type, curve, exportability or permitted operations
- a custom role with broader permissions or a broader assignable scope
- another direct or inherited Azure role on the signer identity at the vault scope

## 3. Configure the protected GitHub environment

In the repository settings, create or review the environment:

```text
sentinel-production
```

Configure an appropriate deployment reviewer before production use. Add these environment variables from the bootstrap result:

```text
AZURE_CLIENT_ID
AZURE_TENANT_ID
AZURE_SUBSCRIPTION_ID
SENTINEL_KEY_VAULT_NAME
SENTINEL_KEY_NAME
```

These are identifiers, not private credentials. Keep them on the protected environment rather than hard-coding them in workflow files.

The environment must not contain:

- client secrets
- certificates with private keys
- private JWK values
- exported Key Vault keys
- Azure access tokens

## 4. Run the OIDC smoke workflow

Run the workflow manually from `main`:

```text
SENTINEL Azure OIDC Smoke
```

The workflow verifies:

- GitHub can request an OIDC token
- Entra accepts only the configured federated workload identity
- Azure resolves the expected tenant and subscription
- the workload identity can read the dedicated signing-key metadata
- the key is EC P-256
- the key permits `sign` and `verify`

The smoke workflow does not sign a production receipt. Digest signing and independent receipt verification belong in a later, separately reviewed integration change.

## 5. Required checks before enabling signing

Do not add a production signing job until all of these are true:

- the environment requires review
- the federated subject exactly matches the protected environment
- the signer application and service principal have no password or certificate credentials
- exactly one federated credential exists on the signer application
- the vault uses Azure RBAC
- purge protection is enabled
- the runtime signer has exactly the custom key-read/sign/verify role at the vault scope
- no additional direct or inherited runtime role exists at that scope
- administrators and runtime signers use separate identities and roles
- the public key and versioned key ID are recorded in the SENTINEL trust registry
- key rotation and revocation procedures are documented
- workflow actions are pinned to reviewed immutable commit SHAs
- Azure outage behavior is fail-closed and does not weaken the normal verifier CI

## Rollback

Rollback must be explicit and ordered:

1. disable the GitHub environment or remove its deployment approval
2. remove the federated identity credential from the Entra application
3. remove the custom signer-role assignment from the service principal
4. disable, but do not immediately destroy, the signing key if receipts may still depend on its public version
5. preserve the public JWK and historical key metadata needed to verify existing receipts
6. remove the application/service principal only after confirming no other workload uses it
7. remove the custom role definition only after its assignments are gone

Do not purge a production signing key merely to roll back GitHub access. Historical receipts require stable public verification material and key-status history.

## Next implementation slice

The next reviewed change should add a separate Key Vault signer adapter that:

1. canonicalizes an unsigned receipt using the existing receipt contract
2. computes SHA-256 locally
3. sends only the digest to Key Vault for ES256 signing
4. emits a JWS-style signature with explicit `alg` and versioned `kid`
5. invokes the existing verifier as an independent step
6. proves through tests and log inspection that no private material is available to the process

Related tracking issue: #11.
