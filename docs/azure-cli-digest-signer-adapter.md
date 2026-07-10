# SENTINEL Azure CLI Key Vault Digest Signer Adapter

## Purpose

`AzureCliKeyVaultDigestSigner` connects the merged SENTINEL external digest-signing contract to an already authenticated Azure CLI session.

```text
Prepared DigestSigningRequest
  -> validate exact Azure Key Vault versioned key ID
  -> decode exactly 32 SHA-256 bytes
  -> convert digest to standard base64 for Azure CLI
  -> az keyvault key sign
  -> validate exact returned kid and raw ES256 result
  -> ExternalSignatureResult
  -> external_signing.finalize_receipt_signature
  -> independent verify_receipt
```

The adapter does not log in to Azure, acquire credentials, store tokens, generate keys, attach signatures to receipts or verify receipts.

## Authentication boundary

The process must already have an authenticated Azure CLI context. In the intended GitHub Actions path, that context is established by the protected `sentinel-production` environment and GitHub OIDC through `azure/login`.

The adapter does not support:

- Azure client secrets;
- certificates with private keys;
- private JWK values;
- `DefaultAzureCredential` or any embedded credential chain;
- interactive login;
- local production key generation;
- exported Key Vault keys.

## Accepted request

The adapter accepts only `DigestSigningRequest` with:

- `algorithm` exactly `ES256`;
- `digest_b64url` decoding canonically to exactly 32 bytes;
- `key_id` matching an exact public Azure Key Vault versioned identifier:

```text
https://<vault>.vault.azure.net/keys/<key-name>/<version>
```

The vault host must use the public `vault.azure.net` suffix, contain a safe 3–24 character vault name and have no user information, port, query, fragment or alternate path. The key name and version are restricted to safe Azure identifier characters.

## Process invocation

The adapter invokes Azure CLI with an argument vector, never through a shell:

```text
az keyvault key sign
  --id <exact-versioned-key-id>
  --algorithm ES256
  --digest <standard-base64-sha256-digest>
  --only-show-errors
  --output json
```

The subprocess boundary is frozen to:

- `shell=False`;
- `check=False` with explicit return-code handling;
- captured stdout and stderr;
- strict UTF-8 decoding;
- a bounded timeout of at most 120 seconds;
- `stdin` disconnected with `DEVNULL`;
- no custom environment or injected credential values.

## Response validation

The adapter fails closed unless the Azure CLI response:

- is a bounded JSON object;
- contains the exact requested versioned `kid`;
- contains exactly one supported signature-value field;
- returns canonical unpadded base64url text;
- decodes to exactly 64 raw ES256 bytes.

The external signing finalizer performs the remaining P-256 scalar-range validation before attaching the signature to a copied receipt.

## Error handling

The adapter never includes any of the following in raised error messages:

- command arguments;
- digest values;
- returned signatures;
- key IDs;
- stdout or stderr;
- bearer tokens or Azure context.

Subprocess exceptions are raised without chained causes so an uncaught traceback cannot reveal the command vector containing the digest or key ID.

## Independent verification

The adapter returns only `ExternalSignatureResult`. It does not claim success beyond structural response validation.

Callers must continue through:

```python
signed_receipt = sign_receipt_with_external_digest_signer(...)
verification = verify_receipt(signed_receipt, trust_registry=public_registry)
```

Only `verify_receipt` may produce `RC_VERIFIED`.

## Offline testability

The command runner is injectable solely to support deterministic failure-path and interoperability tests. Tests prove:

- exact CLI argument construction;
- no shell or custom environment;
- standard-base64 digest transport;
- strict endpoint and versioned-key binding;
- sanitized missing-executable, timeout and non-zero-exit failures;
- malformed response rejection;
- complete mocked Azure CLI signing through the independent verifier.

Test-only ephemeral private keys remain under `tests/` and are not callable from production source.

## Live activation gate

Implementation may be merged before tenant activation. A live signing claim remains **HOLD** until:

1. issue #14 provisions the authorized tenant and protected GitHub environment;
2. the metadata-only OIDC smoke succeeds from protected `main`;
3. the versioned public key and JWK are registered in the trust registry;
4. a protected live Key Vault digest signature passes the existing independent verifier;
5. logs and artifacts are inspected for tokens, private material and accidental Azure context output.

Related: #11, #14 and #20.