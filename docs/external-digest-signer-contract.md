# SENTINEL External ES256 Digest Signer Contract

## Purpose

This contract adds a signing boundary without moving private key custody into the SENTINEL repository, verifier or application process.

```text
canonical unsigned receipt
  -> deterministic JWS protected header + payload
  -> SHA-256 digest of <protected>.<payload>
  -> external signer receives only algorithm + versioned key ID + digest
  -> external signer returns algorithm + exact versioned key ID + raw ES256 signature
  -> SENTINEL attaches the signature structurally
  -> existing independent verifier decides RC_VERIFIED or NOT_VERIFIED
```

The production module is `src/sentinel_core/external_signing.py`. It contains no private-key generation, import, persistence or serialization path.

## Trust separation

The signer and verifier are separate trust domains:

- the signer prepares and attaches a signature;
- the signer never declares its output verified;
- the verifier uses only the public trust registry;
- a structurally accepted signature can still fail independent cryptographic verification;
- the verifier remains available when Azure or another external signer is unavailable.

## External boundary

Only this request may cross the signer boundary:

```text
algorithm
key_id
digest_b64url
```

For the current profile:

- `algorithm` must be `ES256`;
- `key_id` must be a versioned HTTPS identifier ending in `/keys/<name>/<version>`;
- `digest_b64url` is the unpadded base64url encoding of exactly 32 SHA-256 bytes.

The request does not contain the receipt, subject, evidence, policy, payload, access token or any private material.

Azure Key Vault's sign operation is compatible with this boundary because it signs a caller-supplied digest and returns a versioned key identifier plus a base64url operation result. The core contract deliberately does not acquire Azure credentials or depend on an Azure SDK.

## Preparation

`prepare_receipt_signature` performs the following steps:

1. validates the receipt shape, signer role and versioned key identifier;
2. refuses a duplicate signature for the target key;
3. canonicalizes the unsigned receipt through `build_unsigned_receipt_payload`;
4. computes the canonical `sha256:` receipt hash;
5. creates the protected header:

```json
{"alg":"ES256","kid":"<versioned-key-id>","typ":"SENTINEL-JWS"}
```

6. base64url-encodes the canonical protected header and payload;
7. forms `<protected>.<payload>`;
8. computes SHA-256 locally;
9. returns immutable local context plus the narrow external request.

Preparation does not mutate the input receipt and does not call an external service.

## Finalization

`finalize_receipt_signature` fails closed unless:

- the prepared context is internally consistent;
- the receipt's signed fields still canonicalize to the exact prepared payload;
- the existing receipt hash is empty or already correct;
- the returned algorithm is exactly `ES256`;
- the returned versioned `kid` exactly matches the request;
- the signature is canonical unpadded base64url;
- the decoded ES256 signature is exactly 64 raw bytes;
- both raw ES256 scalars `r` and `s` are integers in the P-256 group range `1..n-1`;
- the receipt does not already contain the same `kid`.

Finalization returns a copied receipt, sets the canonical receipt hash and appends one JWS-style signature object. It does not mutate the caller's receipt and does not add any `verified` state.

## Independent verification

After finalization, callers must run:

```python
verify_receipt(signed_receipt, trust_registry=public_registry)
```

Only the verifier may produce `RC_VERIFIED`. A workflow must treat any other result as a hard failure and must not publish the receipt as verified evidence.

## Test-only cryptography

The test suite uses an isolated ephemeral key solely to prove that:

- the external boundary receives only the digest request;
- prehashed ES256 output is encoded in the expected raw 64-byte form;
- zero and out-of-range P-256 scalars are rejected before attachment;
- the existing verifier independently accepts valid output;
- structurally valid but cryptographically unrelated output remains `NOT_VERIFIED`.

This test mechanism is not a production signer implementation and is not callable from production source.

## Azure integration slice

A later Azure adapter may implement the protocol by:

1. receiving `DigestSigningRequest`;
2. calling Azure Key Vault sign with `ES256` and the supplied digest;
3. returning only `ExternalSignatureResult` with the Azure-returned versioned `kid` and base64url value;
4. refusing any key-ID mismatch;
5. leaving final verification to the existing verifier.

No Azure adapter may introduce client-secret support or return a non-versioned key identifier.

## Gate

- Pure contract and red-team tests: may run in normal CI without Azure.
- Azure adapter and live sign smoke: HOLD until the protected environment and authorized tenant activation in #14 are complete.
- Production signing claim: HOLD until a live Key Vault signature passes independent verification and the public JWK is registered with rotation metadata.

Related: #11 and #15.