# SENTINEL Wayback Release Verifier Implementation Checklist

**Status:** HOLD  
**Related specification:** `docs/wayback-release-receipt-gate.md`

The future receipt-bound publication verifier must not be implemented or activated until every item below has a reviewed owner and acceptance test.

## Required inputs

- VERIFIED predecessor manifest;
- proposed PUBLISHED manifest;
- externally produced `sentinel.receipt.v1` release receipt;
- public trust registry;
- optional local bundle root;
- approved policy identifier and version.

## Mandatory checks

- [ ] predecessor status is VERIFIED;
- [ ] predecessor passes release-aware internal validation;
- [ ] proposed status is PUBLISHED;
- [ ] proposed schema and manifest hash pass;
- [ ] immutable evidence fields match predecessor exactly;
- [ ] receipt type is `wayback_publication_release`;
- [ ] receipt release class is A;
- [ ] receipt policy ID and version are approved;
- [ ] required roles include legal, privacy, and SENTINEL release authority;
- [ ] minimum signature threshold is at least three;
- [ ] all receipt signatures pass the existing production verifier;
- [ ] receipt binds the VERIFIED predecessor hash;
- [ ] receipt binds deterministic artifact-set hash;
- [ ] receipt binds review packet, source commit, pipeline run, release scope, and destination;
- [ ] proposed manifest receipt hash matches the verified receipt hash;
- [ ] no circular final-manifest-hash dependency exists;
- [ ] optional local files still match artifact length and SHA-256;
- [ ] result is machine-readable and contains no secrets.

## Mandatory negative tests

- [ ] missing receipt;
- [ ] malformed or invalid receipt;
- [ ] revoked or expired signing key;
- [ ] missing role or threshold;
- [ ] role spoofing;
- [ ] wrong predecessor hash;
- [ ] changed target, snapshot, artifact, source, or limitation;
- [ ] changed release destination or scope;
- [ ] wrong receipt hash in manifest;
- [ ] circular binding attempt;
- [ ] private signing helper or key material introduced into verifier code.

## Governance gates

- [ ] separate pull request;
- [ ] independent code review;
- [ ] dedicated CI gate;
- [ ] CODEOWNERS coverage;
- [ ] threat-model update;
- [ ] policy/schema migration decision;
- [ ] explicit SENTINEL GO for merge;
- [ ] separate explicit GO for any real publication.

Until all required checks and governance gates pass, PUBLISHED remains rejected.
