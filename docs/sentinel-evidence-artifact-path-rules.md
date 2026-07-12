# SENTINEL Evidence Artifact Bundle Path Rules

**Specification ID:** `sentinel.evidence.artifact.path-rules.v1-draft`  
**Status:** DRAFT / HOLD  
**Applies to:** `sentinel.evidence.artifact.v1`  
**Activation authority:** none  
**Publication authority:** none

## 1. Purpose

This document defines the fail-closed path rules for Evidence Artifact members and
for Level 3 `BYTES` verification. It closes ambiguity between descriptor strings,
filesystem normalization, symbolic links, hard links, case handling, and multiple
names for one local object.

The verifier never repairs, normalizes, rewrites, case-folds, or silently accepts
an alternate path spelling. A non-canonical path is invalid evidence input.

## 2. Path model

A member path is a portable POSIX-relative identifier interpreted beneath one
explicitly supplied bundle root. It is not a URL, native operating-system path,
search path, glob, shell expression, or authorization to access another location.

A path must:

- be a non-empty Unicode string;
- use `/` as its only separator;
- be relative;
- contain no leading or trailing `/`;
- contain no empty segment;
- contain no `.` or `..` segment;
- contain no backslash;
- contain no NUL, C0 control character, or DEL;
- remain byte-for-byte unchanged by POSIX path parsing.

Examples accepted:

```text
raw/alpha.html
records/memento-001.json
review/conflict-0001.json
```

Examples rejected:

```text
/raw/alpha.html
raw/alpha.html/
raw//alpha.html
raw/./alpha.html
raw/../alpha.html
raw\alpha.html
```

## 3. No silent normalization

The following operation is prohibited:

```text
invalid descriptor path -> normalize -> accept normalized path
```

The required operation is:

```text
invalid or non-canonical descriptor path -> reject -> SEA_NOT_VERIFIED
```

The descriptor string is part of `member_hash` and therefore part of `H_core`.
Changing it after validation would change the evidence commitment.

## 4. Schema parity

The JSON Schema `safePath` definition and the semantic verifier must reject the
same lexical path classes. A schema-only consumer must not accept empty segments,
dot segments, dot-dot segments, trailing separators, backslashes, or control
characters that the semantic verifier rejects.

Schema validity alone does not establish Level 3 `BYTES`. Filesystem identity,
root confinement, symlink, file type, size, and SHA-256 checks remain mandatory.

## 5. Descriptor-level uniqueness

Before local byte access, every non-null member path must be canonical. During
Level 3 verification, every member must have a path and no two members may contain
the same canonical descriptor path.

String aliases such as `raw/a`, `raw/./a`, and `raw//a` are not three paths. The
last two are invalid and must not reach filesystem resolution.

## 6. Filesystem-level uniqueness

Descriptor uniqueness alone is insufficient. After safe resolution beneath the
bundle root, the verifier must also ensure that no two members refer to the same
local filesystem object.

The identity gate must detect at least:

- identical resolved paths;
- aliases caused by case-insensitive filesystems;
- hard links that share one filesystem identity;
- platform-specific alternate spellings that resolve to one object.

A second member that resolves to an already-bound path or object fails closed.
The verifier does not choose one member as authoritative and does not merge them.

A stable object identity must come from opened-handle metadata or an equivalent
platform file-identity API. If a stable identity is unavailable, the verifier must
not substitute the resolved path as object identity and must not return `BYTES`.
It fails closed with `SEA_NOT_VERIFIED`.

## 7. Symbolic links

The bundle root must not be a symbolic link. No member path component may be a
symbolic link, including intermediate directories and the final component.

A path that remains lexically inside the root but traverses a symbolic link is
invalid even when the symlink target also happens to be inside the root.

## 8. Hard links

Hard links are not forbidden merely because they exist elsewhere in the bundle.
They become invalid when two Evidence Artifact members bind the same filesystem
object under different paths. This prevents duplicate evidence counting and
ambiguous selective disclosure.

## 9. Root confinement

Every resolved member must:

- exist;
- remain beneath the resolved bundle root;
- be a regular file;
- be readable through the verifier's bounded local operation;
- expose stable filesystem object identity for `BYTES`;
- match the descriptor byte length;
- match the descriptor SHA-256 value.

Any failure returns `SEA_NOT_VERIFIED`. A partial bundle never receives `BYTES`.

## 10. Unicode and case

The verifier performs no Unicode NFC, NFD, NFKC, or NFKD transformation. The
original allowed string is committed exactly as supplied. Filesystem identity is
checked separately so that platform normalization or case behavior cannot cause
two members to bind one object unnoticed.

A future normalization policy would be a new profile and cannot redefine v1.

## 11. Race boundary

Path validation, symlink checks, resolution, file identity, size, and hashing are
performed in one local verifier operation. The file is hashed from the opened
handle whose identity and size are inspected.

This substantially narrows replacement races but does not claim protection
against a hostile privileged kernel or storage administrator. High-assurance
operation requires an immutable or read-only evidence store and an independently
reviewed execution environment.

## 12. Required negative tests

The v1 suite must cover at least:

1. leading slash;
2. trailing slash;
3. duplicate separator;
4. `.` segment;
5. `..` segment;
6. backslash;
7. NUL or control character;
8. schema and semantic rejection parity;
9. duplicate canonical descriptor path;
10. final symbolic link;
11. intermediate symbolic link;
12. hard-link alias;
13. unavailable stable filesystem identity;
14. missing member path during `BYTES`;
15. root escape;
16. missing file;
17. byte-length mismatch;
18. SHA-256 mismatch.

## 13. Non-goals

This document does not authorize filesystem writes, archive acquisition,
networking, credentials, signing, trusted-time anchoring, release, production,
or publication. It does not freeze the complete Evidence Artifact Canonical Form;
that occurs only after PR #35 is independently confirmed on its exact final head.
