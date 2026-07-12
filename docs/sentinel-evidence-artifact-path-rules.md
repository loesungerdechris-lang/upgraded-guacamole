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
search path, glob, shell expression, Windows drive path, drive-relative path,
NTFS Alternate Data Stream name, DOS device name, or authorization to access
another location.

A path must:

- be a non-empty Unicode string;
- use `/` as its only separator;
- be relative;
- contain no leading or trailing `/`;
- contain no empty segment;
- contain no `.` or `..` segment;
- contain no colon;
- contain no backslash;
- contain no NUL, C0 control character, or DEL;
- contain no segment ending in a space or dot;
- contain no case-insensitive DOS device segment `CON`, `PRN`, `AUX`, `NUL`,
  `COM1` through `COM9`, or `LPT1` through `LPT9`, with or without an extension;
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
C:/raw/alpha.html
raw/C:alpha.html
raw/alpha.html:stream
raw/file.
raw/file 
raw/CON
raw/con.txt
raw/COM1.bin
raw/LPT9
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
dot segments, dot-dot segments, trailing separators, colons, backslashes, control
characters, trailing dot or space segments, or DOS device names that the semantic
verifier rejects.

Schema validity alone does not establish Level 3 `BYTES`. Filesystem identity,
root confinement, secure opening, file type, size, and SHA-256 checks remain
mandatory.

## 5. Descriptor-level uniqueness

Before local byte access, every non-null member path must be canonical. At every
verification level, no two members may contain the same non-null canonical
descriptor path. During Level 3 verification, every member must have a path.

String aliases such as `raw/a`, `raw/./a`, and `raw//a` are not three paths. The
last two are invalid and must not reach filesystem resolution.

Windows-normalized names are rejected on every platform before resolution. This
prevents a portable descriptor from naming `raw/file.` while a Windows API binds
`raw/file`, or from naming a DOS device instead of a regular file.

## 6. Filesystem-level uniqueness

Descriptor uniqueness alone is insufficient. After safe opening beneath the
bundle root, the verifier must also ensure that no two members refer to the same
local filesystem object.

The identity gate must detect at least:

- identical bound paths;
- aliases caused by case-insensitive filesystems;
- hard links that share one filesystem identity;
- platform-specific alternate spellings that resolve to one object.

A second member that binds an already-used path or object fails closed. The
verifier does not choose one member as authoritative and does not merge them.

A stable object identity must come from opened-handle metadata or an equivalent
platform file-identity API. If a stable identity is unavailable, the verifier must
not substitute the resolved path as object identity and must not return `BYTES`.
It fails closed with `SEA_NOT_VERIFIED`.

## 7. Symbolic links

The bundle root and every member path component are opened component-by-component
through directory handles with no-follow semantics. Intermediate directories and
the final member must never be symbolic links.

A lexical `is_symlink()` precheck is not sufficient and is not authoritative.
The no-follow open itself, followed by `fstat()` of the opened handle, establishes
the file type used for verification.

## 8. Hard links

Hard links are not forbidden merely because they exist elsewhere in the bundle.
They become invalid when two Evidence Artifact members bind the same filesystem
object under different paths. This prevents duplicate evidence counting and
ambiguous selective disclosure.

## 9. Root confinement

Every opened member must:

- be reached through a directory handle rooted at the supplied bundle root;
- be opened with no-follow semantics for every component;
- be a regular file according to `fstat()` on the opened handle;
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

## 11. Race boundary and secure-open capability

JSON input uses a nonblocking, no-follow file-descriptor open before `fstat()` and
bounded reading. This prevents a FIFO from blocking before its non-regular type is
known and prevents a final-component symlink swap from being followed.

Bundle members use component-by-component `openat`-style traversal relative to an
opened bundle-root directory handle. The bytes, size, regular-file type, and stable
object identity are all obtained from the same opened final handle.

A platform must provide the equivalent of `O_NOFOLLOW`, `O_DIRECTORY`,
`O_NONBLOCK`, and directory-relative opening for these file-based verification
paths. If that capability is absent, the prototype fails closed instead of falling
back to path prechecks. In-memory `BINDINGS` verification remains a separate path
and does not imply file or `BYTES` verification.

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
6. colon, drive-qualified path, drive-relative path, or ADS syntax;
7. backslash;
8. NUL or control character;
9. segment ending in a dot;
10. segment ending in a space;
11. case-insensitive DOS device name with and without an extension;
12. schema and semantic rejection parity;
13. duplicate descriptor path at `BINDINGS`;
14. duplicate descriptor path at `BYTES`;
15. final symbolic link at JSON input;
16. FIFO or other non-regular JSON input without blocking;
17. final symbolic link at bundle-member open;
18. intermediate symbolic link;
19. hard-link alias;
20. unavailable stable filesystem identity;
21. missing member path during `BYTES`;
22. root escape;
23. missing file;
24. byte-length mismatch;
25. SHA-256 mismatch.

## 13. Non-goals

This document does not authorize filesystem writes, archive acquisition,
networking, credentials, signing, trusted-time anchoring, release, production,
or publication. It does not freeze the complete Evidence Artifact Canonical Form;
that occurs only after PR #35 is independently confirmed on its exact final head.
