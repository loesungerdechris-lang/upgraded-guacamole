# SENTINEL Evidence Artifact Canonical Form

**Specification ID:** `sentinel.evidence.artifact.canonical-form.v1-working-draft`  
**Status:** WORKING DRAFT / HOLD / NON-NORMATIVE  
**Candidate profile:** `sentinel-canonical-json-v1`  
**Artifact profile:** `sentinel-e2e-evidence-v1`  
**Implementation reference:** PR #35 exact head `0d82bf0bb24e9252de7f9b7deb062b15dc55928a`  
**Activation authority:** none  
**Signing authority:** none  
**Release authority:** none  
**Publication authority:** none

## 1. Status and purpose

This document defines the candidate canonical representation and hash-preimage
rules for the SENTINEL Evidence Artifact v1 profile. Its purpose is to make
independent implementations produce the same descriptor hashes, roots, lifecycle
hash, Merkle proofs, and final `artifact_hash`, also called `H_core`.

This document is deliberately non-normative while PR #35 remains under exact-head
review. The words MUST, MUST NOT, SHOULD, and MAY describe the candidate v1 rules;
they become normative only after the promotion gate in section 22 is satisfied.

This document does not authorize archive access, evidence acquisition, filesystem
writes, signing, trusted-time anchoring, release, production operation, or
publication. Issue #30 remains the separate publication and release-receipt gate.
PR #36 remains reserved for the Independent Verification Kit, conformance vectors,
and verifier CLI contract. No PR is opened by this working draft.

## 2. Conformance layers

A conforming implementation distinguishes the following layers:

1. **Transport parsing** — bounded UTF-8 JSON input and duplicate-key rejection.
2. **Schema validation** — structural validation against the v1 JSON Schema.
3. **Canonical-domain validation** — allowed types, integer range, strings, keys,
   and serialization rules.
4. **Semantic validation** — sorting, uniqueness, provenance profiles, timestamps,
   lifecycle references, root recomputation, and HOLD-only boundaries.
5. **Optional local-byte validation** — complete bundle path, filesystem identity,
   byte length, and SHA-256 verification for Level 3 `BYTES`.

Passing a lower layer never implies that a higher layer has passed. In particular:

```text
schema-valid != canonical-valid != semantically valid != BYTES-verified
```

## 3. Input encoding and JSON parsing

The input artifact JSON MUST:

- be encoded as valid UTF-8;
- contain no UTF-8 byte-order mark;
- be bounded by the verifier's configured maximum input size;
- contain exactly one JSON value at the top level;
- use an object as the top-level value;
- contain no duplicate object keys at any depth.

Invalid UTF-8, a BOM, trailing non-whitespace data, malformed JSON, a non-object
root, or a duplicate key MUST fail closed before hashing.

A parser MUST preserve integer values losslessly. It MUST NOT parse a JSON number
through IEEE-754 binary floating point and then attempt to recover the original
integer. This requirement applies before safe-range validation.

## 4. Allowed canonical-domain types

The candidate v1 canonical domain contains only:

- `null`;
- booleans;
- integers;
- strings;
- arrays;
- objects with string keys.

Floating-point values are forbidden, including values written with a decimal
point or exponent notation. `NaN`, positive infinity, and negative infinity are
forbidden even in parsers that expose them as non-standard extensions.

Integers MUST be within the inclusive range:

```text
-(2^53 - 1) through +(2^53 - 1)
```

Individual schema fields may impose a narrower range.

## 5. Negative zero

JSON integer `-0` is interpreted as the integer value zero. Its canonical output
is the single character:

```text
0
```

The candidate v1 profile does not preserve the lexical distinction between `-0`
and `0`. Decimal or exponent forms such as `-0.0`, `0.0`, or `0e0` are floating
point and are rejected.

## 6. Strings and Unicode

Strings MUST be preserved exactly as parsed. No NFC, NFD, NFKC, NFKD, case folding,
locale transformation, whitespace folding, or line-ending normalization is
performed.

Only Unicode scalar values are permitted. Isolated UTF-16 surrogate code points
in the range `U+D800` through `U+DFFF` MUST be rejected before canonicalization.
A conforming implementation MUST NOT repair, replace, combine, or silently encode
an isolated surrogate.

Unicode noncharacters are permitted in candidate v1 unless a field-specific
schema rule prohibits them. This is an explicit choice so that implementations do
not apply undocumented platform-specific filtering.

Object keys are additionally restricted to ASCII strings in candidate v1. This
makes key ordering independent of Unicode normalization and locale behavior.

**Promotion blocker:** the Python reference implementation at the recorded PR #35
head must add explicit isolated-surrogate rejection and negative tests before this
document can become normative.

## 7. Canonical JSON serialization

The canonical JSON representation MUST satisfy all of the following:

- encoding is UTF-8;
- no byte-order mark;
- no insignificant whitespace;
- no indentation;
- no space after `,` or `:`;
- no trailing newline;
- object keys are sorted by ascending Unicode code-point value;
- arrays retain their validated semantic order;
- `null`, `true`, and `false` use lowercase JSON literals;
- integers use the shortest base-10 representation;
- positive integers have no `+` sign;
- integers have no leading zero except the value zero;
- negative zero serializes as `0`;
- `/` is not escaped as `\/`;
- quotation mark and reverse solidus are escaped as `\"` and `\\`;
- U+0008, U+0009, U+000A, U+000C, and U+000D use `\b`, `\t`, `\n`, `\f`, and
  `\r` respectively;
- other U+0000 through U+001F control characters use `\u00xx` with lowercase
  hexadecimal digits;
- U+2028 and U+2029 are emitted directly as UTF-8, not forcibly escaped;
- all other permitted Unicode scalar values are emitted directly as UTF-8.

The canonical byte sequence is the UTF-8 encoding of this JSON text.

## 8. Missing fields, `null`, and empty collections

A missing field and a field with value `null` are distinct. A conforming verifier
MUST NOT insert omitted optional fields, delete explicit `null` fields, or replace
an empty array with `null` before hashing.

Required fields MUST be present even when their schema permits `null`.

Empty arrays and objects serialize as `[]` and `{}`. Their presence remains part of
the hash preimage.

## 9. Hash identifier representation

All SHA-256 identifiers use this exact textual form:

```text
sha256:<64 lowercase hexadecimal digits>
```

Uppercase hexadecimal, omitted prefix, whitespace, base64, or shortened digests
are invalid.

When a hash identifier becomes input to the Merkle function, the `sha256:` prefix
is removed and the 64 hexadecimal digits are decoded to exactly 32 bytes.

## 10. Descriptor self-hash exclusions

Self-referential hash fields are excluded from their own preimages and only from
their own preimages:

| Structure | Excluded field | Hash result |
|---|---|---|
| member descriptor | `member_hash` | `member_hash` |
| conflict descriptor | `conflict_hash` | `conflict_hash` |
| lifecycle event | `event_hash` | `event_hash` |
| complete artifact | `artifact_hash` | `artifact_hash` / `H_core` |

The field remains structurally required in the completed artifact. A verifier
validates the complete object, removes exactly the named self-hash field from a
deep copy, canonicalizes the remaining object, and hashes the canonical bytes.
No other field may be excluded implicitly.

## 11. Descriptor hash formulas

Let `C(x)` be the canonical UTF-8 byte sequence for value `x`. Let `REMOVE(x, k)`
remove exactly key `k` from a copied object.

```text
member_hash = "sha256:" || HEXLOWER(
    SHA256(C(REMOVE(member, "member_hash")))
)

conflict_hash = "sha256:" || HEXLOWER(
    SHA256(C(REMOVE(conflict, "conflict_hash")))
)

event_hash = "sha256:" || HEXLOWER(
    SHA256(C(REMOVE(event, "event_hash")))
)
```

The exact payload-byte hash is calculated separately:

```text
member.sha256 = "sha256:" || HEXLOWER(SHA256(exact_payload_bytes))
```

The member descriptor binds this payload hash, byte length, path, media type,
source identifier, observation claim, provenance descriptor, and member identity.

## 12. Required semantic ordering

The candidate v1 profile requires deterministic semantic order before root
calculation:

- `members` sorted ascending by `member_id`, with unique `member_id` values;
- `conflicts` sorted ascending by `conflict_id`, with unique `conflict_id` values;
- governance `policies` sorted ascending by `policy_id`, with unique values;
- governance `registries` sorted ascending by `registry_id`, with unique values;
- each lifecycle `input_hashes`, `output_hashes`, and `policy_hashes` array sorted
  ascending and containing unique hash identifiers;
- lifecycle events ordered by consecutive `sequence` starting at zero.

A verifier MUST reject an incorrectly ordered array. It MUST NOT silently sort the
received artifact and then accept it.

## 13. Merkle function

Candidate v1 uses one ordered Merkle function for `evidence_root` and
`conflict_root`.

### 13.1 Empty list

```text
MERKLE([]) = sha256:0000000000000000000000000000000000000000000000000000000000000000
```

This is the explicit `ZERO_HASH`; it is not the SHA-256 hash of an empty string.
The schema requires at least one member, so `evidence_root` is non-empty in a
valid artifact. `conflict_root` may be `ZERO_HASH`.

### 13.2 Leaf

For each ordered hash identifier `h`:

```text
leaf(h) = SHA256(
    UTF8("SENTINEL-EVIDENCE-LEAF-v1") || 0x00 || DIGEST32(h)
)
```

### 13.3 Internal node

```text
node(left, right) = SHA256(
    UTF8("SENTINEL-EVIDENCE-NODE-v1") || 0x00 || left || right
)
```

### 13.4 Odd width

At each level, if the number of nodes is odd, the final node is duplicated as both
left and right input to the next-level node.

### 13.5 Single leaf

A one-element tree root is the domain-separated leaf hash, not the original
member or conflict descriptor hash.

## 14. Merkle domain-separation clarification

Candidate v1 domain-separates leaves from internal nodes. It does **not** use a
different cryptographic prefix for the Evidence tree and Conflict tree.

The two roots remain semantically separated by:

- different ordered input arrays;
- different root fields;
- different count fields;
- complete binding inside `artifact_hash` / `H_core`;
- proof-envelope context described in section 16.

No document or implementation may claim tree-role domain separation in the v1
hash preimage. Introducing tree-specific prefixes would define a new cryptographic
profile and would change all affected roots and conformance vectors.

## 15. Root calculations

For a validated artifact:

```text
evidence_root = MERKLE([member.member_hash in members order])

conflict_root = MERKLE([conflict.conflict_hash in conflicts order])

governance_root = "sha256:" || HEXLOWER(
    SHA256(C(governance_bindings))
)

lifecycle_root = lifecycle[-1].event_hash
```

The `roots.member_count` and `roots.conflict_count` values MUST exactly equal the
corresponding array lengths.

`governance_root` and `lifecycle_root` are not Merkle roots in candidate v1.
`governance_root` is a canonical object hash. `lifecycle_root` is the terminal
hash of the previous-hash-linked lifecycle chain.

## 16. Merkle inclusion-proof context

The core v1 proof algorithm consumes:

- descriptor hash;
- zero-based leaf index;
- total leaf count;
- ordered sibling steps from leaf level toward the root;
- expected root.

Each step contains:

```json
{
  "position": "left or right",
  "hash": "sha256:<64 lowercase hex>"
}
```

The verifier derives the expected sibling position from the current index and
width. A supplied position that disagrees MUST fail. The verifier reduces the
width as `(width + 1) // 2` after every step and succeeds only when the width is
one and the computed root equals the expected root.

For external interchange, the Independent Verification Kit SHOULD wrap the core
proof in this semantic context:

```json
{
  "profile": "sentinel-e2e-evidence-v1",
  "tree_role": "EVIDENCE",
  "root_field": "evidence_root",
  "leaf_index": 0,
  "leaf_count": 1,
  "descriptor_hash": "sha256:<64 lowercase hex>",
  "proof": []
}
```

For conflict proofs, `tree_role` is `CONFLICT` and `root_field` is
`conflict_root`.

`tree_role` and `root_field` are semantic anti-confusion bindings for the proof
envelope. They do not alter the current v1 Merkle hash preimage. A verifier MUST
confirm that the named root field exists in the supplied artifact and equals the
expected root used for proof verification.

## 17. Governance root

`governance_root` hashes the complete `governance_bindings` object without field
exclusions. It binds at least:

- ordered policy identifiers, versions, and hashes;
- ordered registry identifiers, versions, and hashes;
- operation-plan hash;
- source commit;
- parent-stack hash;
- CI workflow hash, run identifier, and result;
- environment descriptor hash when present;
- privacy-review hash when present;
- terms-review hash when present;
- threat-model hash;
- retention-decision hash when present.

A changed governance value requires a new `governance_root`, lifecycle seal, and
`artifact_hash`.

## 18. Lifecycle chain

The first lifecycle event MUST have:

```text
sequence = 0
previous_event_hash = ZERO_HASH
```

Every later event MUST have:

```text
sequence = previous.sequence + 1
previous_event_hash = previous.event_hash
```

Every referenced input, output, or policy hash MUST already be known to the
artifact verifier under the profile's known-hash rules. Hash-reference arrays MUST
be sorted and unique.

Lifecycle timestamps MUST be non-decreasing and MUST NOT occur after artifact
`created_at`.

The terminal event MUST use:

```text
event_type in {INTEGRITY_SEAL, BLOCKED}
decision in {HOLD, BLOCKED}
```

The lifecycle chain has no `VERIFIED`, `RELEASED`, or `PUBLISHED` terminal state in
this profile.

## 19. Timestamp canonical form and honesty

All profile timestamps MUST use RFC 3339 UTC with uppercase `Z`:

```text
YYYY-MM-DDTHH:MM:SSZ
YYYY-MM-DDTHH:MM:SS.fZ
```

Fractional seconds may contain one through six decimal digits. More than six are
rejected before comparison. Offsets other than `Z`, leap-second values unsupported
by the reference parser, invalid calendar values, spaces, and lowercase `z` are
rejected.

`temporal_binding.claimed_created_at` MUST equal artifact `created_at` exactly.
Candidate v1 requires:

```text
anchor_status = UNANCHORED_HOLD
anchor_hashes = []
temporal_anchor_verified = false
```

Canonicalization and integrity verification do not prove trusted wall-clock
existence.

## 20. Bundle paths and Level 3 `BYTES`

Member paths use the separate candidate path profile. A non-null path MUST be an
exact portable POSIX-relative string and MUST contain none of the following:

- leading or trailing `/`;
- empty segment or duplicate `/`;
- `.` segment;
- `..` segment;
- colon;
- backslash;
- NUL, C0 control character, or DEL.

The colon prohibition blocks Windows drive-qualified paths, drive-relative names,
and NTFS Alternate Data Streams. The verifier performs no path repair or silent
normalization.

`path: null` is permitted for descriptor-level `BINDINGS` when allowed by schema.
It is never sufficient for `BYTES`.

Level 3 `BYTES` requires every member to be path-bound and requires all of the
following for every path:

- bundle root exists, is a directory, and is not a symbolic link;
- no member path component is a symbolic link;
- resolved path remains beneath the resolved bundle root;
- object is a regular file;
- descriptor paths are unique;
- normalized resolved paths are unique;
- stable filesystem object identities are unique;
- byte length matches;
- SHA-256 of bytes read from the opened handle matches.

Stable object identity MUST come from opened-handle metadata or an equivalent
platform file-identity API. If stable identity is unavailable, the verifier MUST
fail closed and MUST NOT return `BYTES`. A resolved pathname is not an acceptable
substitute for object identity.

A platform without such a capability is not Level-3-capable for this profile.

## 21. Final artifact hash / `H_core`

After all member hashes, conflict hashes, roots, and lifecycle event hashes are
present, the final core hash is:

```text
artifact_hash = H_core = "sha256:" || HEXLOWER(
    SHA256(C(REMOVE(artifact, "artifact_hash")))
)
```

The preimage includes:

- schema and profile identifiers;
- artifact identifier and HOLD status;
- claimed creation time;
- subject bindings;
- all four roots and both counts;
- complete member descriptors including their `member_hash` values;
- complete governance bindings;
- complete conflict descriptors including their `conflict_hash` values;
- complete lifecycle events including their `event_hash` values;
- temporal HOLD binding;
- release HOLD binding;
- interpretation limits.

There is no circular dependency because only the artifact's own `artifact_hash`
field is excluded. All subordinate hashes are already fixed inputs.

The v1 release binding remains exactly:

```json
{
  "publication": false,
  "verified_envelope_hash": null,
  "release_receipt_hash": null
}
```

`H_core` authorizes nothing by itself.

## 22. Error behavior

Any parse, schema, canonical-domain, ordering, provenance, hash, root, lifecycle,
timestamp, path, filesystem identity, byte-length, or payload-hash failure MUST
produce a non-success result.

The prototype machine state is:

```text
status = SEA_NOT_VERIFIED
integrity_valid = false
level = NONE
release_authorized = false
temporal_anchor_verified = false
```

A failed requested `BYTES` verification MUST NOT be silently downgraded to a
successful `BINDINGS` result.

Successful artifact-only verification without a bundle is `BINDINGS`. Successful
complete local-byte verification is `BYTES`. Neither result proves source truth,
source independence, archive completeness, legal admissibility, rights clearance,
trusted time, human approval, release, or publication authority.

## 23. Cross-language conformance requirements

A conforming independent implementation MUST:

1. reject duplicate JSON keys;
2. parse integers losslessly;
3. reject floats and unsafe integers;
4. reject isolated Unicode surrogates;
5. preserve strings without Unicode normalization;
6. apply the exact escaping and UTF-8 rules in section 7;
7. distinguish missing fields from `null`;
8. enforce semantic ordering rather than silently repairing it;
9. compute all descriptor hashes and roots exactly;
10. reproduce `H_core` exactly;
11. verify even, odd, empty-conflict, and single-leaf Merkle cases;
12. bind proof index, count, position, tree role, and root-field context;
13. enforce lifecycle sequence, previous links, known references, and terminal HOLD;
14. keep Memento discovery identity and datetime `DECLARED`;
15. reject all non-portable bundle path forms, including colon syntax;
16. refuse `BYTES` without stable filesystem identity;
17. expose deterministic machine-readable failure classes or exit codes;
18. operate without network access for conformance execution.

Agreement with one reference implementation is insufficient. Implementations must
pass the same normative vectors once PR #36 is created.

## 24. Required conformance-vector families

The future Independent Verification Kit must include at least:

- minimal valid artifact and exact canonical bytes;
- full `H_core` derivation with every intermediate hash;
- empty conflict tree using `ZERO_HASH`;
- one-leaf, even-leaf, and odd-leaf Merkle trees;
- positive and negative inclusion proofs;
- wrong `tree_role` and wrong `root_field` proof contexts;
- duplicate JSON keys;
- integer limits and out-of-range integers;
- `-0` canonicalizing to `0`;
- decimal and exponent numbers rejected;
- isolated high and low surrogates rejected;
- composed and decomposed Unicode remaining distinct;
- `/`, U+2028, U+2029, quotes, reverse solidus, and control-character escaping;
- missing versus explicit `null` fields;
- over-precision and invalid timestamps;
- Memento provenance escalation attempts;
- unordered or duplicate semantic arrays;
- lifecycle previous-hash and unknown-reference failures;
- path traversal, duplicate separator, dot segments, backslash, controls, drive,
  drive-relative, and ADS paths;
- final and intermediate symlinks;
- hard-link aliases;
- stable filesystem identity unavailable;
- byte-length and payload-hash mismatch;
- attempted release, temporal anchor, or publication fields.

## 25. Promotion gate

This working draft may become normative only when all of the following are true:

1. Codex or another independent reviewer confirms the exact final PR #35 head with
   no unresolved actionable P1 or P2 finding.
2. All prior review threads are evaluated against that exact head; thread state is
   not used as a substitute for technical validation.
3. The Python implementation explicitly rejects isolated surrogates and passes
   dedicated tests.
4. Negative-zero, lossless-number, string-escape, Unicode, and path vectors exist.
5. Canonical bytes and all intermediate hashes are published as normative vectors
   in the separate Independent Verification Kit.
6. At least one independent implementation in another language reproduces the
   vectors without calling or embedding the Python implementation.
7. Schema-only and semantic-verifier behavior is documented and tested for parity
   where schema expression is possible.
8. Proof-envelope context rules are frozen.
9. The canonical-form document and implementation are reviewed together at exact
   commits.
10. No activation, signing, release, production, or publication authority is
    introduced by promotion.

Until then, this document remains a working draft and MUST NOT be cited as a final
standard.

## 26. Deliberate v1 non-claims

The canonical form proves deterministic representation and integrity bindings. It
does not prove:

- that a source statement is true;
- that a source is independent;
- that an archive is complete;
- that absence from an archive proves non-existence;
- that archive time equals publication time;
- that the claimed time is externally anchored;
- that content was lawfully acquired or may be published;
- that a human reviewer approved release;
- that a court must admit the artifact;
- that Issue #30 has been satisfied.

The correct state remains:

```text
WORKING DRAFT / HOLD
release_authorized = false
temporal_anchor_verified = false
publication = false
```
