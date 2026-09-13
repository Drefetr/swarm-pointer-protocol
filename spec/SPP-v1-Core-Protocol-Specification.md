# Swarm Pointer Protocol (SPP)
## Core Protocol Specification — Version 1.0

**Status: FROZEN.** This document defines assertion format `v = 1`.

The `v = 1` objective-validity profile is immutable. Any subsequent change that alters the set of protocol-valid assertions, assertion identity, signature input, proof-of-work calculation, protocol maxima, permitted assertion types, required or prohibited fields, or the mandatory interpretation of an existing field MUST use a new assertion version.

The normative machine-readable conformance suite is distributed alongside this document as `conformance/vectors/suite.json`. Release metadata SHOULD pin the SHA-256 of both this document and that suite.

If two conforming implementations disagree with a behaviour represented by a normative vector, at least one implementation is wrong. If the vectors and prose conflict on a behaviour the vector actually represents, the vector governs and the prose requires an erratum. Vectors do not decide behaviours they do not represent. A negative vector is normative only for the function named by its class.

This specification deliberately keeps application semantics outside the core protocol. The frozen profile concerns identity, authenticity, reference, computational cost, and distribution.

---

# 0. Requirements language

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in RFC 2119 and RFC 8174.

---

# 1. Purpose

SPP is a minimal protocol allowing independent actors to advertise and discover pointers to external information through distributed relays.

SPP does **not** transport the referenced information itself.

SPP distributes authenticated assertions that either advertise an external object within an opaque channel, or advertise a channel-description anchor. Referenced content remains external.

SPP is designed around four principles:

1. **Content remains external.**
2. **Channels are opaque identifiers.**
3. **Protocol actions carry deterministic computational cost proportional to their protocol burden.** Relays decide how expensive participation actually is.
4. **Protocol validity and relay acceptance are separate concepts.**

Principle 3 is a meter, not a claim that v1 parameters make spam economically impossible. One publication costs X; one hundred cost about 100X, before any relay multiplier.

---

# 2. Terminology

An **actor** is a deployment of an SPP identity. The protocol term is actor. “Agent” means only a program that acts as an actor.

## Actor

An actor is identified by a cryptographic public key.

In assertion format v1 the mandatory signing algorithm is Ed25519 (RFC 8032, PureEdDSA).

An actor identity consists only of that public key. No relationship to a human, company, name, email address, or other external identity is implied.

## Object

An object is arbitrary information existing outside SPP.

For the prefix `sha256:`, the object is identified by SHA-256 of its **raw octet stream**:

```text
sha256:X
X = SHA-256(the object's raw octet stream)
```

A BitTorrent infohash, IPFS CID, URL, or other locator-embedded digest does **not** substitute for that identity. Those values, if present, are merely locators.

SPP does not define or inspect the object's contents.

## Locator

A locator is an opaque UTF-8 string describing a possible retrieval method.

Examples include `https://...`, `magnet:?...`, and `ipfs://...`.

SPP assigns no semantics to locator schemes. A locator is only a retrieval hint. The object's hash, not its locator, defines its identity.

Locators are untrusted. See §24.

## Channel

A channel is an opaque identifier used to group assertions.

```text
channel := any syntactically valid sha256:<64 lowercase hex> identifier
```

SPP assigns no topic, ownership, moderation model, or semantic meaning to a channel.

A channel ID is valid even if nobody has ever published, stored, or seen a channel-description assertion for it.

The actor that publishes a channel-description assertion does **not** own the channel. Any actor MAY subsequently publish pointers into any well-formed channel ID, subject to relay policy.

See §10.

## Relay

A relay accepts, indexes, and advertises SPP assertions.

A relay:

- does not own channels;
- does not own referenced objects;
- is not required to retrieve referenced objects;
- is not required to accept every valid assertion;
- may cease carrying any assertion or channel at any time.

---

# 3. Cryptographic primitives

Assertion format v1 uses:

```text
Hash:       SHA-256
Signature:  SPP-Ed25519-1 (RFC 8032 PureEdDSA plus §8A)
Encoding:   UTF-8 I-JSON, then JCS (RFC 8785)
Canonical:  JSON Canonicalization Scheme (JCS / RFC 8785)
```

Future assertion versions MAY define additional suites. A v1 implementation MUST NOT treat an unknown suite or unknown assertion version as v1-valid.

---

# 4. Identifier grammar

All of the following are protocol-valid only when they match exactly. Uppercase hex, omitted prefixes, extra whitespace, and wrong lengths are invalid.

```text
HEXDIGIT    = %x30-39 / %x61-66          ; 0-9 a-f
HEX64       = 64HEXDIGIT
HEX128      = 128HEXDIGIT

sha256-id   = "sha256:" HEX64
actor-id    = "ed25519:" HEX64
sig         = HEX128                     ; 64-byte Ed25519 signature, no prefix

nonce       = "0" / ( %x31-39 *19DIGIT )
              ; and the integer value MUST be <= 18446744073709551615
```

`actor-id` encodes the 32-byte Ed25519 public key.

`sig` encodes the 64-byte signature.

`sha256-id` is the only legal form for:

- assertion `id`;
- pointer `channel`;
- object `hash`;
- parent references;
- channel-description `descriptor.hash`.

There is no double prefix. A channel ID is a `sha256-id`, not `sha256:` plus another `sha256-id`.

---

# 5. Protocol maxima

These are semantic representation bounds for assertion format `v = 1`. An assertion that exceeds any of them is **not** protocol-valid, regardless of work or signature.

They are part of the v1 validation profile. Changing any of these numbers changes the set of protocol-valid assertions and therefore requires a new assertion version.

```text
canonical_body_bytes      <= 1048576     ; 1 MiB of JCS(U)
locator count             <= 256
locator_bytes             <= 8192        ; each locator; see below
parent count              <= 1024
```

`locator_bytes` is the UTF-8 byte length of the **decoded JSON string value**, without JSON quotation marks or escape sequences. `"\\u20ac"` is three bytes (U+20AC), not the length of the escape.

These bounds are on the canonical semantic object, not on the received HTTP body. Insignificant whitespace and escapes can make the raw representation larger than `JCS(U)`. Nested `ext` values can also be arbitrarily deep subject only to the canonical-body byte maximum above. v1 defines no separate protocol nesting-depth maximum.

Raw request-body limits, maximum JSON nesting depth, parser memory limits, recursion limits, and decompression limits are **local transport/resource policy**. They MUST NOT be used to declare an assertion protocol-invalid. An implementation that declines to determine validity because of a local resource limit has made a local rejection, not a protocol-invalidity determination. See §22.

Relays MAY advertise stricter local limits. A relay MUST NOT claim that an assertion exceeding the v1 maxima is protocol-valid.

---

# 6. Assertion identity

Every SPP assertion contains an unsigned body `U` and a signed envelope (see §7).

Before ordinary object reconstruction, the received bytes MUST be:

```text
valid UTF-8
no leading UTF-8 BOM (EF BB BF)
a single JSON value that is an object
I-JSON / RFC 8785-acceptable input, subject to the SPP rules below
```

In particular the input MUST be rejected, and MUST NOT be silently repaired, if it contains:

```text
duplicate member names at any nesting level
lone UTF-16 surrogates
any Unicode noncharacter
JSON numbers outside the RFC 8785 / IEEE-754 binary64 domain
  (non-finite values)
any JSON number token whose parsed binary64 value is negative zero
```

For v1, **Unicode noncharacter** means the complete Unicode noncharacter set: U+FDD0 through U+FDEF, plus U+FFFE and U+FFFF in every Unicode plane (U+FFFE/U+FFFF, U+1FFFE/U+1FFFF, …, U+10FFFE/U+10FFFF).

Negative-zero rejection is an input-token rule. It includes lexical forms such as `-0`, `-0.0`, and `-0e0`, and any other JSON number token that parses to IEEE-754 negative zero.

All JSON number tokens are converted to their RFC 8785 / ECMAScript IEEE-754 binary64 value **before** SPP numeric predicates are evaluated. Constraints on `v` and `created` apply to that resulting value, not to an arbitrary-precision reading of the source digits.

SPP does **not** add a global “safe integer only” restriction. Integers outside 2^53−1 MAY appear inside `ext` and are canonicalized by JCS from their binary64 value. Core field `created` has its own range (§18). `nonce` is a string.

A conventional JSON parser that collapses duplicate keys to the first or last value MUST NOT be used as the sole front-end to JCS. Duplicate names are invalid, not last-wins.

RFC 8785 object-key order is by UTF-16 code units, not UTF-8 code units. Implementations that sort keys as UTF-8 bytes will diverge on supplementary-plane names. The normative conformance suite contains a discriminating supplementary-plane key-order case.

**Implementation note (non-normative):** RFC 8785 number serialization uses ECMAScript binary64 number formatting. An integral binary64 value outside the safe-integer range MUST NOT be serialized merely by converting its exact mathematical value to an arbitrary-precision integer and printing all decimal digits; that can differ from the shortest ECMAScript representation required by JCS. A tested ECMAScript-compatible binary64 serializer is strongly recommended.

```text
J = JCS(U)                  ; RFC 8785, UTF-8 bytes
D = SHA-256(J)              ; 32 raw bytes
id = "sha256:" || hex(D)    ; 64 lowercase hex digits
H  = integer(D)             ; big-endian 256-bit unsigned
```

`U` is reconstructed as follows:

```text
U := every top-level member of the received JSON object
     except the members named "id" and "sig"
```

Nested objects are not stripped. A nested member named `id` remains in `U`. After reconstruction, `U` MUST match the structural schema in §7A.

JSON member names have no host-language magic semantics. Names such as `__proto__`, `constructor`, `prototype`, `toString`, or any other implementation-sensitive property name MUST be preserved as ordinary JSON members during reconstruction. At top level they are then accepted or rejected solely by §7A. Implementations MUST NOT reconstruct `U` through object-copy behaviour that silently drops, inherits, rewrites, or invokes setters for received member names.

A receiver MUST recompute the assertion ID from `U`. The transmitted `id` MUST equal the recomputed ID; otherwise the assertion is invalid.

Implementations MUST use exact integer arithmetic for `H` and for all proof-of-work calculations. IEEE 754 binary64 MUST NOT be used for `H`, `MAX`, `target`, or `Wrequired`.

---

# 7. Signed envelope

A v1 assertion is a single JSON object. The unsigned members sit as siblings of `id` and `sig`:

```json
{
  "v": 1,
  "type": "pointer",
  "actor": "ed25519:<64hex>",
  "channel": "sha256:<64hex>",
  "created": 1789184927,
  "ref": {
    "hash": "sha256:<64hex>",
    "locators": ["https://..."]
  },
  "nonce": "81681",
  "id": "sha256:<64hex>",
  "sig": "<128hex>"
}
```

There is no wrapper object. `id` and `sig` are excluded from `U` and from JCS.

A relay MUST NOT alter an accepted assertion's signed members. Semantic equivalence is equal recomputed `id`. Relays SHOULD store and retransmit JCS form. Bit-identical HTTP bodies are not required.

---

# 7A. Structural schema

v1 has a closed core schema. Authenticated application metadata lives only under the optional top-level member `ext`.

Reserved top-level names:

```text
v, type, actor, created, nonce,
channel, ref, parents, descriptor,
id, sig, ext
```

Any other top-level name is invalid. Reserved names used on the wrong assertion type are invalid.

## Common signed members

Required on every v1 assertion:

```text
v        numeric value mathematically equal to 1 (§18)
type     "channel" or "pointer"
actor    actor-id
created  integral numeric value, §18
nonce    string, §17
```

## Pointer

```text
Required:   channel, ref
Optional:   parents, ext
Prohibited: descriptor
```

`channel` MUST be a `sha256-id`.

`ref` MUST be a reference object.

`parents`, if present, MUST be a JSON array of zero or more `sha256-id` strings. A string, object, or `null` is invalid.

## Channel

```text
Required:   (common members only)
Optional:   descriptor, ext
Prohibited: channel, parents, ref
```

`descriptor`, if present, MUST be a reference object.

## Reference object

Exactly two members, no others:

```text
hash       REQUIRED sha256-id
locators   REQUIRED array of strings
```

Additional members such as `"foo": 1` are invalid. Nested `ext` is not permitted inside a reference object.

## ext

`ext`, if present, MUST be a JSON object. Member names SHOULD be reverse-DNS. Values MUST be acceptable to RFC 8785 JCS. SPP does not additionally restrict `ext` numbers to the IEEE-754 safe-integer range.

`ext` is included in `U` and therefore in the digest, signature, and body-length meter.

`ext` has **no v1 protocol semantics**. A later document that still uses `v = 1` MUST NOT assign consensus meaning to any `ext` key. Application profiles MAY interpret their own keys. Relays MUST hash `ext` and MUST NOT strip it.

Unknown authenticated metadata MUST use `ext`. It MUST NOT invent new top-level field names.

---

# 8. Signatures

Let `D` be the 32-byte assertion digest from §6.

The actor signs a **domain-separated** message using RFC 8032 Pure Ed25519 (not Ed25519ph, not HashEdDSA):

```text
M = ASCII("SPP/1/assertion") || 0x00 || D
sig = Ed25519.Sign(actor_private_key, M)
```

The ASCII prefix is 16 bytes including the NUL:

```text
53 50 50 2f 31 2f 61 73 73 65 72 74 69 6f 6e 00
S  P  P  /  1  /  a  s  s  e  r  t  i  o  n  \0
```

Verification uses the public key encoded in `actor` and the SPP-Ed25519-1 predicate in §8A. If `actor` is malformed, or the predicate rejects, the assertion is invalid.

An SPP actor key MUST NOT be used to sign an arbitrary 32-byte challenge. That is a signing oracle for `D`.

If an external authentication profile is defined, it MUST use a different prefix:

```text
ASCII("SPP/1/auth") || 0x00 || ...
```

The remainder of that profile is outside this document. The prefix is reserved so that v1 assertion signatures and external authentication cannot collide.

---

# 8A. SPP-Ed25519-1 verification profile

“RFC 8032 Pure Ed25519” is not by itself a consensus-exact predicate. Libraries that nominally implement RFC 8032 have differed on non-canonical encodings and small-order points. SPP validity is objective, so v1 freezes one profile.

Let:

```text
p = 2^255 - 19
L = 2^252 + 27742317777372353535851937790883648493
B = edwards25519 base point
A = 32-byte public key from actor
R || S = 32 + 32 bytes of sig
M = SPP/1/assertion || 0x00 || D
```

Rejecting only “`[8]P` is the identity” is not enough. An Edwards25519 point may have both a non-zero prime-order component and a non-zero torsion component. Such a mixed-order point is not itself small-order, so `[8]P ≠ identity`, but multiplication by 8 deletes the torsion. Therefore

```text
[S]B = R + [k]A
```

and

```text
[8][S]B = [8]R + [8][k]A
```

are **not** equivalent on that set. RFC 8032 §5.1.7 specifies the cofactored equation; §8.8 warns that the exact accepted set can differ.

SPP-Ed25519-1 therefore requires prime-order subgroup membership for both `A` and `R`, followed by one exact verification equation.

A verifier MUST:

1. Reject unless `A` and `R` are each exactly 32 bytes and `S` is exactly 32 bytes (already implied by §4).
2. Interpret `S` as a little-endian integer. Reject if `S >= L`.
3. Decode `A` as in RFC 8032 §5.1.3. Reject if decoding fails.
4. Decode `R` as in RFC 8032 §5.1.3. Reject if decoding fails.
5. Reject unless re-encoding `A` with RFC 8032 §5.1.2 yields the original 32 bytes (canonical `A`).
6. Reject unless re-encoding `R` yields the original 32 bytes (canonical `R`).
7. Reject if `A` is the identity. Reject unless `[L]A` is the identity (prime-order subgroup).
8. Reject if `R` is the identity. Reject unless `[L]R` is the identity (prime-order subgroup).
9. Let `k0` be SHA-512(`R_bytes || A_bytes || M`) interpreted as a little-endian integer (RFC 8032). Let `k = k0 mod L`.
10. Accept if and only if `[S]B = R + [k]A` on edwards25519.

Once `A` and `R` are in the order-`L` subgroup, `k mod L` is unambiguous, and multiplying the verification equation by 8 cannot change validity because 8 is invertible modulo prime `L`. Implementations MAY use a cofactored evaluation that is algebraically equivalent on this restricted set. They MUST NOT accept mixed-order `A` or `R`.

Honest RFC 8032 signatures remain valid when they satisfy this profile. The normative conformance suite includes discriminating cases for `S >= L`, identity points, non-canonical encodings, and mixed-order `A` and `R` values that a weaker cofactored verifier could otherwise accept.

---

# 9. Reference object

External information is represented as:

```json
{
  "hash": "sha256:<64hex>",
  "locators": [
    "magnet:?...",
    "https://...",
    "ipfs://..."
  ]
}
```

A reference object contains **exactly** those two members. See §7A.

`hash` identifies the object as defined in §2.

`locators` is a JSON array of strings. It MAY be empty. Empty means the object is identifiable but no retrieval hint is offered. Each element MUST be a JSON string.

Duplicate locators are permitted and each counts toward work and maxima.

Unicode variants of the same visual URL are distinct locators. SPP does not normalize.

---

# 10. Channels

A channel ID is any syntactically valid `sha256-id`.

The protocol does **not** say that a channel-description assertion creates a channel.

Consequences, with no special cases:

```text
advertised channel     description assertion is known
unlisted / capability  only the hash is shared privately
orphaned               a former description is no longer carried
unseen description     a description assertion for that same ID arrives later
```

These are the same kind of channel.

A `type=channel` assertion describes the channel whose ID **is that assertion's own ID**. “A description discovered later” is possible only when the channel ID was already the ID of a description assertion that had not yet been seen. An independently chosen random capability ID cannot later receive a matching `type=channel` assertion short of a SHA-256 preimage. Relays and applications MAY still advertise or publish pointers in that channel; they simply cannot attach the self-ID description mechanism after the fact.

Construction convention, not a validity rule:

> If an actor wants to mint an advertised channel, it MAY publish a `type=channel` assertion and then use that assertion's `id` as the channel ID.

Possession of a channel-description assertion MUST NOT be required for a pointer to be protocol-valid. A relay MAY nevertheless require, prefer, or reject channels according to local admission policy.

A relay address MUST NOT form part of channel identity.

A channel intended as a capability SHOULD be a `sha256-id` whose 256 bits are cryptographically random high-entropy material. Hashing a human channel name or passphrase into syntactically valid `sha256:` form does not create a strong capability.

A capability / unlisted channel provides discoverability-by-possession only. It does not provide confidentiality, access control, authenticated membership, or write authorization. A relay operator learns any channel ID submitted to it. Plaintext HTTP exposes the ID in the request path, so HTTPS is particularly important when secrecy of the identifier matters.

---

# 11. Channel-description assertion

`type` is `channel`. This assertion announces or describes a channel ID equal to its own assertion ID. It does not create the namespace.

Unsigned members of `U`:

```json
{
  "v": 1,
  "type": "channel",
  "actor": "ed25519:<64hex>",
  "created": 1789183927,
  "descriptor": {
    "hash": "sha256:<64hex>",
    "locators": ["https://..."]
  },
  "nonce": "1897339"
}
```

`descriptor` is OPTIONAL. If present, it is a reference object (§9) pointing at external information that describes the channel. SPP does not interpret that information.

If `descriptor` is unused it MUST be omitted. `null` is invalid. `{}` is invalid. An empty `locators` array is allowed if `descriptor` is present; `hash` remains required.

A `channel` assertion MUST NOT contain `channel`, `parents`, or `ref`. `ext` is the only permitted extra top-level member.

---

# 12. Pointer assertion

An actor advertises an object within a channel using a `pointer` assertion.

Unsigned members of `U`:

```json
{
  "v": 1,
  "type": "pointer",
  "actor": "ed25519:<64hex>",
  "channel": "sha256:<64hex>",
  "created": 1789184927,
  "ref": {
    "hash": "sha256:<64hex>",
    "locators": [
      "magnet:?...",
      "https://..."
    ]
  },
  "parents": [
    "sha256:<64hex>"
  ],
  "nonce": "81681"
}
```

`ref` is REQUIRED and MUST be a reference object (§9, §7A).

`channel` is REQUIRED and MUST be a `sha256-id`. It need not name any known assertion.

`parents` is OPTIONAL. If present it MUST be a JSON array of zero or more `sha256-id` strings. If unused it SHOULD be omitted. An empty array is allowed and is a different `U` from omission (see §14).

A `pointer` assertion MUST NOT contain `descriptor`.

Parent references have no protocol-defined meaning. They MAY name pointers, channel-description assertions, unknown IDs, IDs in other channels, or form cycles.

Relays MUST NOT require referenced parents to be known.

Clients that interpret parents MUST treat them as hints, MUST cap recursion, and MUST NOT assume same-channel.

---

# 13. Single-channel rule

Each pointer belongs to exactly one channel.

SPP does not provide a `channels[]` field.

To advertise the same object in ten channels, an actor publishes ten independently signed assertions. Fan-out consumes proportionately more work and relay resources.

---

# 14. Optional members and identity

Omitted, `null`, and empty structured values are not interchangeable.

```text
parents omitted     ≠   "parents": []
descriptor omitted  ≠   "descriptor": null
```

`null` is invalid for `descriptor`, `ref`, `parents`, `locators`, and `hash`.

Each distinct `U` has a distinct ID. Implementations MUST JCS the object they actually received (after removing only `id` and `sig`), not a schema-normalized rewrite.

---

# 15. Proof of work

Every v1 assertion MUST demonstrate work by varying `nonce` until the digest meets a target.

Let:

```text
MAX        = 2^256 - 1
units      = (see §16)
Wrequired  = units × 65536
target     = floor(MAX / Wrequired)
H          = integer value of D, big-endian
```

The assertion is protocol-valid only when:

```text
H <= target
```

using exact unsigned 256-bit / big-integer arithmetic.

Validators that only need an accept/reject decision MUST NOT be required to compute a demonstrated-work score. The consensus test is the comparison above.

`Wdemonstrated` is informational only:

```text
Wdemonstrated = floor(MAX / (H + 1))
```

It MUST NOT be used as the validity test. In particular, `H = target` is **accepted** by `H <= target` and may fail `Wdemonstrated >= Wrequired`. v1 deliberately defines validity by the target comparison; the inverse score is informational only.

Expected SHA-256 attempts for a random digest are approximately `Wrequired`. The constants `65536` and `channel_description_cost = 16` are part of the v1 profile. Changing them requires a new assertion version.

---

# 16. Work units

```text
units =
    1
  + ceil(canonical_body_bytes / 1024)
  + locator_count
  + parent_count
  + channel_description_cost
```

Definitions, bound to JSON paths:

```text
canonical_body_bytes
    UTF-8 byte length of JCS(U), including the candidate nonce
    and any ext member.

locator_count
    type = pointer:  number of elements in U.ref.locators
    type = channel:  number of elements in U.descriptor.locators
                     if descriptor is present; otherwise 0
    Duplicates count. An empty array counts as 0.

parent_count
    type = pointer:  number of elements in U.parents if present;
                     otherwise 0
    type = channel:  0

channel_description_cost
    16 if type = "channel"
     0 if type = "pointer"
```

`channel_description_cost` meters a publicly discoverable channel-description / advertisement assertion. It does not price “creating a channel.” Selecting a 256-bit identifier and publishing a pointer is enough to use a channel. The extra 16 units exist to make mass advertisement of described channels more expensive than ordinary pointers.

One work unit is 65536 expected SHA-256 attempts:

```text
Wrequired = units × 65536
```

`ext` is part of `U` and therefore part of `canonical_body_bytes`. Length meters it. Unknown top-level names are invalid, not metered extensions.

`nonce` is variable-length decimal text. If the candidate nonce changes the JCS length across a 1024-byte boundary, `units` and `target` change. Cost MUST be recomputed from the candidate assertion's actual canonical `U`. Miners MUST NOT cache `Wrequired` across nonce widths.

The normative conformance suite includes a 1024 / 1025-byte pair where `units` steps from 2 to 3.

---

# 17. Nonce

`nonce` is a JSON string, not a JSON number.

```text
"nonce": "918271"
```

Grammar: `"0"` or `[1-9][0-9]{0,19}`, and the integer value MUST be less than or equal to 2^64 − 1 (`18446744073709551615`).

Leading zeros are invalid except for the value `"0"`. A 20-digit string larger than 2^64 − 1 is invalid.

---

# 18. created and other integral core numbers

JSON has only a `number` primitive. After RFC 8785-compatible parse, SPP evaluates v1 numeric predicates against the resulting IEEE-754 binary64 value.

Version classification is performed according to §19 before the v1 predicates below are applied. A numeric `v` whose parsed binary64 value is not exactly 1, including a non-integral value such as `1.5`, is classified as an unsupported version and is not evaluated under the v1 structural schema. Once `v` has been classified as exactly 1, `created` MUST have a finite integral binary64 value in its stated range. Lexically different tokens that parse to the same permitted binary64 value (`1`, `1.0`, `1e0`, `1.0000000000000001` for `v`; likewise for integral `created` values) are equivalent. A token that parses to a non-integer binary64 value for `created` (for example `1000.1`) does not satisfy the v1 predicate.

Negative-zero tokens are rejected earlier at JSON-input (§6).

```text
v       parsed binary64 value MUST be exactly 1 (§19)
created parsed binary64 value MUST be an integer
        satisfying 0 <= created <= 9007199254740991
created is seconds since 1970-01-01T00:00:00Z (Unix time, UTC)
```

`"created":1e20` is invalid because the binary64 value is outside the stated range.

`created` is an actor-asserted timestamp. Receivers MUST NOT treat it as evidence of publication time.

v1 imposes **no** protocol-validity freshness window. Clock synchronisation is not part of objective validity.

PoW stockpiling is therefore allowed. An actor may precompute work for the exact assertion it will later submit. v1 does not provide proof-of-recent-work. If freshness is required later, it needs a separate construction.

Relays MAY reject assertions by `created` as local policy (for example, too far in the future, or older than a retention window).

---

# 19. Version, type, and extensions

The number carried in top-level member `v` is the assertion format version. The frozen profile defined by this document is `v = 1`.

Version classification occurs after §6 JSON-input acceptance and before applying the v1 structural schema:

```text
top-level v missing
    invalid

top-level v present but not a JSON number
    invalid

parsed binary64 value of v exactly 1
    process under the complete v1 profile in this document

any other JSON number accepted by §6
    unsupported version — neither v1-valid nor v1-invalid
```

An implementation processing an unsupported version cannot apply v1 schema, cost, identity, or signature rules to decide that version's validity.

Within `v = 1`:

```text
type not in {"channel", "pointer"}
    invalid. Those two types are the complete v1 set.
    Adding a type requires a new assertion version.

known type, member ext
    hash it as part of U. No v1 protocol semantics.

known type, any other unknown top-level name
    invalid.
```

A later specification MUST NOT retrofit consensus semantics onto v1 `ext` keys or onto names that are unknown/prohibited by this document.

A v1 relay MUST NOT declare an unsupported assertion protocol-valid. It MAY ignore it, reject it locally, or store its bytes opaquely without a validity claim. A `v = 1` assertion with an unknown `type` is invalid, not unsupported.

The `v = 1` profile is permanently frozen. Any later change that alters objective validity MUST use a new assertion version. Prose errata MAY clarify an already-defined rule but MUST NOT change the accepted byte-string set.

---

# 20. Protocol validity

A received JSON object is **v1 protocol-valid** if and only if all of the following hold:

1. The input satisfies the UTF-8 / I-JSON / no-duplicate-name rules in §6.
2. The parsed binary64 value of `v` is exactly 1, and `type` is `channel` or `pointer`.
3. After removing only `id` and `sig`, `U` matches the structural schema in §7A.
4. Identifier fields match §4.
5. `nonce` and `created` match §17 and §18.
6. `JCS(U)` is at most 1 MiB; locator and parent maxima hold (§5).
7. Recomputed `id` equals the transmitted `id`.
8. `H <= target` for units computed from that `U` (§15, §16).
9. `sig` verifies under SPP-Ed25519-1 over `SPP/1/assertion\0 || D` using `actor` (§8, §8A).

Anything else is either invalid or unsupported (§19).

The v1 validity predicate is defined independently of implementation resource limits. A verifier that claims to have determined protocol validity MUST produce a defined classification rather than treating host recursion depth, parser stack limits, or similar local resource ceilings as validity rules. An implementation MAY instead stop early with an explicitly local/resource outcome; that outcome is not `invalid`.

A relay MUST complete every check in this list before describing an assertion as protocol-valid or accepting and indexing it as a valid SPP assertion. A relay MAY reject an assertion without completing these checks. Local rejection without complete validation makes no statement about protocol validity.

Diagnostic stage names, reason strings, CLI exit codes, and other implementation-facing explanations are not protocol fields and are non-normative unless this document explicitly says otherwise.

---

# 21. Relay-local work policy

A relay MAY require more work than the protocol minimum.

```text
relay multiplier = 4
requires H <= floor(MAX / (Wrequired × 4))
```

A relay MAY change this multiplier. A relay MAY reject assertions above or below any locally selected cost threshold, or for any other local reason listed in §22.

An assertion rejected by one relay remains protocol-valid and MAY be accepted by another.

`policy` in the discovery manifest is informational. It is not a promise that any particular assertion will be accepted.

---

# 22. Relay admission

The invariant is:

> A relay MUST NOT label an assertion protocol-valid unless it has performed the §20 checks. It is not required to perform those checks before rejecting.

A relay MAY reject immediately because, among other reasons:

```text
the HTTP request exceeds a raw input limit
the source is rate-limited
the actor is locally blocked
it does not carry the requested channel
it has no remaining storage
the request violates transport policy
JSON nesting or parser memory exceeds a local limit
```

Those rejections are not protocol-invalidity claims.

When a relay does accept and index an assertion as a valid SPP assertion, it MUST have:

```text
1. Parsed the assertion as UTF-8 I-JSON with no duplicate names.
2. Classified v and type (§19).
3. Reconstructed U and enforced §7A.
4. Enforced identifier grammar and semantic maxima.
5. Recomputed id.
6. Validated proof-of-work (§15).
7. Validated SPP-Ed25519-1 (§8A).
8. Applied any remaining local policy.
9. Indexed and advertised the assertion without altering signed members.
```

A relay MAY reject a valid assertion for any reason, including:

- excessive cost or insufficient local work;
- record size within protocol maxima but above local limits;
- actor identity, channel identity, object hash, locator, or locator scheme;
- local legal requirements or abuse policy;
- storage constraints;
- operator preference;
- `created` outside a local window.

No relay is obligated to carry any channel or assertion.

---

# 23. Content retrieval

A relay MUST NOT require successful retrieval of referenced content for protocol validation.

Relays MAY retrieve or inspect referenced material as local policy. SPP itself never requires this. An SPP relay need never possess the objects it advertises.

### Client requirements

A locator is usable for a given object only if the client's locator handler ultimately produces **one finite octet stream**. How an application turns HTTP transfer/content decoding, a multi-file torrent, or another structured retrieval into that stream is outside SPP. SPP assigns no scheme semantics.

The applicable reference is `ref` on a pointer assertion and `descriptor` on a channel assertion. A client that fetches MUST accept the payload only when:

```text
SHA-256(the octet stream produced by the locator handler)
    = the 32 bytes in the applicable reference.hash
```

Otherwise it MUST discard the payload.

If the client does not fetch, this duty does not apply. Hash identity is meaningless without this check on the fetch path.

A client MUST perform all §20 protocol-validity checks before treating a received object as a valid SPP v1 assertion. In particular, a client MUST NOT trust a relay to have performed parsing, schema, identity, proof-of-work, or signature validation. An assertion can have a valid `id`, valid PoW, and a valid signature and still be protocol-invalid (for example, a signed pointer that contains `descriptor`).

---

# 24. Locator hostility

A signature proves only:

> Key K published this locator.

It says nothing about whether the locator is safe to dereference.

An SPP client MUST NOT assume that a locator in a valid signed assertion is safe to fetch.

Clients that aggregate locators from multiple assertions MUST treat the union as hostile input. Preferring locators from a chosen actor or trust set is a client policy, not a protocol rule.

Automated clients MUST account for at least:

```text
loopback and link-local targets     https://127.0.0.1/ ...
cloud metadata addresses            https://169.254.169.254/ ...
local files                         file:///...
unexpected URI schemes
redirect chains
unbounded response size
```

This list is not exhaustive. SPP does not specify a fetch sandbox. That duty sits with the client.

---

# 25. Locator repair

Objects are identified by hash rather than locator.

Any actor MAY publish another pointer referring to the same object hash with different locators. No original assertion is modified.

Clients MAY aggregate locators from valid reference objects — whether `ref` or `descriptor` — that advertise the same object hash, subject to §24.

To make that usable, an HTTP relay SHOULD expose an object index (see §28). That index is not a new protocol primitive. It exposes a mapping the relay already has:

```text
object hash  →  assertions that mention it
```

---

# 26. External actor authentication

An SPP actor identity is an Ed25519 key.

The same key MAY be used outside SPP only under a domain-separated profile (§8). Bindings to OpenPGP identities, domains, Git repositories, organisations, humans, or other agent networks are outside the SPP core. Such bindings MAY themselves be distributed as externally referenced objects.

---

# 27. Relay discovery manifest

An HTTP relay SHOULD expose:

```text
GET /.well-known/spp
```

Paths in the manifest are resolved against the origin that served it. HTTPS is RECOMMENDED.

```json
{
  "v": 1,
  "submit": "/v1/assertions",
  "channels": "/v1/channels",
  "assertion": "/v1/assertions/sha256/{hex}",
  "channel": "/v1/channels/sha256/{hex}/assertions",
  "object": "/v1/objects/sha256/{hex}/assertions",
  "bootstrap_channels": [
    "sha256:0000058da39af8f5e2cb8c1268b45e6f198320a5e5ac53512f4b707e8672986b"
  ],
  "policy": {
    "pow_multiplier": 1,
    "max_record_bytes": 65536,
    "max_locators": 8,
    "max_locator_bytes": 2048,
    "max_parents": 32
  }
}
```

`policy` is informational. Field meanings:

```text
pow_multiplier
    JSON integer >= 1. Local extra work factor from §21.

max_record_bytes
    Maximum raw HTTP request-body size the relay will read,
    in octets, after HTTP transfer-decoding and before JSON parse.
    This is a transport limit, not a protocol-validity bound.
    It is not JCS(U) and is not part of assertion identity.

    Relays MAY reject any non-identity Content-Encoding.
    If a compressed Content-Encoding is accepted, raw-record
    and decompression limits are local policy and SHOULD be
    applied to the decoded representation before JSON parsing.

max_locators, max_locator_bytes, max_parents
    Local limits, each <= the corresponding v1 maximum.
```

A bootstrap manifest MAY be distributed by any out-of-band means.

Other transports are out of assertion format v1.

---

# 28. Minimal HTTP transport profile

This profile is the v1 HTTP interface. Relays that advertise the well-known manifest MUST implement these routes with these path shapes.

Colons do not appear in path segments. The algorithm label and the hex digest are separate segments:

```text
GET /v1/assertions/sha256/<64hex>
GET /v1/channels/sha256/<64hex>/assertions
GET /v1/objects/sha256/<64hex>/assertions
```

`<64hex>` is exactly 64 lowercase hex digits.

Request and response bodies use `Content-Type: application/json`. Relays MAY also accept `application/spp+json` as an alias.

## Submit assertion

```text
POST /v1/assertions
Content-Type: application/json
```

Body: one signed SPP assertion (§7).

```text
200 OK       accepted and immediately retrievable by GET
202 Accepted accepted, indexing pending; GET MAY return 404 until indexed
```

Submitting an assertion the relay already holds MUST be idempotent and SHOULD return 200.

Protocol-invalid or unsupported assertions SHOULD return 400. Policy rejection of a valid assertion SHOULD return 403. Bodies SHOULD be:

```json
{
  "error": "invalid_assertion",
  "message": "proof-of-work below target"
}
```

`error` is a short token; `message` is diagnostic and not normative. Implementations are not required to use identical diagnostic reason/stage tokens for the same rejection; interoperability depends on the protocol classification and the HTTP behaviour specified here, not on diagnostic wording.

## Retrieve assertion

```text
GET /v1/assertions/sha256/<64hex>
```

200 with the signed assertion, or 404.

## List advertised channels

```text
GET /v1/channels
```

Lists channel IDs the relay currently **advertises**. Membership and order are relay-defined. Clients MUST NOT infer chronology.

```json
{
  "items": [
    "sha256:0000058da39af8f5e2cb8c1268b45e6f198320a5e5ac53512f4b707e8672986b"
  ],
  "next": null
}
```

Each `items` element MUST be a `sha256-id` string. It MUST NOT be an object and MUST NOT be a bare hex digest. If the relay holds a channel-description assertion for an advertised ID, that assertion is GET-able at `/v1/assertions/sha256/<hex>` and MAY also appear in the channel-assertion list. It is not inlined here.

A relay MAY carry assertions for unlisted / capability channels without naming those channels in this list. See §29.

## Read channel

```text
GET /v1/channels/sha256/<64hex>/assertions
```

Returns assertions the relay carries for that channel ID. Order is relay-defined. Every returned assertion remains independently verifiable.

```json
{
  "items": [
    { "...complete signed assertion...": "see §7" }
  ],
  "next": null
}
```

Each `items` element MUST be a complete signed assertion object (§7).

## Object index

```text
GET /v1/objects/sha256/<64hex>/assertions
```

Returns assertions the relay carries whose `ref.hash` or `descriptor.hash` equals that object ID. `items` is an array of complete signed assertion objects, same pagination envelope as the channel list.

## Pagination

List responses use:

```json
{
  "items": [ ],
  "next": null
}
```

`next` is `null` or a string matching `1*( ALPHA / DIGIT / "-" / "_" )` (the unpadded base64url alphabet). Relays that need structured cursors encode them as unpadded base64url. The token is passed back as `?cursor=<token>` and needs no further percent-encoding if it matches that alphabet.

Clients MUST treat the token as opaque and MUST NOT parse it.

A supplied `cursor` query value that does not match the grammar above is malformed transport input and SHOULD receive `400 Bad Request`. The meaning and lifetime of a syntactically valid token are relay-local.

Cursor traversal has **no** stability guarantee while records are concurrently inserted or deleted. A client MAY see duplicates, omissions, or a terminated `next` that does not represent a complete historical snapshot. Relays SHOULD document their behaviour; v1 does not require a consistent snapshot.

Single-assertion GET is not paginated.

---

# 29. Relay federation

SPP defines no special relay-to-relay protocol.

A relay MAY synchronize another relay using the same public client interface. A relay is another SPP consumer that additionally redistributes accepted assertions.

No relay needs to trust another relay. Incremental sync beyond cursor pagination is not specified in v1.

“Full scrape” means a complete scrape of the relay's **advertised public surface**:

```text
GET /v1/channels
GET /v1/channels/sha256/<hex>/assertions   for each advertised id
GET /v1/assertions/sha256/<hex>            for each advertised id
```

plus any object-index results the scraper already has hashes for.

The single-assertion GET is required because a relay MAY omit a channel-description assertion from that channel's assertion list while still serving it at `/v1/assertions/sha256/<channel-id>`. Channel-list membership remains relay-defined.

It does **not** mean every assertion the relay is capable of returning to a caller who already possesses an unlisted channel ID. A relay MAY carry capability-channel assertions that do not appear in `GET /v1/channels`. Another relay that only scrapes the public surface will not learn those IDs.

---

# 30. Joining a channel

To read a channel an actor needs only:

```text
1. One or more relay addresses.
2. The channel ID.
```

There is no registration, membership handshake, channel owner, account, password, or central authorization.

---

# 31. Cross-relay channels

A channel is independent of any relay.

Given `channel = sha256:X`, any number of relays MAY advertise assertions for `X`. The channel remains the same channel.

---

# 32. Semantics

SPP assigns no meaning to channel identifiers, object contents, locator contents, parent relationships, or channel descriptors.

Interpretation belongs entirely to clients.

The protocol concerns itself only with identity, authenticity, reference, computational cost, and distribution.

---

# 33. Non-goals

Assertion format v1 does not provide:

```text
content hosting
content moderation
semantic search
message formatting
global ordering
consensus
currency
payments
accounts
access control
private messaging
guaranteed persistence
guaranteed delivery
global deletion
global channel ownership
proof of recent work
```

These MAY be implemented independently above or beside SPP.

---

# 34. Threat model

In scope, with the party that owns the defence:

| Threat | Protocol | Relay | Client |
| --- | --- | --- | --- |
| Unsigned or mutated assertions | signature + recomputed id | MUST verify | MUST verify |
| Bulk cheap publishing | work meter | multiplier / limits | — |
| Sybil identities | none (keys are cheap) | policy | trust sets |
| Locator poisoning | none | MAY filter locators | MUST treat as hostile; MUST verify bytes |
| Fetch-time SSRF / local files | none | MAY refuse schemes | MUST sandbox fetches |
| Relay censorship or omission | multi-relay redundancy | operator choice | use more relays |
| Stolen actor key | none | MAY block actor | out-of-band rotation / revocation objects |
| Stockpiled work | allowed | MAY use `created` policy | — |
| Graph bombs via `parents` | maxima | MAY cap | MUST cap recursion |
| Oversized records | protocol maxima | MAY be stricter | reject oversize |

Accepted v1 risks: keys are cheap; work is a meter; stockpiling is legal; no global deletion; no guaranteed availability.

---

# 35. Core invariant

```text
ASSERTION

actor       cryptographic identity
channel     opaque communication namespace
object      content hash of raw octets
locators    untrusted external retrieval hints
parents     optional assertion relationships
work        metered computational expenditure
signature   domain-separated authenticated authorship
```

For an assertion that reaches the acceptance path, a relay performs:

```text
receive
   ↓
optional early policy / resource rejection
   ↓
verify (§20)
   ↓
remaining local policy
   ↓
index → advertise
```

Early rejection makes no statement about protocol validity.

The relay does not need to understand what is being communicated.

---

# 36. Design rule

Future extensions SHOULD follow:

> If functionality can be represented as an ordinary signed pointer assertion, it SHOULD NOT become a new core protocol primitive.

> If behaviour can be decided independently by a relay, it SHOULD NOT become global protocol policy.

> If information can exist externally behind a content hash, it SHOULD NOT be transported by the SPP relay layer.

The object index in §28 is an index over existing fields, not a new primitive.

---

# Appendix A. Normative conformance suite

The frozen v1 release is accompanied by the machine-readable normative suite:

```text
conformance/vectors/suite.json
```

That suite includes, among other cases:

- positive full-assertion and JCS vectors;
- JSON-input rejection cases;
- structural-schema rejection cases;
- version-classification cases;
- proof-of-work boundary cases;
- SPP-Ed25519-1 discriminators;
- binary64/JCS edge cases;
- deep-nesting cases reaching the 1 MiB semantic boundary.

The suite hash in the release metadata is authoritative for the exact case set. The suite is normative only for the behaviour represented by each case. Subfunction vectors test the named subfunction; rejecting such a vector earlier for an unrelated reason does not demonstrate conformance to that subfunction.

The release metadata SHOULD publish a cryptographic digest of the exact suite artifact. Implementations MUST test against the committed normative artifact rather than silently regenerating expected answers from their own implementation logic.

Historical hostile-review regressions and broader fuzz/property suites are valuable conformance evidence but are not, merely by existing, additional wire-protocol primitives.

---

# Appendix B. Proof-of-work boundary table

Validity is `H <= target`, not `Wdemonstrated >= Wrequired`.

For `units = 3`:

```text
Wrequired = 196608
target    = 0000555555555555555555555555555555555555555555555555555555555555
```

| Case | H | `H <= target` | `Wdemonstrated >= Wrequired` |
| --- | --- | --- | --- |
| H = 0 | `0000…0000` | accept | yes |
| H = 1 | `0000…0001` | accept | yes |
| H = target − 1 | `00005555…5554` | accept | yes |
| H = target | `00005555…5555` | accept | **no** |
| H = target + 1 | `00005555…5556` | reject | no |
| H = 2^256 − 1 | `ffff…ffff` | reject | no |

The `H = target` row is why the inverse demonstrated-work score is informational rather than the consensus validity test.

Additional fixed targets:

```text
units = 2
target = 00007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

units = 19
target = 00000d79435e50d79435e50d79435e50d79435e50d79435e50d79435e50d7943
```

---

# Appendix C. Frozen-profile maintenance

Assertion format `v = 1` is frozen.

The following require a new assertion version:

```text
changing the set of protocol-valid assertions
changing assertion identity
changing signature input or the SPP-Ed25519-1 acceptance predicate
changing proof-of-work validity or work-unit calculation
changing protocol maxima
adding or removing assertion types
changing required/prohibited members
assigning new protocol semantics to an existing v1 field
assigning consensus semantics to v1 ext keys
```

The following do **not**, by themselves, require a new assertion version:

```text
fixing an implementation that violated the frozen rules
adding non-normative implementation guidance
adding tests for behaviour already fixed by the frozen definition
clarifying diagnostic wording
changing relay-local admission policy
adding application-layer profiles over ordinary SPP assertions
correcting prose by erratum when the frozen rule was already unambiguous elsewhere
```

No erratum may be used to change the accepted byte-string set while retaining `v = 1`.

---

# Appendix D. Minimal implementation checklist

A complete v1 verifier needs independent handling for:

```text
raw UTF-8 / JSON-input validation
duplicate-name rejection at every nesting level
BOM, surrogate, noncharacter, and negative-zero rejection
RFC 8785 / ECMAScript binary64 parsing and JCS
UTF-16 code-unit property ordering
exact reconstruction of U
closed §7A schema
identifier grammar
nonce and created predicates
semantic maxima
SHA-256 assertion identity
exact 256-bit proof-of-work arithmetic
SPP-Ed25519-1
version classification
```

Host-language behaviours MUST NOT silently alter JSON semantics. In particular:

- prototype-sensitive property names are ordinary JSON names;
- arbitrary-precision integer formatting is not a substitute for ECMAScript binary64 number serialization;
- host recursion limits are not protocol nesting limits;
- last-wins JSON parsing is not acceptable because duplicate member names are invalid.

Relays that serve accepted assertions should be able to re-validate the served representation to the same assertion `id` under which it was indexed.

