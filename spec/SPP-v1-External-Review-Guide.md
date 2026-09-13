# SPP v1 — External Review Guide

## Status

The accompanying `SPP-v1-Core-Protocol-Specification.md` is the frozen definition of Swarm Pointer Protocol assertion format `v = 1`.

The purpose of this review is **not** to add features to the core protocol. The primary objective is to find any remaining case in which the frozen text permits two good-faith implementations to disagree about objective validity, assertion identity, proof-of-work, signature verification, or the mandatory HTTP profile.

## Primary review challenge

> Find one received byte string for which two implementations that each plausibly follow the frozen specification can disagree about whether it is `v = 1` protocol-valid.

A stronger finding is one where both readings are directly supportable from the prose.

Implementation bugs remain useful findings, but should be distinguished from specification ambiguity.

## Authoritative materials

The review package should contain:

```text
SPP-v1-Core-Protocol-Specification.md
conformance/vectors/suite.json
reference implementations / clean-room implementations
historical regression corpus
```

For a behaviour represented by a normative vector, the vector governs if prose and vector conflict; the prose then requires an erratum. A vector is authoritative only for the behaviour it actually represents.

Release metadata should pin the exact SHA-256 digests of the frozen specification and normative suite.

## Highest-value review surfaces

Reviewers are especially encouraged to attack:

1. raw UTF-8 / JSON-input handling before ordinary object reconstruction;
2. duplicate member names at arbitrary nesting;
3. BOMs, surrogates, Unicode noncharacters, control characters, and negative-zero lexical forms;
4. ECMAScript binary64 parsing and RFC 8785 number serialization;
5. UTF-16 code-unit property ordering;
6. reconstruction of `U`, including host-language-sensitive property names;
7. the closed §7A schema and omission/null/empty distinctions;
8. version classification (`invalid` vs `unsupported`);
9. exact protocol maxima, including the full legal nesting range within 1 MiB;
10. nonce-width changes that move the canonical body across a 1024-byte work-unit boundary;
11. exact 256-bit proof-of-work arithmetic and the `H == target` boundary;
12. SPP-Ed25519-1 canonical point decoding, subgroup membership, `S < L`, and mixed-order points;
13. relay validation/index/serve round trips;
14. capability/unlisted channel behaviour;
15. HTTP route, cursor, and object-index interoperability.

## Classification discipline

Please distinguish:

```text
v1-valid
v1-invalid
unsupported version
relay-local / resource / policy rejection
implementation crash or undefined result
```

A local/resource rejection is not protocol-invalidity.

Diagnostic reason strings, stage names, and CLI wording are non-normative unless the specification explicitly says otherwise.

## Out of scope for the freeze review

The following may be valuable future work but are not reasons to enlarge v1:

- application message formats;
- moderation models;
- channel ownership;
- accounts or membership;
- global ordering;
- semantic search;
- reputation/trust systems;
- useful proof-of-work;
- content hosting;
- SAT/distributed-compute profiles;
- private messaging;
- relay-to-relay special protocols.

These belong above or beside SPP unless they reveal a defect in the existing frozen core.

## Suggested finding format

```text
ID:
Severity:
Surface:
Exact input bytes / reproducible constructor:
Expected reading A:
Expected reading B:
Observed implementations:
Why both readings appear conforming:
Accepted-byte-set impact:
Proposed minimal correction:
Regression vector:
```

For implementation-only findings, replace the dual-reading section with the violated normative rule.

## Freeze standard

The review succeeds by finding a concrete ambiguity or divergence, not by producing a large number of stylistic comments.

A useful final verdict is one of:

```text
FORK_FOUND
PROSE_AMBIGUITY
IMPLEMENTATION_BUG_ONLY
NO_FORK_FOUND
```

If a proposed correction would alter the accepted byte-string set of the already frozen `v = 1` profile, it must be treated as a new assertion version rather than an erratum.
