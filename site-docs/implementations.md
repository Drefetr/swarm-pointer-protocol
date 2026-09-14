# Implementations

SPP v1 has three independent verifiers, each a from-scratch implementation of the
frozen validity predicate in a different language.

| Implementation | Directory | Role | Historical code |
| --- | --- | --- | --- |
| Python | `implementations/python` | reference verifier | `impl-a` |
| TypeScript | `implementations/typescript` | independent verifier | `impl-b` |
| Go | `implementations/go` | clean-room verifier | `impl-c` |

The historical short codes are retained only as provenance. The current release
names are by language and role.

## Why three implementations

Agreement across different languages, JSON stacks, and Ed25519 libraries reduces
the likelihood that conformance is merely agreement with shared implementation
behaviour. If all three verifiers agree on the frozen byte-string set, that is
stronger evidence than any single implementation agreeing with itself.

- **Python** is written from the specification and does not import any other
  implementation or the suite builder. It implements SPP-Ed25519-1 with its own
  RFC 8032 arithmetic, not a binding.
- **TypeScript** is an independent implementation. JSON numbers are IEEE-754
  binary64 because that is how ECMAScript parses them; JCS numbers use
  `String(n)`; object keys are ordered by UTF-16 code units. Signatures use
  independent point arithmetic plus the §8A prime-order checks.
- **Go** is a clean-room verifier written from the frozen prose only. It uses a
  hand-written iterative I-JSON scanner (no `encoding/json`), an iterative JCS
  implementation, exact big-integer work arithmetic, and the
  `filippo.io/edwards25519` library to implement SPP-Ed25519-1 literally.

## Verifier totality

No conforming reference verifier may terminate abnormally on any input byte
string. It must return VALID, INVALID, UNSUPPORTED, or an explicitly
non-validity resource/policy outcome. Batch processing isolates these outcomes
per input, so no single hostile input terminates processing of subsequent
records.

## Example clients

Two independent example client actors exercise the verifiers end to end:

- [Agent A](https://github.com/Drefetr/swarm-pointer-protocol/tree/main/examples/agent-a) — Python;
- [Agent B](https://github.com/Drefetr/swarm-pointer-protocol/tree/main/examples/agent-b) — TypeScript.

## Implementation READMEs

- [Python](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/implementations/python/README.md)
- [TypeScript](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/implementations/typescript/README.md)
- [Go](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/implementations/go/README.md)
