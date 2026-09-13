# implementations/go — Go clean-room SPP v1 verifier

An independent Go implementation of the §20 protocol-validity decision function
for assertion format `v = 1`, written from the frozen v1 prose
(`spec/SPP-v1-Core-Protocol-Specification.md`) only.

## Build

```text
cd implementations/go
go build -o spp-verify.exe .
```

Requirements: Go 1.25.1. The only third-party dependency is
`filippo.io/edwards25519` (required to implement the SPP-Ed25519-1 profile
literally; `crypto/ed25519.Verify` is **not** §8A).

## Run

```text
spp-verify <file>                       # single file
spp-verify --batch <items.json>         # {"name","utf8"}[] -> verdict lines
spp-verify --jcs-batch <items.json>     # parse §6 + JCS -> jcs_hex lines
spp-verify --ed-batch <items.json>      # {"name","A","sig","D"} -> raw §8A
spp-verify --suite <suite.json>         # run the committed normative suite
spp-verify --suite tests/conformance/vectors/suite.json
spp-verify --diagnostic <file>          # print consensus-visible intermediates
```

Exit codes: `0` VALID, `1` INVALID, `2` UNSUPPORTED, `3` internal error.
Exit 3 is only reachable through a file/OS error or a recovered panic, and the
panic path is a last-resort net: fuzzing (3.3M execs) and the structured
totality tests reach no panic.

## Design notes (where the prose drove a non-obvious choice)

* **No `encoding/json`.** `value.go` is a hand-written, fully iterative
  (explicit-stack) I-JSON scanner. It enforces strict whole-input UTF-8, leading
  BOM rejection, duplicate member names at every depth, lone surrogates, Unicode
  noncharacters, non-finite numbers and the `-0` value. Nesting depth is a
  memory question, not a stack-recursion question, so the §5 / RC3 totality
  bound (~175k levels under 1 MiB) is reachable.
* **Iterative JCS.** `jcs.go` canonicalizes with an explicit stack, sorts object
  names by UTF-16 code units (A.9), and escapes exactly per RFC 8785 §3.2.2.2.
* **ECMAScript Number::toString.** Number serialization extracts Go's shortest
  round-trip digits and re-presents them with the ECMAScript fixed/exponent
  thresholds (RFC 8785 §3.2.2.3 / ECMA-262 §6.1.6.1.20). It is *not*
  `strconv.FormatFloat` default output and not arbitrary-precision integer
  rendering (A.13 / A.15). Validated against an independent ECMAScript-style
  oracle over 200,000 biased binary64 values.
* **Exact integer work arithmetic.** `H`, `MAX`, `target` and `Wrequired` use
  `math/big`; validity is `H <= target` (Appendix B, including the
  `H == target` boundary).
* **SPP-Ed25519-1 (`ed25519.go`)** uses `filippo.io/edwards25519` and implements
  §8A steps 1–10 literally: canonical re-encoding of `A` and `R`, `S < L`,
  identity rejection, prime-order subgroup membership via `[L]P = identity`, and
  the exact `[S]B = R + [k]A` equation.
* **Stage fidelity.** The §20 pipeline order in `verify.go` is the one mandated
  by the spec; stage/reason tokens follow the vocabulary in handoff §5.

## Layout

```text
value.go     iterative I-JSON scanner and value model
jcs.go       RFC 8785 canonicalization + ECMAScript number formatting
ident.go     §4 grammar, §7A schema, §17 nonce, §18 created
verify.go    §20 pipeline, units, target
ed25519.go   §8A SPP-Ed25519-1
main.go      CLI (single, batch, jcs-batch, ed-batch, diagnostic)
suite.go     --suite driver and construct-pad / construct-depth builders
*_test.go    Phase A self-tests, totality tests, fuzz target
```
