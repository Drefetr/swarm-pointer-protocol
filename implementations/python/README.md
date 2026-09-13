# implementations/python

Python `spp-verify` for the frozen `v = 1` profile
(`spec/SPP-v1-Core-Protocol-Specification.md`).

It does not import the suite builder, `implementations/typescript/`, or any other implementation. Numbers are coerced to IEEE-754 binary64 before any SPP predicate. Duplicate names, `-0`, noncharacters, and lone surrogates are rejected before ordinary object reconstruction.

Ed25519 is a from-RFC-8032 implementation of SPP-Ed25519-1 (prime-order subgroup, uncofactored equation). It does not call libsodium or PyNaCl.

```text
python implementations/python/spp_verify.py assertion.json
python implementations/python/spp_verify.py --suite tests/conformance/vectors/suite.json
```
