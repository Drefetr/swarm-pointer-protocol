# Fuzz / differential corpus

Seed inputs at the raw-JSON → parsed-object boundary. The useful outcome is an input on which the Python and TypeScript implementations disagree.

Highest-risk surfaces:

```text
duplicate names before reconstruction
-0
binary64 rounding
UTF-16 vs UTF-8 JCS key order
noncharacters
1024-byte work step
1 MiB
nonce width
exact 256-bit work
canonical / mixed-order Ed25519 points
```

Add a file here when a mutation is interesting. Do not treat these seeds as normative unless they are promoted into `vectors/suite.json`.
