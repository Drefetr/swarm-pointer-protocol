# Protocol Reference

!!! warning "This documentation site is explanatory and non-normative"
    Everything on this site, including this page, is a summary. Where this site
    and the frozen v1 package differ, the frozen package governs. Nothing here
    adds, removes, or reinterprets a protocol requirement.

## Normative documents

| Document | Role | Link |
| --- | --- | --- |
| SPP v1 Core Protocol Specification | Normative; defines `v = 1` | [spec/SPP-v1-Core-Protocol-Specification.md](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/spec/SPP-v1-Core-Protocol-Specification.md) |
| SPP v1 External Review Guide | Reviewer / implementer checklist | [spec/SPP-v1-External-Review-Guide.md](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/spec/SPP-v1-External-Review-Guide.md) |
| Normative conformance suite | Machine-readable vectors | [tests/conformance/vectors/suite.json](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/tests/conformance/vectors/suite.json) |
| v1 release | Identity, digests, review record | [docs/releases/v1.md](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/docs/releases/v1.md) |

The frozen specification names its suite by the **release-relative** path
`conformance/vectors/suite.json`; the repository workspace stores the same bytes
under `tests/conformance/`. [spec/README.md](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/spec/README.md)
explains that mapping.

## Quick reference (summary)

### Cryptographic primitives

```text
Hash        SHA-256
Signature   SPP-Ed25519-1 (RFC 8032 PureEdDSA plus the §8A prime-order profile)
Encoding    UTF-8 I-JSON, then JCS (RFC 8785)
```

### Identifiers

```text
sha256-id   "sha256:" followed by 64 lowercase hex digits
actor-id    "ed25519:" followed by 64 lowercase hex digits
sig         128 lowercase hex digits
nonce       "0" or [1-9][0-9]{0,19}, value <= 2^64 - 1 (a JSON string)
```

### Assertion anatomy

```json
{
  "v": 1,
  "type": "pointer",
  "actor": "ed25519:<64hex>",
  "channel": "sha256:<64hex>",
  "created": 1789184927,
  "ref": { "hash": "sha256:<64hex>", "locators": ["https://..."] },
  "nonce": "81681",
  "id": "sha256:<64hex>",
  "sig": "<128hex>"
}
```

`id` and `sig` are excluded from `U`; `U` is `JCS`-canonicalized, hashed with
SHA-256 to produce `id`, and signed over `SPP/1/assertion\0 || D`. Reserved
top-level names are `v, type, actor, created, nonce, channel, ref, parents,
descriptor, id, sig, ext`. Any other name is invalid.

### Protocol maxima (v1)

```text
canonical_body_bytes   <= 1048576   (1 MiB of JCS(U))
locator count          <= 256
locator_bytes          <= 8192      (each decoded UTF-8 locator)
parent count           <= 1024
```

### Proof of work

```text
units      = 1 + ceil(canonical_body_bytes / 1024)
               + locator_count + parent_count + channel_description_cost
Wrequired  = units × 65536
target     = floor((2^256 - 1) / Wrequired)
valid iff  H <= target          (exact integer arithmetic)
```

`units`, `target`, and the boundary cases are defined in
[§15](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/spec/SPP-v1-Core-Protocol-Specification.md#15-proof-of-work)
and
[§16](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/spec/SPP-v1-Core-Protocol-Specification.md#16-work-units).

### Validity checklist (summary of §20)

A received object is `v = 1` protocol-valid only if: the JSON input rules hold;
`v` is exactly 1 and `type` is `channel` or `pointer`; `U` matches the closed
schema; identifier grammar holds; `nonce` and `created` hold; maxima hold;
recomputed `id` equals the transmitted `id`; `H <= target`; and the signature
verifies under SPP-Ed25519-1.

### HTTP profile (summary of §27/§28)

```text
GET  /.well-known/spp                              discovery manifest
POST /v1/assertions                                submit one signed assertion
GET  /v1/assertions/sha256/<64hex>                 retrieve one assertion
GET  /v1/channels                                  list advertised channel ids
GET  /v1/channels/sha256/<64hex>/assertions        channel assertion list
GET  /v1/objects/sha256/<64hex>/assertions         object-index assertion list
```

Full normative text:
[§20 Protocol validity](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/spec/SPP-v1-Core-Protocol-Specification.md#20-protocol-validity) ·
[§27](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/spec/SPP-v1-Core-Protocol-Specification.md#27-relay-discovery-manifest) ·
[§28](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/spec/SPP-v1-Core-Protocol-Specification.md#28-minimal-http-transport-profile)
