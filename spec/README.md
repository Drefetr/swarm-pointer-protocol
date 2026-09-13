# spec — frozen v1 normative package

This directory holds the frozen Swarm Pointer Protocol v1 package:

- [`SPP-v1-Core-Protocol-Specification.md`](SPP-v1-Core-Protocol-Specification.md) — the normative specification (assertion format `v = 1`, **FROZEN**).
- [`SPP-v1-External-Review-Guide.md`](SPP-v1-External-Review-Guide.md) — the reviewer / implementer checklist.

Both documents are intentionally byte-stable. This `README.md` is
**non-normative** packaging metadata: it is not part of the frozen profile and
does not change any requirement in the documents above.

## Normative suite path

The frozen specification (opening notes and Appendix A) and the External Review
Guide name the machine-readable conformance suite by its release-relative path:

```text
conformance/vectors/suite.json
```

That is the layout of the immutable `spp-v1-frozen` release package
(see [`../docs/CHANGELOG.md`](../docs/CHANGELOG.md)). The repository workspace
stores the same bytes under `tests/conformance/`:

| Path named by the frozen documents | Repository workspace path |
| --- | --- |
| `conformance/vectors/suite.json` | `tests/conformance/vectors/suite.json` |
| `SPP-v1-Core-Protocol-Specification.md` | `spec/SPP-v1-Core-Protocol-Specification.md` |
| `SPP-v1-External-Review-Guide.md` | `spec/SPP-v1-External-Review-Guide.md` |

The specification is deliberately not edited to reflect the workspace move:
`v = 1` is frozen and byte-stable. Consume the suite at the workspace path, or
from the release package at the path the specification names.

## Running the suite

[`../tests/conformance/README.md`](../tests/conformance/README.md) documents the
suite format and the per-implementation invocations. The full gate is:

```text
python ci/run_conformance.py
```

## Release metadata

[`../docs/releases/spp-v1-frozen.md`](../docs/releases/spp-v1-frozen.md) pins the
SHA-256 of the specification and of the normative suite, as the specification
recommends, over LF-normalized bytes so the digests are identical on every
platform. Reproduce and verify the whole package with:

```text
python ci/package_frozen.py --check
python ci/package_frozen.py
```
