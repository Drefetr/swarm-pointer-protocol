# v1 Release

!!! danger "SPP v1"
    The `v = 1` objective-validity profile is immutable. Any change that alters
    the set of protocol-valid assertions, assertion identity, signature input,
    proof-of-work, protocol maxima, permitted types, or required/prohibited
    fields requires a **new assertion version**. Prose errata may clarify an
    already-defined rule but must never change the accepted byte-string set while
    retaining `v = 1`.

The values below are taken from the repository release record at
[`docs/releases/v1.md`](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/docs/releases/v1.md).
That file is the source; this page summarizes it.

## Identity

| Item | Value |
| --- | --- |
| Tag | `v1` |
| Assertion format | `v = 1` |
| Specification SHA-256 | `4c450df9cafdd42c746537a72f6bd88d5dbf86390d6e7e51314b3a0134a71019` |
| Review guide SHA-256 | `6335bd8c8d94cbe5b39ef35329c761b735330a321f45f0ec67c5319e7f82683c` |
| Normative suite SHA-256 | `649a58da077818ab34a2ade7ea6b6a87ed4b05222cdeaaeae7fecb5e594493e3` |
| External review | `NO_FORK_FOUND` |

All digests are over **LF-normalized UTF-8 bytes**, so they are identical on
every platform (see [`.gitattributes`](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/.gitattributes)).

## External review

The freeze review returned `VERDICT: NO_FORK_FOUND`: no received byte string was
found on which two conforming readings disagree about `v = 1` protocol validity.
The review guide is the
[SPP-v1 External Review Guide](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/spec/SPP-v1-External-Review-Guide.md).

## Release contents

The `v1.zip` asset lays out the package exactly as the frozen specification names
it:

```text
SPP-v1-Core-Protocol-Specification.md
SPP-v1-External-Review-Guide.md
conformance/vectors/suite.json
LICENSE
RELEASE-NOTES.md
MANIFEST.sha256
```

## Get the release

- [GitHub release `v1`](https://github.com/Drefetr/swarm-pointer-protocol/releases/tag/v1)
- [`v1.zip`](https://github.com/Drefetr/swarm-pointer-protocol/releases/download/v1/v1.zip)
- [Release notes](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/docs/releases/v1.md)

## Reproduce and verify

From a clean checkout of the tagged commit:

```bash
python ci/package_frozen.py --check   # verify frozen digests, write nothing
python ci/package_frozen.py           # stage dist/v1/ and the zip
```

The script verifies the frozen file digests, stages the package, writes
`MANIFEST.sha256`, and produces a deterministic `dist/v1.zip` plus its
`.sha256`.

!!! note "v1 profile vs platform immutability"
    The v1 profile is **content-addressed and pinned** by the digests above. This
    is distinct from GitHub's platform-level "immutable releases" feature; the
    protocol's immutability does not depend on that setting being enabled.
