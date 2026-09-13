# Release: spp-v1-frozen

Immutable release of the SPP v1 protocol definition, the normative conformance
suite, and the external-review record. Tag `spp-v1-frozen`; the tag pins the
release commit, and the content digests below are authoritative.

## Identity

| Item | Value |
| --- | --- |
| Tag | `spp-v1-frozen` |
| Assertion format | `v = 1` (frozen) |
| Specification | `SPP-v1-Core-Protocol-Specification.md` |
| Specification SHA-256 | `4c450df9cafdd42c746537a72f6bd88d5dbf86390d6e7e51314b3a0134a71019` |
| Normative suite | `conformance/vectors/suite.json` |
| Suite SHA-256 | `649a58da077818ab34a2ade7ea6b6a87ed4b05222cdeaaeae7fecb5e594493e3` |
| Review guide | `SPP-v1-External-Review-Guide.md` |
| Review guide SHA-256 | `6335bd8c8d94cbe5b39ef35329c761b735330a321f45f0ec67c5319e7f82683c` |
| External review | `NO_FORK_FOUND` |

All digests are over **LF-normalized UTF-8 bytes**, so they are identical on
every platform (see [`.gitattributes`](../../.gitattributes)).

## External review

The freeze review (`spec/SPP-v1-External-Review-Guide.md` pass) returned
`VERDICT: NO_FORK_FOUND`: no received byte string was found on which two
conforming readings disagree about `v = 1` protocol validity. The post-review F2
(version-classification) and F3 (release-metadata) edits are recorded in the
review addendum and do not alter the accepted byte-string set.

Review records (retained by the maintainers; not part of the distributed tree):

```text
7f46dbdfdcb75fa9bf03fd191837565f3774ff0da16120b1019140b03d0b0fd7  REVIEW.md
df26cc93eb8e212e5715fbffa8cc3725158373b3e937c3c9cb02db90bb578d01  ADDENDUM.md
```

> **Line-ending note.** The addendum's recorded suite digest `e675ed46…` was
> computed over the same suite content in CRLF form. This release normalizes all
> text to LF, so the canonical suite digest is `649a58da…` above. Use the table.

## Contents

The `spp-v1-frozen.zip` asset lays out the package exactly as the frozen
specification names it:

```text
SPP-v1-Core-Protocol-Specification.md
SPP-v1-External-Review-Guide.md
conformance/vectors/suite.json
LICENSE
RELEASE-NOTES.md
MANIFEST.sha256
```

## Reproduce and verify

From a clean checkout of the tagged commit:

```text
python ci/package_frozen.py --check   # verify frozen digests, write nothing
python ci/package_frozen.py           # stage dist/spp-v1-frozen/ and the zip
```

The script verifies the frozen file digests, stages the package, writes
`MANIFEST.sha256`, and produces a deterministic `dist/spp-v1-frozen.zip` plus
its `.sha256`. Verify any single file against the manifest:

```text
python -c "import hashlib,glob;print(hashlib.sha256(open('conformance/vectors/suite.json','rb').read().replace(b'\r\n',b'\n')).hexdigest())"
```
