# Conformance

Machine-readable vectors are normative for the behaviours they represent. If both implementations agree with the vectors and disagree with prose, the prose gets the erratum.

`vectors/suite.json` is independently consumable. Do not import the suite
generator or any other build tooling at runtime.

## Suite format

Each case is:

```json
{
  "id": "A.2",
  "class": "full-assertion",
  "expect": "valid",
  "input": { "kind": "json-text", "utf8": "{...}" },
  "want": {
    "id": "sha256:...",
    "units": 3,
    "target_hex": "00005555..."
  }
}
```

`class` is one of:

```text
json-input       raw bytes → parsed object / reject
schema           reconstructed U → schema-valid / reject
jcs              parsed JSON value → canonical UTF-8 bytes
work             schema-valid U or (H, units) → H <= target
spp-ed25519-1    (A, sig, D) → accept / reject
full-assertion   complete received object → valid / invalid / unsupported
length           constructed U → JCS byte length / maxima
```

A negative case passes only if the named `class` rejects for a reason in `want.reasons` (or any reason, if omitted). A reject at a different layer does not pass.

## Run

```text
python implementations/python/spp_verify.py --suite tests/conformance/vectors/suite.json
npx tsx implementations/typescript/src/cli.ts --suite tests/conformance/vectors/suite.json
python tests/conformance/diff_verify.py
python tests/conformance/test_jcs_numbers.py
python tests/conformance/test_regressions.py
python tests/conformance/test_property_names.py
python tests/conformance/test_nesting_depth.py
python tests/conformance/mutate_diff.py
python tests/conformance/fuzz_binary64.py --count 200000
python tests/interoperability/relay-tests/run_tests.py
```

`build_suite.py --check` gates the committed `suite.json` against the generator,
which reads the source vector object `vectors/source.json`.
`test_regressions.py` consumes `regressions/*.json` as raw bytes (never rebuilt from
objects) and requires both implementations to agree on every consensus-visible field.
`fuzz_binary64.py` checks a random + biased binary64 corpus against an independent
ECMAScript/V8 oracle in addition to the two implementations.
`test_property_names.py` exercises `Object.prototype`-hostile member names:
unknown top-level names must be schema-rejected, while the same names inside `ext`
must survive JCS, hashing and signing as ordinary members.
`test_nesting_depth.py` sweeps paired nesting-depth cases (mined-valid,
work-failure, id-mismatch, schema-illegal) from the RC3 fork band up to the
exact 1 MiB canonical-body boundary: nesting depth is transport policy (§5),
so a conforming verifier must render a §20 verdict across the entire range.
Historical hostile-review records and the RC3 clean-room handoff are retained
locally under `local/rc3-evidence/` and are not part of the distributed package.

## Verifier totality (RC3 freeze gate)

No conforming reference verifier may terminate abnormally on any input byte
string. It must return VALID, INVALID, UNSUPPORTED, or an explicitly
non-validity resource/policy outcome (for example RESOURCE_REJECT or an
internal-error record that makes no validity claim). Batch processing must
isolate such outcomes per input, so no single hostile input terminates
processing of subsequent records. This is implementation discipline rather
than wire protocol, but the RC3 hostile review demonstrated why it belongs in
the release/conformance criteria: a reference verifier that crashes halfway
through §20 is not an implementation of that predicate.

## Freeze bar

Identical `id`, `sig`, `units`, `target`, and validity on this suite plus `fuzz-corpus/`, from two independent implementations. Relays come after that. See the repository root README.

## Change control

Adding a vector that locks an already-stated rule is allowed. Changing an expected result requires the same bar as a spec change.
