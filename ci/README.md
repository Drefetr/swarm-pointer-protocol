# ci

`run_conformance.py` is the single gate that verifies the frozen v1 package.

```text
python ci/run_conformance.py                 # full (200k fuzz)
python ci/run_conformance.py --quick         # 20k fuzz
python ci/run_conformance.py --skip-relay
```

Gates:

| Gate | Command | Freeze meaning |
| --- | --- | --- |
| frozen package identity | `ci/package_frozen.py --check` | spec and suite bytes match the pinned release digests |
| generated-vector drift | `tests/conformance/build_suite.py --check` | committed `suite.json` is provably the generator output |
| Python conformance | `implementations/python/spp_verify.py --suite` | Python implementation consumes committed artifact |
| TypeScript conformance | `implementations/typescript/src/cli.ts --suite` | TypeScript implementation consumes committed artifact |
| TypeScript typecheck | `implementations/typescript tsc --noEmit` | TypeScript implementation type-checks |
| differential suite | `tests/conformance/diff_verify.py` | both impls agree case-by-case |
| JCS numbers | `tests/conformance/test_jcs_numbers.py` | number path tested independently of schema |
| permanent regressions | `tests/conformance/test_regressions.py` | exact hostile-review bytes agree |
| property-name hostility | `tests/conformance/test_property_names.py` | `Object.prototype`-hostile member names handled |
| nesting-depth totality | `tests/conformance/test_nesting_depth.py` | a defined §20 verdict across the legal depth range |
| differential mutation | `tests/conformance/mutate_diff.py` | corpus classified by target subfunction |
| binary64 fuzz | `tests/conformance/fuzz_binary64.py` | random corpus vs Python, TypeScript, independent V8 oracle |
| relay interop | `tests/interoperability/relay-tests/run_tests.py` | relays interoperate over §28 |
| durable relay | `implementations/relay/test_relay.py` | SQLite relay persists assertions and indexes |
| durable two-agent e2e | `tests/interoperability/durable-e2e/run_tests.py` | cross-language actor exchange survives cold restart |
| multi-relay federation e2e | `tests/interoperability/multi-relay-e2e/run_tests.py` | two relays synchronize via ordinary GET + POST |

Implementations never regenerate expected results. They read
`tests/conformance/vectors/suite.json` and `tests/conformance/regressions/*.json` as fixed
byte strings.

`package_frozen.py` also assembles the immutable release package in the layout
the frozen specification names; see `docs/releases/spp-v1-frozen.md`.
