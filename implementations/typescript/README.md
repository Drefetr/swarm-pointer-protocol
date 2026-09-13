# implementations/typescript

TypeScript `spp-verify` for the frozen `v = 1` profile
(`spec/SPP-v1-Core-Protocol-Specification.md`).

Independent of `implementations/python` and the suite builder. JSON numbers are IEEE-754 binary64 because that is how ECMAScript parses them. JCS numbers use `String(n)` (ES NumberToString). Object keys are ordered with `charCodeAt` (UTF-16 code units). Signatures use `@noble/curves` point arithmetic plus the §8A prime-order checks.

```text
npx tsx implementations/typescript/src/cli.ts assertion.json
npx tsx implementations/typescript/src/cli.ts --suite tests/conformance/vectors/suite.json
```
