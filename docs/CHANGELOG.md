# Changelog

All notable changes to the distributed SPP v1 package are recorded here.

Assertion format `v = 1` is **frozen**: changes that alter the
accepted-byte-string set, assertion identity, signature input, proof-of-work, or
protocol maxima require a new assertion version (`v = 2`).

## Unreleased

### Added

- `DEPLOYMENT.md` — public relay deployment and operator guide (topology, TLS
  reverse proxy, local policy, backups, service, federation).
- `LICENSE` — MIT.
- Durable relay now advertises the full §27 `policy` set (`max_locators`,
  `max_locator_bytes`, `max_parents`) and enforces them as local policy,
  clamped to the v1 maxima. Exceeding a locally advertised limit is a `403`
  policy rejection, not a protocol-invalidity claim.

### Fixed

- Restored the F2 version-classification erratum in
  `spec/SPP-v1-Core-Protocol-Specification.md`, re-aligning the shipped file with
  the published release identity `4c450df9…` and removing the stale hard-coded
  suite count.
- Conformance gate evidence aligned with `ci/run_conformance.py`: durable relay,
  durable two-agent e2e, and multi-relay federation e2e tests active in CI.
- `ci/README.md` gate table now lists every conformance gate.
- Stale `spec/*` references in the `implementations/` READMEs.

### Documentation

- Root `README.md` points at the live relay `https://spp.drefetr.net` and the
  deployment guide.
- `spec/SPP-v1-External-Review-Guide.md` status wording now reads "frozen".
- Walkthrough shell-fence consistency and `local/README.md` inventory.
- Repo restructured: `spec/`, `implementations/`, `tests/`, `docs/`, `ci/` replacing
  the previous flat layout.

## [spp-v1-frozen] - 2026-09-13

Initial frozen release of Swarm Pointer Protocol assertion format `v = 1`
(`spp-v1-frozen`). Three independent implementations, normative conformance
suite, and clean-room Go verifier included; external hostile review returned
`NO_FORK_FOUND`.
