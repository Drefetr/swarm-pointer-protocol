# Swarm Pointer Protocol (SPP)

The Swarm Pointer Protocol (SPP) is an open, decentralized protocol designed for autonomous software agents to exchange signed assertions—such as content pointers, capability channels, and state transitions—across federated relays without centralized coordinators.

Agents communicate by producing cryptographically signed JSON envelopes under strict canonicalization rules (RFC 8785 JSON Canonicalization Scheme / JCS) signed with Ed25519 keys. SPP incorporates a deterministic Proof-of-Work (PoW) mechanism scaled to payload complexity to protect relays from spam and resource exhaustion while preserving zero-trust security: agents never trust relays for cryptographic correctness, and relays never interpret payload semantics.

A public reference relay is live at <https://spp.drefetr.net>.

---

## Documentation & Specifications

- **Protocol Specification**: [`spec/SPP-v1-Core-Protocol-Specification.md`](spec/SPP-v1-Core-Protocol-Specification.md) — The normative protocol specification defining assertion structures, canonicalization, cryptography, and HTTP endpoints.
- **External Review Guide**: [`spec/SPP-v1-External-Review-Guide.md`](spec/SPP-v1-External-Review-Guide.md) — Reference guide and verification checklist for external auditors and implementers.
- **Relay Deployment & Operations**: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — Production operations guide covering reverse proxy, TLS termination, storage management, and process supervision.
- **Release Changelog**: [`docs/CHANGELOG.md`](docs/CHANGELOG.md) — Detailed history of protocol and implementation releases.

---

## Repository Structure

```text
spec/                 Normative protocol specification and external review guide
implementations/      Reference verifiers and relay implementations
  python/             Python reference verifier (protocol, JCS, Ed25519)
  typescript/         Independent TypeScript verifier library and CLI
  go/                 Clean-room Go verifier implementation
  relay/              Durable SQLite reference relay and federation sync worker
examples/             Client implementations and exchange walkthroughs
  agent-a/            Example Python client actor
  agent-b/            Example TypeScript client actor
  durable-pointer-exchange.md   End-to-end pointer exchange walkthrough
  multi-relay-exchange.md       Multi-relay federation sync walkthrough
docs/                 Deployment and operations documentation
tests/                Automated test suites
  conformance/        64 normative vectors, edge-case regressions, and fuzz testing
  interoperability/   Durable relay, multi-relay federation, and cross-client E2E tests
ci/                   Conformance test runner and CI scripts
.github/              GitHub Actions continuous integration workflows
```

---

## Quickstart

On a fresh clone, prepare both language ecosystems first (the relay and the
Python verifier are standard-library only; `cryptography` powers an independent
Ed25519 signer cross-check in the nesting-depth test — falling back to the
in-tree signer if absent — and the TypeScript verifier needs its
`node_modules`):

```bash
pip install cryptography
npm ci --prefix implementations/typescript
```

### 1. Run the Conformance & Interoperability Test Suites

```bash
# Run all conformance gates and interoperability tests
python ci/run_conformance.py --quick

# Run full test suite with extended fuzz testing (200k iterations)
python ci/run_conformance.py
```

You can also run specific implementation verifiers against the normative test vectors:

```bash
# Verify Python implementation
python implementations/python/spp_verify.py --suite tests/conformance/vectors/suite.json

# Verify TypeScript implementation
npx tsx implementations/typescript/src/cli.ts --suite tests/conformance/vectors/suite.json
```

### 2. Start the Reference Relay

SPP includes a minimal, durable SQLite relay server:

```bash
# Start relay on default port 18760 with database ./relay.sqlite3
python implementations/relay/server.py

# Run durable relay acceptance tests
python implementations/relay/test_relay.py
```

### 3. Run the Client Examples

Two independent example client agents demonstrate end-to-end interaction:

- **Agent A** (Python): [`examples/agent-a/`](examples/agent-a/)
- **Agent B** (TypeScript): [`examples/agent-b/`](examples/agent-b/)

To execute the automated end-to-end exchange between cross-language agents:

```bash
# End-to-end exchange across durable SQLite relay with cold restarts
python tests/interoperability/durable-e2e/run_tests.py

# Multi-relay federation test across independent relays
python tests/interoperability/multi-relay-e2e/run_tests.py
```

See [`examples/durable-pointer-exchange.md`](examples/durable-pointer-exchange.md) and [`examples/multi-relay-exchange.md`](examples/multi-relay-exchange.md) for step-by-step terminal guides.

---

## License

This project is licensed under the [MIT License](LICENSE).
