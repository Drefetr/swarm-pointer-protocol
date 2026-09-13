# Durable two-agent SPP v1 end-to-end exchange

Demonstrates an actual durable, cross-language SPP v1 exchange:

```text
Agent A (Python)                Persistent relay (Python)              Agent B (TypeScript)
   |                                     |                                     |
   | external object OA  --publish-->  verify -> index  <--poll--              |
   | pointer PA                                                                 |
   |                                     |  --------------------------------  |
   |                              <--poll--  PB  <--publish-- pointer PB        |
   |                                                                           |
   fetch OB + verify sha256                                                   fetch OA + verify sha256
```

Every process is then terminated and restarted from disk, and the exchange
continues. The relay never fetches, hosts, or interprets referenced content.

## Layout

```text
interoperability/durable-e2e/
    run_tests.py        process orchestrator and assertions
    README.md
    fixtures/           exact external-object bytes (a1.bin, b1.bin, ...)
```

The two actors are the independently implemented clients:

```text
examples/agent-a/agent.py   Python, built on the Python verifier
examples/agent-b/agent.ts   TypeScript, built on the TypeScript verifier
```

## Run

```text
python tests/interoperability/durable-e2e/run_tests.py
```

Requires TypeScript dependencies (`npm ci` in `implementations/typescript`). The harness allocates a
temporary working directory, uses the fixed test ports

```text
relay        18760
policy relay 18761
A object     18870
B object     18871
```

and prints a transcript:

```text
PASS relay discovery
PASS capability channel hidden from advertisement
PASS A published PA
PASS B independently validated PA
PASS B fetched OA and verified sha256
PASS B published PB
PASS A independently validated PB
PASS A fetched OB and verified sha256
PASS pagination
PASS relay restart
PASS agent restart
PASS cold restart
PASS content-tamper rejection
PASS invalid-assertion rejection
PASS local-policy distinction
PASS idempotency

E2E PASS
```

On failure the temporary working directory is preserved and its path is
printed. Pass `--keep` to preserve it even on success.

## What is exercised

The harness only starts processes and inspects the relay and object servers. It
never mines, signs, submits, polls, or dereferences a locator on the agents'
behalf; all protocol actions are separate `clients/agent-a` and
`clients/agent-b` CLI invocations. Served assertions are independently
revalidated against the frozen `impl-a` v1 profile for the assertion-level
checks.

```text
Test 1   random capability channel is absent from GET /v1/channels but readable
         at GET /v1/channels/sha256/<id>/assertions
Test 2   A publishes PA; relay persists/indexes it; B independently validates
         PA, fetches OA, checks SHA-256, stores it, and records PA as seen
Test 3   B publishes PB with parents=[PA]; A performs the mirror checks
Test 4   relay page size 2; both actors traverse every `next` cursor, validate
         every assertion, and never re-deliver a seen id
Test 5   relay stopped and restarted on the same SQLite file; assertions,
         indexes, and the advertised/capability distinction survive
Test 6   both actors restarted on the same state directories; identities, seen
         ids, and stored objects survive; new publication A4 is received
Test 7   relay and both actors terminated and rebuilt from disk only; old data
         is readable, old objects fetchable, identities and seen state intact,
         and a fresh pointer exchange (A5, B4) works
Test 10  a locator returns bytes whose SHA-256 differs from `ref.hash`; the
         pointer assertion is accepted but the payload is rejected
Test 11  channel, ref.hash, actor, and signature are mutated post-signing; the
         relay rejects each with 400 and changes nothing
Test 12  a relay with SPP_BLOCK_ACTOR returns 403 for an otherwise valid
         assertion another relay accepts with 200
Test 13  byte-for-byte resubmission is idempotent: one record, one channel
         entry, one object entry
```

## Client state

Each actor keeps its state directory self-contained:

```text
<state>/key.hex             32-byte Ed25519 seed
<state>/state.json          actor, seen assertion ids, published ids, objects
<state>/objects/<hex>       content-addressed external objects
<state>/published/<hex>.json  canonical signed envelopes this actor authored
```

The object HTTP server (`serve`) exposes stored objects at
`GET /objects/sha256/<64hex>` plus `GET /health`.

## Relationship to the frozen profile

The demonstration does not change the v1 validity profile. Assertions are
produced by the clients and validated on every receiver path (and by the
relay) with the frozen verifiers. The relay performs exactly:

```text
receive -> verify -> policy -> persist/index -> advertise
```

and stores only opaque locators.
