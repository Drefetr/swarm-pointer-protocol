# SPP v1 multi-relay federation end-to-end

Demonstrates that assertion identity and channel identity do not depend on any
particular relay, and that relays synchronize using only the ordinary frozen v1
public client interface (ordinary `GET` + `POST`).

```text
                 Relay R1
                /        \
               /          \
        Agent A            Agent B
               \          /
                \        /
                 Relay R2

        R1 ── standard SPP GET ──> federation worker ── standard SPP POST ──> R2
        R2 ── standard SPP GET ──> federation worker ── standard SPP POST ──> R1
```

There is:

```text
no shared relay database
no shared relay filesystem
no internal relay RPC
no special federation endpoint
no direct database replication
```

## Layout

```text
tests/interoperability/multi-relay-e2e/
    run_tests.py        process orchestrator and assertions
    README.md
```

The components are the existing durable relay and the independent clients:

```text
implementations/relay/server.py             durable §27/§28 relay
examples/agent-a/agent.py                   Python actor, built on the Python verifier
examples/agent-b/agent.ts                   TypeScript actor, built on the TypeScript verifier
implementations/relay/federation/sync.py    ordinary-client federation worker
```

## Requirements

- Python 3.10+
- Node 20+ and TypeScript dependencies installed (`npm ci` in `implementations/typescript`)

## Run

```text
python tests/interoperability/multi-relay-e2e/run_tests.py
```

Fixed test ports:

```text
Relay R1        18760      state/relay-r1.sqlite3
Relay R2        18761      state/relay-r2.sqlite3
Agent A object  18872
Agent B object  18873
hostile mock    18874
```

Every component receives a separate persistent state directory. After startup
the harness treats each component as a black box; all activity occurs through
HTTP, the client CLIs, and process-specific persistence. No relay database is
ever edited directly.

## Transcript

```text
PASS R1 independent startup
PASS R2 independent startup
PASS shared channel identity
PASS capability channel hidden on R1
PASS capability channel hidden on R2
PASS A published PA only to R1
PASS B published PB only to R2
PASS Agent A reconstructed union
PASS Agent B reconstructed union
PASS R1 -> R2 synchronization
PASS R2 -> R1 synchronization
PASS federation idempotency
PASS advertised public scrape
PASS explicit capability-channel synchronization
PASS relay-local policy divergence
PASS R1 failure
PASS continued operation through R2
PASS R1 recovery
PASS catch-up synchronization
PASS independent arrival order
PASS object-index federation
PASS cross-relay parent reference
PASS hostile source relay validation
PASS full cold restart
PASS post-restart synchronization

MULTI-RELAY E2E PASS
```

On failure the temporary working directory is preserved, its path is printed,
and relay, federation, agent, and mock logs are kept. Pass `--keep` to preserve
the tree even on success.

## What is exercised

```text
Test  1  two durable relays start independently on separate databases
Test  2  one random capability channel id C is used on both relays; every
         assertion's `channel` equals C
Test  3  C is absent from GET /v1/channels on both relays, yet directly
         readable at GET /v1/channels/sha256/<C>/assertions
Test  4  R1 = {PA, PC}, R2 = {PB, PD}: disjoint local channel subsets
Test  5  each agent polls both relays, validates every assertion under §20,
         deduplicates globally by assertion id, and fetches peer objects
Test  6  explicit capability-channel sync R1 -> R2 unions the channel
Test  7  explicit capability-channel sync R2 -> R1 completes the union
Test  8  repeating both syncs forwards nothing and duplicates nothing
Test  9  a channel assertion is advertised on R1, absent on R2, then the
         advertised-surface scrape propagates it to R2
Test 10  a new pointer is synchronizable only with the channel id in hand,
         confirming the advertised/capability distinction
Test 11  R2 restarts with SPP_BLOCK_ACTOR; the worker forwards an otherwise
         valid assertion from the blocked actor and records destination 403
         without reclassifying it as invalid; R1 still holds both actors
Test 12  R1 is stopped; Agent A still publishes through R2 and Agent B still
         discovers the new assertion through R2
Test 13  R1 restarts from disk, is caught up from R2, and both converge
Test 14  deliberately different insertion orders still converge to the same
         accepted assertion-id set (no storage/HTTP/chronology ordering claimed)
Test 15  two assertions referencing one object with different locators produce
         a federated object index on both relays; no assertion is modified
Test 16  a child on R2 references a parent unknown to R2 at submission time;
         the parent relationship is unchanged after synchronization
Test 17  a hostile mock source returns one valid, one invalid, and one corrupted
         assertion; the worker forwards only the valid one
Test 18  relays, agents, and object servers are destroyed and rebuilt from disk;
         prior state is preserved and a rerun of sync is idempotent
Test 19  after restart, new publications on each relay synchronize to the union
```

## Client state

Each actor keeps its state directory self-contained:

```text
<state>/key.hex               32-byte Ed25519 seed
<state>/state.json            actor, seen assertion ids, published ids, objects
<state>/objects/<hex>         content-addressed external objects
<state>/published/<hex>.json  canonical signed envelopes this actor authored
```

## Multi-relay clients

Both clients accept a repeatable `--relay`:

```text
--relay http://127.0.0.1:18760 --relay http://127.0.0.1:18761
```

Clients treat relays as independent: they submit to each specified relay, query
each separately, independently validate every assertion received, deduplicate
globally by assertion id, and tolerate one or more unreachable relays. Per-relay
connection and submission status is reported in the result object and is local
state only. One assertion observed on two relays is still one assertion.

## Relationship to the frozen profile

This demonstration does not change the v1 validity profile. The worker and both
clients validate every received assertion with the frozen verifiers, and the
relay performs exactly:

```text
receive -> verify -> policy -> persist/index -> advertise
```

The v1 accepted-byte-string set, normative vectors, SPP work rules, signature
rules, schema, and HTTP wire profile are unchanged.
