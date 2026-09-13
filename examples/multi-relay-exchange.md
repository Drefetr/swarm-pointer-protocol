# Multi-relay federation — manual walkthrough

The simplest manual version of the multi-relay SPP v1 federation demonstration.
Two independent durable relays each hold a different subset of the same opaque
channel; agents reconstruct the union by querying both; a federation worker
makes the relays converge using only ordinary SPP `GET` + `POST`.

Requirements: Python 3.10+, Node 20+, and `impl-b` dependencies installed
(`npm ci` in `impl-b`).

> Shell note: command blocks below are shown in POSIX form. On Windows
> PowerShell use the equivalent syntax; `$C` is a shell variable you set once
> in the current terminal.

Throughout, use one random capability channel id:

```text
python -c "import os; print('sha256:' + os.urandom(32).hex())"
```

Set it once and reuse it everywhere below:

```text
C=sha256:<64hex>
```

---

## 1. Start two relays

In terminal 1:

```text
python implementations/relay/server.py --host 127.0.0.1 --port 18760 --db ./relay-r1.sqlite3
```

In terminal 2:

```text
python implementations/relay/server.py --host 127.0.0.1 --port 18761 --db ./relay-r2.sqlite3
```

They share no database and no state. Confirm discovery on both:

```text
curl http://127.0.0.1:18760/.well-known/spp
curl http://127.0.0.1:18761/.well-known/spp
```

## 2. Create the actors and object servers

In terminal 3:

```text
python examples/agent-a/agent.py init --state ./state-a
python examples/agent-a/agent.py serve --state ./state-a --port 18872
```

In terminal 4:

```text
npx tsx examples/agent-b/agent.ts init --state ./state-b
npx tsx examples/agent-b/agent.ts serve --state ./state-b --port 18873
```

## 3. Publish a divergent initial state

The capability channel is never advertised. Read it before use — it succeeds
and is empty on both relays:

```text
curl http://127.0.0.1:18760/v1/channels/sha256/<64hex>/assertions
curl http://127.0.0.1:18761/v1/channels/sha256/<64hex>/assertions
```

Agent A publishes two pointers to R1 only:

```text
printf 'Hello from A one.\n' > a1.bin
printf 'Hello from A two.\n' > a2.bin

python examples/agent-a/agent.py publish --state ./state-a \
    --relay http://127.0.0.1:18760 \
    --channel $C --file a1.bin --object-base http://127.0.0.1:18872

python examples/agent-a/agent.py publish --state ./state-a \
    --relay http://127.0.0.1:18760 \
    --channel $C --file a2.bin --object-base http://127.0.0.1:18872
```

Agent B publishes two pointers to R2 only:

```text
printf 'Hello from B one.\n' > b1.bin
printf 'Hello from B two.\n' > b2.bin

npx tsx examples/agent-b/agent.ts publish --state ./state-b \
    --relay http://127.0.0.1:18761 \
    --channel $C --file b1.bin --object-base http://127.0.0.1:18873

npx tsx examples/agent-b/agent.ts publish --state ./state-b \
    --relay http://127.0.0.1:18761 \
    --channel $C --file b2.bin --object-base http://127.0.0.1:18873
```

Now `R1(C) = {PA, PC}` and `R2(C) = {PB, PD}`, but all four carry the same
channel id `C`. Inspect the two lists directly:

```text
curl http://127.0.0.1:18760/v1/channels/sha256/<64hex>/assertions
curl http://127.0.0.1:18761/v1/channels/sha256/<64hex>/assertions
```

## 4. Each client reconstructs the union

Pass both relays; the clients query each independently, validate every
assertion under `§20`, deduplicate by assertion id, and fetch peer objects:

```text
python examples/agent-a/agent.py poll --state ./state-a \
    --relay http://127.0.0.1:18760 --relay http://127.0.0.1:18761 --channel $C

npx tsx examples/agent-b/agent.ts poll --state ./state-b \
    --relay http://127.0.0.1:18760 --relay http://127.0.0.1:18761 --channel $C
```

Both report the same four assertion ids in their `seen` set. No relay is
authoritative.

## 5. Federate the two relays

Explicitly synchronize the capability channel (it is not advertised, so it
cannot be found by a public scrape):

```text
python implementations/relay/federation/sync.py \
    --source http://127.0.0.1:18760 \
    --destination http://127.0.0.1:18761 \
    --channel $C

python implementations/relay/federation/sync.py \
    --source http://127.0.0.1:18761 \
    --destination http://127.0.0.1:18760 \
    --channel $C
```

Each worker reads candidate assertions, validates them locally, and submits
only the valid ones. Run both commands again: nothing new is forwarded and no
duplicate appears.

## 6. Advertised public surface

Publish a channel-description assertion to R1 only:

```text
python examples/agent-a/agent.py publish-channel --state ./state-a \
    --relay http://127.0.0.1:18760
```

It now appears in R1's `GET /v1/channels` but not R2's. Synchronize the
advertised surface (no `--channel`), and R2 advertises it too:

```text
curl http://127.0.0.1:18760/v1/channels
curl http://127.0.0.1:18761/v1/channels

python implementations/relay/federation/sync.py \
    --source http://127.0.0.1:18760 \
    --destination http://127.0.0.1:18761

curl http://127.0.0.1:18761/v1/channels
```

The capability channel `C` still does not appear in either list.

## 7. Policy is local, not consensus

Restart R2 while blocking Agent A's actor id:

```text
# terminal 2
SPP_BLOCK_ACTOR=<ed25519:actor-a> python implementations/relay/server.py \
    --host 127.0.0.1 --port 18761 --db ./relay-r2.sqlite3
```

Publish one fresh pointer from A to R1 and from B to R2, then sync R1 -> R2.
The worker records a destination `403` for A's assertion while still reporting
it as source-valid; R2 simply does not carry it. This is a pass condition:
federation is not consensus and replication is not mandatory mirroring.

## 8. Relay failure and recovery

Stop R1. Both agents keep working through R2:

```text
python examples/agent-a/agent.py publish --state ./state-a \
    --relay http://127.0.0.1:18760 --relay http://127.0.0.1:18761 \
    --channel $C --file a1.bin --object-base http://127.0.0.1:18872
```

The unreachable relay is recorded as local status; R2 accepts the assertion.
Restart R1 and run `R2 -> R1` again to catch it up. The channel continued to
function while R1 did not exist.

---

For the fully automated version, including object-index federation, cross-relay
parent references, a hostile source relay, and a full cold restart, run:

```text
python interoperability/multi-relay-e2e/run_tests.py
```
