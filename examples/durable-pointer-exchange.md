# Durable pointer exchange — manual walkthrough

The simplest manual version of the durable two-agent SPP v1 exchange. Two
independently implemented actors share one opaque channel through a persistent
relay, exchange pointers to externally hosted objects, then restart every
process from disk and continue. The relay never fetches or understands the
referenced objects.

Throughout, replace `<CHANNEL>` with one randomly chosen capability id:

```text
python -c "import os; print('sha256:' + os.urandom(32).hex())"
```

Set it once and use the same value in both actors. Requirements: Python 3.10+,
Node 20+, and TypeScript dependencies installed (`npm ci` in
`implementations/typescript`).

> Shell note: command blocks below are shown in POSIX form. On Windows
> PowerShell use the equivalent syntax; `$CHANNEL` is a shell variable you set
> once in the current terminal.

---

## 1. Start the relay

In terminal 1:

```text
python implementations/relay/server.py --host 127.0.0.1 --port 18760 --db ./relay.sqlite3
```

Confirm discovery:

```text
curl http://127.0.0.1:18760/.well-known/spp
```

## 2. Start Agent A's object server

Create A's identity and state, then start its object server. In terminal 2:

```text
python examples/agent-a/agent.py init --state ./state-a
python examples/agent-a/agent.py serve --state ./state-a --port 18870
```

## 3. Start Agent B's object server

Create B's identity and state, then start its object server. In terminal 3:

```text
npx tsx examples/agent-b/agent.ts init --state ./state-b
npx tsx examples/agent-b/agent.ts serve --state ./state-b --port 18871
```

Both actors print their `ed25519:` identity. The identities are generated
locally and persist in `<state>/key.hex`; they are unrelated keys.

## 4. Configure one shared channel

The channel is the random capability id from above. It is never advertised by
the relay: possession of the id is the only discoverability mechanism.

```text
CHANNEL=sha256:<64hex>
```

Read it before use — it succeeds and is empty:

```text
curl http://127.0.0.1:18760/v1/channels/sha256/<64hex>/assertions
```

## 5. A publishes a pointer

Create the external object and publish a pointer to it. The relay stores only
the signed pointer and the opaque locator.

```text
printf 'Hello from agent A.\n' > a1.bin

python examples/agent-a/agent.py publish \
    --state ./state-a \
    --relay http://127.0.0.1:18760 \
    --channel $CHANNEL \
    --file a1.bin \
    --object-base http://127.0.0.1:18870
```

The result carries `assertion_id` (call it `PA`) and `object_hash` (`OA`).

## 6. B polls and fetches

```text
npx tsx examples/agent-b/agent.ts poll \
    --state ./state-b \
    --relay http://127.0.0.1:18760 \
    --channel $CHANNEL
```

B independently validates `PA`, fetches `OA` from A's object server at the
locator, verifies `SHA-256(bytes) == ref.hash`, stores the bytes in its inbox,
and records `PA` as seen. Its result reports `"fetched":true,"hash_ok":true,
"stored":true`.

## 7. B publishes a pointer

```text
printf 'Hello from agent B.\n' > b1.bin

npx tsx examples/agent-b/agent.ts publish \
    --state ./state-b \
    --relay http://127.0.0.1:18760 \
    --channel $CHANNEL \
    --file b1.bin \
    --object-base http://127.0.0.1:18871 \
    --parents <PA>
```

`--parents` optionally links the new pointer (`PB`) to `PA`. Parents are hints;
the relay does not require them to be known.

## 8. A polls and fetches

```text
python examples/agent-a/agent.py poll \
    --state ./state-a \
    --relay http://127.0.0.1:18760 \
    --channel $CHANNEL
```

A repeats the same validation, fetch, and SHA-256 checks in the opposite
direction, demonstrating bidirectional pointer exchange.

## 9. Restart everything

Stop terminals 1–3 (Ctrl+C). Nothing is kept in memory.

```text
# terminal 1
python implementations/relay/server.py --host 127.0.0.1 --port 18760 --db ./relay.sqlite3

# terminal 2
python examples/agent-a/agent.py serve --state ./state-a --port 18870

# terminal 3
npx tsx examples/agent-b/agent.ts serve --state ./state-b --port 18871
```

The relay reloads assertions and indexes from the same SQLite file; the actors
reload the same identities, seen-id sets, and stored objects from their state
directories.

## 10. Continue

Old pointers are still found but not delivered twice:

```text
npx tsx examples/agent-b/agent.ts poll --state ./state-b --relay http://127.0.0.1:18760 --channel $CHANNEL
python examples/agent-a/agent.py poll --state ./state-a --relay http://127.0.0.1:18760 --channel $CHANNEL
```

Both report `"new":0` for previously seen assertions. Publish a new pointer and
the exchange continues normally:

```text
printf 'Agent A object two.\n' > a2.bin
python examples/agent-a/agent.py publish --state ./state-a --relay http://127.0.0.1:18760 --channel $CHANNEL --file a2.bin --object-base http://127.0.0.1:18870
npx tsx examples/agent-b/agent.ts poll --state ./state-b --relay http://127.0.0.1:18760 --channel $CHANNEL
```

---

## What the relay did

```text
receive -> verify -> policy -> persist/index -> advertise
```

At no point did it fetch, host, or interpret `a1.bin` or `b1.bin`. Object
identity lives in `ref.hash`; the locator is an untrusted retrieval hint.

For the fully automated version, including relaying and pagination at page
size 2, tamper rejection, invalid-assertion rejection, local relay policy, and
idempotency, run:

```text
python tests/interoperability/durable-e2e/run_tests.py
```
