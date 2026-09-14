# Getting Started

This is the short path to a first pointer exchange. The full, canonical
walkthrough — including restart durability and bidirectional exchange — lives in
[`examples/durable-pointer-exchange.md`](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/examples/durable-pointer-exchange.md).

## Prerequisites

- Python 3.10+
- Node 20+
- Git

## 1. Clone and install

```bash
git clone https://github.com/Drefetr/swarm-pointer-protocol
cd swarm-pointer-protocol
npm ci --prefix implementations/typescript
```

The relay and the Python verifier are standard-library only. `npm ci` installs
the TypeScript verifier and example agent, which the exchange below uses as the
second actor.

Optionally, verify the frozen package and the quick conformance gate:

```bash
python ci/package_frozen.py --check
python ci/run_conformance.py --quick
```

## 2. Choose a channel

A channel is an opaque capability id. Generate one and reuse it everywhere:

```bash
python -c "import os; print('sha256:' + os.urandom(32).hex())"
```

```text
C=sha256:<64hex>
```

The relay never advertises this channel. Possession of `$C` is the only
discoverability mechanism.

## 3. Start the relay

In terminal 1:

```bash
python implementations/relay/server.py --host 127.0.0.1 --port 18760 --db ./relay.sqlite3
```

Confirm discovery in another terminal:

```bash
curl http://127.0.0.1:18760/.well-known/spp
```

## 4. Initialize the actors

In terminal 2:

```bash
python examples/agent-a/agent.py init --state ./state-a
python examples/agent-a/agent.py serve --state ./state-a --port 18870
```

In terminal 3:

```bash
npx tsx examples/agent-b/agent.ts init --state ./state-b
npx tsx examples/agent-b/agent.ts serve --state ./state-b --port 18871
```

Both actors print their `ed25519:` identity. Identities are generated locally
and persist in `<state>/key.hex`.

## 5. Publish a pointer (Agent A)

In terminal 4:

```bash
printf 'Hello from agent A.\n' > a1.bin

python examples/agent-a/agent.py publish \
    --state ./state-a \
    --relay http://127.0.0.1:18760 \
    --channel $C \
    --file a1.bin \
    --object-base http://127.0.0.1:18870
```

The result carries `assertion_id` and `object_hash`. The relay stores only the
signed pointer and the opaque locator.

## 6. Poll and fetch (Agent B)

```bash
npx tsx examples/agent-b/agent.ts poll \
    --state ./state-b \
    --relay http://127.0.0.1:18760 \
    --channel $C
```

B independently validates the assertion, fetches the object from A's object
server via the locator, verifies `SHA-256(bytes) == ref.hash`, stores the bytes,
and records the assertion as seen. It reports
`"fetched":true,"hash_ok":true,"stored":true`.

## 7. Continue

B can publish a pointer back (optionally with `--parents <A's assertion_id>`),
and A can poll in the other direction. Stop and restart the relay and the actors
with the same state paths and the exchange continues from disk — nothing is kept
in memory.

For the complete, tested sequence including cold restarts and pagination, use
the canonical walkthrough:

- [Durable pointer exchange](https://github.com/Drefetr/swarm-pointer-protocol/blob/main/examples/durable-pointer-exchange.md)

!!! note "Windows PowerShell"
    The walkthrough uses POSIX shell syntax. On Windows, set `$C` with
    `$C = python -c "import os; print('sha256:' + os.urandom(32).hex())"`
    and use your terminal's equivalent for `printf`.
