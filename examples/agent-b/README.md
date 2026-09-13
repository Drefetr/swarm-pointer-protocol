# Agent B — TypeScript SPP v1 actor

An acting SPP v1 client, **not** a relay. It owns an Ed25519 identity and a
content-addressed object store, mines and signs pointer assertions, submits
them to a relay, polls a capability channel, independently validates every
received assertion with the independent TypeScript verifier, fetches referenced
objects from their locators, and accepts payloads only after the `§23` SHA-256
check.

It is unrelated to Agent A: a different language, JSON stack, and Ed25519
implementation. It imports the verifier from `../../implementations/typescript/src`
(`check`, `curve`, `canon`, `scan`) and uses `node:crypto` only for hashing and
seed-to-public-key derivation.

The relay is never trusted for validity: every assertion returned by a relay
is revalidated here under the complete `§20` profile.

## Requirements

- Node 20+
- `typescript` dependencies installed (`npm ci` in `implementations/typescript`)
- Run with `npx tsx` or `implementations/typescript/node_modules/.bin/tsx`

## Commands

```text
npx tsx examples/agent-b/agent.ts init --state <dir>
npx tsx examples/agent-b/agent.ts status --state <dir>

npx tsx examples/agent-b/agent.ts publish \
    --state <dir> --relay <url> [--relay <url> ...] --channel sha256:<64hex> \
    --file <path> --object-base <url> [--parents id,id] [--created <unix>]

npx tsx examples/agent-b/agent.ts publish-channel \
    --state <dir> --relay <url> [--relay <url> ...] [--descriptor-hash sha256:<64hex>] [--created <unix>]

npx tsx examples/agent-b/agent.ts poll \
    --state <dir> --relay <url> [--relay <url> ...] --channel sha256:<64hex>

npx tsx examples/agent-b/agent.ts serve --state <dir> [--host 127.0.0.1] --port <port>

npx tsx examples/agent-b/agent.ts submit --relay <url> [--relay <url> ...] --file <assertion.json>
```

`--relay` is repeatable. `publish`, `publish-channel`, and `submit` post to
each specified relay and report per-relay status. `poll` queries each relay
separately, independently validates every assertion, and deduplicates globally
by assertion id. Relays are treated as independent and one or more may be
unreachable; per-relay connection and submission status is local state only.

Every command prints one JSON result object on stdout, matching the Agent A
result schema so the two can be driven by the same harness.

- `publish` stores the file as an external object, adds an
  `http(s)://<object-base>/objects/sha256/<hex>` locator, mines and signs a
  pointer assertion, submits it, and saves the canonical envelope under
  `<state>/published/`.
- `poll` walks the channel list to `next == null`, validates each assertion
  with the TypeScript verifier, deduplicates by assertion id, fetches the first
  `ref.locators` entry that yields a finite octet stream, and stores it only
  when its SHA-256 equals `ref.hash`.
- `submit` posts raw bytes to a relay and reports the HTTP result without local
  validation.
- `serve` is the actor's own object server: `GET /objects/sha256/<64hex>` and
  `GET /health`.

## State

```text
<state>/key.hex              32-byte Ed25519 seed
<state>/state.json           actor, seen assertion ids, published ids, objects
<state>/objects/<hex>        content-addressed external objects
<state>/published/<hex>.json canonical signed envelopes
```

## Fetch policy

Locators are treated as hostile (`§24`). Only `http` and `https` are fetched;
other schemes are refused. Responses are bounded to 16 MiB and time-limited.
The demo actor deliberately permits loopback targets because the peer object
server is local. It performs no other reachability filtering.
