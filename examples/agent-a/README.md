# Agent A — Python SPP v1 actor

An acting SPP v1 client, **not** a relay. It owns an Ed25519 identity and a
content-addressed object store, mines and signs pointer assertions, submits
them to a relay, polls a capability channel, independently validates every
received assertion with the frozen `impl-a` verifier, fetches referenced
objects from their locators, and accepts payloads only after the `§23` SHA-256
check.

The relay is never trusted for validity: every assertion returned by a relay
is revalidated here under the complete `§20` profile.

## Requirements

- Python 3.10+ (uses `X | None` syntax)
- No third-party packages

It imports the verifier and crypto from `implementations/python/` (`protocol`, `jcs`,
`ed25519_spp`).

## Commands

```text
python examples/agent-a/agent.py init --state <dir>
python examples/agent-a/agent.py status --state <dir>

python examples/agent-a/agent.py publish \
    --state <dir> --relay <url> [--relay <url> ...] --channel sha256:<64hex> \
    --file <path> --object-base <url> [--parents id,id] [--created <unix>]

python examples/agent-a/agent.py publish-channel \
    --state <dir> --relay <url> [--relay <url> ...] \
    [--descriptor-hash sha256:<64hex>] [--descriptor-locator <url>] [--created <unix>]

python examples/agent-a/agent.py poll \
    --state <dir> --relay <url> [--relay <url> ...] --channel sha256:<64hex>

python examples/agent-a/agent.py serve --state <dir> [--host 127.0.0.1] --port <port>

python examples/agent-a/agent.py submit --relay <url> [--relay <url> ...] --file <assertion.json>
```

`--relay` is repeatable. `publish`, `publish-channel`, and `submit` post to
each specified relay and report per-relay status. `poll` queries each relay
separately, independently validates every assertion, and deduplicates globally
by assertion id. Relays are treated as independent and one or more may be
unreachable; per-relay connection and submission status is local state only.

Every command prints one JSON result object on stdout.

- `publish` stores the file as an external object, adds an
  `http(s)://<object-base>/objects/sha256/<hex>` locator, mines and signs a
  pointer assertion, submits it, and saves the canonical envelope under
  `<state>/published/`.
- `poll` walks the channel list to `next == null`, validates each assertion,
  deduplicates by assertion id, fetches the first `ref.locators` entry that
  yields a finite octet stream, and stores it only when its SHA-256 equals
  `ref.hash`.
- `submit` is a transport-level action: it posts raw bytes to a relay and
  reports the HTTP result. It performs no local validation, which is what makes
  relay rejection behaviour observable.
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

## Mining

`mine()` searches the nonce space by patching the decimal nonce digits into a
canonical JCS template, computing one work target per nonce digit width. It
then puts the finished envelope through the frozen `impl-a` verifier, so the
producer optimisation can never emit a non-valid assertion.

## Transport and User-Agent

The actor identifies itself on every outbound HTTP request as
`User-Agent: SPP-Agent-A/1`, for both relay requests and object-locator fetches.
SPP v1 does not require any particular `User-Agent`, and a conforming client
must not need to impersonate a browser. The public reference relay is fronted by
Cloudflare, whose browser-integrity heuristics can reject requests that lack a
browser-like signature (observed as Cloudflare Error 1010). That rejection is
relay-local transport policy, not a protocol validity decision, and an operator
can relax it for the relay host so bare machine clients work unchanged.
