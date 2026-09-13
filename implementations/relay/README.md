# Durable SPP v1 relay

A small persistent HTTP relay implementing the frozen SPP v1
[`§27`/`§28`](../../spec/SPP-v1-Core-Protocol-Specification.md) profile.

It is a **relay**, not an application server. It receives signed assertions,
completes the full frozen `§20` validation with the `impl-a` verifier, applies
local policy, persists the canonical signed bytes, indexes them, and serves the
frozen HTTP routes. It never fetches, hosts, or interprets referenced content:
`ref.locators[]` and `descriptor.locators[]` are opaque signed strings.

The in-memory reference relays (`implementations/python/relay.py`, `implementations/typescript/src/relay.ts`) are
unchanged and remain the interoperability references.

## Layout

```text
implementations/relay/
    README.md
    server.py       HTTP profile, admission, local policy
    store.py        SQLite persistence and cursor pagination
    schema.sql      storage schema and indexes
    test_relay.py   durable-relay acceptance tests
    federation/     ordinary-client federation sync worker
```

## Requirements

- Python 3.10+ (the module uses `X | None` type syntax)
- SQLite (stdlib `sqlite3`)
- No third-party packages

## Run

```text
python implementations/relay/server.py
```

Defaults to `http://127.0.0.1:18760` with database `./relay.sqlite3` and page
size 32.

Explicit options:

```text
python implementations/relay/server.py --host 127.0.0.1 --port 18760 --db ./relay.sqlite3 --page-size 32
```

### Configuration

CLI options:

```text
--host          bind address                 default 127.0.0.1   (env SPP_HOST)
--port          TCP port                     default 18760       (env SPP_PORT)
--db            SQLite database path         default ./relay.sqlite3 (env SPP_DB)
--page-size     list page size               default 32          (env SPP_PAGE_SIZE)
```

Local policy environment variables:

```text
SPP_POW_MULTIPLIER      local extra work factor, integer >= 1   default 1
SPP_MAX_RECORD_BYTES    maximum raw request body, octets        default 65536
SPP_MAX_LOCATORS        locators per reference object           default 256  (v1 max)
SPP_MAX_LOCATOR_BYTES   decoded bytes per locator               default 8192 (v1 max)
SPP_MAX_PARENTS         parents per pointer                     default 1024 (v1 max)
SPP_BLOCK_ACTOR         reject this actor id, if set            default unset
SPP_BLOCK_CHANNEL       reject this channel id, if set          default unset
```

The three locator/parent limits are local policy clamped to the v1 maxima (§5).
The discovery manifest `policy` object reports all five numeric limits.
Exceeding a locally advertised limit is a `403` policy rejection and is never a
statement that the assertion is protocol-invalid (§21, §22).

Local policy is separate from protocol validity. A relay rejection is never a
statement that the assertion is protocol-invalid (`§21`, `§22`).

## HTTP interface (frozen `§27`/`§28`)

```text
GET  /.well-known/spp                              discovery manifest
POST /v1/assertions                                submit one signed assertion
GET  /v1/assertions/sha256/<64hex>                 retrieve one assertion
GET  /v1/channels                                  list advertised channel ids
GET  /v1/channels/sha256/<64hex>/assertions        channel assertion list
GET  /v1/objects/sha256/<64hex>/assertions         object-index assertion list
```

Submit responses: `200` accepted (immediately retrievable) or idempotent
duplicate; `400` protocol-invalid or unsupported; `403` local-policy rejection.

`GET /v1/channels` lists only advertised channels. A channel-type assertion
advertises its own id. A pointer in a capability/unlisted channel is readable at
`GET /v1/channels/sha256/<64hex>/assertions` but does not make that channel
advertised.

Lists return `{"items": [...], "next": <token|null>}`. `next` is an opaque
unpadded-base64url cursor; a query value that does not match the base64url
alphabet is rejected with `400 Bad Request`. v1 guarantees no snapshot stability
across concurrent inserts.

## Storage

SQLite in WAL mode; every admission commits transactionally.

```text
assertions            seq, id UNIQUE, envelope BLOB, type, actor,
                      channel, object_hash, accepted_at
advertised_channels   channel PRIMARY KEY, assertion_id
indexes               assertions(channel), assertions(object_hash), assertions(actor)
```

`envelope` is the canonical complete signed assertion. Index derivation happens
only after `§20` validation succeeds:

```text
pointer   channel = U.channel       object_hash = U.ref.hash
channel   channel = assertion.id    object_hash = U.descriptor.hash (if present)
```

A stored assertion always independently revalidates to the id under which it is
indexed; signed members are never altered.

## Durability

Stop and restart with the same `--db`:

```text
python implementations/relay/server.py --db ./relay.sqlite3
```

Ids, canonical bytes, advertised channels, and all indexes survive unchanged. No
client state is needed to rebuild the relay.

## Tests

```text
python implementations/relay/test_relay.py
```

Starts the relay against a temporary database and covers fresh startup, pointer
and channel acceptance, invalid/unsupported rejection, duplicates, assertion
GET, channel and object indexes, advertised channels, capability channels,
pagination, malformed cursors, the local PoW multiplier, the serve/revalidate
identity invariant, concurrent submissions, restart persistence, and a source
guard that no referenced content is fetched. It is also run by
`ci/run_conformance.py`.
