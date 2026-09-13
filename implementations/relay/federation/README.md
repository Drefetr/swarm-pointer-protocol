# SPP v1 federation sync worker

A federation worker is an **ordinary SPP client**. SPP v1 defines no special
relay-to-relay protocol: a relay synchronizes from another relay by acting as a
client, independently validating retrieved assertions, and redistributing the
ones it chooses to accept through the destination's own admission path.

```text
source relay
    │  GET  (frozen §27/§28 public surface)
    ▼
sync worker
    │  local §20 validation with the impl-a verifier
    ▼
destination relay
    ▲  POST (ordinary submission, destination policy applies)
```

The worker never:

```text
copies relay databases
accesses relay internals
trusts source-side validation
forces destination acceptance
mutates an assertion
```

## Layout

```text
implementations/relay/federation/
    sync.py      the federation worker (an ordinary SPP client)
    README.md
```

## Requirements

- Python 3.10+
- No third-party packages
- It imports the verifier from `implementations/python/` (`protocol`)

## Usage

```text
python implementations/relay/federation/sync.py --source <url> --destination <url> [--channel sha256:<64hex>] [--log <file>]
```

### Advertised surface

Without `--channel`, the worker scrapes the source's advertised public surface,
exactly as the frozen federation model describes:

```text
GET /v1/channels
```

For each advertised channel id:

```text
GET /v1/assertions/sha256/<id>                 the channel assertion
GET /v1/channels/sha256/<id>/assertions        the channel's assertions
```

and follows every pagination cursor to `next == null`.

### Explicit capability channel

Capability channels are deliberately absent from `GET /v1/channels`. They are
reachable only by a client that already possesses the channel id:

```text
python implementations/relay/federation/sync.py \
  --source http://127.0.0.1:18760 \
  --destination http://127.0.0.1:18761 \
  --channel sha256:<C>
```

The worker then reads that one channel's assertion list and validates each
result independently.

## Behaviour

For every received assertion the worker:

```text
serialize -> frozen §20 validate -> POST /v1/assertions
```

- A protocol-invalid or corrupted assertion is rejected locally and is **never**
  submitted onward. The source relay is not treated as a trusted validator.
- A destination `4xx` is recorded as a **destination rejection**, not as a
  source invalidity. Federation is not consensus, and replication is not
  mandatory mirroring: protocol-valid does not imply accepted everywhere.
- Resubmitting an assertion already present at the destination stays harmless
  and idempotent.

Every run prints exactly one JSON diagnostics object:

```text
ok, command, source, destination, mode, channel, channels,
discovered, valid, invalid, forwarded, duplicates, rejected,
results[], errors[]
```

`--log <file>` appends the same JSON object as one line to that file.

## Relationship to the frozen profile

The worker only uses the public HTTP interface and the frozen validation
profile. It does not add any route, field, or wire behaviour. The v1
accepted-byte-string set, normative vectors, work rules, signature rules,
schema, and HTTP wire profile are unchanged.
