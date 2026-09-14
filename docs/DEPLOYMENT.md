# SPP v1 relay deployment and operations

Operator guide for running the durable SPP v1 relay in `implementations/relay/` as a public
endpoint. It complements `implementations/relay/README.md` (the relay's own behaviour and HTTP
interface) with the surrounding environment the frozen profile assumes but does
not specify.

Normative references: `spec/SPP-v1-Core-Protocol-Specification.md` §10 (channel
secrecy), §21–§22 (local work policy and admission), §27 (discovery manifest),
§28 (HTTP profile), §34 (threat model).

## Live reference relay

```text
https://spp.drefetr.net
```

It is an ordinary frozen v1 relay: the process is `implementations/relay/server.py` with the
default local policy and one configured bootstrap channel. Observed discovery
manifest (2026-09-14):

```json
{
  "v": 1,
  "submit": "/v1/assertions",
  "channels": "/v1/channels",
  "assertion": "/v1/assertions/sha256/{hex}",
  "channel": "/v1/channels/sha256/{hex}/assertions",
  "object": "/v1/objects/sha256/{hex}/assertions",
  "bootstrap_channels": [
    "sha256:00000a3d6190118e7f764ad792bf0dbc50a25a25592e6287b0067141f974f839"
  ],
  "policy": {
    "pow_multiplier": 1,
    "max_record_bytes": 65536,
    "max_locators": 256,
    "max_locator_bytes": 8192,
    "max_parents": 1024
  }
}
```

The bootstrap channel is an advertised seed: a channel-description assertion
whose `descriptor` locators point at the project repository, plus a pointer to
the same object. It is a discovery hint only — not ownership, and not a validity
rule.

Confirm it from any host:

```text
curl https://spp.drefetr.net/.well-known/spp
```

## Topology

The relay serves **plain HTTP** and has no TLS support of its own. It is meant
to bind loopback and sit behind a TLS-terminating reverse proxy:

```text
clients ── HTTPS (443) ──> reverse proxy ── HTTP ──> implementations/relay/server.py (127.0.0.1:18760)
                                                            │
                                                            └── SQLite (WAL)
```

Terminating TLS is not optional in practice. §10 states that a relay operator
learns any channel ID submitted to it, and that plaintext HTTP exposes the ID in
the request path; HTTPS is particularly important when secrecy of the identifier
matters. Capability / unlisted channels provide discoverability-by-possession
only — HTTPS protects the identifier in transit, not the channel contents.

## Requirements

- Python 3.10+ (the module uses `X | None` type syntax)
- SQLite via the standard-library `sqlite3` module
- No third-party Python packages
- A reverse proxy with TLS (Caddy, nginx, etc.)

## Run

```text
python implementations/relay/server.py \
    --host 127.0.0.1 \
    --port 18760 \
    --db /var/lib/spp/relay.sqlite3 \
    --page-size 32
```

Defaults and environment overrides are documented in `implementations/relay/README.md`. In
production, always pass an explicit `--db` on durable storage and bind to
loopback (`--host 127.0.0.1`); the default `./relay.sqlite3` is relative to the
working directory.

## Local policy

Policy is relay-local and is separate from protocol validity: a relay rejection
is never a statement that an assertion is protocol-invalid (§21–§22).

```text
SPP_POW_MULTIPLIER      local extra work factor, integer >= 1   live: 1
SPP_MAX_RECORD_BYTES    maximum raw request body, octets        live: 65536
SPP_MAX_LOCATORS        locators per reference object           default: 256  (v1 max)
SPP_MAX_LOCATOR_BYTES   decoded bytes per locator               default: 8192 (v1 max)
SPP_MAX_PARENTS         parents per pointer                     default: 1024 (v1 max)
SPP_BLOCK_ACTOR         reject this actor id, if set            live: unset
SPP_BLOCK_CHANNEL       reject this channel id, if set          live: unset
```

To raise the cost of bulk publishing on a public relay, increase
`SPP_POW_MULTIPLIER` and restart. Note that a relay-local multiplier causes the
relay to reject otherwise protocol-valid assertions produced at the protocol
minimum; those assertions remain valid elsewhere (§21). Advertise the value you
enforce — the manifest reports `pow_multiplier`.

### Manifest note

The relay advertises the full §27 `policy` set — `pow_multiplier`,
`max_record_bytes`, `max_locators`, `max_locator_bytes`, and `max_parents`
(defaults are the v1 maxima from §5) — and `bootstrap_channels` from its
optional configuration file (default `[]`). A fresh client with no configured
seed therefore has no advertised channel to discover; capability channels are
reachable only with the channel id in hand (§29).

To publish a seed channel, set `bootstrap_channels` in a relay configuration
file passed with `--config`:

```json
{
  "bootstrap_channels": ["sha256:<64hex>"]
}
```

See `implementations/relay/relay.config.example.json`. The manifest is public,
so a bootstrap entry should be an advertised seed channel rather than a
capability channel, and some relay must carry the channel's assertions for the
hint to lead anywhere. The live instance advertises the full policy set and the
seed channel above.

## TLS and reverse proxy

The relay does not redirect, set HSTS, or negotiate certificates. Do all of that
at the proxy. Example configurations (adapt to your environment):

### Caddy

```text
spp.drefetr.net {
    reverse_proxy 127.0.0.1:18760
    request_body {
        max_size 64KB
    }
}
```

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name spp.drefetr.net;

    ssl_certificate     /etc/letsencrypt/live/spp.drefetr.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/spp.drefetr.net/privkey.pem;

    client_max_body_size 64k;

    location / {
        proxy_pass http://127.0.0.1:18760;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}

server {
    listen 80;
    server_name spp.drefetr.net;
    return 301 https://$host$request_uri;
}
```

Keep the proxy body limit at or below `SPP_MAX_RECORD_BYTES` so oversized bodies
are rejected at the edge with an HTTP status rather than reaching the relay.

### Cloudflare and other CDNs

The live relay is fronted by Cloudflare. Cloudflare's browser-integrity
heuristics can reject API clients that do not present a browser-like signature —
for example a bare `urllib` request with the default `User-Agent`, returned as
**Error 1010**. SPP v1 requires no particular `User-Agent`, so this is edge
transport policy, not a protocol decision. If machine clients are rejected,
exempt the relay host from the browser-integrity check, or have clients send a
stable identifying `User-Agent` (see `examples/agent-a/README.md`).

## Abuse control and observability

The relay itself has **no** built-in rate limiting, connection limiting, or
request timeout. §22 permits a relay to reject rate-limited sources, but the
implementation leaves that to the deployment layer. On a public endpoint:

- apply per-IP connection/request rate limits and a request timeout at the proxy;
- keep `SPP_MAX_RECORD_BYTES` modest (the live value is 65536);
- raise `SPP_POW_MULTIPLIER` if bulk publishing becomes a problem;
- block abusive actors/channels with `SPP_BLOCK_ACTOR` / `SPP_BLOCK_CHANNEL`;
- configure request logging deliberately (see below);
- watch database growth and disk headroom; SPP provides no deletion or storage
  guarantee (§33).

### Request logging

Request logging is deployment-local and operator-controlled. The reference
implementation makes no guarantee about it: it may log, may not log, and may
change at any time. Do not rely on a particular logging behaviour, and do not
treat the process output as either a guaranteed access log or a guaranteed
absence of one.

§10 capability channel IDs can appear in request paths, so any layer that
records request lines — the relay process, the systemd journal, or the reverse
proxy and any CDN in front of it — can persist the identifier. If secrecy of an
identifier matters, configure logging at the layers you control to avoid
capturing or to redact request paths, and account for journal/proxy retention
alongside the storage guidance below.

## Data and backups

State lives entirely in the SQLite database (WAL mode); a relay can be rebuilt
from it with no client state (`implementations/relay/README.md`, "Durability"). To take a
consistent backup, either stop the relay, or checkpoint and copy the database
plus its `-wal`/`-shm` files:

```text
sqlite3 /var/lib/spp/relay.sqlite3 ".backup '/backups/relay-$(date +%F).sqlite3'"
```

Restore by pointing `--db` at the copy. Do not run two relay processes against
the same database file; SQLite permits one writer.

## Process management

Run the relay as a supervised service so it restarts on failure and boot. The
repository ships a systemd unit template
([`deploy/spp-relay.service`](../deploy/spp-relay.service)) and an installer
([`deploy/install.sh`](../deploy/install.sh)) that creates the `spp` user,
clones the tree, writes a starter config at `/etc/spp/relay.conf.json`, installs
the unit, and starts the relay:

```text
sudo bash deploy/install.sh
# custom repo URL and install root:
sudo bash deploy/install.sh https://github.com/Drefetr/swarm-pointer-protocol /opt/spp
```

Re-running the installer updates the tree in place (`git pull`) and restarts the
service; it never touches the database. To install by hand, create the account
and data directory, place the tree at a fixed path, substitute the install-root
placeholder in the template, and copy it to
`/etc/systemd/system/spp-relay.service`. The unit uses an absolute `ExecStart`
and passes `--config`:

```ini
[Unit]
Description=SPP v1 durable relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=spp
Group=spp
WorkingDirectory=/opt/spp
Environment=SPP_MAX_RECORD_BYTES=65536
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 /opt/spp/implementations/relay/server.py \
    --host 127.0.0.1 \
    --port 18760 \
    --db /var/lib/spp/relay.sqlite3 \
    --config /etc/spp/relay.conf.json
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/spp

[Install]
WantedBy=multi-user.target
```

After editing a unit, run `systemctl daemon-reload` before restarting.

## Health and verification

The relay has no dedicated health route; the discovery manifest is the liveness
check:

```text
curl -fsS https://spp.drefetr.net/.well-known/spp
curl -fsS https://spp.drefetr.net/v1/channels
```

An empty/unknown capability channel reads as an empty list, not a 404:

```text
curl -fsS https://spp.drefetr.net/v1/channels/sha256/<64hex>/assertions
```

## Federation

This relay federates like any other SPP client. `implementations/relay/federation/sync.py`
reads the source's public surface and posts accepted assertions to the
destination, both over ordinary HTTP:

```text
python implementations/relay/federation/sync.py \
    --source https://spp.drefetr.net \
    --destination https://<other-relay> \
    [--channel sha256:<64hex>]
```

Run it from cron/systemd timer for periodic catch-up. Federation is not
consensus and is not mandatory mirroring; destination policy still applies
(`implementations/relay/federation/README.md`).

## Upgrade discipline

v1 is frozen. Deployments may pick up implementation fixes and non-normative
documentation, but the accepted-byte-string set, assertion identity, signature
input, proof-of-work, maxima, and the HTTP profile must not change under
`v = 1`. Any objective-validity change is a new assertion version (§ Appendix C
of the protocol specification). Upgrading the relay in place against the same `--db` is safe:
persisted ids, canonical bytes, advertised channels, and indexes survive.
