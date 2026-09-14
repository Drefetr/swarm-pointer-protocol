#!/usr/bin/env python3
"""SPP v1 durable HTTP relay.

A persistent SPP relay — not an application server. It receives signed
assertions, performs the complete frozen §20 validation using the Python reference
verifier, applies local policy, persists the canonical signed bytes, indexes
them, and serves the frozen §27/§28 HTTP profile.

It never fetches, hosts, or interprets referenced content: locators in `ref`
and `descriptor` are treated as opaque signed strings.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "implementations" / "python"))

from store import BadCursor, Store, decode_cursor  # noqa: E402
from jcs import canonicalize_bytes  # noqa: E402
from protocol import (  # noqa: E402
    SppError,
    UnsupportedError,
    parse_object,
    reconstruct_u,
    validate_bytes,
)

MAX_H = (1 << 256) - 1
UNIT_SCALE = 65536
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
SHA256_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# v1 protocol maxima (§5). Local policy limits are clamped to these.
PROTO_MAX_LOCATORS = 256
PROTO_MAX_LOCATOR_BYTES = 8192
PROTO_MAX_PARENTS = 1024


@dataclass
class Config:
    host: str = "127.0.0.1"
    port: int = 18760
    db: str = "./relay.sqlite3"
    page_size: int = 32
    pow_multiplier: int = 1
    max_record_bytes: int = 65536
    max_locators: int = PROTO_MAX_LOCATORS
    max_locator_bytes: int = PROTO_MAX_LOCATOR_BYTES
    max_parents: int = PROTO_MAX_PARENTS
    block_actor: str = ""
    block_channel: str = ""
    bootstrap_channels: tuple[str, ...] = ()


def local_work_ok(ident: str, units: int, multiplier: int) -> bool:
    h = int(ident[7:], 16)
    return h <= MAX_H // (units * UNIT_SCALE * multiplier)


def reference_locators(u: dict) -> list:
    ref = u.get("ref") if u.get("type") == "pointer" else u.get("descriptor")
    if isinstance(ref, dict):
        locs = ref.get("locators")
        if isinstance(locs, list):
            return locs
    return []


def list_body(items_json: bytes, nxt: str | None) -> bytes:
    nxt_b = b"null" if nxt is None else json.dumps(nxt).encode("ascii")
    return b'{"items":' + items_json + b',"next":' + nxt_b + b"}"


class Handler(BaseHTTPRequestHandler):
    server_version = "spp-relay/1"
    cfg: Config
    store: Store

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("spp-relay: " + fmt % args + "\n")

    def _send(self, code: int, body, ctype: str = "application/json") -> None:
        data = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _err(self, code: int, token: str, message: str) -> None:
        self._send(code, {"error": token, "message": message})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query, keep_blank_values=True)
        cursor = q.get("cursor", [None])[0]
        after_seq = 0
        if cursor is not None:
            try:
                after_seq = decode_cursor(cursor)
            except BadCursor as e:
                return self._err(400, "bad_cursor", str(e))

        if path == "/.well-known/spp":
            return self._send(
                200,
                {
                    "v": 1,
                    "submit": "/v1/assertions",
                    "channels": "/v1/channels",
                    "assertion": "/v1/assertions/sha256/{hex}",
                    "channel": "/v1/channels/sha256/{hex}/assertions",
                    "object": "/v1/objects/sha256/{hex}/assertions",
                    "bootstrap_channels": list(self.cfg.bootstrap_channels),
                    "policy": {
                        "pow_multiplier": self.cfg.pow_multiplier,
                        "max_record_bytes": self.cfg.max_record_bytes,
                        "max_locators": self.cfg.max_locators,
                        "max_locator_bytes": self.cfg.max_locator_bytes,
                        "max_parents": self.cfg.max_parents,
                    },
                },
            )

        if path == "/v1/channels":
            ids, nxt = self.store.advertised_channels(after_seq)
            items = json.dumps(ids, separators=(",", ":")).encode("utf-8")
            return self._send(200, list_body(items, nxt))

        parts = path.strip("/").split("/")
        if parts[:3] == ["v1", "assertions", "sha256"] and len(parts) == 4:
            if not HEX64_RE.fullmatch(parts[3]):
                return self._err(404, "not_found", "route")
            blob = self.store.get_assertion(parts[3])
            if blob is None:
                return self._err(404, "not_found", "unknown assertion")
            return self._send(200, blob)
        if parts[:3] == ["v1", "channels", "sha256"] and len(parts) == 5 and parts[4] == "assertions":
            if not HEX64_RE.fullmatch(parts[3]):
                return self._err(404, "not_found", "route")
            blobs, nxt = self.store.channel_assertions(parts[3], after_seq)
            return self._send(200, list_body(b"[" + b",".join(blobs) + b"]", nxt))
        if parts[:3] == ["v1", "objects", "sha256"] and len(parts) == 5 and parts[4] == "assertions":
            if not HEX64_RE.fullmatch(parts[3]):
                return self._err(404, "not_found", "route")
            blobs, nxt = self.store.object_assertions(parts[3], after_seq)
            return self._send(200, list_body(b"[" + b",".join(blobs) + b"]", nxt))
        return self._err(404, "not_found", "route")

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/v1/assertions":
            return self._err(404, "not_found", "route")
        enc = self.headers.get("Content-Encoding", "")
        if enc and enc.lower() != "identity":
            return self._err(400, "bad_encoding", "non-identity Content-Encoding")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype not in ("application/json", "application/spp+json"):
            return self._err(400, "bad_type", "Content-Type")
        try:
            n = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            return self._err(400, "bad_length", "Content-Length")
        if n < 0 or n > self.cfg.max_record_bytes:
            return self._err(400, "too_large", "max_record_bytes")
        body = self.rfile.read(n)
        if len(body) > self.cfg.max_record_bytes:
            return self._err(400, "too_large", "max_record_bytes")

        try:
            info = validate_bytes(body)
        except UnsupportedError as e:
            return self._err(400, "unsupported_assertion", e.reason)
        except SppError as e:
            return self._err(400, "invalid_assertion", f"{e.stage}:{e.reason}")

        # The exact received bytes passed §20. Reconstruct the complete signed
        # envelope from that same parse and store its canonical form. The
        # canonical envelope preserves U, so it revalidates to the same id.
        env = parse_object(body)
        canonical = canonicalize_bytes(env)

        actor = str(env.get("actor", ""))
        if self.cfg.block_actor and actor == self.cfg.block_actor:
            return self._err(403, "policy", "actor blocked")
        channel_field = str(env.get("channel", ""))
        if self.cfg.block_channel and channel_field == self.cfg.block_channel:
            return self._err(403, "policy", "channel blocked")
        if not local_work_ok(info["id"], info["units"], self.cfg.pow_multiplier):
            return self._err(403, "policy", "local proof-of-work multiplier")

        u = reconstruct_u(env)
        locators = reference_locators(u)
        if len(locators) > self.cfg.max_locators:
            return self._err(403, "policy", "max_locators")
        if any(len(s.encode("utf-8")) > self.cfg.max_locator_bytes for s in locators):
            return self._err(403, "policy", "max_locator_bytes")
        parents = u.get("parents")
        if isinstance(parents, list) and len(parents) > self.cfg.max_parents:
            return self._err(403, "policy", "max_parents")
        if u["type"] == "channel":
            channel = info["id"]
            descriptor = u.get("descriptor")
            object_hash = descriptor["hash"] if isinstance(descriptor, dict) else None
        else:
            channel = u["channel"]
            object_hash = u["ref"]["hash"]

        inserted = self.store.add(
            ident=info["id"],
            envelope=canonical,
            type_=u["type"],
            actor=actor,
            channel=channel,
            object_hash=object_hash,
        )
        return self._send(200, {"id": info["id"], "duplicate": not inserted})


class Relay(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class ConfigError(Exception):
    pass


def _pairs_no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ConfigError(f"duplicate config key: {key}")
        out[key] = value
    return out


def load_config_file(path: str) -> dict:
    """Load and validate the optional relay configuration file.

    The file is a JSON object. Unknown keys are rejected so that typos fail at
    startup rather than being silently ignored. The only defined key is
    ``bootstrap_channels``, a list of ``sha256:<64hex>`` identifiers served
    verbatim in the §27 discovery manifest.
    """
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"cannot read config {path}: {e}") from e
    try:
        data = json.loads(raw, object_pairs_hook=_pairs_no_duplicates)
    except json.JSONDecodeError as e:
        raise ConfigError(f"config {path} is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError("config root must be a JSON object")
    allowed = {"bootstrap_channels", "_comment"}
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigError("unknown config key(s): " + ", ".join(unknown))
    if "_comment" in data and not isinstance(data["_comment"], str):
        raise ConfigError("_comment must be a string")
    channels = data.get("bootstrap_channels", [])
    if not isinstance(channels, list):
        raise ConfigError("bootstrap_channels must be an array of sha256:<64hex> identifiers")
    seen: set[str] = set()
    for index, channel in enumerate(channels):
        if not isinstance(channel, str) or not SHA256_ID_RE.fullmatch(channel):
            raise ConfigError(f"bootstrap_channels[{index}] is not a sha256:<64hex> identifier")
        if channel in seen:
            raise ConfigError(f"duplicate bootstrap channel: {channel}")
        seen.add(channel)
    return {"bootstrap_channels": tuple(channels)}


def local_limit(env: dict, name: str, proto_max: int) -> int:
    return max(0, min(int(env.get(name, str(proto_max))), proto_max))


def build_config(argv: list[str] | None = None) -> Config:
    env = os.environ
    ap = argparse.ArgumentParser(description="SPP v1 durable HTTP relay")
    ap.add_argument("--host", default=env.get("SPP_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(env.get("SPP_PORT", "18760")))
    ap.add_argument("--db", default=env.get("SPP_DB", "./relay.sqlite3"))
    ap.add_argument("--page-size", type=int, default=int(env.get("SPP_PAGE_SIZE", "32")))
    ap.add_argument("--config", default=None, metavar="PATH", help="optional JSON relay configuration file")
    args = ap.parse_args(argv)
    bootstrap_channels: tuple[str, ...] = ()
    if args.config:
        try:
            bootstrap_channels = load_config_file(args.config)["bootstrap_channels"]
        except ConfigError as e:
            raise SystemExit(f"spp-relay: {e}")
    return Config(
        host=args.host,
        port=args.port,
        db=args.db,
        page_size=max(1, args.page_size),
        pow_multiplier=max(1, int(env.get("SPP_POW_MULTIPLIER", "1"))),
        max_record_bytes=int(env.get("SPP_MAX_RECORD_BYTES", "65536")),
        max_locators=local_limit(env, "SPP_MAX_LOCATORS", PROTO_MAX_LOCATORS),
        max_locator_bytes=local_limit(env, "SPP_MAX_LOCATOR_BYTES", PROTO_MAX_LOCATOR_BYTES),
        max_parents=local_limit(env, "SPP_MAX_PARENTS", PROTO_MAX_PARENTS),
        block_actor=env.get("SPP_BLOCK_ACTOR", ""),
        block_channel=env.get("SPP_BLOCK_CHANNEL", ""),
        bootstrap_channels=bootstrap_channels,
    )


def main(argv: list[str] | None = None) -> None:
    cfg = build_config(argv)
    Handler.cfg = cfg
    Handler.store = Store(cfg.db, cfg.page_size)
    httpd = Relay((cfg.host, cfg.port), Handler)
    print(f"spp-relay http://{cfg.host}:{cfg.port} db={cfg.db}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
