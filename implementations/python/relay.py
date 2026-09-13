#!/usr/bin/env python3
"""Tiny §28 HTTP relay. Uses Python reference validation. No shared server with TypeScript."""

from __future__ import annotations

import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from jcs import canonicalize_bytes  # noqa: E402
from protocol import SppError, UnsupportedError, validate_bytes  # noqa: E402
from json_input import parse_object  # noqa: E402

MAX_H = (1 << 256) - 1
HEX64 = 64
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class Store:
    def __init__(self) -> None:
        self.envelopes: dict[str, dict] = {}
        self.order: list[str] = []
        self.channel_of: dict[str, list[str]] = {}
        self.object_of: dict[str, list[str]] = {}
        self.advertised: list[str] = []
        self.multiplier = max(1, int(os.environ.get("SPP_POW_MULTIPLIER", "1")))
        self.max_record = int(os.environ.get("SPP_MAX_RECORD_BYTES", "65536"))
        self.page = max(1, int(os.environ.get("SPP_PAGE_SIZE", "2")))
        self.block_actor = os.environ.get("SPP_BLOCK_ACTOR", "")
        self.block_channel = os.environ.get("SPP_BLOCK_CHANNEL", "")

    def put(self, env: dict, ident: str) -> None:
        digest = ident[7:]
        if digest in self.envelopes:
            return
        self.envelopes[digest] = env
        self.order.append(digest)
        u = {k: v for k, v in env.items() if k not in ("id", "sig")}
        if u.get("type") == "channel":
            self.advertised.append(digest)
            self.channel_of.setdefault(digest, []).append(digest)
            desc = u.get("descriptor") or {}
            h = desc.get("hash")
            if isinstance(h, str) and h.startswith("sha256:"):
                self.object_of.setdefault(h[7:], []).append(digest)
        elif u.get("type") == "pointer":
            ch = str(u.get("channel", ""))
            if ch.startswith("sha256:"):
                self.channel_of.setdefault(ch[7:], []).append(digest)
            ref = u.get("ref") or {}
            h = ref.get("hash")
            if isinstance(h, str) and h.startswith("sha256:"):
                self.object_of.setdefault(h[7:], []).append(digest)


STORE = Store()


def page(items: list[str], cursor: str | None) -> tuple[list[str], str | None]:
    try:
        start = int(cursor) if cursor else 0
    except ValueError:
        raise ValueError("bad-cursor")  # handled by the request layer
    start = max(0, start)
    chunk = items[start : start + STORE.page]
    nxt = start + len(chunk)
    return chunk, (str(nxt) if nxt < len(items) else None)


def local_work_ok(ident: str, units: int) -> bool:
    h = int(ident[7:], 16)
    return h <= MAX_H // (units * 65536 * STORE.multiplier)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("relay-a: " + fmt % args + "\n")

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
        path = urlparse(self.path).path
        q = parse_qs(urlparse(self.path).query)
        cursor = q.get("cursor", [None])[0]
        if cursor is not None:
            try:
                int(cursor)
            except ValueError:
                return self._err(400, "bad_cursor", "cursor must be an integer")
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
                    "bootstrap_channels": [],
                    "policy": {
                        "pow_multiplier": STORE.multiplier,
                        "max_record_bytes": STORE.max_record,
                    },
                },
            )
        if path == "/v1/channels":
            ids, nxt = page([f"sha256:{h}" for h in STORE.advertised], cursor)
            return self._send(200, {"items": ids, "next": nxt})
        parts = path.strip("/").split("/")
        if parts[:3] == ["v1", "assertions", "sha256"] and len(parts) == 4:
            if not HEX64_RE.fullmatch(parts[3]):
                return self._err(404, "not_found", "route")
            env = STORE.envelopes.get(parts[3])
            if not env:
                return self._err(404, "not_found", "unknown assertion")
            return self._send(200, canonicalize_bytes(env))
        if parts[:3] == ["v1", "channels", "sha256"] and len(parts) == 5 and parts[4] == "assertions":
            if not HEX64_RE.fullmatch(parts[3]):
                return self._err(404, "not_found", "route")
            ids, nxt = page(STORE.channel_of.get(parts[3], []), cursor)
            items = [STORE.envelopes[i] for i in ids]
            return self._send(200, {"items": items, "next": nxt})
        if parts[:3] == ["v1", "objects", "sha256"] and len(parts) == 5 and parts[4] == "assertions":
            if not HEX64_RE.fullmatch(parts[3]):
                return self._err(404, "not_found", "route")
            ids, nxt = page(STORE.object_of.get(parts[3], []), cursor)
            items = [STORE.envelopes[i] for i in ids]
            return self._send(200, {"items": items, "next": nxt})
        return self._err(404, "not_found", "route")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/v1/assertions":
            return self._err(404, "not_found", "route")
        enc = self.headers.get("Content-Encoding", "")
        if enc and enc.lower() not in ("identity",):
            return self._err(400, "bad_encoding", "non-identity Content-Encoding")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype not in ("application/json", "application/spp+json"):
            return self._err(400, "bad_type", "Content-Type")
        n = int(self.headers.get("Content-Length") or "0")
        if n > STORE.max_record:
            return self._err(400, "too_large", "max_record_bytes")
        body = self.rfile.read(n)
        if len(body) > STORE.max_record:
            return self._err(400, "too_large", "max_record_bytes")
        try:
            info = validate_bytes(body)
        except UnsupportedError as e:
            return self._err(400, "unsupported_assertion", e.reason)
        except SppError as e:
            return self._err(400, "invalid_assertion", f"{e.stage}:{e.reason}")
        env = parse_object(body)
        actor = str(env.get("actor", ""))
        channel = str(env.get("channel", ""))
        if STORE.block_actor and actor == STORE.block_actor:
            return self._err(403, "policy", "actor blocked")
        if STORE.block_channel and channel == STORE.block_channel:
            return self._err(403, "policy", "channel blocked")
        if not local_work_ok(info["id"], info["units"]):
            return self._err(403, "policy", "local proof-of-work multiplier")
        existed = info["id"][7:] in STORE.envelopes
        STORE.put(env, info["id"])
        self._send(200, {"id": info["id"], "duplicate": existed})


def main() -> None:
    port = 18760
    args = sys.argv[1:]
    if "--port" in args:
        port = int(args[args.index("--port") + 1])
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"relay-a http://127.0.0.1:{port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
