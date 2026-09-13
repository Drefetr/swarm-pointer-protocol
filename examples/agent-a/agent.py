#!/usr/bin/env python3
"""SPP v1 demo actor — Agent A (Python).

This is an acting SPP client, not a relay. It owns an Ed25519 identity and a
content-addressed object store, mines and signs pointer assertions, submits
them to a relay, polls a capability channel, independently validates every
received assertion with the frozen `impl-a` verifier, fetches referenced
objects from their locators, and accepts payloads only after the §23 SHA-256
check.

The relay is never trusted for validity: every fetched assertion is re-checked
against the complete §20 profile here.

Commands:
    init     create identity + state directory
    status   print actor, seen ids, stored objects
    publish  store a file as an external object and publish a pointer
    poll     read a channel, validate, fetch, and verify referenced objects
    serve    run the agent's object HTTP server
    submit   post a raw assertion file to a relay (transport-level action)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "implementations" / "python"))

from ed25519_spp import public_from_private, sign  # noqa: E402
from jcs import canonicalize_bytes  # noqa: E402
from protocol import (  # noqa: E402
    MAX_NONCE,
    SppError,
    UnsupportedError,
    target_for_units,
    validate_bytes,
    work_units,
)

SHA256_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_FETCH_BYTES = 16 * 1024 * 1024
FETCH_TIMEOUT = 20.0
USER_AGENT = "SPP-Agent-A/1"


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #

def state_paths(state_dir: Path) -> dict:
    return {
        "dir": state_dir,
        "key": state_dir / "key.hex",
        "state": state_dir / "state.json",
        "objects": state_dir / "objects",
        "published": state_dir / "published",
    }


def load_state(state_dir: Path) -> tuple[dict, bytes]:
    p = state_paths(state_dir)
    if not p["key"].exists() or not p["state"].exists():
        raise SystemExit(f"agent A not initialised in {state_dir} (run: init)")
    key = bytes.fromhex(p["key"].read_text(encoding="ascii").strip())
    state = json.loads(p["state"].read_text(encoding="utf-8"))
    return state, key


def save_state(state_dir: Path, state: dict) -> None:
    p = state_paths(state_dir)
    tmp = p["state"].with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    tmp.replace(p["state"])


def store_object(state_dir: Path, data: bytes) -> tuple[str, str]:
    h = hashlib.sha256(data).hexdigest()
    p = state_paths(state_dir)
    p["objects"].mkdir(parents=True, exist_ok=True)
    obj = p["objects"] / h
    if not obj.exists():
        obj.write_bytes(data)
    return "sha256:" + h, h


# --------------------------------------------------------------------------- #
# mining / signing
# --------------------------------------------------------------------------- #

def mine(U: dict, private_key: bytes) -> dict:
    """Mine a v1 assertion for U (which must not carry `nonce`) and sign it.

    Only the nonce value changes between candidates inside one digit-width
    block, so the canonical template is built once per width and the decimal
    nonce digits are patched in place. Every produced envelope is then put
    through the frozen impl-a verifier, so a producer optimisation can never
    yield a non-valid assertion.
    """
    base = {k: v for k, v in U.items() if k != "nonce"}
    for width in range(1, 21):
        lo = 0 if width == 1 else 10 ** (width - 1)
        hi = 9 if width == 1 else 10 ** width - 1
        if lo > MAX_NONCE:
            break
        hi = min(hi, MAX_NONCE)
        placeholder = "0" if width == 1 else "1" + "0" * (width - 1)
        template = canonicalize_bytes({**base, "nonce": placeholder})
        marker = b'"nonce":"'
        idx = template.find(marker)
        if idx < 0:  # pragma: no cover - defensive
            raise SppError("work", "nonce-not-found")
        off = idx + len(marker)
        units = work_units(base, len(template))
        target = target_for_units(units)
        buf = bytearray(template)
        for n in range(lo, hi + 1):
            digits = str(n) if width == 1 else f"{n:0{width}d}"
            buf[off:off + width] = digits.encode("ascii")
            digest = hashlib.sha256(buf).digest()
            if int.from_bytes(digest, "big") <= target:
                ident = "sha256:" + digest.hex()
                env = dict(base)
                env["nonce"] = digits
                env["id"] = ident
                env["sig"] = sign(private_key, digest).hex()
                raw = canonicalize_bytes(env)
                info = validate_bytes(raw)
                if info["id"] != ident:  # pragma: no cover - defensive
                    raise SppError("identity", "mined-id-mismatch")
                return env
    raise SppError("work", "nonce-space-exhausted")


# --------------------------------------------------------------------------- #
# http
# --------------------------------------------------------------------------- #

def http_raw(method: str, url: str, body: bytes | None = None,
             headers: dict | None = None, timeout: float = 30.0) -> tuple[int, bytes]:
    merged = {"User-Agent": USER_AGENT}
    if headers:
        merged.update(headers)
    req = urllib.request.Request(url, data=body, method=method, headers=merged)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def fetch_object(locator: str) -> bytes:
    """Fetch one finite octet stream. Locators are hostile input (§24)."""
    scheme = urlparse(locator).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"refused scheme: {scheme!r}")
    req = urllib.request.Request(locator, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        data = resp.read(MAX_FETCH_BYTES + 1)
    if len(data) > MAX_FETCH_BYTES:
        raise ValueError("object too large")
    return data


def relay_url(base: str, path: str) -> str:
    return base.rstrip("/") + path


def relay_list(args) -> list[str]:
    """Normalised, de-duplicated relay base URLs from a repeatable --relay."""
    out: list[str] = []
    for raw in getattr(args, "relay", None) or []:
        base = raw.rstrip("/")
        if base and base not in out:
            out.append(base)
    return out


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")


def cmd_init(args) -> int:
    d = Path(args.state)
    p = state_paths(d)
    d.mkdir(parents=True, exist_ok=True)
    p["objects"].mkdir(exist_ok=True)
    p["published"].mkdir(exist_ok=True)
    created = False
    if p["key"].exists():
        key = bytes.fromhex(p["key"].read_text(encoding="ascii").strip())
    else:
        key = secrets.token_bytes(32)
        p["key"].write_text(key.hex(), encoding="ascii")
        created = True
    actor = "ed25519:" + public_from_private(key).hex()
    if p["state"].exists():
        state = json.loads(p["state"].read_text(encoding="utf-8"))
    else:
        state = {"actor": actor, "seen": [], "published": [], "objects": []}
    state["actor"] = actor
    save_state(d, state)
    emit({"ok": True, "command": "init", "actor": actor, "state": str(d), "created": created})
    return 0


def cmd_status(args) -> int:
    state, _ = load_state(Path(args.state))
    emit({
        "ok": True,
        "command": "status",
        "actor": state["actor"],
        "seen": state["seen"],
        "published": state["published"],
        "objects": state["objects"],
    })
    return 0


def cmd_publish(args) -> int:
    d = Path(args.state)
    state, key = load_state(d)
    if not SHA256_ID.fullmatch(args.channel):
        raise SystemExit(f"invalid channel: {args.channel}")
    data = Path(args.file).read_bytes()
    object_hash, object_hex = store_object(d, data)
    locator = args.object_base.rstrip("/") + "/objects/sha256/" + object_hex
    created = args.created if args.created is not None else int(time.time())
    U = {
        "v": 1.0,
        "type": "pointer",
        "actor": state["actor"],
        "channel": args.channel,
        "created": float(created),
        "ref": {"hash": object_hash, "locators": [locator]},
    }
    if args.parents:
        U["parents"] = [x for x in args.parents.split(",") if x]
    env = mine(U, key)
    raw = canonicalize_bytes(env)
    ident = env["id"]

    saved = state_paths(d)["published"] / (ident.split(":", 1)[1] + ".json")
    saved.write_bytes(raw)

    relay_results: list[dict] = []
    stored = False
    first_status: int | None = None
    for base in relay_list(args):
        try:
            code, resp = http_raw(
                "POST",
                relay_url(base, "/v1/assertions"),
                raw,
                {"Content-Type": "application/json", "Content-Length": str(len(raw))},
            )
        except Exception as e:  # unreachable relay: tolerate, keep local status
            relay_results.append({"relay": base, "status": 0, "duplicate": False,
                                  "error": type(e).__name__})
            continue
        try:
            body = json.loads(resp.decode("utf-8"))
        except Exception:
            body = {"raw": resp.decode("utf-8", "replace")}
        relay_results.append({
            "relay": base,
            "status": code,
            "duplicate": bool(body.get("duplicate", False)),
            "error": body.get("error"),
        })
        if first_status is None:
            first_status = code
        if code == 200:
            stored = True

    accepted = [r for r in relay_results if r["status"] == 200]
    if stored:
        if object_hash not in state["objects"]:
            state["objects"].append(object_hash)
        if ident not in state["published"]:
            state["published"].append(ident)
        save_state(d, state)

    emit({
        "ok": stored,
        "command": "publish",
        "actor": state["actor"],
        "channel": args.channel,
        "assertion_id": ident,
        "object_hash": object_hash,
        "file": str(args.file),
        "status": first_status,
        "duplicate": all(r["duplicate"] for r in accepted) if accepted else False,
        "error": next((r["error"] for r in relay_results if r["status"] != 200), None),
        "stored": stored,
        "saved": str(saved),
        "object_base": args.object_base,
        "relays": relay_results,
    })
    return 0


def cmd_publish_channel(args) -> int:
    d = Path(args.state)
    state, key = load_state(d)
    created = args.created if args.created is not None else int(time.time())
    U = {"v": 1.0, "type": "channel", "actor": state["actor"], "created": float(created)}
    if args.descriptor_hash:
        U["descriptor"] = {"hash": args.descriptor_hash, "locators": list(args.descriptor_locator or [])}
    env = mine(U, key)
    raw = canonicalize_bytes(env)
    ident = env["id"]
    saved = state_paths(d)["published"] / (ident.split(":", 1)[1] + ".json")
    saved.write_bytes(raw)

    relay_results: list[dict] = []
    stored = False
    first_status: int | None = None
    for base in relay_list(args):
        try:
            code, resp = http_raw(
                "POST",
                relay_url(base, "/v1/assertions"),
                raw,
                {"Content-Type": "application/json", "Content-Length": str(len(raw))},
            )
        except Exception as e:
            relay_results.append({"relay": base, "status": 0, "duplicate": False,
                                  "error": type(e).__name__})
            continue
        try:
            body = json.loads(resp.decode("utf-8"))
        except Exception:
            body = {"raw": resp.decode("utf-8", "replace")}
        relay_results.append({
            "relay": base,
            "status": code,
            "duplicate": bool(body.get("duplicate", False)),
            "error": body.get("error"),
        })
        if first_status is None:
            first_status = code
        if code == 200:
            stored = True

    accepted = [r for r in relay_results if r["status"] == 200]
    if stored and ident not in state["published"]:
        state["published"].append(ident)
        save_state(d, state)
    emit({
        "ok": stored,
        "command": "publish-channel",
        "actor": state["actor"],
        "assertion_id": ident,
        "status": first_status,
        "duplicate": all(r["duplicate"] for r in accepted) if accepted else False,
        "error": next((r["error"] for r in relay_results if r["status"] != 200), None),
        "saved": str(saved),
        "relays": relay_results,
    })
    return 0


def cmd_submit(args) -> int:
    raw = Path(args.file).read_bytes()
    try:
        envelope = json.loads(raw.decode("utf-8"))
        ident = envelope.get("id")
    except Exception:
        envelope = {}
        ident = None

    relay_results: list[dict] = []
    first_status: int | None = None
    ok = False
    for base in relay_list(args):
        try:
            code, resp = http_raw(
                "POST",
                relay_url(base, "/v1/assertions"),
                raw,
                {"Content-Type": "application/json", "Content-Length": str(len(raw))},
            )
        except Exception as e:
            relay_results.append({"relay": base, "status": 0, "error": type(e).__name__})
            continue
        try:
            body = json.loads(resp.decode("utf-8"))
        except Exception:
            body = {"raw": resp.decode("utf-8", "replace")}
        relay_results.append({
            "relay": base,
            "status": code,
            "error": body.get("error"),
            "response_id": body.get("id"),
            "duplicate": bool(body.get("duplicate", False)),
        })
        if first_status is None:
            first_status = code
        if code == 200:
            ok = True

    emit({
        "ok": ok,
        "command": "submit",
        "status": first_status,
        "error": next((r.get("error") for r in relay_results if r["status"] != 200), None),
        "assertion_id": ident,
        "response_id": next((r.get("response_id") for r in relay_results
                             if r["status"] == 200), None),
        "duplicate": all(r.get("duplicate", False) for r in relay_results
                         if r["status"] == 200) if ok else False,
        "relays": relay_results,
    })
    return 0


def _list_page(base: str, path: str, cursor: str | None) -> tuple[dict, str | None]:
    url = relay_url(base, path)
    if cursor:
        url += "?cursor=" + cursor
    try:
        code, raw = http_raw("GET", url)
    except Exception as e:  # unreachable relay is local status, not a validity claim
        raise SppError("relay", f"GET {path} -> {type(e).__name__}") from e
    if code != 200:
        raise SppError("relay", f"GET {path} -> {code}")
    try:
        return json.loads(raw.decode("utf-8")), None
    except Exception as e:
        raise SppError("relay", f"GET {path} -> malformed-json") from e


def cmd_poll(args) -> int:
    d = Path(args.state)
    state, _ = load_state(d)
    if not SHA256_ID.fullmatch(args.channel):
        raise SystemExit(f"invalid channel: {args.channel}")
    seen = list(state["seen"])
    seen_set = set(seen)
    objects = list(state["objects"])
    object_set = set(objects)

    channel_hex = args.channel.split(":", 1)[1]
    path = f"/v1/channels/sha256/{channel_hex}/assertions"

    pages = 0
    discovered = 0
    results: list[dict] = []
    errors: list[str] = []
    relays: list[dict] = []
    processed: set[str] = set()

    def consider(base: str, env: dict) -> None:
        nonlocal discovered
        discovered += 1
        ser = json.dumps(env, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        try:
            info = validate_bytes(ser)
        except UnsupportedError as e:
            results.append({"assertion_id": env.get("id"), "valid": False,
                            "new": False, "reason": f"unsupported:{e.reason}",
                            "relay": base})
            return
        except SppError as e:
            results.append({"assertion_id": env.get("id"), "valid": False,
                            "new": False, "reason": f"{e.stage}:{e.reason}",
                            "relay": base})
            return

        aid = info["id"]
        if aid in processed:
            return
        processed.add(aid)
        if aid in seen_set:
            results.append({"assertion_id": aid, "valid": True, "new": False,
                            "type": env.get("type"), "reason": "duplicate",
                            "relay": base})
            return

        seen_set.add(aid)
        seen.append(aid)
        res = {
            "assertion_id": aid,
            "valid": True,
            "new": True,
            "type": env.get("type"),
            "actor": env.get("actor"),
            "object_hash": None,
            "locator": None,
            "fetched": False,
            "hash_ok": False,
            "stored": False,
            "reason": None,
            "relay": base,
        }
        if env.get("type") == "pointer":
            ref = env["ref"]
            want = ref["hash"]
            res["object_hash"] = want
            for loc in ref["locators"]:
                res["locator"] = loc
                try:
                    data = fetch_object(loc)
                except Exception as e:  # noqa: BLE001 - report, keep trying
                    res["reason"] = f"fetch:{type(e).__name__}"
                    continue
                res["fetched"] = True
                got = "sha256:" + hashlib.sha256(data).hexdigest()
                if got == want:
                    store_object(d, data)
                    if want not in object_set:
                        object_set.add(want)
                        objects.append(want)
                    res["hash_ok"] = True
                    res["stored"] = True
                    res["reason"] = None
                    break
                res["hash_ok"] = False
                res["reason"] = "hash-mismatch"
            if not res["fetched"] and res["reason"] is None:
                res["reason"] = "no-usable-locator"
            elif not res["fetched"]:
                res["reason"] = res["reason"] or "fetch-failed"
        results.append(res)

    # Query each relay separately. A relay is a local source of candidate
    # assertions, never the authority on identity: dedup is global by id.
    for base in relay_list(args):
        cursor: str | None = None
        relay_pages = 0
        relay_errors: list[str] = []
        while True:
            try:
                page, _ = _list_page(base, path, cursor)
            except SppError as e:
                relay_errors.append(str(e))
                errors.append(f"{base}: {e}")
                break
            relay_pages += 1
            for env in page.get("items", []):
                consider(base, env)
            cursor = page.get("next")
            if not cursor:
                break
        pages += relay_pages
        relays.append({"relay": base, "pages": relay_pages, "errors": relay_errors})

    state["seen"] = seen
    state["objects"] = objects
    save_state(d, state)
    emit({
        "ok": True,
        "command": "poll",
        "actor": state["actor"],
        "channel": args.channel,
        "pages": pages,
        "discovered": discovered,
        "new": sum(1 for r in results if r.get("new")),
        "valid": sum(1 for r in results if r.get("valid")),
        "invalid": sum(1 for r in results if not r.get("valid")),
        "stored": sum(1 for r in results if r.get("stored")),
        "results": results,
        "errors": errors,
        "relays": relays,
    })
    return 0


# --------------------------------------------------------------------------- #
# object server
# --------------------------------------------------------------------------- #

class _ObjectHandler(BaseHTTPRequestHandler):
    root: Path

    def log_message(self, fmt: str, *args) -> None:  # silence access log
        pass

    def _send(self, code: int, data: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/health":
            return self._send(200, b"ok", "text/plain")
        m = re.fullmatch(r"/objects/sha256/([0-9a-f]{64})", self.path)
        if not m:
            return self._send(404, b"not found", "text/plain")
        obj = self.root / m.group(1)
        if not obj.is_file():
            return self._send(404, b"not found", "text/plain")
        return self._send(200, obj.read_bytes(), "application/octet-stream")


def cmd_serve(args) -> int:
    state, _ = load_state(Path(args.state))
    _ObjectHandler.root = state_paths(Path(args.state))["objects"]
    httpd = ThreadingHTTPServer((args.host, args.port), _ObjectHandler)
    emit({"ok": True, "command": "serve", "actor": state["actor"],
          "host": args.host, "port": args.port})
    httpd.serve_forever()
    return 0


# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="SPP v1 demo actor — Agent A (Python)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init")
    p.add_argument("--state", required=True)

    p = sub.add_parser("status")
    p.add_argument("--state", required=True)

    p = sub.add_parser("publish")
    p.add_argument("--state", required=True)
    p.add_argument("--relay", required=True, action="append",
                   help="relay base URL (repeatable; submit to each)")
    p.add_argument("--channel", required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--object-base", required=True)
    p.add_argument("--parents", default="")
    p.add_argument("--created", type=int, default=None)

    p = sub.add_parser("poll")
    p.add_argument("--state", required=True)
    p.add_argument("--relay", required=True, action="append",
                   help="relay base URL (repeatable; query each)")
    p.add_argument("--channel", required=True)

    p = sub.add_parser("publish-channel")
    p.add_argument("--state", required=True)
    p.add_argument("--relay", required=True, action="append",
                   help="relay base URL (repeatable)")
    p.add_argument("--descriptor-hash", default=None)
    p.add_argument("--descriptor-locator", action="append", default=None)
    p.add_argument("--created", type=int, default=None)

    p = sub.add_parser("submit")
    p.add_argument("--relay", required=True, action="append",
                   help="relay base URL (repeatable)")
    p.add_argument("--file", required=True)

    p = sub.add_parser("serve")
    p.add_argument("--state", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return {
        "init": cmd_init,
        "status": cmd_status,
        "publish": cmd_publish,
        "publish-channel": cmd_publish_channel,
        "poll": cmd_poll,
        "submit": cmd_submit,
        "serve": cmd_serve,
    }[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
