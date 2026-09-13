#!/usr/bin/env python3
"""SPP v1 federation sync worker.

A federation worker is an ordinary SPP client, not a relay and not a special
relay-to-relay protocol. It reads assertions from a *source* relay over the
frozen public interface, independently revalidates every one of them with the
`impl-a` verifier, and submits the valid ones to a *destination* relay where
local policy decides acceptance.

It never:

    copies relay databases
    accesses relay internals
    trusts source-side validation
    forces destination acceptance
    mutates an assertion

Two public synchronization modes are supported:

    advertised
        Scrape the source's advertised public surface: GET /v1/channels, then
        for each advertised channel id GET the channel assertion and its
        channel assertion list. This is the exact v1 federation model.

    channel
        Explicitly synchronize one capability channel by id. Capability
        channels are deliberately absent from GET /v1/channels, so they are
        reachable only by a client that already possesses the channel id.

Usage:
    python implementations/relay/federation/sync.py --source URL --destination URL [--channel ID] [--log FILE]

Every run prints exactly one JSON diagnostics object.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "implementations" / "python"))

from protocol import SppError, UnsupportedError, validate_bytes  # noqa: E402

SHA256_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FETCH_TIMEOUT = 20.0


def relay_url(base: str, path: str) -> str:
    return base.rstrip("/") + path


def http_get_json(url: str) -> tuple[int, object | None]:
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, None
    except Exception:
        return 0, None


def http_post_json(url: str, raw: bytes) -> tuple[int, object | None]:
    req = urllib.request.Request(
        url,
        data=raw,
        method="POST",
        headers={"Content-Type": "application/json", "Content-Length": str(len(raw))},
    )
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            try:
                return resp.status, json.loads(resp.read().decode("utf-8"))
            except Exception:
                return resp.status, None
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, None
    except Exception:
        return 0, None


def list_advertised(base: str) -> tuple[list[str], list[str]]:
    ids: list[str] = []
    errors: list[str] = []
    cursor: str | None = None
    while True:
        url = relay_url(base, "/v1/channels")
        if cursor:
            url += "?cursor=" + cursor
        code, page = http_get_json(url)
        if code != 200 or not isinstance(page, dict):
            errors.append(f"GET /v1/channels -> {code}")
            break
        ids.extend(x for x in page.get("items", []) if isinstance(x, str))
        cursor = page.get("next")
        if not cursor:
            break
    return ids, errors


def list_channel(base: str, channel_hex: str) -> tuple[list[dict], list[str]]:
    items: list[dict] = []
    errors: list[str] = []
    cursor: str | None = None
    path = f"/v1/channels/sha256/{channel_hex}/assertions"
    while True:
        url = relay_url(base, path)
        if cursor:
            url += "?cursor=" + cursor
        code, page = http_get_json(url)
        if code != 200 or not isinstance(page, dict):
            errors.append(f"GET {path} -> {code}")
            break
        items.extend(x for x in page.get("items", []) if isinstance(x, dict))
        cursor = page.get("next")
        if not cursor:
            break
    return items, errors


def channel_hex_of(value: str) -> str | None:
    if SHA256_ID.fullmatch(value):
        return value.split(":", 1)[1]
    if HEX64.fullmatch(value):
        return value
    return None


def sync(source: str, destination: str, channel: str | None,
         log_path: str | None) -> int:
    errors: list[str] = []
    channels: list[str] = []

    if channel is not None:
        hexid = channel_hex_of(channel)
        if hexid is None:
            print(json.dumps({"ok": False, "command": "sync",
                              "error": f"invalid channel {channel}"},
                             separators=(",", ":")))
            return 2
        channels = ["sha256:" + hexid]
        mode = "channel"
    else:
        channels, adv_errors = list_advertised(source)
        errors.extend(adv_errors)
        mode = "advertised"

    # Gather candidate items. Each item is (channel_id, envelope_object).
    gathered: list[tuple[str, dict]] = []
    for cid in channels:
        hexid = cid.split(":", 1)[1]
        items, ch_errors = list_channel(source, hexid)
        errors.extend(ch_errors)
        for env in items:
            gathered.append((cid, env))
        if mode == "advertised":
            # Retrieve the advertised channel-description assertion itself.
            code, one = http_get_json(
                relay_url(source, f"/v1/assertions/sha256/{hexid}")
            )
            if code == 200 and isinstance(one, dict):
                gathered.append((cid, one))

    results: list[dict] = []
    processed: set[str] = set()
    valid = invalid = forwarded = duplicates = rejected = 0

    for cid, env in gathered:
        try:
            raw = json.dumps(env, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except Exception as e:  # noqa: BLE001 - malformed source item
            invalid += 1
            results.append({"channel": cid, "assertion_id": env.get("id"),
                            "valid": False, "reason": f"encode:{type(e).__name__}",
                            "forwarded": False})
            continue

        # Independent §20 validation. The source relay is never trusted.
        try:
            info = validate_bytes(raw)
            aid = info["id"]
            valid += 1
        except UnsupportedError as e:
            invalid += 1
            results.append({"channel": cid, "assertion_id": env.get("id"),
                            "valid": False, "reason": f"unsupported:{e.reason}",
                            "forwarded": False})
            continue
        except SppError as e:
            invalid += 1
            results.append({"channel": cid, "assertion_id": env.get("id"),
                            "valid": False, "reason": f"{e.stage}:{e.reason}",
                            "forwarded": False})
            continue
        except Exception as e:  # noqa: BLE001 - defensive
            invalid += 1
            results.append({"channel": cid, "assertion_id": env.get("id"),
                            "valid": False, "reason": f"error:{type(e).__name__}",
                            "forwarded": False})
            continue

        if aid in processed:
            continue
        processed.add(aid)

        code, body = http_post_json(relay_url(destination, "/v1/assertions"), raw)
        if code == 200:
            dup = bool(body.get("duplicate")) if isinstance(body, dict) else False
            if dup:
                duplicates += 1
            else:
                forwarded += 1
            results.append({
                "channel": cid,
                "assertion_id": aid,
                "valid": True,
                "reason": None,
                "destination_status": code,
                "duplicate": dup,
                "forwarded": not dup,
            })
        else:
            # Destination policy is independent of source validity: record the
            # rejection without reclassifying the assertion as invalid.
            rejected += 1
            results.append({
                "channel": cid,
                "assertion_id": aid,
                "valid": True,
                "reason": "destination-rejected",
                "destination_status": code,
                "destination_error": body.get("error") if isinstance(body, dict) else None,
                "forwarded": False,
            })

    summary = {
        "ok": not errors,
        "command": "sync",
        "source": source,
        "destination": destination,
        "mode": mode,
        "channel": channel,
        "channels": len(channels),
        "discovered": len(gathered),
        "valid": valid,
        "invalid": invalid,
        "forwarded": forwarded,
        "duplicates": duplicates,
        "rejected": rejected,
        "results": results,
        "errors": errors,
    }
    line = json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
    if log_path:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    print(line)
    return 0 if summary["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="SPP v1 federation sync worker")
    ap.add_argument("--source", required=True, help="source relay base URL")
    ap.add_argument("--destination", required=True, help="destination relay base URL")
    ap.add_argument("--channel", default=None,
                    help="explicit capability channel id (sha256:<64hex>)")
    ap.add_argument("--log", default=None, help="append JSON diagnostics to this file")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return sync(args.source.rstrip("/"), args.destination.rstrip("/"),
                args.channel, args.log)


if __name__ == "__main__":
    raise SystemExit(main())
