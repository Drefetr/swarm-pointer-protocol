#!/usr/bin/env python3
"""Durable SPP v1 relay tests.

Starts `relay/server.py` against a temporary SQLite database and exercises the
frozen §27/§28 HTTP profile plus the durable-relay acceptance gate:

    fresh startup, pointer/channel acceptance, invalid/unsupported rejection,
    duplicates, assertion GET, channel/object indexes, advertised channels,
    capability channels, pagination, malformed cursors, local PoW policy,
    serve/revalidate identity, concurrent submissions, restart persistence,
    and a source guard that no referenced content is ever fetched.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
VEC = json.loads((ROOT / "tests" / "conformance" / "vectors" / "source.json").read_text(encoding="utf-8"))
SERVER = HERE / "server.py"

sys.path.insert(0, str(ROOT / "implementations" / "python"))
from jcs import canonicalize_bytes  # noqa: E402
from protocol import SppError as SppErrorA  # noqa: E402
from protocol import parse_object as parse_object_a  # noqa: E402
from protocol import validate_bytes as validate_bytes_a  # noqa: E402

try:
    import psutil  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    psutil = None

MAIN_PORT = 18820
POW_PORT = 18821
CONC_PORT = 18822
LIMIT_PORT = 18823
ALL_PORTS = (MAIN_PORT, POW_PORT, CONC_PORT, LIMIT_PORT)

TMP = Path(tempfile.mkdtemp(prefix="spp-relay-test-"))
MAIN_DB = TMP / "main.sqlite3"


def env_json(key: str) -> bytes:
    return json.dumps(VEC[key]["envelope"], ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def http(method: str, port: int, path: str, body: bytes | None = None, headers: dict | None = None):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=body, method=method, headers=headers or {}
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def get_json(port: int, path: str):
    code, raw = http("GET", port, path)
    return code, json.loads(raw.decode("utf-8"))


def post(port: int, body: bytes):
    code, raw = http(
        "POST",
        port,
        "/v1/assertions",
        body,
        {"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    try:
        return code, json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return code, {"raw": raw}


def wait(port: int, timeout: float = 10.0) -> None:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            code, _ = http("GET", port, "/.well-known/spp")
            if code == 200:
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise SystemExit(f"timeout waiting for relay on {port}")


def stop(p: subprocess.Popen) -> None:
    if psutil is not None:
        try:
            proc = psutil.Process(p.pid)
            tree = proc.children(recursive=True) + [proc]
        except psutil.Error:
            tree = []
        for q in tree:
            try:
                q.kill()
            except psutil.Error:
                pass
        for q in tree:
            try:
                q.wait(timeout=3)
            except Exception:
                pass
    else:
        p.terminate()
    try:
        p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()


def sweep_ports() -> None:
    if psutil is None:
        return
    for conn in psutil.net_connections(kind="tcp"):
        if conn.status == "LISTEN" and conn.pid is not None and conn.laddr:
            if conn.laddr.port in ALL_PORTS:
                try:
                    psutil.Process(conn.pid).kill()
                except psutil.Error:
                    pass


def start(db: Path, port: int, page_size: int = 1, extra_env: dict | None = None) -> subprocess.Popen:
    env = os.environ.copy()
    env["SPP_PAGE_SIZE"] = str(page_size)
    if extra_env:
        env.update(extra_env)
    p = subprocess.Popen(
        [sys.executable, str(SERVER), "--port", str(port), "--db", str(db), "--page-size", str(page_size)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wait(port)
    return p


def all_items(port: int, path: str) -> list:
    code, page = get_json(port, path)
    if code != 200:
        raise AssertionError(f"GET {path} -> {code}")
    items = list(page["items"])
    nxt = page["next"]
    while nxt:
        code, page = get_json(port, f"{path}?cursor={nxt}")
        if code != 200:
            raise AssertionError(f"GET {path}?cursor={nxt} -> {code}")
        items.extend(page["items"])
        nxt = page["next"]
    return items


def revalidate(env: dict) -> dict:
    raw = json.dumps(env, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return revalidate_bytes(raw)


def revalidate_bytes(raw: bytes) -> dict:
    try:
        return validate_bytes_a(raw)
    except SppErrorA as e:
        raise AssertionError(f"bytes fail frozen validation: {e}")


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def run() -> int:
    sweep_ports()
    proc = start(MAIN_DB, MAIN_PORT, page_size=1)
    failed = 0

    a1 = env_json("A1_channel")
    a2 = env_json("A2_pointer")
    a3 = env_json("A3_unlisted")
    a6 = env_json("A6_channel_no_descriptor")
    a7 = env_json("A7_pointer_with_parent")
    a8 = env_json("A8_pointer_with_ext")

    a1_id = VEC["A1_channel"]["id"]
    a2_id = VEC["A2_pointer"]["id"]
    a3_id = VEC["A3_unlisted"]["id"]
    a3_ch = VEC["A3_unlisted"]["u"]["channel"]
    a6_id = VEC["A6_channel_no_descriptor"]["id"]
    a1_hex = a1_id[7:]
    a2_hex = a2_id[7:]
    a3_hex = a3_id[7:]
    obj = VEC["object"]["hash"]
    obj_hex = obj[7:]

    def case(name: str, fn) -> None:
        nonlocal failed
        try:
            fn()
            print(f"PASS {name}")
        except Exception as e:
            failed += 1
            print(f"FAIL {name}: {e}")

    def fresh_startup():
        check(MAIN_DB.exists(), "db file not created on startup")
        code, man = get_json(MAIN_PORT, "/.well-known/spp")
        check(code == 200, f"manifest -> {code}")
        check(man["v"] == 1, man)
        check(man["submit"] == "/v1/assertions", man)
        check(man["channels"] == "/v1/channels", man)
        check(man["assertion"] == "/v1/assertions/sha256/{hex}", man)
        check(man["channel"] == "/v1/channels/sha256/{hex}/assertions", man)
        check(man["object"] == "/v1/objects/sha256/{hex}/assertions", man)
        check(man["bootstrap_channels"] == [], man)
        check(man["policy"] == {
            "pow_multiplier": 1,
            "max_record_bytes": 65536,
            "max_locators": 256,
            "max_locator_bytes": 8192,
            "max_parents": 1024,
        }, man)
        check(all_items(MAIN_PORT, "/v1/channels") == [], "fresh db is not empty")
        code, _ = http("GET", MAIN_PORT, f"/v1/assertions/sha256/{a1_hex}")
        check(code == 404, f"unknown assertion -> {code}")

    def valid_pointer_acceptance():
        code, r = post(MAIN_PORT, a2)
        check(code == 200 and r["id"] == a2_id and r["duplicate"] is False, f"{code} {r}")

    def valid_channel_acceptance():
        code, r = post(MAIN_PORT, a1)
        check(code == 200 and r["id"] == a1_id and r["duplicate"] is False, f"{code} {r}")

    def invalid_assertion_rejection():
        code, r = post(MAIN_PORT, b'{"v":1,"v":1,"type":"pointer"}')
        check(code == 400 and r.get("error") == "invalid_assertion", f"{code} {r}")

    def unsupported_version_rejection():
        code, r = post(MAIN_PORT, b'{"v":2}')
        check(code == 400 and r.get("error") == "unsupported_assertion", f"{code} {r}")

    def duplicate_submission():
        code, r = post(MAIN_PORT, a2)
        check(code == 200 and r.get("duplicate") is True and r["id"] == a2_id, f"{code} {r}")

    def assertion_get():
        code, raw = http("GET", MAIN_PORT, f"/v1/assertions/sha256/{a2_hex}")
        check(code == 200, f"GET assertion -> {code}")
        info = revalidate_bytes(raw)
        check(info["id"] == a2_id, f"served {info['id']} != {a2_id}")
        check(raw == canonicalize_bytes(parse_object_a(raw)), "stored bytes are not canonical")

    def channel_index():
        ids = {e["id"] for e in all_items(MAIN_PORT, f"/v1/channels/sha256/{a1_hex}/assertions")}
        check({a1_id, a2_id} <= ids, f"{ids}")

    def object_index():
        ids = {e["id"] for e in all_items(MAIN_PORT, f"/v1/objects/sha256/{obj_hex}/assertions")}
        check(a2_id in ids, f"{ids}")

    def advertised_channel_list():
        ids = all_items(MAIN_PORT, "/v1/channels")
        check(a1_id in ids, f"{ids}")
        check(a3_ch not in ids, "capability channel must not be advertised")

    def capability_channel_not_advertised():
        code, r = post(MAIN_PORT, a3)
        check(code == 200 and r["id"] == a3_id, f"{code} {r}")
        ids = all_items(MAIN_PORT, "/v1/channels")
        check(a3_ch not in ids, "capability channel advertised")
        lst = {e["id"] for e in all_items(MAIN_PORT, f"/v1/channels/sha256/{a3_ch[7:]}/assertions")}
        check(a3_id in lst, f"capability channel direct read failed: {lst}")

    def pagination():
        code, r = post(MAIN_PORT, a6)
        check(code == 200 and r["id"] == a6_id, f"{code} {r}")
        # page size is 1: two advertised channels must paginate.
        code, page1 = get_json(MAIN_PORT, "/v1/channels")
        check(code == 200 and page1["next"] is not None and len(page1["items"]) == 1, page1)
        code, page2 = get_json(MAIN_PORT, f"/v1/channels?cursor={page1['next']}")
        check(code == 200 and len(page2["items"]) >= 1, page2)
        seen = set(page1["items"]) | set(page2["items"])
        check({a1_id, a6_id} <= seen, f"{seen}")
        # channel assertion list also paginates
        code, cp1 = get_json(MAIN_PORT, f"/v1/channels/sha256/{a1_hex}/assertions")
        check(code == 200 and cp1["next"] is not None and len(cp1["items"]) == 1, cp1)

    def malformed_cursor():
        code, r = get_json(MAIN_PORT, "/v1/channels?cursor=%25")
        check(code == 400 and r.get("error") == "bad_cursor", f"{code} {r}")
        code, _ = http("GET", MAIN_PORT, "/v1/channels?cursor=%2B")
        check(code == 400, f"'+' cursor -> {code}")

    def local_pow_multiplier():
        db = TMP / "pow.sqlite3"
        p = start(db, POW_PORT, page_size=2, extra_env={"SPP_POW_MULTIPLIER": "1000000"})
        try:
            code, r = post(POW_PORT, a2)
            check(code == 403 and r.get("error") == "policy", f"{code} {r}")
            check(all_items(POW_PORT, "/v1/channels") == [], "rejected assertion was indexed")
        finally:
            stop(p)

    def local_locator_limit():
        # A valid pointer has at least one locator; a zero local budget must
        # reject it as policy (403), never as protocol-invalid, and index nothing.
        db = TMP / "limit.sqlite3"
        p = start(db, LIMIT_PORT, page_size=2, extra_env={"SPP_MAX_LOCATORS": "0"})
        try:
            code, r = post(LIMIT_PORT, a2)
            check(code == 403 and r.get("error") == "policy", f"{code} {r}")
            check(all_items(LIMIT_PORT, "/v1/channels") == [], "rejected assertion was indexed")
        finally:
            stop(p)

    def serve_revalidate_invariant():
        for port, path in (
            (MAIN_PORT, f"/v1/channels/sha256/{a1_hex}/assertions"),
            (MAIN_PORT, f"/v1/objects/sha256/{obj_hex}/assertions"),
        ):
            for env in all_items(port, path):
                info = revalidate(env)
                check(info["id"] == env["id"], f"{path}: {env['id']} -> {info['id']}")

    def concurrent_submissions():
        db = TMP / "conc.sqlite3"
        p = start(db, CONC_PORT, page_size=32)
        try:
            keys = ["A1_channel", "A2_pointer", "A3_unlisted", "A6_channel_no_descriptor",
                    "A7_pointer_with_parent", "A8_pointer_with_ext"]
            bodies = [(k, env_json(k)) for k in keys]
            # Each assertion is raced by two workers: exercises both fresh
            # inserts and concurrent duplicate handling.
            tasks = bodies + bodies

            def submit(item):
                k, body = item
                return k, post(CONC_PORT, body)

            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
                results = list(ex.map(submit, tasks))
            for k, (code, r) in results:
                check(code == 200 and r["id"] == VEC[k]["id"], f"{k} -> {code} {r}")

            for k in keys:
                code, raw = http("GET", CONC_PORT, f"/v1/assertions/sha256/{VEC[k]['id'][7:]}")
                check(code == 200, f"missing {k} after concurrent writes")
                check(revalidate_bytes(raw)["id"] == VEC[k]["id"], f"{k} served bytes mismatch")

            adv = set(all_items(CONC_PORT, "/v1/channels"))
            check(adv == {VEC["A1_channel"]["id"], VEC["A6_channel_no_descriptor"]["id"]}, f"{adv}")
            want = {VEC["A1_channel"]["id"], VEC["A2_pointer"]["id"],
                    VEC["A7_pointer_with_parent"]["id"]}
            got = {e["id"] for e in all_items(CONC_PORT, f"/v1/channels/sha256/{a1_hex}/assertions")}
            check(want <= got, f"channel index corrupt: {got}")
            for env in all_items(CONC_PORT, f"/v1/objects/sha256/{obj_hex}/assertions"):
                check(revalidate(env)["id"] == env["id"], "object index served invalid bytes")
        finally:
            stop(p)

    def restart_persistence():
        nonlocal proc
        ids = [a1_id, a2_id, a3_id, a6_id]
        before = {}
        for aid in ids:
            code, raw = http("GET", MAIN_PORT, f"/v1/assertions/sha256/{aid[7:]}")
            check(code == 200, f"pre-restart GET {aid} -> {code}")
            before[aid] = raw
        order_before = [e["id"] for e in all_items(MAIN_PORT, f"/v1/channels/sha256/{a1_hex}/assertions")]

        stop(proc)
        proc = start(MAIN_DB, MAIN_PORT, page_size=1)

        for aid in ids:
            code, raw = http("GET", MAIN_PORT, f"/v1/assertions/sha256/{aid[7:]}")
            check(code == 200, f"post-restart GET {aid} -> {code}")
            check(raw == before[aid], f"canonical bytes changed across restart: {aid}")
            check(revalidate_bytes(raw)["id"] == aid, f"indexed id changed across restart: {aid}")
        adv = set(all_items(MAIN_PORT, "/v1/channels"))
        check(a1_id in adv, f"advertised channels lost: {adv}")
        obj_ids = {e["id"] for e in all_items(MAIN_PORT, f"/v1/objects/sha256/{obj_hex}/assertions")}
        check(a2_id in obj_ids, f"object index lost: {obj_ids}")
        order_after = [e["id"] for e in all_items(MAIN_PORT, f"/v1/channels/sha256/{a1_hex}/assertions")]
        check(order_before == order_after, f"seq order changed: {order_before} != {order_after}")

    def no_referenced_content_fetched():
        forbidden = ("urllib.request", "urlopen", "http.client", "requests.", "httpx", "aiohttp", "socket.socket")
        for src in (HERE / "server.py", HERE / "store.py"):
            text = src.read_text(encoding="utf-8")
            for token in forbidden:
                check(token not in text, f"{src.name} contains fetch token {token!r}")

    cases = [
        ("fresh-database-startup", fresh_startup),
        ("valid-pointer-acceptance", valid_pointer_acceptance),
        ("valid-channel-acceptance", valid_channel_acceptance),
        ("invalid-assertion-rejection", invalid_assertion_rejection),
        ("unsupported-version-rejection", unsupported_version_rejection),
        ("duplicate-submission", duplicate_submission),
        ("assertion-get", assertion_get),
        ("channel-index", channel_index),
        ("object-index", object_index),
        ("advertised-channel-list", advertised_channel_list),
        ("capability-channel-direct-read", capability_channel_not_advertised),
        ("pagination", pagination),
        ("malformed-cursor", malformed_cursor),
        ("local-pow-multiplier", local_pow_multiplier),
        ("local-locator-limit", local_locator_limit),
        ("serve-revalidate-invariant", serve_revalidate_invariant),
        ("concurrent-submissions", concurrent_submissions),
        ("restart-persistence", restart_persistence),
        ("no-referenced-content-fetched", no_referenced_content_fetched),
    ]

    try:
        for name, fn in cases:
            case(name, fn)
    finally:
        stop(proc)
        sweep_ports()
        shutil.rmtree(TMP, ignore_errors=True)

    print(f"{'ok' if failed == 0 else 'FAIL'}: {len(cases) - failed}/{len(cases)} durable-relay cases")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())
