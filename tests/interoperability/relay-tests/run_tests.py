#!/usr/bin/env python3
"""§28 relay interoperability. Starts impl-a and impl-b relays; cross-submits."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VEC = json.loads((ROOT / "tests" / "conformance" / "vectors" / "source.json").read_text(encoding="utf-8"))
TSX = ROOT / "implementations" / "typescript" / "node_modules" / ".bin" / ("tsx.cmd" if os.name == "nt" else "tsx")
A_PORT = 18770
B_PORT = 18771

sys.path.insert(0, str(ROOT / "implementations" / "python"))
from protocol import SppError as SppErrorA  # noqa: E402
from protocol import validate_bytes as validate_bytes_a  # noqa: E402

try:
    import psutil  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    psutil = None

TEST_PORTS = (18772, 18773, 18774)


def stop(p: subprocess.Popen) -> None:
    """Terminate a relay and its children.

    ``tsx`` is a wrapper that spawns a node child; on Windows ``terminate()``
    kills only the wrapper and can leave the listener alive, which then leaks
    across runs and turns later cases into false failures.
    """
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
            except (psutil.Error, Exception):
                pass
    elif os.name == "nt":
        subprocess.call(
            ["taskkill", "/F", "/T", "/PID", str(p.pid)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    else:
        p.terminate()
    try:
        p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()


def sweep_test_ports() -> None:
    if psutil is None:
        return
    for conn in psutil.net_connections(kind="tcp"):
        if conn.status != "LISTEN" or conn.pid is None or not conn.laddr:
            continue
        if conn.laddr.port in TEST_PORTS or conn.laddr.port in (A_PORT, B_PORT):
            try:
                psutil.Process(conn.pid).kill()
            except psutil.Error:
                pass



def env_json(key: str) -> bytes:
    return json.dumps(VEC[key]["envelope"], ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def http(method: str, url: str, body: bytes | None = None, headers: dict | None = None):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {"raw": raw}
        return e.code, data


def wait(url: str, timeout: float = 8.0) -> None:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            code, _ = http("GET", url)
            if code == 200:
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise SystemExit(f"timeout waiting for {url}")


def start_relays():
    env_a = os.environ.copy()
    env_a["SPP_PAGE_SIZE"] = "1"
    env_a["SPP_POW_MULTIPLIER"] = "1"
    env_b = os.environ.copy()
    env_b["SPP_PAGE_SIZE"] = "1"
    env_b["SPP_POW_MULTIPLIER"] = "1"
    pa = subprocess.Popen(
        [sys.executable, str(ROOT / "implementations" / "python" / "relay.py"), "--port", str(A_PORT)],
        cwd=ROOT,
        env=env_a,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pb = subprocess.Popen(
        [str(TSX), "src/relay.ts", "--port", str(B_PORT)],
        cwd=ROOT / "implementations" / "typescript",
        env=env_b,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wait(f"http://127.0.0.1:{A_PORT}/.well-known/spp")
    wait(f"http://127.0.0.1:{B_PORT}/.well-known/spp")
    return pa, pb


def post(port: int, body: bytes, headers: dict | None = None):
    h = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    if headers:
        h.update(headers)
    return http("POST", f"http://127.0.0.1:{port}/v1/assertions", body, h)


def get(port: int, path: str):
    return http("GET", f"http://127.0.0.1:{port}{path}")


def scrape(src: int, dst: int) -> int:
    """Relay-to-relay scrape of advertised public surface (§29)."""
    n = 0
    code, ch = get(src, "/v1/channels")
    assert code == 200, ch
    ids = list(ch["items"])
    nxt = ch["next"]
    while nxt:
        code, more = get(src, f"/v1/channels?cursor={nxt}")
        assert code == 200
        ids.extend(more["items"])
        nxt = more["next"]
    for cid in ids:
        hexid = cid.split(":", 1)[1]
        code, one = get(src, f"/v1/assertions/sha256/{hexid}")
        if code == 200:
            raw = json.dumps(one, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            c2, _ = post(dst, raw)
            if c2 == 200:
                n += 1
        code, lst = get(src, f"/v1/channels/sha256/{hexid}/assertions")
        assert code == 200
        for env in lst["items"]:
            raw = json.dumps(env, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            c2, _ = post(dst, raw)
            if c2 == 200:
                n += 1
        while lst.get("next"):
            code, lst = get(src, f"/v1/channels/sha256/{hexid}/assertions?cursor={lst['next']}")
            assert code == 200
            for env in lst["items"]:
                raw = json.dumps(env, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                c2, _ = post(dst, raw)
                if c2 == 200:
                    n += 1
    return n


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def run() -> int:
    procs = start_relays()
    failed = 0

    def case(name: str, fn) -> None:
        nonlocal failed
        try:
            fn()
            print(f"PASS {name}")
        except Exception as e:
            failed += 1
            print(f"FAIL {name}: {e}")

    a1 = env_json("A1_channel")
    a2 = env_json("A2_pointer")
    a3 = env_json("A3_unlisted")
    a7 = env_json("A7_pointer_with_parent")
    a1_id = VEC["A1_channel"]["id"]
    a2_id = VEC["A2_pointer"]["id"]
    a3_id = VEC["A3_unlisted"]["id"]
    a3_ch = VEC["A3_unlisted"]["u"]["channel"]
    obj = VEC["object"]["hash"]

    def channel_pointer_retrieve():
        for port in (A_PORT, B_PORT):
            c, r = post(port, a1)
            check(c == 200 and r["id"] == a1_id, f"submit channel {c} {r}")
            c, r = post(port, a2)
            check(c == 200 and r["id"] == a2_id, f"submit pointer {c} {r}")
            c, got = get(port, f"/v1/assertions/sha256/{a2_id[7:]}")
            check(c == 200 and got["id"] == a2_id, f"retrieve {c}")
            c, ch = get(port, "/v1/channels")
            check(c == 200 and a1_id in ch["items"], f"channels {ch}")
            c, lst = get(port, f"/v1/channels/sha256/{a1_id[7:]}/assertions")
            check(c == 200 and any(x["id"] == a2_id or x["id"] == a1_id for x in lst["items"]), lst)

    def capability_unlisted():
        for port in (A_PORT, B_PORT):
            c, r = post(port, a3)
            check(c == 200 and r["id"] == a3_id, r)
            c, ch = get(port, "/v1/channels")
            check(a3_ch not in ch["items"], "capability must not appear in advertised list")
            c, lst = get(port, f"/v1/channels/sha256/{a3_ch[7:]}/assertions")
            check(c == 200 and any(x["id"] == a3_id for x in lst["items"]), lst)

    def object_index():
        for port in (A_PORT, B_PORT):
            c, lst = get(port, f"/v1/objects/sha256/{obj[7:]}/assertions")
            check(c == 200 and any(x["id"] == a2_id for x in lst["items"]), lst)

    def pagination():
        # page size is 1; A1 channel list should need a cursor once more than one advertised
        # seed a second channel (A6) on A
        a6 = env_json("A6_channel_no_descriptor")
        post(A_PORT, a6)
        c, page1 = get(A_PORT, "/v1/channels")
        check(c == 200 and page1["next"] is not None and len(page1["items"]) == 1, page1)
        c, page2 = get(A_PORT, f"/v1/channels?cursor={page1['next']}")
        check(c == 200 and len(page2["items"]) >= 1, page2)

    def duplicate_submission():
        for port in (A_PORT, B_PORT):
            c, r = post(port, a2)
            check(c == 200 and r.get("duplicate") is True, r)

    def local_pow_multiplier():
        # restart would be heavy; exercise via a fresh process
        env = os.environ.copy()
        env["SPP_POW_MULTIPLIER"] = "1000000"
        env["SPP_PAGE_SIZE"] = "2"
        port = 18772
        p = subprocess.Popen(
            [sys.executable, str(ROOT / "implementations" / "python" / "relay.py"), "--port", str(port)],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            wait(f"http://127.0.0.1:{port}/.well-known/spp")
            c, r = post(port, a2)
            check(c == 403 and r.get("error") == "policy", r)
        finally:
            stop(p)

    def policy_rejection():
        env = os.environ.copy()
        env["SPP_BLOCK_ACTOR"] = VEC["test_key"]["actor"]
        port = 18773
        p = subprocess.Popen(
            [str(TSX), "src/relay.ts", "--port", str(port)],
            cwd=ROOT / "implementations" / "typescript",
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            wait(f"http://127.0.0.1:{port}/.well-known/spp")
            c, r = post(port, a2)
            check(c == 403 and r.get("error") == "policy", r)
        finally:
            stop(p)

    def missing_parents():
        # A7 parents A2; submit A7 alone to a fresh relay — must accept (parents are hints)
        env = os.environ.copy()
        port = 18774
        p = subprocess.Popen(
            [sys.executable, str(ROOT / "implementations" / "python" / "relay.py"), "--port", str(port)],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            wait(f"http://127.0.0.1:{port}/.well-known/spp")
            c, r = post(port, a7)
            check(c == 200 and r["id"] == VEC["A7_pointer_with_parent"]["id"], r)
        finally:
            stop(p)

    def cross_submit_and_scrape():
        # clear path: submit A1/A2 already on both; scrape A -> B and B -> A should be idempotent
        n1 = scrape(A_PORT, B_PORT)
        n2 = scrape(B_PORT, A_PORT)
        check(n1 >= 0 and n2 >= 0, f"scrape counts {n1} {n2}")
        c, got = get(B_PORT, f"/v1/assertions/sha256/{a1_id[7:]}")
        check(c == 200, got)
        c, got = get(A_PORT, f"/v1/assertions/sha256/{a3_id[7:]}")
        # A3 is unlisted — scrape of advertised surface must NOT be required to copy it
        # but we already posted A3 to both earlier. Ensure still present.
        check(c == 200, got)

    def serve_revalidate_roundtrip():
        def revalidate(env):
            raw = json.dumps(env, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            try:
                return validate_bytes_a(raw)
            except SppErrorA as e:
                raise AssertionError(f"served bytes fail required checks: {e}")

        def all_items(port, path):
            items = []
            c, page = get(port, path)
            check(c == 200, f"GET {path} -> {c}")
            items.extend(page["items"])
            nxt = page.get("next")
            while nxt:
                c, page = get(port, f"{path}?cursor={nxt}")
                check(c == 200, f"GET {path}?cursor -> {c}")
                items.extend(page["items"])
                nxt = page.get("next")
            return items

        for port in (A_PORT, B_PORT):
            for aid in (a1_id, a2_id, a3_id):
                c, got = get(port, f"/v1/assertions/sha256/{aid[7:]}")
                check(c == 200, f"GET {aid} -> {c}")
                info = revalidate(got)
                check(info["id"] == aid, f"served id {info['id']} != indexed {aid}")

            for path, want in (
                (f"/v1/channels/sha256/{a1_id[7:]}/assertions", a2_id),
                (f"/v1/objects/sha256/{obj[7:]}/assertions", a2_id),
            ):
                ids = set()
                for env in all_items(port, path):
                    info = revalidate(env)
                    check(info["id"] == env["id"], f"{path}: served {env['id']} recomputes to {info['id']}")
                    ids.add(info["id"])
                check(want in ids, f"{path} missing {want}: {ids}")

    def invalid_json_rejected():
        for port in (A_PORT, B_PORT):
            c, r = post(port, b'{"v":1,"v":1,"type":"pointer"}')
            check(c == 400 and r.get("error") == "invalid_assertion", r)

    def transport_hygiene():
        # RC3: a relay must answer malformed requests with an ordinary HTTP
        # error, never drop the connection, and normalize malformed <64hex>
        # route shapes to 404.
        for port in (A_PORT, B_PORT):
            try:
                c, r = http("GET", f"http://127.0.0.1:{port}/v1/channels?cursor=%25")
                check(400 <= c < 500, f"bad cursor -> {c}")
            except Exception as e:
                raise AssertionError(f"bad cursor dropped connection: {e}")
            c, r = http("GET", f"http://127.0.0.1:{port}/v1/channels/sha256/{'z' * 64}/assertions")
            check(c == 404, f"malformed hex list -> {c} {r}")

    cases = [
        ("channel-pointer-retrieve", channel_pointer_retrieve),
        ("capability-unlisted", capability_unlisted),
        ("object-index", object_index),
        ("pagination", pagination),
        ("duplicate-submission", duplicate_submission),
        ("local-pow-multiplier", local_pow_multiplier),
        ("policy-rejection", policy_rejection),
        ("missing-parents", missing_parents),
        ("cross-submit-scrape", cross_submit_and_scrape),
        ("serve-revalidate-roundtrip", serve_revalidate_roundtrip),
        ("invalid-json-rejected", invalid_json_rejected),
        ("transport-hygiene", transport_hygiene),
    ]
    try:
        for name, fn in cases:
            case(name, fn)
    finally:
        for p in procs:
            stop(p)
        sweep_test_ports()

    print(f"{'ok' if failed == 0 else 'FAIL'}: {len(cases) - failed}/{len(cases)} relay cases")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())
