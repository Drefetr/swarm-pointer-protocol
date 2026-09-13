#!/usr/bin/env python3
"""SPP v1 multi-relay federation end-to-end demonstration.

Starts two independent durable relays, two independently implemented clients
(Python Agent A, TypeScript Agent B), two object servers, and a standalone
federation sync worker. It proves that assertion identity and channel identity
do not depend on any particular relay, and that relays synchronize using only
the ordinary frozen v1 public client interface (GET + POST).

The harness only orchestrates processes and inspects them over HTTP. It never
mines, signs, submits, polls, or dereferences a locator on an agent's behalf;
every protocol action is a separate CLI invocation. Served assertions are
independently revalidated here against the frozen `impl-a` v1 profile.

Usage:
    python tests/interoperability/multi-relay-e2e/run_tests.py [--keep]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FIX = ROOT / "tests" / "interoperability" / "durable-e2e" / "fixtures"
RELAY = ROOT / "implementations" / "relay" / "server.py"
AGENT_A = ROOT / "examples" / "agent-a" / "agent.py"
AGENT_B = ROOT / "examples" / "agent-b" / "agent.ts"
SYNC = ROOT / "implementations" / "relay" / "federation" / "sync.py"
TSX = ROOT / "implementations" / "typescript" / "node_modules" / ".bin" / ("tsx.cmd" if os.name == "nt" else "tsx")
PY = sys.executable

sys.path.insert(0, str(ROOT / "implementations" / "python"))
from protocol import SppError, UnsupportedError, validate_bytes  # noqa: E402

try:
    import psutil  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    psutil = None

R1_PORT = 18760
R2_PORT = 18761
A_OBJ_PORT = 18872
B_OBJ_PORT = 18873
MOCK_PORT = 18874
ALL_PORTS = (R1_PORT, R2_PORT, A_OBJ_PORT, B_OBJ_PORT, MOCK_PORT)

R1 = f"http://127.0.0.1:{R1_PORT}"
R2 = f"http://127.0.0.1:{R2_PORT}"

SHA256_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
ED25519_ID = re.compile(r"^ed25519:[0-9a-f]{64}$")

EXPECTED = [
    "R1 independent startup",
    "R2 independent startup",
    "shared channel identity",
    "capability channel hidden on R1",
    "capability channel hidden on R2",
    "A published PA only to R1",
    "B published PB only to R2",
    "Agent A reconstructed union",
    "Agent B reconstructed union",
    "R1 -> R2 synchronization",
    "R2 -> R1 synchronization",
    "federation idempotency",
    "advertised public scrape",
    "explicit capability-channel synchronization",
    "relay-local policy divergence",
    "R1 failure",
    "continued operation through R2",
    "R1 recovery",
    "catch-up synchronization",
    "independent arrival order",
    "object-index federation",
    "cross-relay parent reference",
    "hostile source relay validation",
    "full cold restart",
    "post-restart synchronization",
]

# --------------------------------------------------------------------------- #
# process control
# --------------------------------------------------------------------------- #

def kill_tree(p: subprocess.Popen) -> None:
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
    elif os.name == "nt":
        subprocess.call(["taskkill", "/F", "/T", "/PID", str(p.pid)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        p.terminate()
    try:
        p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()


def sweep_ports() -> None:
    if psutil is None:
        return
    try:
        conns = psutil.net_connections(kind="tcp")
    except psutil.Error:
        return
    for conn in conns:
        if conn.status == "LISTEN" and conn.pid is not None and conn.laddr:
            if conn.laddr.port in ALL_PORTS:
                try:
                    psutil.Process(conn.pid).kill()
                except psutil.Error:
                    pass


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #

def http_get(port: int, path: str, timeout: float = 10.0) -> tuple[int, bytes]:
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception:
        return 0, b""


def get_json(port: int, path: str) -> tuple[int, dict]:
    code, raw = http_get(port, path)
    try:
        return code, json.loads(raw.decode("utf-8"))
    except Exception:
        return code, {"raw": raw.decode("utf-8", "replace")}


def all_items(port: int, path: str) -> list:
    code, page = get_json(port, path)
    assert code == 200, f"GET {path} -> {code} {page}"
    items = list(page["items"])
    nxt = page.get("next")
    while nxt:
        code, page = get_json(port, f"{path}?cursor={nxt}")
        assert code == 200, f"GET {path}?cursor={nxt} -> {code}"
        items.extend(page["items"])
        nxt = page.get("next")
    return items


def wait_http(port: int, paths: tuple[str, ...] = ("/.well-known/spp",), timeout: float = 40.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        for pth in paths:
            code, _ = http_get(port, pth)
            if code == 200:
                return
        time.sleep(0.1)
    raise AssertionError(f"timeout waiting for HTTP on port {port}")


def revalidate_bytes(raw: bytes) -> dict:
    try:
        return validate_bytes(raw)
    except UnsupportedError as e:
        raise AssertionError(f"served bytes classified unsupported: {e.reason}")
    except SppError as e:
        raise AssertionError(f"served bytes fail frozen validation: {e.stage}:{e.reason}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# hostile mock source relay
# --------------------------------------------------------------------------- #

class MockHandler(BaseHTTPRequestHandler):
    routes: dict = {}

    def log_message(self, fmt: str, *args) -> None:
        pass

    def _json(self, code: int, obj) -> None:
        data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/.well-known/spp":
            return self._json(200, {"v": 1, "submit": "/v1/assertions", "channels": "/v1/channels"})
        if path in self.routes:
            return self._json(200, {"items": self.routes[path], "next": None})
        return self._json(404, {"error": "not_found", "message": "route"})


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #

class Harness:
    def __init__(self, keep: bool) -> None:
        self.keep = keep
        self.tmp = Path(tempfile.mkdtemp(prefix="spp-multi-relay-"))
        self.logs = self.tmp / "logs"
        self.logs.mkdir()
        self.procs: dict[str, subprocess.Popen] = {}
        self.passed: list[str] = []
        self.mock: ThreadingHTTPServer | None = None
        self.A_STATE = self.tmp / "agent-a"
        self.B_STATE = self.tmp / "agent-b"
        self.R1_DB = self.tmp / "relay-r1.sqlite3"
        self.R2_DB = self.tmp / "relay-r2.sqlite3"
        self.channel = "sha256:" + os.urandom(32).hex()
        self.actor_a = ""
        self.actor_b = ""

    # -- transcript ------------------------------------------------------- #

    def p(self, label: str) -> None:
        print(f"PASS {label}", flush=True)
        self.passed.append(label)

    # -- processes -------------------------------------------------------- #

    def start(self, name: str, argv: list[str], env: dict | None = None) -> subprocess.Popen:
        e = os.environ.copy()
        if env:
            e.update(env)
        log = open(self.logs / f"{name}.log", "ab")
        proc = subprocess.Popen(argv, cwd=ROOT, env=e, stdout=log, stderr=subprocess.STDOUT)
        self.procs[name] = proc
        return proc

    def stop(self, name: str) -> None:
        proc = self.procs.pop(name, None)
        if proc is not None:
            kill_tree(proc)

    def stop_all(self) -> None:
        for name in list(self.procs):
            self.stop(name)
        if self.mock is not None:
            self.mock.shutdown()
            self.mock.server_close()
            self.mock = None

    def start_relay(self, name: str, port: int, db: Path, env: dict | None = None) -> None:
        self.start(name, [PY, str(RELAY), "--port", str(port), "--db", str(db),
                          "--page-size", "2"], env)
        wait_http(port)

    def start_objects(self) -> None:
        self.start("obj-a", [PY, str(AGENT_A), "serve", "--state", str(self.A_STATE),
                             "--port", str(A_OBJ_PORT)])
        self.start("obj-b", [str(TSX), str(AGENT_B), "serve", "--state", str(self.B_STATE),
                             "--port", str(B_OBJ_PORT)])
        wait_http(A_OBJ_PORT, ("/health",))
        wait_http(B_OBJ_PORT, ("/health",))

    def start_mock(self, routes: dict) -> None:
        MockHandler.routes = routes
        self.mock = ThreadingHTTPServer(("127.0.0.1", MOCK_PORT), MockHandler)
        t = threading.Thread(target=self.mock.serve_forever, daemon=True)
        t.start()
        wait_http(MOCK_PORT)

    # -- client CLIs ------------------------------------------------------ #

    def a(self, *args: str) -> list[str]:
        return [PY, str(AGENT_A), *args]

    def b(self, *args: str) -> list[str]:
        return [str(TSX), str(AGENT_B), *args]

    def run_client(self, argv: list[str]) -> dict:
        proc = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=600)
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip().startswith("{")]
        if not lines:
            raise AssertionError(
                f"client produced no JSON result: {argv}\nstdout={proc.stdout}\nstderr={proc.stderr}"
            )
        return json.loads(lines[-1])

    def a_status(self) -> dict:
        return self.run_client(self.a("status", "--state", str(self.A_STATE)))

    def b_status(self) -> dict:
        return self.run_client(self.b("status", "--state", str(self.B_STATE)))

    # -- protocol actions through the CLIs -------------------------------- #

    def publish(self, agent: str, fixture: str, obj_port: int, state: Path,
                relays: list[str], channel: str | None = None,
                parents: str | None = None) -> dict:
        argv = (self.a if agent == "a" else self.b)("publish", "--state", str(state))
        for r in relays:
            argv += ["--relay", r]
        argv += [
            "--channel", channel or self.channel,
            "--file", str(FIX / fixture),
            "--object-base", f"http://127.0.0.1:{obj_port}",
        ]
        if parents:
            argv += ["--parents", parents]
        return self.run_client(argv)

    def poll(self, agent: str, state: Path, relays: list[str],
             channel: str | None = None) -> dict:
        argv = (self.a if agent == "a" else self.b)("poll", "--state", str(state))
        for r in relays:
            argv += ["--relay", r]
        argv += ["--channel", channel or self.channel]
        return self.run_client(argv)

    def publish_channel(self, agent: str, state: Path, relays: list[str]) -> dict:
        argv = (self.a if agent == "a" else self.b)("publish-channel", "--state", str(state))
        for r in relays:
            argv += ["--relay", r]
        return self.run_client(argv)

    def sync(self, source: str, destination: str, channel: str | None = None) -> dict:
        argv = [PY, str(SYNC), "--source", source, "--destination", destination]
        if channel:
            argv += ["--channel", channel]
        return self.run_client(argv)

    # -- relay views ------------------------------------------------------ #

    def channel_ids(self, port: int, channel: str) -> list[str]:
        return [e["id"] for e in all_items(
            port, f"/v1/channels/sha256/{channel.split(':', 1)[1]}/assertions")]

    def object_ids(self, port: int, obj_hash: str) -> list[str]:
        return [e["id"] for e in all_items(
            port, f"/v1/objects/sha256/{obj_hash.split(':', 1)[1]}/assertions")]

    def advertised(self, port: int) -> list[str]:
        return list(all_items(port, "/v1/channels"))

    def assertion(self, port: int, aid: str) -> dict:
        code, env = get_json(port, f"/v1/assertions/sha256/{aid.split(':', 1)[1]}")
        self.check(code == 200, f"GET assertion {aid} -> {code}")
        return env

    # -- assertions ------------------------------------------------------- #

    def check(self, cond: bool, msg: str) -> None:
        if not cond:
            raise AssertionError(msg)

    def fixture(self, name: str) -> bytes:
        return (FIX / name).read_bytes()

    def object_file(self, state: Path, obj_hash: str) -> Path:
        return state / "objects" / obj_hash.split(":", 1)[1]

    def result_for(self, poll: dict, assertion_id: str) -> dict:
        for r in poll["results"]:
            if r["assertion_id"] == assertion_id:
                return r
        raise AssertionError(
            f"{assertion_id} not in poll results: "
            f"{[r['assertion_id'] for r in poll['results']]}"
        )

    def same_set(self, a: list[str], b: list[str]) -> bool:
        return sorted(set(a)) == sorted(set(b))


def run(keep: bool) -> int:
    sweep_ports()
    h = Harness(keep)
    print(f"# working directory: {h.tmp}", flush=True)
    C = h.channel

    try:
        # -------- setup -------------------------------------------------- #
        a_init = h.run_client(h.a("init", "--state", str(h.A_STATE)))
        b_init = h.run_client(h.b("init", "--state", str(h.B_STATE)))
        h.actor_a, h.actor_b = a_init["actor"], b_init["actor"]
        h.check(bool(ED25519_ID.match(h.actor_a)), f"actor A {h.actor_a}")
        h.check(bool(ED25519_ID.match(h.actor_b)), f"actor B {h.actor_b}")

        h.start_relay("r1", R1_PORT, h.R1_DB)
        h.start_relay("r2", R2_PORT, h.R2_DB)
        h.start_objects()

        c1, m1 = get_json(R1_PORT, "/.well-known/spp")
        c2, m2 = get_json(R2_PORT, "/.well-known/spp")
        h.check(c1 == 200 and m1.get("v") == 1, f"R1 manifest {c1} {m1}")
        h.check(c2 == 200 and m2.get("v") == 1, f"R2 manifest {c2} {m2}")
        h.p("R1 independent startup")
        h.p("R2 independent startup")

        # -------- deliberately divergent initial state ------------------- #
        pubs = {
            "pa": h.publish("a", "a1.bin", A_OBJ_PORT, h.A_STATE, [R1]),
            "pc": h.publish("a", "a2.bin", A_OBJ_PORT, h.A_STATE, [R1]),
            "pb": h.publish("b", "b1.bin", B_OBJ_PORT, h.B_STATE, [R2]),
            "pd": h.publish("b", "b2.bin", B_OBJ_PORT, h.B_STATE, [R2]),
        }
        for k, r in pubs.items():
            h.check(r["status"] == 200 and r["stored"], f"publish {k} -> {r}")
            h.check(bool(SHA256_ID.match(r["assertion_id"])), f"{k} id syntax")
        pa, pc = pubs["pa"]["assertion_id"], pubs["pc"]["assertion_id"]
        pb, pd = pubs["pb"]["assertion_id"], pubs["pd"]["assertion_id"]

        for port, aid in ((R1_PORT, pa), (R1_PORT, pc), (R2_PORT, pb), (R2_PORT, pd)):
            env = h.assertion(port, aid)
            h.check(env.get("channel") == C, f"{aid} channel {env.get('channel')} != {C}")
        h.p("shared channel identity")

        h.check(C not in h.advertised(R1_PORT), "C advertised on R1")
        h.p("capability channel hidden on R1")
        h.check(C not in h.advertised(R2_PORT), "C advertised on R2")
        h.p("capability channel hidden on R2")

        h.check(h.same_set(h.channel_ids(R1_PORT, C), [pa, pc]), "R1 initial set")
        h.check(h.same_set(h.channel_ids(R2_PORT, C), [pb, pd]), "R2 initial set")
        h.check(pa not in h.channel_ids(R2_PORT, C), "PA leaked to R2 before sync")
        h.p("A published PA only to R1")
        h.check(pb not in h.channel_ids(R1_PORT, C), "PB leaked to R1 before sync")
        h.p("B published PB only to R2")

        # -------- multi-relay client union ------------------------------- #
        poll_a = h.poll("a", h.A_STATE, [R1, R2])
        for aid in (pa, pb, pc, pd):
            h.check(h.result_for(poll_a, aid)["valid"], f"A deemed {aid} invalid")
        for aid in (pb, pd):
            res = h.result_for(poll_a, aid)
            h.check(res["fetched"] and res["hash_ok"] and res["stored"],
                    f"A failed to fetch peer object for {aid}: {res}")
        h.check({pa, pb, pc, pd} <= set(h.a_status()["seen"]), "A union incomplete")
        h.p("Agent A reconstructed union")

        poll_b = h.poll("b", h.B_STATE, [R1, R2])
        for aid in (pa, pb, pc, pd):
            h.check(h.result_for(poll_b, aid)["valid"], f"B deemed {aid} invalid")
        for aid in (pa, pc):
            res = h.result_for(poll_b, aid)
            h.check(res["fetched"] and res["hash_ok"] and res["stored"],
                    f"B failed to fetch peer object for {aid}: {res}")
        h.check({pa, pb, pc, pd} <= set(h.b_status()["seen"]), "B union incomplete")
        h.p("Agent B reconstructed union")

        # -------- R1 -> R2 ----------------------------------------------- #
        r = h.sync(R1, R2, C)
        h.check(r["valid"] == 2 and r["invalid"] == 0, f"R1->R2 validation {r}")
        h.check(r["forwarded"] == 2, f"R1->R2 forwarded {r['forwarded']}")
        h.check(h.same_set(h.channel_ids(R1_PORT, C), [pa, pc]), "R1 changed on R1->R2")
        h.check(h.same_set(h.channel_ids(R2_PORT, C), [pa, pb, pc, pd]), "R2 not union")
        for aid in (pa, pc):
            h.check(h.assertion(R2_PORT, aid).get("channel") == C, f"{aid} channel changed")
        code, raw = http_get(R2_PORT, f"/v1/assertions/sha256/{pa.split(':', 1)[1]}")
        h.check(code == 200 and revalidate_bytes(raw)["id"] == pa,
                "replicated PA does not independently revalidate on R2")
        h.p("R1 -> R2 synchronization")

        # -------- R2 -> R1 ----------------------------------------------- #
        r = h.sync(R2, R1, C)
        h.check(r["invalid"] == 0, f"R2->R1 validation {r}")
        h.check(h.same_set(h.channel_ids(R1_PORT, C), [pa, pb, pc, pd]), "R1 not union")
        h.check(h.same_set(h.channel_ids(R2_PORT, C), [pa, pb, pc, pd]), "R2 changed")
        h.p("R2 -> R1 synchronization")

        # -------- idempotency -------------------------------------------- #
        before_r1 = h.channel_ids(R1_PORT, C)
        before_r2 = h.channel_ids(R2_PORT, C)
        r12 = h.sync(R1, R2, C)
        r21 = h.sync(R2, R1, C)
        h.check(r12["forwarded"] == 0 and r21["forwarded"] == 0, "repeat sync forwarded records")
        h.check(h.same_set(h.channel_ids(R1_PORT, C), before_r1), "R1 changed on repeat")
        h.check(h.same_set(h.channel_ids(R2_PORT, C), before_r2), "R2 changed on repeat")
        h.check(len(h.channel_ids(R1_PORT, C)) == len(set(h.channel_ids(R1_PORT, C))), "R1 dup ids")
        h.check(len(h.channel_ids(R2_PORT, C)) == len(set(h.channel_ids(R2_PORT, C))), "R2 dup ids")
        h.p("federation idempotency")

        # -------- advertised public scrape ------------------------------- #
        adv = h.publish_channel("a", h.A_STATE, [R1])
        h.check(adv["status"] == 200, f"publish-channel {adv}")
        adv_id = adv["assertion_id"]
        h.check(adv_id in h.advertised(R1_PORT), "advertised id missing on R1")
        h.check(adv_id not in h.advertised(R2_PORT), "advertised id unexpectedly on R2")
        r = h.sync(R1, R2)
        h.check(r["mode"] == "advertised", f"sync mode {r['mode']}")
        h.check(adv_id in h.advertised(R2_PORT), "advertised id not scraped to R2")
        h.check(get_json(R2_PORT, f"/v1/assertions/sha256/{adv_id.split(':', 1)[1]}")[0] == 200,
                "advertised assertion not served by R2")
        h.p("advertised public scrape")

        # -------- explicit capability-channel synchronization ------------- #
        pe = h.publish("a", "a3.bin", A_OBJ_PORT, h.A_STATE, [R1])
        h.check(pe["status"] == 200, f"PE publish {pe}")
        pe_id = pe["assertion_id"]
        h.check(pe_id not in h.channel_ids(R2_PORT, C), "PE present on R2 before explicit sync")
        h.check(pe_id not in h.advertised(R2_PORT), "capability channel became advertised")
        r = h.sync(R1, R2, C)
        h.check(r["mode"] == "channel", f"sync mode {r['mode']}")
        h.check(pe_id in h.channel_ids(R2_PORT, C), "PE not synced by explicit channel")
        h.p("explicit capability-channel synchronization")

        # -------- relay-local policy divergence --------------------------- #
        C_policy = "sha256:" + os.urandom(32).hex()
        qa = h.publish("a", "a4.bin", A_OBJ_PORT, h.A_STATE, [R1], channel=C_policy)
        qb = h.publish("b", "b3.bin", B_OBJ_PORT, h.B_STATE, [R2], channel=C_policy)
        h.check(qa["status"] == 200 and qb["status"] == 200, "policy pre-publish failed")
        qa_id, qb_id = qa["assertion_id"], qb["assertion_id"]
        h.check(h.same_set(h.channel_ids(R1_PORT, C_policy), [qa_id]), "R1 policy pre-set")
        h.check(h.same_set(h.channel_ids(R2_PORT, C_policy), [qb_id]), "R2 policy pre-set")

        # R2 blocks actor A; R1 accepts A and B. Federation is not consensus.
        h.stop("r2")
        h.start_relay("r2", R2_PORT, h.R2_DB, env={"SPP_BLOCK_ACTOR": h.actor_a})
        r = h.sync(R1, R2, C_policy)
        qa_res = next(x for x in r["results"] if x["assertion_id"] == qa_id)
        h.check(qa_res["valid"] is True, f"QA reclassified invalid: {qa_res}")
        h.check(qa_res["destination_status"] == 403 and not qa_res["forwarded"],
                f"QA not policy-rejected: {qa_res}")
        h.check(qa_id not in h.channel_ids(R2_PORT, C_policy), "blocked QA accepted by R2")
        r = h.sync(R2, R1, C_policy)
        h.check(qb_id in h.channel_ids(R1_PORT, C_policy), "QB not synced to R1")
        h.check(qa_id in h.channel_ids(R1_PORT, C_policy), "QA lost on R1")
        h.check(h.same_set(h.channel_ids(R2_PORT, C_policy), [qb_id]), "R2 policy set changed")
        h.stop("r2")
        h.start_relay("r2", R2_PORT, h.R2_DB, env={"SPP_BLOCK_ACTOR": ""})
        h.p("relay-local policy divergence")

        # -------- relay failure and client failover ----------------------- #
        h.sync(R1, R2, C)
        h.sync(R2, R1, C)
        h.check(h.same_set(h.channel_ids(R1_PORT, C), h.channel_ids(R2_PORT, C)), "not converged")
        h.stop("r1")
        pe2 = h.publish("a", "a5.bin", A_OBJ_PORT, h.A_STATE, [R1, R2])
        h.check(pe2["stored"], f"publish during R1 outage failed: {pe2}")
        h.check(pe2["relays"][0]["status"] == 0, "down relay not recorded unreachable")
        pe2_id = pe2["assertion_id"]
        h.check(pe2_id in h.channel_ids(R2_PORT, C), "PE2 missing on R2")
        h.p("R1 failure")

        poll_b = h.poll("b", h.B_STATE, [R1, R2])
        res = h.result_for(poll_b, pe2_id)
        h.check(res["valid"] and res["new"], f"B did not discover PE2 via R2: {res}")
        h.check(res["fetched"] and res["hash_ok"] and res["stored"], f"B failed PE2 fetch: {res}")
        h.p("continued operation through R2")

        # -------- relay recovery and catch-up ----------------------------- #
        h.start_relay("r1", R1_PORT, h.R1_DB)
        h.check(pe2_id not in h.channel_ids(R1_PORT, C), "restarted R1 unexpectedly has PE2")
        h.p("R1 recovery")
        h.sync(R2, R1, C)
        h.sync(R2, R1)
        h.check(pe2_id in h.channel_ids(R1_PORT, C), "R1 did not catch up PE2")
        h.check(h.same_set(h.channel_ids(R1_PORT, C), h.channel_ids(R2_PORT, C)),
                "relays not converged after catch-up")
        h.p("catch-up synchronization")

        # -------- deliberately different arrival order -------------------- #
        C_order = "sha256:" + os.urandom(32).hex()
        y1 = h.publish("a", "a1.bin", A_OBJ_PORT, h.A_STATE, [R1], channel=C_order)
        y2 = h.publish("a", "a2.bin", A_OBJ_PORT, h.A_STATE, [R1], channel=C_order)
        y3 = h.publish("b", "b1.bin", B_OBJ_PORT, h.B_STATE, [R2], channel=C_order)
        y4 = h.publish("b", "b2.bin", B_OBJ_PORT, h.B_STATE, [R2], channel=C_order)
        order_ids = [y["assertion_id"] for y in (y1, y2, y3, y4)]
        h.check(h.same_set(h.channel_ids(R1_PORT, C_order), order_ids[:2]), "order R1 pre")
        h.check(h.same_set(h.channel_ids(R2_PORT, C_order), order_ids[2:]), "order R2 pre")
        h.sync(R1, R2, C_order)
        h.sync(R2, R1, C_order)
        h.check(h.same_set(h.channel_ids(R1_PORT, C_order), order_ids), "order R1 post")
        h.check(h.same_set(h.channel_ids(R2_PORT, C_order), order_ids), "order R2 post")
        h.p("independent arrival order")

        # -------- object-index federation --------------------------------- #
        C_object = "sha256:" + os.urandom(32).hex()
        o_hash = "sha256:" + sha256_hex(h.fixture("a3.bin"))
        pa_obj = h.publish("a", "a3.bin", A_OBJ_PORT, h.A_STATE, [R1], channel=C_object)
        pb_obj = h.publish("b", "a3.bin", B_OBJ_PORT, h.B_STATE, [R2], channel=C_object)
        h.check(pa_obj["object_hash"] == o_hash and pb_obj["object_hash"] == o_hash,
                "shared object hash mismatch")
        h.sync(R1, R2, C_object)
        h.sync(R2, R1, C_object)
        for port in (R1_PORT, R2_PORT):
            ids = h.object_ids(port, o_hash)
            h.check(pa_obj["assertion_id"] in ids and pb_obj["assertion_id"] in ids,
                    f"object index not federated on {port}: {ids}")
        h.p("object-index federation")

        # -------- cross-relay parent reference ---------------------------- #
        C_parent = "sha256:" + os.urandom(32).hex()
        pap = h.publish("a", "a1.bin", A_OBJ_PORT, h.A_STATE, [R1], channel=C_parent)
        pbp = h.publish("b", "b1.bin", B_OBJ_PORT, h.B_STATE, [R2], channel=C_parent,
                        parents=pap["assertion_id"])
        h.check(pbp["status"] == 200, f"parent reference rejected by R2: {pbp}")
        h.sync(R1, R2, C_parent)
        h.sync(R2, R1, C_parent)
        for port in (R1_PORT, R2_PORT):
            env = h.assertion(port, pbp["assertion_id"])
            h.check(env.get("parents") == [pap["assertion_id"]],
                    f"parents changed on {port}: {env.get('parents')}")
            h.check(h.same_set(h.channel_ids(port, C_parent),
                               [pap["assertion_id"], pbp["assertion_id"]]),
                    f"parent channel set on {port}")
        h.p("cross-relay parent reference")

        # -------- hostile source relay ------------------------------------ #
        C_hostile = "sha256:" + os.urandom(32).hex()
        host = h.publish("a", "a2.bin", A_OBJ_PORT, h.A_STATE, [R1], channel=C_hostile)
        valid_id = host["assertion_id"]
        valid_env = h.assertion(R1_PORT, valid_id)
        invalid = json.loads(json.dumps(valid_env))
        invalid["ref"]["hash"] = "sha256:" + "11" * 32
        corrupted = json.loads(json.dumps(valid_env))
        sig = corrupted["sig"]
        corrupted["sig"] = ("1" if sig[0] != "1" else "2") + sig[1:]
        route = f"/v1/channels/sha256/{C_hostile.split(':', 1)[1]}/assertions"
        h.start_mock({route: [valid_env, invalid, corrupted]})
        r = h.sync(f"http://127.0.0.1:{MOCK_PORT}", R2, C_hostile)
        h.check(len(r["results"]) == 3, f"hostile attempt count {len(r['results'])}")
        h.check(r["valid"] == 1 and r["invalid"] == 2, f"hostile classification {r}")
        h.check(r["forwarded"] == 1, f"hostile forwarded {r['forwarded']}")
        h.check(h.channel_ids(R2_PORT, C_hostile) == [valid_id], "hostile destination polluted")
        h.check(h.channel_ids(R1_PORT, C_hostile) == [valid_id], "hostile source changed")
        if h.mock is not None:
            h.mock.shutdown()
            h.mock.server_close()
            h.mock = None
        h.p("hostile source relay validation")

        # -------- full cold restart --------------------------------------- #
        S = set(h.channel_ids(R1_PORT, C))
        h.check(S == set(h.channel_ids(R2_PORT, C)), "pre-restart divergence")
        a_seen = set(h.a_status()["seen"])
        b_seen = set(h.b_status()["seen"])
        adv_before = sorted(h.advertised(R2_PORT))
        h.stop("r1")
        h.stop("r2")
        h.stop("obj-a")
        h.stop("obj-b")
        h.start_relay("r1", R1_PORT, h.R1_DB)
        h.start_relay("r2", R2_PORT, h.R2_DB)
        h.start_objects()
        h.check(set(h.channel_ids(R1_PORT, C)) == S, "R1 state lost across restart")
        h.check(set(h.channel_ids(R2_PORT, C)) == S, "R2 state lost across restart")
        h.check(set(h.a_status()["seen"]) >= a_seen, "A state lost")
        h.check(set(h.b_status()["seen"]) >= b_seen, "B state lost")
        h.check(sorted(h.advertised(R2_PORT)) == adv_before, "advertised set changed")
        r = h.sync(R1, R2, C)
        h.check(r["forwarded"] == 0, "post-restart sync not idempotent")
        h.p("full cold restart")

        # -------- post-restart continued exchange ------------------------- #
        pf = h.publish("a", "a4.bin", A_OBJ_PORT, h.A_STATE, [R1])
        pg = h.publish("b", "b3.bin", B_OBJ_PORT, h.B_STATE, [R2])
        h.check(pf["status"] == 200 and pg["status"] == 200, "post-restart publish failed")
        h.sync(R1, R2, C)
        h.sync(R2, R1, C)
        union = S | {pf["assertion_id"], pg["assertion_id"]}
        h.check(set(h.channel_ids(R1_PORT, C)) == union, "R1 post-restart union")
        h.check(set(h.channel_ids(R2_PORT, C)) == union, "R2 post-restart union")
        h.p("post-restart synchronization")

        # -------- transcript ---------------------------------------------- #
        print("", flush=True)
        if h.passed == EXPECTED:
            print("MULTI-RELAY E2E PASS", flush=True)
            h.stop_all()
            sweep_ports()
            if not keep:
                shutil.rmtree(h.tmp, ignore_errors=True)
            return 0
        print(f"FAIL transcript mismatch: {h.passed}", flush=True)
        print(f"MULTI-RELAY E2E FAIL (working directory preserved: {h.tmp})", flush=True)
        h.stop_all()
        return 1

    except Exception as e:  # noqa: BLE001 - report and preserve workspace
        import traceback
        traceback.print_exc()
        print(f"FAIL: {e}", flush=True)
        print(f"MULTI-RELAY E2E FAIL (working directory preserved: {h.tmp})", flush=True)
        h.stop_all()
        sweep_ports()
        return 1


def main() -> int:
    ap = argparse.ArgumentParser(description="SPP v1 multi-relay federation e2e")
    ap.add_argument("--keep", action="store_true", help="preserve the working directory even on success")
    args = ap.parse_args()
    return run(args.keep)


if __name__ == "__main__":
    raise SystemExit(main())




