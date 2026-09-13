#!/usr/bin/env python3
"""Durable two-agent SPP v1 end-to-end exchange.

Demonstrates a real cross-language SPP v1 sequence between two independently
implemented actors and a persistent relay, then destroys and rebuilds every
process from disk.

The harness only orchestrates processes and inspects the relay / object
servers. It never mines, signs, submits, polls, or dereferences locators on the
agents' behalf; every protocol action is performed by the `examples/agent-a`
(Python) and `examples/agent-b` (TypeScript) CLIs as separate processes. Served
assertions are independently revalidated here with the frozen `impl-a` verifier.

Sequence (SPP v1 Durable Two-Agent Exchange test plan):

    relay discovery
    capability channel hidden from advertisement
    A publishes PA, B validates + fetches OA
    B publishes PB, A validates + fetches OB
    pagination + deduplication
    relay restart
    agent restart
    cold restart
    content-tamper rejection
    invalid-assertion rejection
    local-policy distinction
    idempotency

Usage:
    python tests/interoperability/durable-e2e/run_tests.py [--keep]
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
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FIX = HERE / "fixtures"
RELAY = ROOT / "implementations" / "relay" / "server.py"
AGENT_A = ROOT / "examples" / "agent-a" / "agent.py"
AGENT_B = ROOT / "examples" / "agent-b" / "agent.ts"
TSX = ROOT / "implementations" / "typescript" / "node_modules" / ".bin" / ("tsx.cmd" if os.name == "nt" else "tsx")
PY = sys.executable

sys.path.insert(0, str(ROOT / "implementations" / "python"))
from protocol import SppError, UnsupportedError, validate_bytes  # noqa: E402

try:
    import psutil  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    psutil = None

RELAY_PORT = 18760
A_OBJ_PORT = 18870
B_OBJ_PORT = 18871
POLICY_PORT = 18761
ALL_PORTS = (RELAY_PORT, A_OBJ_PORT, B_OBJ_PORT, POLICY_PORT)

SHA256_ID = re.compile(r"^sha256:[0-9a-f]{64}$")

EXPECTED = [
    "relay discovery",
    "capability channel hidden from advertisement",
    "A published PA",
    "B independently validated PA",
    "B fetched OA and verified sha256",
    "B published PB",
    "A independently validated PB",
    "A fetched OB and verified sha256",
    "pagination",
    "relay restart",
    "agent restart",
    "cold restart",
    "content-tamper rejection",
    "invalid-assertion rejection",
    "local-policy distinction",
    "idempotency",
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


# --------------------------------------------------------------------------- #
# independent revalidation (§20) of served bytes
# --------------------------------------------------------------------------- #

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
# driver
# --------------------------------------------------------------------------- #

class Harness:
    def __init__(self, keep: bool) -> None:
        self.keep = keep
        self.tmp = Path(tempfile.mkdtemp(prefix="spp-durable-e2e-"))
        self.logs = self.tmp / "logs"
        self.logs.mkdir()
        self.procs: dict[str, subprocess.Popen] = {}
        self.passed: list[str] = []
        self.A_STATE = self.tmp / "agent-a"
        self.B_STATE = self.tmp / "agent-b"
        self.DB = self.tmp / "relay.sqlite3"
        self.POLICY_DB = self.tmp / "policy.sqlite3"
        self.channel = "sha256:" + os.urandom(32).hex()

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

    def start_relay(self, name: str = "relay", env: dict | None = None) -> None:
        self.start(name, [PY, str(RELAY), "--port", str(RELAY_PORT), "--db", str(self.DB), "--page-size", "2"], env)
        wait_http(RELAY_PORT)

    def start_objects(self) -> None:
        self.start("obj-a", [PY, str(AGENT_A), "serve", "--state", str(self.A_STATE), "--port", str(A_OBJ_PORT)])
        self.start("obj-b", [str(TSX), str(AGENT_B), "serve", "--state", str(self.B_STATE), "--port", str(B_OBJ_PORT)])
        wait_http(A_OBJ_PORT, ("/health",))
        wait_http(B_OBJ_PORT, ("/health",))

    # -- client CLIs ------------------------------------------------------ #

    def a(self, *args: str) -> list[str]:
        return [PY, str(AGENT_A), *args]

    def b(self, *args: str) -> list[str]:
        return [str(TSX), str(AGENT_B), *args]

    def run_client(self, argv: list[str]) -> dict:
        proc = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=600)
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip().startswith("{")]
        if not lines:
            raise AssertionError(f"client produced no JSON result: {argv}\nstdout={proc.stdout}\nstderr={proc.stderr}")
        return json.loads(lines[-1])

    def a_status(self) -> dict:
        return self.run_client(self.a("status", "--state", str(self.A_STATE)))

    def b_status(self) -> dict:
        return self.run_client(self.b("status", "--state", str(self.B_STATE)))

    # -- fixtures --------------------------------------------------------- #

    def fixture(self, name: str) -> bytes:
        return (FIX / name).read_bytes()

    def object_file(self, state: Path, obj_hash: str) -> Path:
        return state / "objects" / obj_hash.split(":", 1)[1]

    def publish(self, agent: str, fixture: str, obj_port: int, state: Path,
                parents: str | None = None) -> dict:
        argv = (self.a if agent == "a" else self.b)(
            "publish",
            "--state", str(state),
            "--relay", f"http://127.0.0.1:{RELAY_PORT}",
            "--channel", self.channel,
            "--file", str(FIX / fixture),
            "--object-base", f"http://127.0.0.1:{obj_port}",
        )
        if parents:
            argv += ["--parents", parents]
        return self.run_client(argv)

    def poll(self, agent: str, state: Path) -> dict:
        argv = (self.a if agent == "a" else self.b)(
            "poll", "--state", str(state), "--relay", f"http://127.0.0.1:{RELAY_PORT}", "--channel", self.channel
        )
        return self.run_client(argv)

    def result_for(self, poll: dict, assertion_id: str) -> dict:
        for r in poll["results"]:
            if r["assertion_id"] == assertion_id:
                return r
        raise AssertionError(f"{assertion_id} not in poll results: {[r['assertion_id'] for r in poll['results']]}")

    # -- relay views ------------------------------------------------------ #

    def channel_path(self) -> str:
        return f"/v1/channels/sha256/{self.channel.split(':', 1)[1]}/assertions"

    def channel_ids(self) -> list[str]:
        return [e["id"] for e in all_items(RELAY_PORT, self.channel_path())]

    def object_ids(self, obj_hash: str) -> list[str]:
        return [e["id"] for e in all_items(RELAY_PORT, f"/v1/objects/sha256/{obj_hash.split(':', 1)[1]}/assertions")]

    # -- assertions ------------------------------------------------------- #

    def check(self, cond: bool, msg: str) -> None:
        if not cond:
            raise AssertionError(msg)

    def db_digest(self) -> str:
        h = hashlib.sha256()
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(self.DB) + suffix)
            if p.exists():
                h.update(suffix.encode("ascii"))
                h.update(p.read_bytes())
        return h.hexdigest()


# --------------------------------------------------------------------------- #
# test sequence
# --------------------------------------------------------------------------- #

def run(keep: bool) -> int:
    sweep_ports()
    h = Harness(keep)
    print(f"# working directory: {h.tmp}", flush=True)

    try:
        # -------- setup -------------------------------------------------- #
        a_init = h.run_client(h.a("init", "--state", str(h.A_STATE)))
        b_init = h.run_client(h.b("init", "--state", str(h.B_STATE)))
        actor_a = a_init["actor"]
        actor_b = b_init["actor"]
        h.check(bool(re.match(r"^ed25519:[0-9a-f]{64}$", actor_a)), f"actor A {actor_a}")
        h.check(bool(re.match(r"^ed25519:[0-9a-f]{64}$", actor_b)), f"actor B {actor_b}")

        h.start_relay()
        h.start_objects()

        code, man = get_json(RELAY_PORT, "/.well-known/spp")
        h.check(code == 200 and man["v"] == 1, f"manifest {code} {man}")
        h.check(man["submit"] == "/v1/assertions" and man["channel"] == "/v1/channels/sha256/{hex}/assertions", man)
        h.p("relay discovery")

        # -------- Test 1: capability channel ----------------------------- #
        adv = all_items(RELAY_PORT, "/v1/channels")
        h.check(h.channel not in adv, "capability channel advertised before use")
        code, page = get_json(RELAY_PORT, h.channel_path())
        h.check(code == 200, f"capability channel read -> {code}")
        h.check(page["items"] == [], f"capability channel not empty: {page}")
        h.p("capability channel hidden from advertisement")

        # -------- Test 2: A → B ------------------------------------------ #
        pub_a = h.publish("a", "a1.bin", A_OBJ_PORT, h.A_STATE)
        h.check(pub_a["status"] == 200 and pub_a["stored"], f"A publish {pub_a}")
        pa, oa = pub_a["assertion_id"], pub_a["object_hash"]
        h.check(bool(SHA256_ID.match(pa)), f"PA id syntax {pa}")

        code, raw = http_get(RELAY_PORT, f"/v1/assertions/sha256/{pa.split(':', 1)[1]}")
        h.check(code == 200, f"single GET PA -> {code}")
        info = revalidate_bytes(raw)
        h.check(info["id"] == pa, f"PA revalidates to {info['id']} != {pa}")
        h.check(pa in h.channel_ids(), "PA missing from channel index")
        h.check(pa in h.object_ids(oa), "PA missing from object index")
        h.p("A published PA")

        poll_b = h.poll("b", h.B_STATE)
        res = h.result_for(poll_b, pa)
        h.check(res["valid"] and res["new"], f"B rejected PA: {res}")
        h.p("B independently validated PA")

        h.check(res["fetched"] and res["hash_ok"] and res["stored"], f"B fetch failed: {res}")
        stored = h.object_file(h.B_STATE, oa)
        h.check(stored.is_file(), "B did not store OA")
        h.check(stored.read_bytes() == h.fixture("a1.bin"), "B stored OA bytes differ from a1.bin")
        h.check(sha256_hex(stored.read_bytes()) == oa.split(":", 1)[1], "B stored OA hash mismatch")
        h.check(pa in h.b_status()["seen"], "B did not record PA as seen")
        h.p("B fetched OA and verified sha256")

        # -------- Test 3: B → A ------------------------------------------ #
        pub_b = h.publish("b", "b1.bin", B_OBJ_PORT, h.B_STATE, parents=pa)
        h.check(pub_b["status"] == 200 and pub_b["stored"], f"B publish {pub_b}")
        pb, ob = pub_b["assertion_id"], pub_b["object_hash"]
        h.check(bool(SHA256_ID.match(pb)), f"PB id syntax {pb}")

        code, env_pb = get_json(RELAY_PORT, f"/v1/assertions/sha256/{pb.split(':', 1)[1]}")
        h.check(code == 200, f"single GET PB -> {code}")
        h.check(env_pb.get("parents") == [pa], f"PB parents {env_pb.get('parents')} != [{pa}]")
        h.p("B published PB")

        poll_a = h.poll("a", h.A_STATE)
        res = h.result_for(poll_a, pb)
        h.check(res["valid"] and res["new"], f"A rejected PB: {res}")
        h.p("A independently validated PB")

        h.check(res["fetched"] and res["hash_ok"] and res["stored"], f"A fetch failed: {res}")
        stored = h.object_file(h.A_STATE, ob)
        h.check(stored.is_file() and stored.read_bytes() == h.fixture("b1.bin"), "A stored OB differs from b1.bin")
        h.check(sha256_hex(stored.read_bytes()) == ob.split(":", 1)[1], "A stored OB hash mismatch")
        h.check(pb in h.a_status()["seen"], "A did not record PB as seen")
        h.p("A fetched OB and verified sha256")

        # -------- Test 4: pagination + dedup ----------------------------- #
        for fixture, agent, port, state in (
            ("a2.bin", "a", A_OBJ_PORT, h.A_STATE),
            ("a3.bin", "a", A_OBJ_PORT, h.A_STATE),
            ("b2.bin", "b", B_OBJ_PORT, h.B_STATE),
            ("b3.bin", "b", B_OBJ_PORT, h.B_STATE),
        ):
            r = h.publish(agent, fixture, port, state)
            h.check(r["status"] == 200, f"publish {fixture} -> {r}")

        total = len(h.channel_ids())
        h.check(total >= 6, f"channel too small for pagination: {total}")

        for agent, state in (("a", h.A_STATE), ("b", h.B_STATE)):
            poll = h.poll(agent, state)
            h.check(poll["errors"] == [], f"{agent} poll errors {poll['errors']}")
            h.check(poll["pages"] >= 2, f"{agent} did not paginate: {poll['pages']}")
            h.check(poll["discovered"] == total, f"{agent} discovered {poll['discovered']} != {total}")
            h.check(all(r["valid"] for r in poll["results"]), f"{agent} saw an invalid assertion")
            h.check(poll["invalid"] == 0, f"{agent} invalid {poll['invalid']}")
            again = h.poll(agent, state)
            h.check(again["new"] == 0, f"{agent} re-delivered {again['new']} seen assertions")
            h.check(len(set(h.a_status()["seen"] if agent == "a" else h.b_status()["seen"])) == total,
                    f"{agent} seen set != channel size")
        h.p("pagination")

        # -------- Test 5: relay persistence ------------------------------ #
        adv_pub = h.run_client(h.a(
            "publish-channel", "--state", str(h.A_STATE),
            "--relay", f"http://127.0.0.1:{RELAY_PORT}",
        ))
        h.check(adv_pub["status"] == 200, f"publish-channel {adv_pub}")
        adv_id = adv_pub["assertion_id"]
        h.check(adv_id in all_items(RELAY_PORT, "/v1/channels"), "advertised channel missing")
        h.check(h.channel not in all_items(RELAY_PORT, "/v1/channels"), "capability channel advertised")

        chan_before = sorted(h.channel_ids())
        known_ids = sorted(set(chan_before) | {adv_id})
        obj_hashes = [pub_a["object_hash"], pub_b["object_hash"]]
        for fixture in ("a2.bin", "a3.bin", "b2.bin", "b3.bin"):
            data = h.fixture(fixture)
            obj_hashes.append("sha256:" + sha256_hex(data))
        obj_before = {oh: sorted(h.object_ids(oh)) for oh in obj_hashes}
        adv_before = sorted(all_items(RELAY_PORT, "/v1/channels"))

        h.stop("relay")
        db_hash = h.db_digest()
        print(f"# relay database sha256: {db_hash}", flush=True)

        h.start_relay()
        for aid in known_ids:
            code, raw = http_get(RELAY_PORT, f"/v1/assertions/sha256/{aid.split(':', 1)[1]}")
            h.check(code == 200, f"post-restart GET {aid} -> {code}")
            h.check(revalidate_bytes(raw)["id"] == aid, f"post-restart revalidate {aid}")
        h.check(sorted(h.channel_ids()) == chan_before, "channel index changed across restart")
        for oh, want in obj_before.items():
            h.check(sorted(h.object_ids(oh)) == want, f"object index changed for {oh}")
        adv_after = sorted(all_items(RELAY_PORT, "/v1/channels"))
        h.check(adv_after == adv_before and adv_id in adv_after, f"advertised set changed: {adv_after}")
        h.check(h.channel not in adv_after, "capability channel became advertised after restart")
        code, page = get_json(RELAY_PORT, h.channel_path())
        h.check(code == 200 and len(page["items"]) >= 1, "capability channel unreadable after restart")
        h.p("relay restart")

        # -------- Test 6: agent persistence ------------------------------ #
        a_before, b_before = h.a_status(), h.b_status()
        h.stop("obj-a")
        h.stop("obj-b")
        h.start_objects()

        for agent, state, before, status_fn in (
            ("a", h.A_STATE, a_before, h.a_status),
            ("b", h.B_STATE, b_before, h.b_status),
        ):
            poll = h.poll(agent, state)
            h.check(poll["errors"] == [], f"{agent} restart poll errors {poll['errors']}")
            h.check(poll["new"] == 0, f"{agent} re-delivered {poll['new']} assertions after restart")
            after = status_fn()
            h.check(after["actor"] == before["actor"], f"{agent} identity changed")
            h.check(sorted(after["seen"]) == sorted(before["seen"]), f"{agent} seen set changed")
            h.check(sorted(after["objects"]) == sorted(before["objects"]), f"{agent} stored objects changed")

        for state, obj_hash in ((h.A_STATE, pub_a["object_hash"]), (h.B_STATE, pub_b["object_hash"])):
            code, raw = http_get(A_OBJ_PORT if state == h.A_STATE else B_OBJ_PORT,
                                 f"/objects/sha256/{obj_hash.split(':', 1)[1]}")
            h.check(code == 200 and sha256_hex(raw) == obj_hash.split(":", 1)[1], "stored object not served after restart")

        h.p("agent restart")

        a4 = h.publish("a", "a4.bin", A_OBJ_PORT, h.A_STATE)
        h.check(a4["status"] == 200, f"A4 publish {a4}")
        poll_b = h.poll("b", h.B_STATE)
        res = h.result_for(poll_b, a4["assertion_id"])
        h.check(res["new"] and res["stored"] and res["hash_ok"], f"B did not receive A4: {res}")
        h.check(h.object_file(h.B_STATE, a4["object_hash"]).read_bytes() == h.fixture("a4.bin"), "A4 bytes mismatch")

        # -------- Test 7: full cold restart ------------------------------ #
        a_id_before, b_id_before = h.a_status()["actor"], h.b_status()["actor"]
        h.stop("relay")
        h.stop("obj-a")
        h.stop("obj-b")
        h.start_relay()
        h.start_objects()

        all_ids = sorted(set(h.channel_ids()) | {adv_id})
        for aid in all_ids:
            code, raw = http_get(RELAY_PORT, f"/v1/assertions/sha256/{aid.split(':', 1)[1]}")
            h.check(code == 200, f"cold-restart GET {aid} -> {code}")
            h.check(revalidate_bytes(raw)["id"] == aid, f"cold-restart revalidate {aid}")
        h.check(h.a_status()["actor"] == a_id_before and h.b_status()["actor"] == b_id_before,
                "identity changed across cold restart")
        a_seen_before = set(h.a_status()["seen"])
        b_seen_before = set(h.b_status()["seen"])
        chan_total = set(h.channel_ids())
        h.poll("a", h.A_STATE)
        h.poll("b", h.B_STATE)
        h.check(a_seen_before <= set(h.a_status()["seen"]), "A lost seen state")
        h.check(b_seen_before <= set(h.b_status()["seen"]), "B lost seen state")
        h.check(chan_total <= set(h.a_status()["seen"]), "A did not catch up to the channel")
        h.check(chan_total <= set(h.b_status()["seen"]), "B did not catch up to the channel")

        old_objs = set(h.a_status()["objects"]) | set(h.b_status()["objects"])
        for obj_hash in old_objs:
            port = A_OBJ_PORT if h.object_file(h.A_STATE, obj_hash).exists() else B_OBJ_PORT
            code, raw = http_get(port, f"/objects/sha256/{obj_hash.split(':', 1)[1]}")
            h.check(code == 200 and sha256_hex(raw) == obj_hash.split(":", 1)[1], f"old object lost {obj_hash}")

        a5 = h.publish("a", "a5.bin", A_OBJ_PORT, h.A_STATE)
        h.check(a5["status"] == 200, f"A5 publish {a5}")
        b4 = h.publish("b", "b4.bin", B_OBJ_PORT, h.B_STATE)
        h.check(b4["status"] == 200, f"B4 publish {b4}")
        res_b = h.result_for(h.poll("b", h.B_STATE), a5["assertion_id"])
        h.check(res_b["new"] and res_b["stored"], f"B did not receive A5: {res_b}")
        res_a = h.result_for(h.poll("a", h.A_STATE), b4["assertion_id"])
        h.check(res_a["new"] and res_a["stored"], f"A did not receive B4: {res_a}")
        h.p("cold restart")

        # -------- Test 10: content tampering ----------------------------- #
        tamper_pub = h.publish("a", "t1.bin", A_OBJ_PORT, h.A_STATE)
        h.check(tamper_pub["status"] == 200, f"tamper publish {tamper_pub}")
        pt, ot = tamper_pub["assertion_id"], tamper_pub["object_hash"]
        target = h.object_file(h.A_STATE, ot)
        good = target.read_bytes()
        target.write_bytes(b"these are not the bytes you signed for\n")
        h.check(sha256_hex(target.read_bytes()) != ot.split(":", 1)[1], "tamper did not change the object")

        poll_b = h.poll("b", h.B_STATE)
        res = h.result_for(poll_b, pt)
        h.check(res["valid"], "tampered pointer assertion was rejected as invalid")
        h.check(res["new"] and res["fetched"], f"tampered pointer was not fetched: {res}")
        h.check(res["hash_ok"] is False and res["stored"] is False, f"tampered payload accepted: {res}")
        h.check(res["reason"] == "hash-mismatch", f"unexpected tamper reason: {res['reason']}")
        h.check(not h.object_file(h.B_STATE, ot).exists(), "tampered payload entered B's inbox")
        h.check(ot not in h.b_status()["objects"], "tampered payload recorded as stored")
        target.write_bytes(good)
        h.p("content-tamper rejection")

        # -------- Test 11: invalid assertion ----------------------------- #
        valid_file = h.A_STATE / "published" / (pa.split(":", 1)[1] + ".json")
        original = json.loads(valid_file.read_text(encoding="utf-8"))

        def variant(name: str, mutate) -> Path:
            env = json.loads(json.dumps(original))
            mutate(env)
            p = h.tmp / f"invalid-{name}.json"
            p.write_text(json.dumps(env, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            return p

        def flip_sig(env):
            s = env["sig"]
            env["sig"] = ("1" if s[0] != "1" else "2") + s[1:]

        mutated = [
            ("channel", variant("channel", lambda e: e.__setitem__("channel", "sha256:" + "11" * 32))),
            ("ref", variant("ref", lambda e: e["ref"].__setitem__("hash", "sha256:" + "22" * 32))),
            ("actor", variant("actor", lambda e: e.__setitem__("actor", "ed25519:" + "33" * 32))),
            ("sig", variant("sig", flip_sig)),
        ]

        adv_snapshot = sorted(all_items(RELAY_PORT, "/v1/channels"))
        chan_snapshot = sorted(h.channel_ids())
        obj_snapshot = sorted(h.object_ids(oa))

        for name, path in mutated:
            r = h.run_client(h.a("submit", "--relay", f"http://127.0.0.1:{RELAY_PORT}", "--file", str(path)))
            h.check(r["status"] == 400, f"mutated {name} -> {r}")

        h.check(sorted(all_items(RELAY_PORT, "/v1/channels")) == adv_snapshot, "advertised DB changed")
        h.check(sorted(h.channel_ids()) == chan_snapshot, "channel index changed")
        h.check(sorted(h.object_ids(oa)) == obj_snapshot, "object index changed")
        h.p("invalid-assertion rejection")

        # -------- Test 12: local relay policy ---------------------------- #
        h.start(
            "policy",
            [PY, str(RELAY), "--port", str(POLICY_PORT), "--db", str(h.POLICY_DB), "--page-size", "2"],
            env={"SPP_BLOCK_ACTOR": actor_a},
        )
        wait_http(POLICY_PORT)
        r = h.run_client(h.a("submit", "--relay", f"http://127.0.0.1:{POLICY_PORT}", "--file", str(valid_file)))
        h.check(r["status"] == 403 and r["error"] == "policy", f"blocked relay -> {r}")
        r = h.run_client(h.a("submit", "--relay", f"http://127.0.0.1:{RELAY_PORT}", "--file", str(valid_file)))
        h.check(r["status"] == 200, f"unblocked relay -> {r}")
        h.stop("policy")
        h.p("local-policy distinction")

        # -------- Test 13: idempotency ----------------------------------- #
        for _ in range(2):
            r = h.run_client(h.a("submit", "--relay", f"http://127.0.0.1:{RELAY_PORT}", "--file", str(valid_file)))
            h.check(r["status"] == 200 and r["assertion_id"] == pa, f"idempotent submit -> {r}")
        h.check(h.channel_ids().count(pa) == 1, "duplicate channel-index entry")
        h.check(h.object_ids(oa).count(pa) == 1, "duplicate object-index entry")
        h.p("idempotency")

        # -------- transcript --------------------------------------------- #
        print("", flush=True)
        if h.passed == EXPECTED:
            print("E2E PASS", flush=True)
            h.stop_all()
            sweep_ports()
            if not keep:
                shutil.rmtree(h.tmp, ignore_errors=True)
            return 0
        print(f"FAIL transcript mismatch: {h.passed}", flush=True)
        print(f"E2E FAIL (working directory preserved: {h.tmp})", flush=True)
        h.stop_all()
        return 1

    except Exception as e:  # noqa: BLE001 - report and preserve workspace
        import traceback
        traceback.print_exc()
        print(f"FAIL: {e}", flush=True)
        print(f"E2E FAIL (working directory preserved: {h.tmp})", flush=True)
        h.stop_all()
        sweep_ports()
        return 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Durable two-agent SPP v1 end-to-end exchange")
    ap.add_argument("--keep", action="store_true", help="preserve the working directory even on success")
    args = ap.parse_args()
    return run(args.keep)


if __name__ == "__main__":
    raise SystemExit(main())
