#!/usr/bin/env python3
"""spp-verify for impl-a. Reads the spec; does not import tools/."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from ed25519_spp import verify_spp_ed25519_1  # noqa: E402
from jcs import canonicalize, canonicalize_bytes  # noqa: E402
from json_input import JsonInputError, parse_utf8  # noqa: E402
from protocol import (  # noqa: E402
    SIG,
    UNIT_SCALE,
    MAX_JCS,
    SppError,
    UnsupportedError,
    check_schema,
    is_int_value,
    parse_any,
    reconstruct_u,
    sha256_id_of,
    target_for_units,
    validate_bytes,
    work_ok,
    work_units,
)


def format_valid(info: dict) -> str:
    return (
        "VALID\n"
        f"id: {info['id']}\n"
        f"units: {info['units']}\n"
        f"target: {info['target_hex']}\n"
    )


def format_invalid(err: SppError) -> str:
    kind = "UNSUPPORTED" if isinstance(err, UnsupportedError) else "INVALID"
    return f"{kind}\nstage: {err.stage}\nreason: {err.reason}\n"


def run_diagnostic(path: Path) -> tuple[int, str]:
    """Run the full §20 pipeline with verbose intermediate output."""
    data = path.read_bytes()
    lines: list[str] = []

    def add(label: str, value: object) -> None:
        lines.append(f"{label}: {value}")

    try:
        obj = parse_utf8(data)
        if not isinstance(obj, dict):
            raise SppError("json-input", "not-object")
    except (JsonInputError, SppError) as e:
        reason = e.reason if isinstance(e, (JsonInputError, SppError)) else str(e)
        stage = "json-input"
        add("status", "INVALID")
        add("stage", stage)
        add("reason", reason)
        return 1, "\n".join(lines) + "\n"

    try:
        # Version / type quick check
        if (
            "v" in obj
            and isinstance(obj["v"], float)
            and math.isfinite(obj["v"])
            and obj["v"] != 1.0
        ):
            raise UnsupportedError("version", "unknown-v")

        u = reconstruct_u(obj)
        add("v", obj.get("v"))
        add("type", u.get("type"))
        add("actor", u.get("actor"))
        add("created", u.get("created"))
        add("nonce", u.get("nonce"))

        check_schema(u)

        jcs_bytes = canonicalize_bytes(u)
        jcs_str = jcs_bytes.decode("utf-8")
        add("JCS(U)", jcs_str)
        add("canonical_body_bytes", len(jcs_bytes))

        if len(jcs_bytes) > MAX_JCS:
            raise SppError("length", "jcs-too-large")

        ident, digest = sha256_id_of(jcs_bytes)
        add("D", digest.hex())
        add("id_computed", ident)
        add("id_received", obj.get("id"))

        h = int.from_bytes(digest, "big")
        add("H", f"{h:064x}")

        if "id" not in obj or not isinstance(obj["id"], str):
            raise SppError("identifier", "missing-id")
        if obj["id"] != ident:
            raise SppError("identity", "id-mismatch")

        t = u["type"]
        if t == "pointer":
            loc = len(u["ref"]["locators"])
            parents = len(u["parents"]) if "parents" in u else 0
            cdc = 0
        elif t == "channel":
            loc = len(u["descriptor"]["locators"]) if "descriptor" in u else 0
            parents = 0
            cdc = 16
        else:
            raise SppError("schema", "unknown-type")
        add("locator_count", loc)
        add("parent_count", parents)
        add("channel_description_cost", cdc)

        units = work_units(u, len(jcs_bytes))
        tgt = target_for_units(units)
        wrequired = units * UNIT_SCALE
        add("units", units)
        add("Wrequired", wrequired)
        add("target", f"{tgt:064x}")

        pow_ok = work_ok(h, units)
        add("PoW", "PASS" if pow_ok else "FAIL")
        if not pow_ok:
            raise SppError("work", "insufficient-work")

        if "sig" not in obj or not isinstance(obj["sig"], str) or not SIG.fullmatch(obj["sig"]):
            raise SppError("signature", "signature")
        actor_hex = u["actor"].split(":", 1)[1]
        sig_ok = verify_spp_ed25519_1(
            bytes.fromhex(actor_hex), bytes.fromhex(obj["sig"]), digest
        )
        add("signature", "PASS" if sig_ok else "FAIL")
        if not sig_ok:
            raise SppError("signature", "signature")

        add("status", "VALID")
        return 0, "\n".join(lines) + "\n"

    except UnsupportedError as e:
        add("status", "UNSUPPORTED")
        add("stage", e.stage)
        add("reason", e.reason)
        return 2, "\n".join(lines) + "\n"
    except SppError as e:
        add("status", "INVALID")
        add("stage", e.stage)
        add("reason", e.reason)
        return 1, "\n".join(lines) + "\n"


def verify_file(path: Path) -> tuple[int, str]:
    data = path.read_bytes()
    try:
        info = validate_bytes(data)
    except SppError as e:
        code = 2 if isinstance(e, UnsupportedError) else 1
        return code, format_invalid(e)
    except RecursionError as e:  # defensive: never a validity statement
        return 3, "ERROR\nstage: internal\nreason: resource-exhausted\n"
    except Exception as e:  # isolate: a bug must not look like a verdict
        return 3, f"ERROR\nstage: internal\nreason: {type(e).__name__}\n"
    return 0, format_valid(info)


def _pad_u(inp: dict) -> dict:
    return {
        "v": 1.0,
        "type": "pointer",
        "actor": inp["actor"],
        "channel": inp["channel"],
        "created": float(inp["created"]),
        "ref": {"hash": inp["hash"], "locators": []},
        "ext": {"pad": "a" * int(inp["pad_len"])},
        "nonce": str(inp["nonce"]),
    }


def _deep_u(inp: dict) -> dict:
    inner: object = 1
    for _ in range(int(inp["depth"])):
        inner = {"a": inner}
    return {
        "v": 1.0,
        "type": "pointer",
        "actor": inp["actor"],
        "channel": inp["channel"],
        "created": float(inp["created"]),
        "ref": {"hash": inp["hash"], "locators": []},
        "ext": {"deep": inner},
        "nonce": str(inp["nonce"]),
    }


def run_case(case: dict) -> tuple[bool, str]:
    cid = case["id"]
    cls = case["class"]
    expect = case["expect"]
    inp = case["input"]
    want = case.get("want") or {}
    reasons = set(want.get("reasons") or [])

    def fail(msg: str) -> tuple[bool, str]:
        return False, f"{cid} FAIL {msg}"

    try:
        if cls == "full-assertion":
            info = validate_bytes(inp["utf8"].encode("utf-8"))
            if expect != "valid":
                return fail(f"expected {expect}, got valid")
            for k in ("id", "units", "target_hex", "jcs", "sig"):
                if k in want and info.get(k) != want[k]:
                    return fail(f"{k} mismatch")
            return True, f"{cid} PASS"

        if cls == "json-input":
            parse_utf8(inp["utf8"].encode("utf-8"))
            if expect == "invalid":
                return fail("json-input accepted")
            return True, f"{cid} PASS"

        if cls == "schema":
            obj = parse_utf8(inp["utf8"].encode("utf-8"))
            if not isinstance(obj, dict):
                raise SppError("schema", "schema")
            check_schema(reconstruct_u(obj) if "id" in obj or "sig" in obj else obj)
            if expect == "invalid":
                return fail("schema accepted")
            return True, f"{cid} PASS"

        if cls == "jcs":
            obj = parse_utf8(inp["utf8"].encode("utf-8"))
            jcs = canonicalize_bytes(obj)
            if "jcs_hex" in want and jcs.hex() != want["jcs_hex"]:
                return fail(f"jcs hex {jcs.hex()}")
            if "jcs" in want and jcs.decode("utf-8") != want["jcs"]:
                return fail("jcs mismatch")
            if "id" in want:
                ident, _ = sha256_id_of(jcs)
                if ident != want["id"]:
                    return fail(f"id {ident}")
            return True, f"{cid} PASS"

        if cls == "length":
            if inp["kind"] == "construct-pad":
                u = _pad_u(inp)
            elif inp["kind"] == "construct-depth":
                u = _deep_u(inp)
            else:
                obj = parse_utf8(inp["utf8"].encode("utf-8"))
                u = reconstruct_u(obj) if isinstance(obj, dict) else obj
                check_schema(u)
            jcs = canonicalize_bytes(u)
            if "jcs_bytes" in want and len(jcs) != want["jcs_bytes"]:
                return fail(f"jcs_bytes {len(jcs)}")
            if expect == "invalid":
                if len(jcs) > 1048576:
                    raise SppError("length", "jcs-too-large")
                check_schema(u)
                return fail("length accepted")
            check_schema(u)
            if "units" in want:
                units = work_units(u, len(jcs))
                if units != want["units"]:
                    return fail(f"units {units}")
            return True, f"{cid} PASS"

        if cls == "work":
            units = int(inp["units"])
            h = int(inp["H_hex"], 16)
            ok = work_ok(h, units)
            tgt = target_for_units(units)
            if "target_hex" in want and f"{tgt:064x}" != want["target_hex"]:
                return fail("target mismatch")
            if ok != want.get("accept", expect == "valid"):
                return fail(f"accept={ok}")
            return True, f"{cid} PASS"

        if cls == "spp-ed25519-1":
            ok = verify_spp_ed25519_1(
                bytes.fromhex(inp["A"]),
                bytes.fromhex(inp["sig"]),
                bytes.fromhex(inp["D"]),
            )
            if expect == "invalid" and ok:
                return fail("signature accepted")
            if expect == "valid" and not ok:
                return fail("signature rejected")
            return True, f"{cid} PASS"

        return fail(f"unknown class {cls}")
    except JsonInputError as e:
        if expect == "invalid" and (not reasons or e.reason in reasons):
            return True, f"{cid} PASS"
        return fail(f"json-input {e.reason}")
    except UnsupportedError as e:
        if expect == "unsupported" and (not reasons or e.reason in reasons):
            return True, f"{cid} PASS"
        return fail(f"unsupported {e.reason}")
    except SppError as e:
        if expect == "invalid" and (not reasons or e.reason in reasons):
            return True, f"{cid} PASS"
        return fail(f"{e.stage}:{e.reason}")


def run_suite(path: Path) -> int:
    suite = json.loads(path.read_text(encoding="utf-8"))
    failed = 0
    for case in suite["cases"]:
        ok, line = run_case(case)
        print(line)
        if not ok:
            failed += 1
    total = len(suite["cases"])
    print(f"{total - failed}/{total} passed")
    return 1 if failed else 0


def verdict_record(data: bytes) -> dict:
    try:
        info = validate_bytes(data)
        return {"status": "VALID", **{k: info[k] for k in ("id", "units", "target_hex")}}
    except UnsupportedError as e:
        return {"status": "UNSUPPORTED", "stage": e.stage, "reason": e.reason}
    except SppError as e:
        return {"status": "INVALID", "stage": e.stage, "reason": e.reason}
    except Exception as e:  # isolate: internal failure is not a validity claim
        return {"status": "ERROR", "stage": "internal", "reason": type(e).__name__}


def run_batch(path: Path) -> int:
    items = json.loads(path.read_text(encoding="utf-8"))
    for item in items:
        try:
            rec = verdict_record(item["utf8"].encode("utf-8"))
        except Exception as e:  # isolate: one hostile input must not kill the batch
            rec = {"status": "ERROR", "stage": "internal", "reason": f"{type(e).__name__}"}
        rec["name"] = item["name"]
        print(json.dumps(rec, ensure_ascii=False))
    return 0


def run_jcs_batch(path: Path) -> int:
    items = json.loads(path.read_text(encoding="utf-8"))
    for item in items:
        raw = item["utf8"].encode("utf-8")
        try:
            obj = parse_any(raw)
            jcs = canonicalize_bytes(obj)
            print(json.dumps({"name": item["name"], "status": "OK", "jcs_hex": jcs.hex()}, ensure_ascii=False))
        except JsonInputError as e:
            print(json.dumps({"name": item["name"], "status": "INVALID", "reason": e.reason}, ensure_ascii=False))
    return 0


def run_ed_batch(path: Path) -> int:
    items = json.loads(path.read_text(encoding="utf-8"))
    for item in items:
        ok = verify_spp_ed25519_1(
            bytes.fromhex(item["A"]),
            bytes.fromhex(item["sig"]),
            bytes.fromhex(item["D"]),
        )
        print(
            json.dumps(
                {"name": item["name"], "status": "VALID" if ok else "INVALID"},
                ensure_ascii=False,
            )
        )
    return 0


def main(argv: list[str]) -> int:
    # Diagnostics print raw JCS(U), which can contain any Unicode. Never let
    # the console encoding turn diagnostics into a second hostile-input surface.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    if len(argv) == 3 and argv[1] == "--suite":
        return run_suite(Path(argv[2]))
    if len(argv) == 3 and argv[1] == "--batch":
        return run_batch(Path(argv[2]))
    if len(argv) == 3 and argv[1] == "--jcs-batch":
        return run_jcs_batch(Path(argv[2]))
    if len(argv) == 3 and argv[1] == "--ed-batch":
        return run_ed_batch(Path(argv[2]))
    if len(argv) == 3 and argv[1] == "--diagnostic":
        code, text = run_diagnostic(Path(argv[2]))
        sys.stdout.write(text)
        return code
    if len(argv) != 2 or argv[1] in ("-h", "--help"):
        print(
            "usage: spp-verify assertion.json | --suite suite.json"
            " | --batch/--jcs-batch/--ed-batch items.json"
            " | --diagnostic assertion.json",
            file=sys.stderr,
        )
        return 3
    code, text = verify_file(Path(argv[1]))
    sys.stdout.write(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

