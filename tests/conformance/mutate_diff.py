"""Differential corpus. HARD disagreement (validity / JCS bytes) is a freeze blocker."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
A2 = json.loads((ROOT / "tests" / "conformance" / "vectors" / "a2.json").read_text(encoding="utf-8"))
CORPUS = ROOT / "tests" / "conformance" / "fuzz-corpus"
TSX = ROOT / "implementations" / "typescript" / "node_modules" / ".bin" / ("tsx.cmd" if os.name == "nt" else "tsx")


def compact(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def base() -> str:
    return compact(A2)


def mutations() -> list[tuple[str, str]]:
    b = base()
    out: list[tuple[str, str]] = []

    def add(name: str, raw: str) -> None:
        out.append((name, raw))

    add("clean", b)
    add("ws-pretty", json.dumps(A2, indent=2))
    add("trailing-nl", b + "\n")
    add("trailing-junk", b + " ")
    add("dup-v", '{"v":1,"v":1,' + b[len('{"v":1,') :])
    add("dup-nested", compact({**A2, "ext": {"a": 1}}).replace('"ext":{"a":1}', '"ext":{"a":1,"a":2}'))
    add("dup-empty-key", '{"v":1,"":1,"":2}')
    add("dup-ref-hash", '{"v":1,"ref":{"hash":"x","hash":"y","locators":[]}}')
    add("v-1.0", '{"v":1.0,' + b[len('{"v":1,') :])
    add("v-1e0", '{"v":1e0,' + b[len('{"v":1,') :])
    add("v-1E0", '{"v":1E0,' + b[len('{"v":1,') :])
    add("v-round", '{"v":1.0000000000000001,' + b[len('{"v":1,') :])
    add("v-next", '{"v":1.0000000000000002,' + b[len('{"v":1,') :])
    add("v-2", compact({**A2, "v": 2}))
    add("v-0", compact({**A2, "v": 0}))
    add("v-1.5", compact({**A2, "v": 1.5}))
    add("v-string", compact({**A2, "v": "1"}))
    add("v-true", '{"v":true,"type":"pointer"}')
    add("created-neg", compact({**A2, "created": -1}))
    add("created-hi", compact({**A2, "created": 9007199254740992}))
    add("created-max", compact({**A2, "created": 9007199254740991}))
    add("created-zero", compact({**A2, "created": 0}))
    add("created-frac-round", compact({**A2, "created": 1789184927.0000001}))
    add("created-1e20", compact({**A2, "created": 1e20}))
    add("negzero", '{"created":-0}')
    add("negzero-frac", '{"n":-0.0}')
    add("negzero-exp", '{"n":-0e0}')
    add("negzero-underflow", '{"n":-1e-400}')
    add("pos-underflow", '{"n":1e-400}')
    add("overflow-inf", '{"n":1e400}')
    add("nonce-lead", compact({**A2, "nonce": "018"}))
    add("nonce-00", compact({**A2, "nonce": "00"}))
    add("nonce-empty", compact({**A2, "nonce": ""}))
    add("nonce-2e64", compact({**A2, "nonce": "18446744073709551616"}))
    add("nonce-max", compact({**A2, "nonce": "18446744073709551615"}))
    add("nonce-0", compact({**A2, "nonce": "0"}))
    add("nonce-number", compact({**{k: v for k, v in A2.items() if k != "nonce"}, "nonce": 81681}))
    add("upper-hex", compact({**A2, "channel": A2["channel"].upper()}))
    add("short-id", compact({**A2, "channel": "sha256:00"}))
    add("actor-upper", compact({**A2, "actor": A2["actor"].upper()}))
    add("parents-str", compact({**A2, "parents": A2["id"]}))
    add("parents-null", compact({**A2, "parents": None}))
    add("parents-empty", compact({**A2, "parents": []}))
    extra = dict(A2)
    extra["x"] = "no"
    add("unknown-top", compact(extra))
    ptr = dict(A2)
    ptr["descriptor"] = {"hash": A2["ref"]["hash"], "locators": []}
    add("pointer+desc", compact(ptr))
    add("ref-foo", compact({**A2, "ref": {**A2["ref"], "foo": 1}}))
    add("ref-null", compact({**A2, "ref": None}))
    add("locators-null", compact({**A2, "ref": {"hash": A2["ref"]["hash"], "locators": None}}))
    add("locator-8193", compact({**A2, "ref": {"hash": A2["ref"]["hash"], "locators": ["x" * 8193]}}))
    add("locator-8192", compact({**A2, "ref": {"hash": A2["ref"]["hash"], "locators": ["x" * 8192]}}))
    add("surrogate", r'{"x":"\uD800"}')
    add("trail-surrogate", r'{"x":"\uDC00"}')
    add("pair-surrogate", r'{"x":"\uD800\uDC00"}')
    add("nonchar", r'{"ext":{"n":"\uFDD0"}}')
    add("nonchar-fffe", r'{"ext":{"n":"\uFFFE"}}')
    add("nonchar-10ffff", r'{"ext":{"n":"\uDBFF\uDFFF"}}')
    add("nonchar-key", r'{"\uFDD0":1}')
    add("literal-nonchar", '{"n":"\ufdd0"}')
    add("zero-sig", compact({**A2, "sig": "00" * 64}))
    add("short-sig", compact({**A2, "sig": "00"}))
    add("sig-upper", compact({**A2, "sig": A2["sig"].upper()}))
    add("id-mismatch", compact({**A2, "id": "sha256:" + "00" * 32}))
    add("missing-id", compact({k: v for k, v in A2.items() if k != "id"}))
    add("missing-sig", compact({k: v for k, v in A2.items() if k != "sig"}))
    add("array-top", "[1,2]")
    add("null-top", "null")
    add("empty", "")
    add("bom", "\ufeff" + b)
    add("comments", '{"v":1/*x*/}')
    add("trailing-comma", '{"v":1,}')
    add("single-quotes", "{'v':1}")
    add("plus-number", '{"n":+1}')
    add("bare-inf", '{"n":Infinity}')
    add("nested-id-kept", compact({**A2, "ext": {"id": "not-stripped"}}))
    add("type-channel-on-pointer-shape", compact({**A2, "type": "channel"}))
    add("future-type", compact({**A2, "type": "futureThing"}))
    add("a9", '{"\U00010000":2,"\ue000":1}')
    add("utf8-vs-utf16-keys", '{"\ue000":1,"\U00010000":2}')
    add("ext-round", '{"n":9007199254740993}')
    add("ext-2e53", '{"n":9007199254740992}')
    add("rfc8785-example", '{"n":333333333.33333329}')
    add("n-0.1", '{"n":0.1}')
    add("n-1e-6", '{"n":1e-6}')
    add("n-1e-7", '{"n":1e-7}')
    add("n-1e20", '{"n":1e20}')
    add("n-1e21", '{"n":1e21}')
    add("n-1e22", '{"n":1e22}')
    add("ctrl-unescaped", '{"n":"\u0001"}')
    add("ctrl-escaped", r'{"n":"\u0001"}')
    # 1024-byte work boundary (A.5 shape, unsigned U only → invalid as full assertion)
    actor = A2["actor"]
    ch = A2["channel"]
    h = A2["ref"]["hash"]
    add(
        "pad-1024-units-shape",
        compact(
            {
                "v": 1,
                "type": "pointer",
                "actor": actor,
                "channel": ch,
                "created": 1789184927,
                "ref": {"hash": h, "locators": []},
                "ext": {"pad": "a" * 680},
                "nonce": "9",
            }
        ),
    )
    add(
        "pad-1025-units-shape",
        compact(
            {
                "v": 1,
                "type": "pointer",
                "actor": actor,
                "channel": ch,
                "created": 1789184927,
                "ref": {"hash": h, "locators": []},
                "ext": {"pad": "a" * 680},
                "nonce": "10",
            }
        ),
    )
    # RC3: deep-nesting cases. §5 makes nesting depth transport policy, not
    # validity; both implementations must render §20 verdicts, never crash.
    deep600 = '{"a":' * 600 + "1" + "}" * 600
    add(
        "deep-ext-shape",
        compact(
            {
                "v": 1,
                "type": "pointer",
                "actor": actor,
                "channel": ch,
                "created": 1789184927,
                "ref": {"hash": h, "locators": []},
                "ext": {"deep": json.loads('{"a":' * 600 + "1" + "}" * 600)},
                "nonce": "9",
            }
        ),
    )
    add("deep-dup-name", '{"ext":{"deep":' + deep600[:-1] + ',"a":2}}')
    add("deep-unknown-top", '{"x":' + deep600 + "}")
    return out


def ed25519_cases() -> list[tuple[str, dict]]:
    src = json.loads((ROOT / "tests" / "conformance" / "vectors" / "source.json").read_text(encoding="utf-8"))
    out = []
    out.append(
        (
            "ed-a1-ok",
            {
                "A": src["test_key"]["public_key_hex"],
                "sig": src["A1_channel"]["sig"],
                "D": src["A1_channel"]["d_hex"],
            },
        )
    )
    out.append(
        (
            "ed-n14",
            {
                "A": src["test_key"]["public_key_hex"],
                "sig": src["ed25519"]["A1_sig_S_plus_L"],
                "D": src["A1_channel"]["d_hex"],
            },
        )
    )
    out.append(
        (
            "ed-n15",
            {
                "A": src["ed25519"]["identity_A"],
                "sig": src["A1_channel"]["sig"],
                "D": src["A1_channel"]["d_hex"],
            },
        )
    )
    out.append(("ed-n19", src["N19_ed25519"]))
    out.append(("ed-n20", src["N20_ed25519"]))
    return out


def jcs_cases() -> list[tuple[str, str]]:
    nums = [
        "0",
        "1",
        "-1",
        "1.0",
        "0.1",
        "0.3",
        "1.1",
        "1e-6",
        "1e-7",
        "1e20",
        "1e21",
        "1e22",
        "9007199254740991",
        "9007199254740992",
        "9007199254740993",
        "333333333.33333329",
        "5e-324",
        "2.2250738585072014e-308",
        "1.7976931348623157e+308",
        "0.000001",
        "100000000000000000000",
        "1.2345e-10",
        "6.02214076e+23",
        # RC2 regression: large integral binary64; ECMAScript form vs exact int
        "36101157879172420000",
        # More large integral values near 2^53+ boundaries
        "295147905179352830000",
        "999999999999999700000",
    ]
    out = [(f"num-{n}", f'{{"n":{n}}}') for n in nums]
    out.append(("a9", '{"\U00010000":2,"\ue000":1}'))
    out.append(("keys-ascii", '{"b":1,"a":2}'))
    out.append(("ctrl", r'{"n":"\u0001\u001f"}'))
    out.append(("quote", '{"n":"a\\"b"}'))
    out.append(("slash", '{"n":"a/b"}'))
    out.append(("bools", '{"a":true,"b":false,"c":null}'))
    out.append(("arr", '{"a":[1,2,{"z":0,"a":1}]}'))
    return out


# --- Workstream J: classify mutations by the subfunction they intend to exercise ---
#
# Target names mirror Appendix D: JSON-input, schema, JCS, work, SPP-Ed25519-1,
# full assertion. A mutation that agrees between implementations but stops at a
# layer earlier than its target did NOT actually exercise that subfunction.

_JSON_INPUT = {
    "trailing-junk", "dup-v", "dup-nested", "dup-empty-key", "dup-ref-hash",
    "negzero", "negzero-frac", "negzero-exp", "negzero-underflow",
    "overflow-inf", "surrogate", "trail-surrogate",
    "nonchar", "nonchar-fffe", "nonchar-10ffff", "nonchar-key",
    "literal-nonchar", "array-top", "null-top", "empty", "bom", "comments",
    "trailing-comma", "single-quotes", "plus-number", "bare-inf",
    "ctrl-unescaped",
}
_VERSION = {"v-1.0", "v-1e0", "v-1E0", "v-round", "v-next", "v-2", "v-0", "v-1.5", "v-string", "v-true"}
_NUMERIC = {"created-neg", "created-hi", "created-max", "created-zero", "created-frac-round", "created-1e20"}
_SCHEMA = {
    "nonce-lead", "nonce-00", "nonce-empty", "nonce-2e64", "nonce-max", "nonce-0",
    "nonce-number", "parents-str", "parents-null", "unknown-top",
    "pointer+desc", "ref-foo", "ref-null", "locators-null", "locator-8193",
    "type-channel-on-pointer-shape", "future-type",
}
_IDENTIFIER = {"upper-hex", "short-id", "actor-upper", "missing-id"}
_IDENTITY = {"id-mismatch"}
_SIGNATURE = {"zero-sig", "short-sig", "sig-upper", "missing-sig"}
_JCS = {"a9", "utf8-vs-utf16-keys", "ext-round", "ext-2e53", "rfc8785-example",
        "n-0.1", "n-1e-6", "n-1e-7", "n-1e20", "n-1e21", "n-1e22", "ctrl-escaped"}

_ACCEPTABLE_STAGE = {
    "json-input": {"json-input"},
    "version": {"version", "schema"},
    "numeric-core": {"numeric-core", "created", "identifier", "identity"},
    "schema": {"schema", "length", "identity", "nonce"},
    "identifier": {"identifier", "identity"},
    "identity": {"identity"},
    "work": {"work"},
    "signature": {"signature"},
    "jcs": None,
    "full-assertion": None,
}


def target_of(name: str) -> str:
    if name in _JSON_INPUT:
        return "json-input"
    if name in _VERSION:
        return "version"
    if name in _NUMERIC:
        return "numeric-core"
    if name in _SCHEMA:
        return "schema"
    if name in _IDENTIFIER:
        return "identifier"
    if name in _IDENTITY:
        return "identity"
    if name in _SIGNATURE:
        return "signature"
    if name in _JCS:
        return "jcs"
    return "full-assertion"


def classify_report(a_list: list[dict], b_list: list[dict], kind: str) -> list[dict]:
    """Record target stage and both results for every case, flagging stage misses."""
    am = {r["name"]: r for r in a_list}
    bm = {r["name"]: r for r in b_list}
    report: list[dict] = []
    for name in dict.fromkeys([*am, *bm]):
        ar, br = am.get(name, {}), bm.get(name, {})
        if kind == "jcs":
            target = "jcs"
            astage = bstage = "jcs" if ar.get("status") == "OK" else "json-input"
            stage_match = True
        elif kind == "ed":
            target = "spp-ed25519-1"
            astage = bstage = "signature"
            stage_match = True
        else:
            target = target_of(name)
            astage, bstage = ar.get("stage"), br.get("stage")
            if target == "jcs":
                # JCS numbers are exercised by the dedicated --jcs-batch lane,
                # not by the full-assertion lane.
                stage_match = None
            else:
                acceptable = _ACCEPTABLE_STAGE.get(target)
                if acceptable is None or astage is None:
                    stage_match = None
                else:
                    stage_match = astage in acceptable and bstage in acceptable
        report.append({
            "name": name,
            "target": target,
            "expected": None,
            "impl_a": ar,
            "impl_b": br,
            "stage_matches_target": stage_match,
        })
    return report


def run_tool(args: list[str], cwd: Path) -> list[dict]:
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0 and not p.stdout:
        raise SystemExit(f"tool failed: {args}\n{p.stderr}")
    recs = []
    for line in p.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        recs.append(json.loads(line))
    return recs


def compare_maps(a_list: list[dict], b_list: list[dict], kind: str) -> int:
    am = {r["name"]: r for r in a_list}
    bm = {r["name"]: r for r in b_list}
    names = list(dict.fromkeys([*am, *bm]))
    hard = 0
    soft = 0
    for name in names:
        ar, br = am.get(name), bm.get(name)
        if ar is None or br is None:
            print(f"HARD {kind} {name} missing a={ar} b={br}")
            hard += 1
            continue
        if kind == "verify" or kind == "ed":
            hard_diff = ar.get("status") != br.get("status")
            if ar.get("status") == "VALID" and br.get("status") == "VALID":
                hard_diff = hard_diff or any(
                    ar.get(k) != br.get(k) for k in ("id", "units", "target_hex") if k in ar or k in br
                )
            soft_diff = (ar.get("stage"), ar.get("reason")) != (br.get("stage"), br.get("reason"))
            if kind == "ed":
                soft_diff = False
        else:
            hard_diff = (ar.get("status"), ar.get("jcs_hex"), ar.get("reason")) != (
                br.get("status"),
                br.get("jcs_hex"),
                br.get("reason"),
            )
            soft_diff = False
        if hard_diff:
            print(f"HARD {kind} {name}")
            print(f"  a: {ar}")
            print(f"  b: {br}")
            hard += 1
        elif soft_diff:
            print(f"SOFT {kind} {name} a={ar.get('stage')}:{ar.get('reason')} b={br.get('stage')}:{br.get('reason')}")
            soft += 1
        else:
            print(f"AGREE {kind} {name} {ar.get('status') or ar.get('jcs_hex', '')[:16]}")
    print(f"{kind}: {hard} hard, {soft} soft, {len(names)} cases")
    return hard


def write_batch(items: list[tuple[str, str]], path: Path) -> None:
    path.write_text(
        json.dumps([{"name": n, "utf8": u} for n, u in items], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def seed_corpus(items: list[tuple[str, str]]) -> None:
    d = CORPUS / "generated"
    d.mkdir(parents=True, exist_ok=True)
    for name, raw in items:
        safe = name.replace("/", "_")
        (d / f"{safe}.json").write_bytes(raw.encode("utf-8"))


def main() -> int:
    muts = mutations()
    jcs = jcs_cases()
    eds = ed25519_cases()
    seed_corpus(muts)
    batch = CORPUS / "_batch.json"
    jcs_batch = CORPUS / "_jcs_batch.json"
    ed_batch = CORPUS / "_ed_batch.json"
    write_batch(muts, batch)
    write_batch(jcs, jcs_batch)
    ed_batch.write_text(
        json.dumps([{"name": n, **rec} for n, rec in eds], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    a_v = run_tool([sys.executable, str(ROOT / "implementations" / "python" / "spp_verify.py"), "--batch", str(batch)], ROOT)
    b_v = run_tool([str(TSX), "src/cli.ts", "--batch", str(batch)], ROOT / "implementations" / "typescript")
    a_j = run_tool([sys.executable, str(ROOT / "implementations" / "python" / "spp_verify.py"), "--jcs-batch", str(jcs_batch)], ROOT)
    b_j = run_tool([str(TSX), "src/cli.ts", "--jcs-batch", str(jcs_batch)], ROOT / "implementations" / "typescript")
    a_e = run_tool([sys.executable, str(ROOT / "implementations" / "python" / "spp_verify.py"), "--ed-batch", str(ed_batch)], ROOT)
    b_e = run_tool([str(TSX), "src/cli.ts", "--ed-batch", str(ed_batch)], ROOT / "implementations" / "typescript")

    hard = (
        compare_maps(a_v, b_v, "verify")
        + compare_maps(a_j, b_j, "jcs")
        + compare_maps(a_e, b_e, "ed")
    )

    # Workstream J: record target stage and results; flag subfunctions that were
    # not actually reached (e.g. a JCS case that stopped at schema validation).
    report = (
        classify_report(a_v, b_v, "verify")
        + classify_report(a_j, b_j, "jcs")
        + classify_report(a_e, b_e, "ed")
    )
    report_path = CORPUS / "mutation-report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    misses = [r for r in report if r["stage_matches_target"] is False]
    print(f"wrote {report_path} ({len(report)} cases, {len(misses)} wrong-stage)")
    for r in misses:
        print(f"WRONG-STAGE {r['name']} target={r['target']} "
              f"a={r['impl_a'].get('stage')} b={r['impl_b'].get('stage')}")

    batch.unlink(missing_ok=True)
    jcs_batch.unlink(missing_ok=True)
    ed_batch.unlink(missing_ok=True)
    print("FREEZE BLOCKER" if hard else "ok", f"{hard} hard disagreements")
    return 1 if hard else 0


if __name__ == "__main__":
    raise SystemExit(main())
