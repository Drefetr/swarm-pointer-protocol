"""Property-name hostility suite.

Two directions, both consensus-critical:

1. An unknown *top-level* member named after an ``Object.prototype`` property
   (``__proto__`` above all) must survive ``U`` reconstruction and then be
   rejected by the §7A closed schema. It must never be silently dropped by a
   prototype-sensitive object operation. A single such drop turns an invalid
   assertion into a "VALID" one under a byte-identical transmitted ``id``.

2. The same names inside ``ext`` are ordinary authenticated JCS members. They
   must survive canonicalization exactly, be hashed, and be signed: an assertion
   whose ``ext`` contains them must still verify under both implementations with
   the same recomputed ``id``.

Implementation under test: impl-a (Python, in-process) and impl-b (TypeScript).
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "implementations" / "python"))

from jcs import canonicalize_bytes  # noqa: E402
from json_input import parse_utf8  # noqa: E402
from protocol import (  # noqa: E402
    SppError,
    UnsupportedError,
    mine_and_sign,
    validate_bytes,
)

TSX = ROOT / "implementations" / "typescript" / "node_modules" / ".bin" / "tsx.cmd"
VEC = json.loads((ROOT / "tests" / "conformance" / "vectors" / "source.json").read_text(encoding="utf-8"))
NAMES = json.loads(
    (ROOT / "tests" / "conformance" / "property-names.json").read_text(encoding="utf-8")
)["names"]

A2TXT = json.dumps(VEC["A2_pointer"]["envelope"], ensure_ascii=False, separators=(",", ":"))
A2_U = dict(VEC["A2_pointer"]["u"])


def a_verdict(raw: bytes) -> str:
    try:
        validate_bytes(raw)
        return "VALID"
    except UnsupportedError:
        return "UNSUPPORTED"
    except SppError:
        return "INVALID"


def run_impl_b(flag: str, items: list[tuple[str, str]]) -> dict[str, dict]:
    batch = [{"name": n, "utf8": u} for n, u in items]
    with tempfile.NamedTemporaryFile(
        suffix=".json", mode="w", encoding="utf-8", delete=False
    ) as f:
        json.dump(batch, f, ensure_ascii=False)
        fname = f.name
    try:
        p = subprocess.run(
            [str(TSX), "src/cli.ts", flag, fname],
            cwd=ROOT / "implementations" / "typescript",
            capture_output=True,
            text=True,
        )
        out: dict[str, dict] = {}
        for line in p.stdout.splitlines():
            if line.strip():
                rec = json.loads(line)
                out[rec["name"]] = rec
        return out
    finally:
        Path(fname).unlink(missing_ok=True)


def test_top_level_unknown() -> int:
    cases: list[tuple[str, str]] = []
    for name in NAMES:
        for label, val in (("prim", "1"), ("obj", "{}"), ("arr", "[]")):
            cases.append((
                f"{name}-{label}",
                '{"%s":%s,%s' % (name, val, A2TXT[1:]),
            ))
    bres = run_impl_b("--batch", cases)
    bad = 0
    for name, text in cases:
        a = a_verdict(text.encode("utf-8"))
        b = bres.get(name, {}).get("status")
        if a == "VALID" or b == "VALID":
            bad += 1
            print(f"FAIL top-level {name}: impl-a={a} impl-b={b} (must be schema-rejected)")
        elif a != "INVALID" or b != "INVALID":
            bad += 1
            print(f"FAIL top-level {name}: impl-a={a} impl-b={b}")
        else:
            print(f"PASS top-level {name}: both INVALID")
    return bad


def test_ext_members_are_ordinary() -> int:
    cases: list[tuple[str, str]] = []
    for name in NAMES:
        cases.append((f"single-{name}", '{"ext":{"%s":1}}' % name))
    combined = {name: i for i, name in enumerate(NAMES)}
    cases.append((
        "combined",
        json.dumps({"ext": combined}, ensure_ascii=False, separators=(",", ":")),
    ))
    bres = run_impl_b("--jcs-batch", cases)
    bad = 0
    for name, text in cases:
        ahex = canonicalize_bytes(parse_utf8(text.encode("utf-8"))).hex()
        bhex = bres.get(name, {}).get("jcs_hex")
        if bhex != ahex:
            bad += 1
            print(f"FAIL ext-jcs {name}: impl-a={ahex} impl-b={bhex}")
            continue
        rendered = bytes.fromhex(ahex).decode("utf-8")
        expected_keys = [n for n in NAMES if f'"{n}"' in text]
        missing = [n for n in expected_keys if f'"{n}"' not in rendered]
        if missing:
            bad += 1
            print(f"FAIL ext-jcs {name}: dropped {missing} from JCS {rendered!r}")
        else:
            print(f"PASS ext-jcs {name}: {len(expected_keys)} hostile key(s) preserved")
    return bad


def test_ext_full_assertion() -> int:
    u = parse_utf8(json.dumps(A2_U, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    u["ext"] = {name: i for i, name in enumerate(NAMES)}
    env = mine_and_sign(u, bytes.fromhex(VEC["test_key"]["private_key_hex"]))
    raw = json.dumps(env, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    try:
        info_a = validate_bytes(raw)
    except SppError as e:
        print(f"FAIL ext-full: impl-a rejected the mined assertion: {e}")
        return 1
    bres = run_impl_b("--batch", [("ext-full", raw.decode("utf-8"))])
    b = bres.get("ext-full", {})
    if b.get("status") != "VALID":
        print(f"FAIL ext-full: impl-b={b}")
        return 1
    if b.get("id") != info_a["id"]:
        print(f"FAIL ext-full: id mismatch a={info_a['id']} b={b.get('id')}")
        return 1
    jcs = canonicalize_bytes({**u, "nonce": env["nonce"]}).decode("utf-8")
    missing = [n for n in NAMES if f'"{n}"' not in jcs]
    if missing:
        print(f"FAIL ext-full: hostile ext keys absent from JCS: {missing}")
        return 1
    print(f"PASS ext-full: both VALID, id={info_a['id']}, all hostile ext keys hashed")
    return 0


def main() -> int:
    print(f"Property-name hostility suite ({len(NAMES)} names x 3 shapes)")
    bad = 0
    print("\n-- unknown top-level members must be schema-rejected --")
    bad += test_top_level_unknown()
    print("\n-- hostile names inside ext must survive JCS exactly --")
    bad += test_ext_members_are_ordinary()
    print("\n-- a full assertion whose ext uses hostile names must verify --")
    bad += test_ext_full_assertion()
    print()
    if bad:
        print(f"FREEZE BLOCKER: {bad} property-name failure(s)")
        return 1
    print("all property-name hostility checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
