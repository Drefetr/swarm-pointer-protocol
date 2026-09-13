"""Dedicated JCS number test suite — Workstream C.

Tests the exact path:
    raw JSON value
        -> JSON-input validation (binary64 parse, -0 rejection)
        -> JCS serialization
        -> exact expected UTF-8 bytes

Runs both impl-a (Python) and impl-b (TypeScript) and compares.
Any disagreement is a hard error.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TSX = ROOT / "implementations" / "typescript" / "node_modules" / ".bin" / "tsx.cmd"

# ---------------------------------------------------------------------------
# Test corpus: (name, input_json_text, expected_jcs OR None if invalid)
# ---------------------------------------------------------------------------
# expected_jcs=None means the input should be rejected at json-input stage.
CASES: list[tuple[str, str, str | None]] = [
    # Basic values
    ("zero", '{"n":0}', '{"n":0}'),
    ("one", '{"n":1}', '{"n":1}'),
    ("neg-one", '{"n":-1}', '{"n":-1}'),
    ("one-point-zero", '{"n":1.0}', '{"n":1}'),
    ("one-e0", '{"n":1e0}', '{"n":1}'),
    ("one-full-trip", '{"n":1.0000000000000001}', '{"n":1}'),  # rounds to 1.0
    # Safe-integer boundary
    ("max-safe-int", '{"n":9007199254740991}', '{"n":9007199254740991}'),
    ("safe-int-2e53", '{"n":9007199254740992}', '{"n":9007199254740992}'),
    # A.13: value above safe-int range
    ("a13-above-safe", '{"n":9007199254740993}', '{"n":9007199254740992}'),
    # A.15 / hostile-review: large integral binary64, ECMAScript shortest-round-trip
    ("a15-hostile-review", '{"n":36101157879172420000}', '{"n":36101157879172420000}'),
    # Verify exact mathematical integer form also collapses to same binary64
    ("a15-wrong-exact-int", '{"n":36101157879172419584}', '{"n":36101157879172420000}'),
    # Subnormals / min/max finite
    ("min-subnormal", '{"n":5e-324}', '{"n":5e-324}'),
    ("max-double", '{"n":1.7976931348623157e+308}', '{"n":1.7976931348623157e+308}'),
    # Fixed vs exponent boundary around 1e21
    ("just-below-1e21", '{"n":1e20}', '{"n":100000000000000000000}'),
    ("exactly-1e21", '{"n":1e21}', '{"n":1e+21}'),
    ("just-above-1e21", '{"n":1e22}', '{"n":1e+22}'),
    # Fixed vs exponent boundary around 1e-6
    ("just-above-1e-6", '{"n":0.000001}', '{"n":0.000001}'),
    ("just-below-1e-6", '{"n":1e-7}', '{"n":1e-7}'),
    ("exactly-1e-6", '{"n":1e-6}', '{"n":0.000001}'),
    # RFC 8785 rounding example
    # 333333333.33333329 parses to binary64 333333333.3333333
    ("rfc8785-example", '{"n":333333333.33333329}', '{"n":333333333.3333333}'),
    # Large integral values with binary64 rounding
    ("large-1", '{"n":295147905179352830000}', '{"n":295147905179352830000}'),
    ("large-2-near-1e23", '{"n":9.999999999999997e+22}', '{"n":9.999999999999997e+22}'),
    ("large-3-1e23", '{"n":1e+23}', '{"n":1e+23}'),
    # 1.0000000000000001e+23 is a distinct representable binary64 from 1e+23
    ("large-4", '{"n":1.0000000000000001e+23}', '{"n":1.0000000000000001e+23}'),
    # 999999999999999900000 parses to binary64 9.999999999999999e+20
    ("large-5", '{"n":999999999999999700000}', '{"n":999999999999999700000}'),
    ("large-6", '{"n":999999999999999900000}', '{"n":999999999999999900000}'),
    # Small values
    ("neg-1e-7", '{"n":-1e-7}', '{"n":-1e-7}'),
    ("point-1", '{"n":0.1}', '{"n":0.1}'),
    ("point-3", '{"n":0.3}', '{"n":0.3}'),
    # Negative-zero: must be rejected
    ("neg-zero-rejected", '{"n":-0}', None),
    ("neg-zero-frac", '{"n":-0.0}', None),
    ("neg-zero-exp", '{"n":-0e0}', None),
    # Identity: different tokens, same binary64
    ("two-forms-1", '{"n":100000000000000000000}', '{"n":100000000000000000000}'),
    ("two-forms-2", '{"n":1e20}', '{"n":100000000000000000000}'),
    # SPP A.13 companion
    ("a13-companion", '{"n":9007199254740992}', '{"n":9007199254740992}'),
]


def run_jcs_batch(items: list[tuple[str, str]], impl: str) -> dict[str, dict]:
    batch = [{"name": n, "utf8": u} for n, u in items]
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", encoding="utf-8", delete=False) as f:
        json.dump(batch, f, ensure_ascii=False)
        fname = f.name

    if impl == "a":
        args = [sys.executable, str(ROOT / "implementations" / "python" / "spp_verify.py"), "--jcs-batch", fname]
        cwd = ROOT
    else:
        args = [str(TSX), "src/cli.ts", "--jcs-batch", fname]
        cwd = ROOT / "implementations" / "typescript"

    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    result: dict[str, dict] = {}
    for line in p.stdout.splitlines():
        line = line.strip()
        if line:
            rec = json.loads(line)
            result[rec["name"]] = rec
    return result


def hex_to_str(h: str) -> str:
    return bytes.fromhex(h).decode("utf-8")


def main() -> int:
    test_items = [(name, utf8) for name, utf8, _ in CASES]
    expected = {name: exp for name, _, exp in CASES}

    print(f"Running {len(test_items)} JCS number cases against impl-a and impl-b...")
    a_results = run_jcs_batch(test_items, "a")
    b_results = run_jcs_batch(test_items, "b")

    hard_failures = 0
    for name, utf8, exp_jcs in CASES:
        ar = a_results.get(name, {})
        br = b_results.get(name, {})

        a_ok = ar.get("status") == "OK"
        b_ok = br.get("status") == "OK"
        a_jcs = hex_to_str(ar["jcs_hex"]) if a_ok and "jcs_hex" in ar else None
        b_jcs = hex_to_str(br["jcs_hex"]) if b_ok and "jcs_hex" in br else None

        # Agreement check first
        if ar.get("status") != br.get("status") or ar.get("jcs_hex") != br.get("jcs_hex"):
            print(f"HARD {name}")
            print(f"  impl-a: {ar}")
            print(f"  impl-b: {br}")
            hard_failures += 1
            continue

        # Expected value check
        if exp_jcs is None:
            # Should be rejected
            if a_ok:
                print(f"FAIL {name}: expected rejection, got OK (jcs={a_jcs!r})")
                hard_failures += 1
                continue
            print(f"PASS {name}: AGREE REJECTED reason={ar.get('reason')}")
        else:
            if not a_ok:
                print(f"FAIL {name}: expected OK, got rejection ({ar.get('reason')})")
                hard_failures += 1
                continue
            if a_jcs != exp_jcs:
                print(f"FAIL {name}: wrong JCS")
                print(f"  expected: {exp_jcs!r}")
                print(f"  impl-a:   {a_jcs!r}")
                print(f"  impl-b:   {b_jcs!r}")
                hard_failures += 1
                continue
            print(f"PASS {name}: AGREE jcs={a_jcs!r}")

    print()
    total = len(CASES)
    if hard_failures:
        print(f"HARD FAILURES: {hard_failures} / {total}")
    else:
        print(f"All {total} JCS number cases agree")
    return 1 if hard_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
