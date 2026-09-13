"""Binary64 differential fuzzer — Workstream D.

Generates random IEEE-754 binary64 values, serializes through impl-a and impl-b,
and requires exact UTF-8 byte equality. An independent ECMAScript/V8 oracle lane
(raw ``JSON.parse`` + ``JSON.stringify``, not either implementation's JCS code)
is also checked so that two co-buggy implementations cannot agree with each other.

Usage:
    python fuzz_binary64.py [--count N] [--seed S] [--save-failures DIR] [--no-oracle]

Default: 100,000 random finite binary64 values.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TSX = ROOT / "implementations" / "typescript" / "node_modules" / ".bin" / "tsx.cmd"
NODE = "node"
REGRESSIONS_DIR = ROOT / "tests" / "conformance" / "regressions"

# Independent oracle: raw V8 via Node, no impl-a/impl-b code. This is the
# ECMAScript Number::toString behaviour that RFC 8785 normatively references.
_ORACLE_JS = r"""
const fs = require("fs");
const items = JSON.parse(fs.readFileSync(process.env.SPP_BATCH, "utf8"));
for (const it of items) {
  try {
    const v = JSON.parse(it.utf8);
    const s = JSON.stringify(v);
    console.log(JSON.stringify({name: it.name, status: "OK",
      jcs_hex: Buffer.from(s, "utf8").toString("hex")}));
  } catch (e) {
    console.log(JSON.stringify({name: it.name, status: "INVALID",
      reason: String(e)}));
  }
}
"""


def random_finite_double(rng: random.Random) -> float:
    """Generate a random finite IEEE-754 binary64 value.

    Negative zero is excluded: SPP v1 rejects the ``-0`` token at JSON input,
    so it is not part of the JCS number domain under test here.
    """
    while True:
        bits = rng.getrandbits(64)
        val = struct.unpack("d", struct.pack("Q", bits))[0]
        if not math.isfinite(val):
            continue
        if val == 0.0 and math.copysign(1.0, val) < 0:
            continue
        return val


def _biased_doubles(rng: random.Random, count: int) -> list[float]:
    """Generate a biased corpus of binary64 values."""
    vals: list[float] = []

    # Standard random values
    rand_count = count * 7 // 10
    while len(vals) < rand_count:
        vals.append(random_finite_double(rng))

    # Powers of 2 and their neighbors
    for exp in range(-1074, 1024):
        for delta in (-1, 0, 1):
            v = math.ldexp(1.0, exp)
            bits = struct.unpack("Q", struct.pack("d", v))[0]
            n = bits + delta
            if 0 <= n < (1 << 64):
                cand = struct.unpack("d", struct.pack("Q", n))[0]
                if math.isfinite(cand):
                    vals.append(cand)

    # Powers of 10 and their neighbors
    for exp in range(-308, 309):
        try:
            v = float(f"1e{exp}")
            if math.isfinite(v) and v > 0:
                bits = struct.unpack("Q", struct.pack("d", v))[0]
                for delta in (-2, -1, 0, 1, 2):
                    n = bits + delta
                    if 0 <= n < (1 << 64):
                        cand = struct.unpack("d", struct.pack("Q", n))[0]
                        if math.isfinite(cand):
                            vals.append(cand)
        except (ValueError, OverflowError):
            pass

    # Around 2^53 (safe-integer boundary)
    boundary = 1 << 53
    for delta in range(-100, 101):
        v = float(boundary + delta)
        if math.isfinite(v):
            vals.append(v)

    # Around 1e21 (fixed/exponent boundary)
    for exp in range(-5, 6):
        bits = struct.unpack("Q", struct.pack("d", 1e21))[0]
        n = bits + exp
        if 0 <= n < (1 << 64):
            cand = struct.unpack("d", struct.pack("Q", n))[0]
            if math.isfinite(cand):
                vals.append(cand)

    # Around 1e-6 (fixed/exponent boundary)
    bits_1e6 = struct.unpack("Q", struct.pack("d", 1e-6))[0]
    for delta in range(-5, 6):
        n = bits_1e6 + delta
        if 0 <= n < (1 << 64):
            cand = struct.unpack("d", struct.pack("Q", n))[0]
            if math.isfinite(cand):
                vals.append(cand)

    # Subnormals
    for bits in [1, 2, 3, (1 << 52) - 1, (1 << 52) - 2]:
        cand = struct.unpack("d", struct.pack("Q", bits))[0]
        if math.isfinite(cand):
            vals.append(cand)

    # Large integral values (common source of drift)
    for shift in range(53, 64):
        base = float(1 << shift)
        for delta in range(-5, 6):
            v = base + delta * (1 << (shift - 52))
            if math.isfinite(v):
                vals.append(v)

    # Fill remaining with random
    while len(vals) < count:
        vals.append(random_finite_double(rng))

    rng.shuffle(vals)
    return vals[:count]


def run_jcs_batch(items: list[tuple[str, str]], impl: str) -> dict[str, str]:
    """Run a jcs-batch and return {name: jcs_hex | 'ERR:reason'}."""
    batch = [{"name": n, "utf8": u} for n, u in items]
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", encoding="utf-8", delete=False) as f:
        json.dump(batch, f, ensure_ascii=False)
        fname = f.name

    try:
        if impl == "a":
            args = [sys.executable, str(ROOT / "implementations" / "python" / "spp_verify.py"), "--jcs-batch", fname]
            cwd = ROOT
            env = None
        elif impl == "b":
            args = [str(TSX), "src/cli.ts", "--jcs-batch", fname]
            cwd = ROOT / "implementations" / "typescript"
            env = None
        elif impl == "oracle":
            args = [NODE, "-e", _ORACLE_JS]
            cwd = ROOT
            env = {**os.environ, "SPP_BATCH": fname}
        else:
            raise ValueError(f"unknown impl {impl!r}")

        p = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
        result: dict[str, str] = {}
        for line in p.stdout.splitlines():
            line = line.strip()
            if line:
                rec = json.loads(line)
                if rec.get("status") == "OK":
                    result[rec["name"]] = rec["jcs_hex"]
                else:
                    result[rec["name"]] = f"ERR:{rec.get('reason','?')}"
        return result
    finally:
        Path(fname).unlink(missing_ok=True)


def fuzz(count: int, seed: int, save_dir: Path | None, use_oracle: bool = True) -> int:
    rng = random.Random(seed)
    values = _biased_doubles(rng, count)

    # Build items: use the float's repr as JSON (it parses to the same binary64)
    items: list[tuple[str, str]] = []
    for i, v in enumerate(values):
        # Use Python's repr for the number token — produces a valid JSON number
        # that parses to exactly v when consumed as IEEE-754 binary64
        token = repr(v)
        items.append((f"v{i}", f'{{"n":{token}}}'))

    print(f"Fuzzing {count} binary64 values (seed={seed}, oracle={use_oracle})...")

    batch_size = 5000
    total_hard = 0
    total_oracle = 0
    failures: list[dict] = []
    oracle_failures: list[dict] = []

    for start in range(0, len(items), batch_size):
        batch = items[start : start + batch_size]
        a_res = run_jcs_batch(batch, "a")
        b_res = run_jcs_batch(batch, "b")
        o_res = run_jcs_batch(batch, "oracle") if use_oracle else {}

        for idx, (name, utf8) in enumerate(batch):
            ah = a_res.get(name, "MISSING")
            bh = b_res.get(name, "MISSING")
            if ah != bh:
                global_idx = start + idx
                v = values[global_idx]
                total_hard += 1
                failures.append({
                    "value": v,
                    "token": utf8,
                    "impl_a": ah,
                    "impl_b": bh,
                })
                if total_hard <= 20:
                    print(f"HARD fuzz disagreement: v={v!r}")
                    print(f"  impl-a: {ah}")
                    print(f"  impl-b: {bh}")
            if use_oracle:
                oh = o_res.get(name, "MISSING")
                if oh != ah:
                    global_idx = start + idx
                    v = values[global_idx]
                    total_oracle += 1
                    oracle_failures.append({
                        "value": v,
                        "token": utf8,
                        "impl_a": ah,
                        "impl_b": bh,
                        "oracle": oh,
                    })
                    if total_oracle <= 20:
                        print(f"HARD oracle disagreement: v={v!r}")
                        print(f"  impl-a: {ah}")
                        print(f"  impl-b: {bh}")
                        print(f"  oracle: {oh}")

        done = min(start + batch_size, len(items))
        print(f"  {done}/{len(items)} processed, {total_hard} impl disagreements, "
              f"{total_oracle} oracle disagreements so far")

    if failures and save_dir:
        save_dir.mkdir(parents=True, exist_ok=True)
        out = save_dir / "fuzz_binary64_failures.json"
        out.write_text(json.dumps(failures, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Saved {len(failures)} failure(s) to {out}")
    if oracle_failures and save_dir:
        save_dir.mkdir(parents=True, exist_ok=True)
        out = save_dir / "fuzz_binary64_oracle_failures.json"
        out.write_text(json.dumps(oracle_failures, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Saved {len(oracle_failures)} oracle failure(s) to {out}")

    print()
    if total_hard or total_oracle:
        print(f"FREEZE BLOCKER: {total_hard} binary64 JCS disagreements, "
              f"{total_oracle} oracle disagreements")
    else:
        print(f"OK: {count} binary64 values agree between impl-a, impl-b"
              f"{' and independent oracle' if use_oracle else ''}")
    return 1 if (total_hard or total_oracle) else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Binary64 JCS differential fuzzer")
    parser.add_argument("--count", type=int, default=100_000, help="Number of values to test")
    parser.add_argument("--seed", type=int, default=20260912, help="RNG seed")
    parser.add_argument("--save-failures", type=str, default=str(REGRESSIONS_DIR),
                        help="Directory to save failure cases")
    parser.add_argument("--no-oracle", action="store_true",
                        help="Disable the independent ECMAScript/V8 oracle lane")
    args = parser.parse_args()
    save_dir = Path(args.save_failures) if args.save_failures else None
    return fuzz(args.count, args.seed, save_dir, use_oracle=not args.no_oracle)


if __name__ == "__main__":
    raise SystemExit(main())
