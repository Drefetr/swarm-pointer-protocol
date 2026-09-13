#!/usr/bin/env python3
"""RC3 conformance CI driver.

Runs the gates that must pass before ``v = 1`` can be frozen:

    1. generated-vector drift      committed suite.json == generator output
    2. impl-a conformance          committed suite.json, independently
    3. impl-b conformance          committed suite.json, independently
    4. differential suite          impl-a vs impl-b on suite.json
    5. JCS number tests            dedicated number path, both impls
    6. permanent regressions       exact-byte hostile-review fixtures
    7. property-name hostility     Object.prototype-hostile member names
    8. nesting-depth totality      paired depth sweep to the 1 MiB boundary
    9. differential mutation       corpus classified by target subfunction
   10. binary64 fuzz               random + biased corpus, independent oracle
   11. relay interoperability      both relays over the HTTP profile
   12. durable relay               SQLite §27/§28 relay persistence
   13. durable two-agent e2e       cross-language pointer exchange + cold restart
   14. multi-relay federation e2e  two relays, client union, GET/POST federation

Implementations only ever consume the committed ``tests/conformance/vectors/suite.json``.
They never regenerate expected results at test time.

Usage:
    python ci/run_conformance.py [--fuzz-count N] [--quick] [--skip-relay]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUITE = ROOT / "tests" / "conformance" / "vectors" / "suite.json"
BIN = ROOT / "implementations" / "typescript" / "node_modules" / ".bin"
TSX = BIN / ("tsx.cmd" if os.name == "nt" else "tsx")
TSC = BIN / ("tsc.cmd" if os.name == "nt" else "tsc")


def run(label: str, cmd: list[str], cwd: Path = ROOT) -> bool:
    print(f"\n=== {label} ===")
    print("$ " + " ".join(str(c) for c in cmd))
    p = subprocess.run(cmd, cwd=cwd)
    ok = p.returncode == 0
    print(f"--- {label}: {'PASS' if ok else 'FAIL'} (exit {p.returncode})")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fuzz-count", type=int, default=200_000)
    ap.add_argument("--quick", action="store_true", help="reduce fuzz corpus")
    ap.add_argument("--skip-relay", action="store_true")
    args = ap.parse_args()
    fuzz_count = 20_000 if args.quick else args.fuzz_count

    py = sys.executable
    steps: list[tuple[str, list[str], Path]] = [
        ("generated-vector drift",
         [py, str(ROOT / "tests" / "conformance" / "build_suite.py"), "--check"], ROOT),
        ("impl-a conformance",
         [py, str(ROOT / "implementations" / "python" / "spp_verify.py"), "--suite", str(SUITE)], ROOT),
        ("impl-b conformance",
         [str(TSX), "src/cli.ts", "--suite", str(SUITE)], ROOT / "implementations" / "typescript"),
        ("impl-b typecheck",
         [str(TSC), "--noEmit"], ROOT / "implementations" / "typescript"),
        ("differential suite",
         [py, str(ROOT / "tests" / "conformance" / "diff_verify.py")], ROOT),
        ("JCS number tests",
         [py, str(ROOT / "tests" / "conformance" / "test_jcs_numbers.py")], ROOT),
        ("permanent regressions",
         [py, str(ROOT / "tests" / "conformance" / "test_regressions.py")], ROOT),
        ("property-name hostility",
         [py, str(ROOT / "tests" / "conformance" / "test_property_names.py")], ROOT),
        ("nesting-depth totality",
         [py, str(ROOT / "tests" / "conformance" / "test_nesting_depth.py")] + (["--quick"] if args.quick else []), ROOT),
        ("differential mutation",
         [py, str(ROOT / "tests" / "conformance" / "mutate_diff.py")], ROOT),
        ("binary64 fuzz",
         [py, str(ROOT / "tests" / "conformance" / "fuzz_binary64.py"),
          "--count", str(fuzz_count)], ROOT),
    ]
    if not args.skip_relay:
        steps.append(
            ("relay interoperability",
             [py, str(ROOT / "tests" / "interoperability" / "relay-tests" / "run_tests.py")], ROOT)
        )
        steps.append(
            ("durable relay",
             [py, str(ROOT / "implementations" / "relay" / "test_relay.py")], ROOT)
        )
        steps.append(
            ("durable two-agent e2e",
             [py, str(ROOT / "tests" / "interoperability" / "durable-e2e" / "run_tests.py")], ROOT)
        )
        steps.append(
            ("multi-relay federation e2e",
             [py, str(ROOT / "tests" / "interoperability" / "multi-relay-e2e" / "run_tests.py")], ROOT)
        )

    results: list[tuple[str, bool]] = []
    for label, cmd, cwd in steps:
        results.append((label, run(label, cmd, cwd)))

    print("\n================ SUMMARY ================")
    failed = 0
    for label, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
        failed += 0 if ok else 1
    print("=========================================")
    if failed:
        print(f"FREEZE BLOCKER: {failed} gate(s) failed")
        return 1
    print("all gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
