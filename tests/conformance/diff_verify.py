"""Run the Python and TypeScript implementations against the same suite. Any disagreement is a freeze blocker."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SUITE = ROOT / "tests" / "conformance" / "vectors" / "suite.json"


def run(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    a = run([sys.executable, str(ROOT / "implementations" / "python" / "spp_verify.py"), "--suite", str(SUITE)])
    tsx = ROOT / "implementations" / "typescript" / "node_modules" / ".bin" / ("tsx.cmd" if os.name == "nt" else "tsx")
    b = run([str(tsx), str(ROOT / "implementations" / "typescript" / "src" / "cli.ts"), "--suite", str(SUITE)])
    print("=== impl-a ===")
    print(a[1])
    print("=== impl-b ===")
    print(b[1])
    if a[0] != 0 or b[0] != 0:
        print("FREEZE BLOCKER: a suite runner failed")
        return 1
    pa = [ln for ln in a[1].splitlines() if ln.endswith(" PASS") or " FAIL " in ln]
    pb = [ln for ln in b[1].splitlines() if ln.endswith(" PASS") or " FAIL " in ln]
    if pa != pb:
        print("FREEZE BLOCKER: impl-a and impl-b disagree")
        for x, y in zip(pa, pb):
            if x != y:
                print(f"  a: {x}")
                print(f"  b: {y}")
        return 1
    print(f"agree: {len(pa)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
