"""Permanent regression fixtures — Workstream A.

Each file under ``conformance/regressions/`` is consumed as raw bytes. The
fixture is never rebuilt from a structured object: the exact original input
byte sequence is what gets handed to both verifiers.

The harness runs ``--diagnostic`` on both implementations and requires that
they agree on every consensus-visible intermediate:

    JCS(U), canonical_body_bytes, D, id, H, units, Wrequired,
    target, PoW, signature, status

A disagreement in any of those is a freeze blocker.

Usage:
    python conformance/test_regressions.py [REGRESSIONS_DIR]
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TSX = ROOT / "implementations" / "typescript" / "node_modules" / ".bin" / "tsx.cmd"
DEFAULT_DIR = ROOT / "tests" / "conformance" / "regressions"

REQUIRED = (
    "JCS(U)",
    "canonical_body_bytes",
    "D",
    "id_computed",
    "H",
    "units",
    "Wrequired",
    "target",
    "PoW",
    "signature",
    "status",
)


def parse_diag(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ": " in line:
            label, value = line.split(": ", 1)
            out[label] = value
    return out


def run_diag(path: Path, impl: str) -> dict[str, str]:
    if impl == "a":
        args = [sys.executable, str(ROOT / "implementations" / "python" / "spp_verify.py"),
                "--diagnostic", str(path.resolve())]
        cwd = ROOT
    else:
        args = [str(TSX), "src/cli.ts", "--diagnostic", str(path.resolve())]
        cwd = ROOT / "implementations" / "typescript"
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if p.returncode not in (0, 1, 2):
        raise SystemExit(f"{impl} diagnostic failed on {path.name}:\n{p.stderr}")
    return parse_diag(p.stdout)


def main(argv: list[str]) -> int:
    reg_dir = Path(argv[1]) if len(argv) > 1 else DEFAULT_DIR
    fixtures = sorted(reg_dir.glob("*.json"))
    if not fixtures:
        print(f"FAIL: no regression fixtures in {reg_dir}")
        return 1

    hard = 0
    for fixture in fixtures:
        # Sanity: fixture is consumed as bytes, not round-tripped.
        raw = fixture.read_bytes()
        print(f"== {fixture.name} ({len(raw)} bytes) ==")

        a = run_diag(fixture, "a")
        b = run_diag(fixture, "b")

        for label in REQUIRED:
            av = a.get(label)
            bv = b.get(label)
            if av != bv:
                print(f"  HARD {label}:")
                print(f"    impl-a: {av!r}")
                print(f"    impl-b: {bv!r}")
                hard += 1
            else:
                print(f"  AGREE {label}: {av}")

        # Any other label present in both should also match; report as soft.
        for label in sorted(set(a) & set(b)):
            if label in REQUIRED or label in ("v", "created"):
                continue
            if a[label] != b[label]:
                print(f"  SOFT {label}: a={a[label]!r} b={b[label]!r}")

    print()
    if hard:
        print(f"FREEZE BLOCKER: {hard} regression disagreement(s)")
        return 1
    print(f"OK: {len(fixtures)} regression fixture(s) agree on all required fields")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
