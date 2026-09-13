#!/usr/bin/env python3
"""Assemble the immutable ``spp-v1-frozen`` release package.

The frozen specification names the normative suite at
``conformance/vectors/suite.json``. This script reproduces that layout from the
repository, verifies the frozen byte digests, writes a SHA-256 manifest, and
packages a deterministic archive.

Text is normalized to LF so the digests are identical on every platform.

Usage:
    python ci/package_frozen.py [--out DIR] [--check]

    --out DIR   output directory (default: dist)
    --check     verify frozen digests only; write nothing

Output (under ``dist/`` by default):
    spp-v1-frozen/            staged package tree
    spp-v1-frozen/MANIFEST.sha256
    spp-v1-frozen.zip         deterministic archive (ZIP_STORED, fixed metadata)
    spp-v1-frozen.zip.sha256  archive digest
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Frozen digests over LF-normalized bytes. These are the release identity from
# the freeze review; a mismatch means a frozen artifact was edited.
FROZEN = {
    "spec/SPP-v1-Core-Protocol-Specification.md":
        "4c450df9cafdd42c746537a72f6bd88d5dbf86390d6e7e51314b3a0134a71019",
    "tests/conformance/vectors/suite.json":
        "649a58da077818ab34a2ade7ea6b6a87ed4b05222cdeaaeae7fecb5e594493e3",
}

# Repository path -> path inside the release package.
PACKAGE = [
    ("spec/SPP-v1-Core-Protocol-Specification.md", "SPP-v1-Core-Protocol-Specification.md"),
    ("spec/SPP-v1-External-Review-Guide.md", "SPP-v1-External-Review-Guide.md"),
    ("tests/conformance/vectors/suite.json", "conformance/vectors/suite.json"),
    ("LICENSE", "LICENSE"),
    ("docs/releases/spp-v1-frozen.md", "RELEASE-NOTES.md"),
]

ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def normalized_bytes(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_manifest(files: list[tuple[str, bytes]]) -> bytes:
    return "".join(
        f"{digest(data)}  {name}\n" for name, data in sorted(files)
    ).encode("utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="dist", help="output directory (default: dist)")
    ap.add_argument("--check", action="store_true", help="verify digests only")
    args = ap.parse_args()

    out = (ROOT / args.out).resolve()
    files: list[tuple[str, bytes]] = []
    failed = False

    for repo_rel, archive_rel in PACKAGE:
        src = ROOT / repo_rel
        if not src.is_file():
            print(f"MISSING  {repo_rel}", file=sys.stderr)
            failed = True
            continue
        data = normalized_bytes(src)
        files.append((archive_rel, data))
        actual = digest(data)
        expected = FROZEN.get(repo_rel)
        if expected is not None and expected != actual:
            print(f"TAMPERED {repo_rel}\n  expected {expected}\n  actual   {actual}",
                  file=sys.stderr)
            failed = True
        else:
            print(f"ok       {archive_rel}  {actual}")

    if failed:
        return 1
    if args.check:
        print("frozen digests verified")
        return 0

    manifest = build_manifest(files)

    pkg = out / "spp-v1-frozen"
    if pkg.exists():
        shutil.rmtree(pkg)
    for name, data in files:
        dest = pkg / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    (pkg / "MANIFEST.sha256").write_bytes(manifest)

    entries = sorted(files + [("MANIFEST.sha256", manifest)], key=lambda x: x[0])
    zip_path = out / "spp-v1-frozen.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as z:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=ZIP_EPOCH)
            info.create_system = 0
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_STORED
            z.writestr(info, data)

    archive_digest = digest(zip_path.read_bytes())
    (out / "spp-v1-frozen.zip.sha256").write_text(
        f"{archive_digest}  spp-v1-frozen.zip\n", encoding="ascii"
    )
    print(f"\narchive  {zip_path}")
    print(f"sha256   {archive_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
