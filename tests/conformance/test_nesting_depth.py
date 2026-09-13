"""Nesting-depth conformance suite (RC3).

§5: JSON nesting depth is local transport/resource policy and MUST NOT be used
to declare an assertion protocol-invalid; the 1 MiB canonical-body bound is the
only semantic size limit. The semantically permitted depth therefore reaches
~174,705 levels for a minimal nested `ext`, and a conforming verifier must
render a §20 verdict across that entire range.

For every probed depth this suite runs PAIRED cases so that every validation
stage stays reachable, not merely "the parser stopped crashing":

  valid       mined, correctly signed assertion          -> both VALID
  work-fail   true id, real signature, unmined           -> both INVALID work
  id-mismatch valid structure, foreign id/sig            -> both INVALID identity
  schema-bad  valid structure, parents as a string       -> both INVALID schema
  jcs         canonical-byte identity via id pinning     -> both agree

Depths: the observed RC2 transition band (490..2201) at single-level
resolution around the old cliffs, then deliberately far higher, up to the
exact 1 MiB boundary and one level past it.

Case construction is independent of both implementations: U bodies are built
by string surgery, digests with hashlib, signatures with OpenSSL (cross-checked
against impl-a's pure-arithmetic signer at import time).

Usage:
    python conformance/test_nesting_depth.py [--quick]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "implementations" / "python"))

from ed25519_spp import sign as sign_a  # noqa: E402  (cross-check only)
from protocol import target_for_units  # noqa: E402

TSX = ROOT / "implementations" / "typescript" / "node_modules" / ".bin" / "tsx.cmd"
TMP = Path(__file__).resolve().parent / "fuzz-corpus" / "generated"

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

TEST_SK = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
TEST_PK = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
MAXH = (1 << 256) - 1
SRC = json.loads((ROOT / "tests" / "conformance" / "vectors" / "source.json").read_text(encoding="utf-8"))
ND = SRC["nesting_depth"]
ACTOR = SRC["test_key"]["actor"]
OHASH = SRC["object"]["hash"]
A3_CH = SRC["A3_unlisted"]["u"]["channel"]
A2_ID = SRC["A2_pointer"]["id"]
A2_SIG = SRC["A2_pointer"]["sig"]

_sk = Ed25519PrivateKey.from_private_bytes(TEST_SK)
assert _sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) == TEST_PK


def sign_openssl(d: bytes) -> bytes:
    return _sk.sign(b"SPP/1/assertion\x00" + d)


if sign_openssl(bytes(32)) != sign_a(TEST_SK, bytes(32)):
    raise SystemExit("signer cross-check failed")


def nest(d: int) -> str:
    return '{"a":' * d + "1" + "}" * d


def u_parts(d: int) -> tuple[str, str]:
    """(prefix, suffix) around the nonce value; prefix carries the bulk (ext).

    JCS key order is fixed, so U = prefix + nonce + suffix exactly.
    """
    prefix = (
        '{"actor":"' + ACTOR
        + '","channel":"' + A3_CH
        + '","created":1789184927'
        + ',"ext":{"deep":' + nest(d)
        + '},"nonce":"'
    )
    suffix = '","ref":{"hash":"' + OHASH + '","locators":[]},"type":"pointer","v":1}'
    return prefix, suffix


def units_of_len(body_len: int) -> int:
    return 1 + -(-body_len // 1024)


def units_of(u: str) -> int:
    return units_of_len(len(u.encode("utf-8")))


def envelope(u: str, ident: str, sig_hex: str) -> str:
    return u[:-1] + ',"id":"' + ident + '","sig":"' + sig_hex + '"}'


def mine(d: int) -> tuple[str, int]:
    """Smallest nonce >= 0 with H <= target. Uses a precomputed SHA-256 state
    for the (bulky) prefix; per-nonce cost is O(nonce + suffix), not O(depth)."""
    prefix, suffix = u_parts(d)
    base = hashlib.sha256(prefix.encode("utf-8"))
    suffix_b = suffix.encode("utf-8")
    nonce = 0
    while True:
        nb = str(nonce).encode("utf-8")
        h = base.copy()
        h.update(nb)
        h.update(suffix_b)
        body_len = len(prefix.encode("utf-8")) + len(nb) + len(suffix_b)
        units = units_of_len(body_len)
        target = MAXH // (units * 65536)
        if int.from_bytes(h.digest(), "big") <= target:
            return prefix + str(nonce) + suffix, nonce
        nonce += 1


def unmined_above_target(d: int) -> tuple[str, str]:
    prefix, suffix = u_parts(d)
    base = hashlib.sha256(prefix.encode("utf-8"))
    suffix_b = suffix.encode("utf-8")
    nonce = 0
    while True:
        nb = str(nonce).encode("utf-8")
        h = base.copy()
        h.update(nb)
        h.update(suffix_b)
        body_len = len(prefix.encode("utf-8")) + len(nb) + len(suffix_b)
        units = units_of_len(body_len)
        target = MAXH // (units * 65536)
        if int.from_bytes(h.digest(), "big") > target:
            return prefix + str(nonce) + suffix, str(nonce)
        nonce += 1


def run_batch(items: list[dict], impl: str) -> dict[str, dict]:
    TMP.mkdir(parents=True, exist_ok=True)
    f = TMP / "_depth_batch.json"
    f.write_text(json.dumps(items, ensure_ascii=False), encoding="utf-8")
    if impl == "a":
        cmd = [sys.executable, str(ROOT / "implementations" / "python" / "spp_verify.py"), "--batch", str(f)]
        cwd = ROOT
    else:
        cmd = [str(TSX), "src/cli.ts", "--batch", str(f)]
        cwd = ROOT / "implementations" / "typescript"
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=1800,
                       encoding="utf-8", errors="replace")
    res: dict[str, dict] = {}
    for line in p.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        res[r["name"]] = r
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="skip mined cases above depth 2201")
    args = ap.parse_args()

    moderate = [490, 494, 495, 496, 599, 600, 601, 999, 1000, 1500, 2200, 2201]
    deep = [5000, 20000, 50000]
    max_fit = ND["max_fit_depth"]
    extreme = [max_fit, max_fit + 1]

    items: list[dict] = []
    expect: dict[str, dict] = {}

    def add(name: str, raw: str, want: dict):
        items.append({"name": name, "utf8": raw})
        expect[name] = want

    for d in moderate:
        if d in (495, 600, 2200):
            rec = ND["depths"][str(d)]
            add(f"d{d}-valid", rec["mined"]["envelope"],
                {"status": "VALID", "id": rec["mined"]["id"], "units": rec["mined"]["units"],
                 "target_hex": rec["mined"]["target_hex"]})
        else:
            u_m, nonce_m = mine(d)
            jb = u_m.encode("utf-8")
            dig = hashlib.sha256(jb).digest()
            ident = "sha256:" + dig.hex()
            units = units_of(u_m)
            add(f"d{d}-valid", envelope(u_m, ident, sign_openssl(dig).hex()),
                {"status": "VALID", "id": ident, "units": units,
                 "target_hex": f"{target_for_units(units):064x}"})
        u_f, nonce_f = unmined_above_target(d)
        dig_f = hashlib.sha256(u_f.encode("utf-8")).digest()
        ident_f = "sha256:" + dig_f.hex()
        add(f"d{d}-work-fail", envelope(u_f, ident_f, sign_openssl(dig_f).hex()),
            {"status": "INVALID", "stage": "work", "reason": "insufficient-work"})
        add(f"d{d}-id-mismatch", envelope(u_f, A2_ID, A2_SIG),
            {"status": "INVALID", "stage": "identity", "reason": "id-mismatch"})
        add(f"d{d}-schema-bad", u_f[:-1] + ',"parents":"' + OHASH + '"}',
            {"status": "INVALID", "stage": "schema", "reason": "schema"})

    for d in deep:
        u_f, nonce_f = unmined_above_target(d)
        dig_f = hashlib.sha256(u_f.encode("utf-8")).digest()
        ident_f = "sha256:" + dig_f.hex()
        add(f"d{d}-work-fail", envelope(u_f, ident_f, sign_openssl(dig_f).hex()),
            {"status": "INVALID", "stage": "work", "reason": "insufficient-work"})
        add(f"d{d}-id-mismatch", envelope(u_f, A2_ID, A2_SIG),
            {"status": "INVALID", "stage": "identity", "reason": "id-mismatch"})
        add(f"d{d}-schema-bad", u_f[:-1] + ',"parents":"' + OHASH + '"}',
            {"status": "INVALID", "stage": "schema", "reason": "schema"})
        if not args.quick:
            print(f"mining depth {d} ...", flush=True)
            u_m, nonce_m = mine(d)
            dig_m = hashlib.sha256(u_m.encode("utf-8")).digest()
            ident_m = "sha256:" + dig_m.hex()
            units_m = units_of(u_m)
            add(f"d{d}-valid", envelope(u_m, ident_m, sign_openssl(dig_m).hex()),
                {"status": "VALID", "id": ident_m, "units": units_m,
                 "target_hex": f"{target_for_units(units_m):064x}"})

    for d in extreme:
        tag = "max-fit" if d == max_fit else "over-1mib"
        u_f, nonce_f = unmined_above_target(d)
        dig_f = hashlib.sha256(u_f.encode("utf-8")).digest()
        ident_f = "sha256:" + dig_f.hex()
        if tag == "max-fit":
            add(f"d{tag}-work-fail", envelope(u_f, ident_f, sign_openssl(dig_f).hex()),
                {"status": "INVALID", "stage": "work", "reason": "insufficient-work"})
            add(f"d{tag}-id-mismatch", envelope(u_f, A2_ID, A2_SIG),
                {"status": "INVALID", "stage": "identity", "reason": "id-mismatch"})
        else:
            add(f"d{tag}-length", envelope(u_f, ident_f, sign_openssl(dig_f).hex()),
                {"status": "INVALID", "stage": "length", "reason": "jcs-too-large"})

    print(f"nesting-depth suite: {len(items)} cases at depths "
          f"{moderate}{'' if args.quick else ' + ' + str(deep)} + extremes {extreme}")

    ra = run_batch(items, "a")
    rb = run_batch(items, "b")

    hard = 0
    for name, want in expect.items():
        ar, br = ra.get(name), rb.get(name)
        if ar is None or br is None:
            print(f"HARD {name}: missing a={ar is not None} b={br is not None}")
            hard += 1
            continue
        for k, v in want.items():
            if ar.get(k) != v or br.get(k) != v:
                print(f"HARD {name}: want {k}={v} a={ar.get(k)} b={br.get(k)}")
                hard += 1
    if hard:
        print(f"FREEZE BLOCKER: {hard} nesting-depth failures")
        return 1
    print(f"OK: {len(items)} nesting-depth cases agree with expected §20 verdicts on both impls")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
