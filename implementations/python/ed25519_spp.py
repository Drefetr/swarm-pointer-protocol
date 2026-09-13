"""SPP-Ed25519-1 from RFC 8032 plus spec §8A. Pure integer arithmetic."""

from __future__ import annotations

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _xrecover(y: int) -> int:
    yy = (y * y) % P
    u = (yy - 1) % P
    v = (D * yy + 1) % P
    x2 = (u * _inv(v)) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = (x * I) % P
    if (x * x - x2) % P != 0:
        raise ValueError("not on curve")
    if x % 2 != 0:
        x = P - x
    return x


def _point_add(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = a
    x2, y2 = b
    den_x = (1 + D * x1 * x2 * y1 * y2) % P
    den_y = (1 - D * x1 * x2 * y1 * y2) % P
    x3 = ((x1 * y2 + x2 * y1) * _inv(den_x)) % P
    y3 = ((y1 * y2 + x1 * x2) * _inv(den_y)) % P
    return x3, y3


def _point_mul(s: int, pt: tuple[int, int]) -> tuple[int, int]:
    r = (0, 1)
    q = pt
    while s:
        if s & 1:
            r = _point_add(r, q)
        q = _point_add(q, q)
        s >>= 1
    return r


BY = (4 * pow(5, P - 2, P)) % P
BX = _xrecover(BY)
B = (BX, BY)
IDENT = (0, 1)


def encode_point(pt: tuple[int, int]) -> bytes:
    x, y = pt
    out = bytearray(y.to_bytes(32, "little"))
    if x & 1:
        out[31] |= 0x80
    return bytes(out)


def decode_point(raw: bytes) -> tuple[int, int]:
    if len(raw) != 32:
        raise ValueError("length")
    y = int.from_bytes(raw, "little")
    x_sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    if y >= P:
        raise ValueError("y")
    try:
        x = _xrecover(y)
    except ValueError as e:
        raise ValueError("curve") from e
    if x_sign:
        x = P - x
    if x == 0 and x_sign:
        raise ValueError("sign")
    pt = (x, y)
    if encode_point(pt) != raw:
        raise ValueError("non-canonical")
    return pt


def _is_ident(pt: tuple[int, int]) -> bool:
    return pt == IDENT


def sha512(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return h.digest()


def assertion_message(d: bytes) -> bytes:
    return b"SPP/1/assertion\x00" + d


def verify_spp_ed25519_1(a_bytes: bytes, sig: bytes, d: bytes) -> bool:
    if len(a_bytes) != 32 or len(sig) != 64 or len(d) != 32:
        return False
    r_bytes, s_bytes = sig[:32], sig[32:]
    s = int.from_bytes(s_bytes, "little")
    if s >= L:
        return False
    try:
        a = decode_point(a_bytes)
        r = decode_point(r_bytes)
    except ValueError:
        return False
    if _is_ident(a) or _is_ident(r):
        return False
    if not _is_ident(_point_mul(L, a)):
        return False
    if not _is_ident(_point_mul(L, r)):
        return False
    m = assertion_message(d)
    k0 = int.from_bytes(sha512(r_bytes, a_bytes, m), "little")
    k = k0 % L
    left = _point_mul(s, B)
    right = _point_add(r, _point_mul(k, a))
    return left == right


def sign(private_key: bytes, d: bytes) -> bytes:
    if len(private_key) != 32:
        raise ValueError("sk")
    h = sha512(private_key)
    s = int.from_bytes(h[:32], "little")
    s &= (1 << 254) - 8
    s |= 1 << 254
    prefix = h[32:]
    a = encode_point(_point_mul(s, B))
    m = assertion_message(d)
    r = int.from_bytes(sha512(prefix, m), "little") % L
    r_pt = _point_mul(r, B)
    r_bytes = encode_point(r_pt)
    k = int.from_bytes(sha512(r_bytes, a, m), "little") % L
    s_out = (r + k * s) % L
    return r_bytes + s_out.to_bytes(32, "little")


def public_from_private(private_key: bytes) -> bytes:
    h = sha512(private_key)
    s = int.from_bytes(h[:32], "little")
    s &= (1 << 254) - 8
    s |= 1 << 254
    return encode_point(_point_mul(s, B))
