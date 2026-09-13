/** SPP-Ed25519-1 on @noble/curves. Do not use library verify(); it is not ┬º8A. */

import { ed25519 } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha512";

const Point = ed25519.ExtendedPoint;
const L = ed25519.CURVE.n;

function leInt(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = 0; i < b.length; i++) x |= BigInt(b[i]!) << (8n * BigInt(i));
  return x;
}

function mulFull(p: InstanceType<typeof Point>, n: bigint) {
  let acc = Point.ZERO;
  let base = p;
  let s = n;
  while (s > 0n) {
    if (s & 1n) acc = acc.add(base);
    base = base.double();
    s >>= 1n;
  }
  return acc;
}

function decodeCanonical(raw: Uint8Array) {
  if (raw.length !== 32) return null;
  let pt: InstanceType<typeof Point>;
  try {
    pt = Point.fromHex(raw);
  } catch {
    return null;
  }
  const enc = pt.toRawBytes();
  if (enc.length !== 32) return null;
  for (let i = 0; i < 32; i++) if (enc[i] !== raw[i]) return null;
  return pt;
}

export function assertionMsg(d: Uint8Array): Uint8Array {
  const p = new TextEncoder().encode("SPP/1/assertion");
  const out = new Uint8Array(p.length + 1 + d.length);
  out.set(p, 0);
  out[p.length] = 0;
  out.set(d, p.length + 1);
  return out;
}

export function verifySppEd25519(a: Uint8Array, sig: Uint8Array, d: Uint8Array): boolean {
  if (a.length !== 32 || sig.length !== 64 || d.length !== 32) return false;
  const rBytes = sig.slice(0, 32);
  const sBytes = sig.slice(32);
  const s = leInt(sBytes);
  if (s >= L) return false;
  const A = decodeCanonical(a);
  const R = decodeCanonical(rBytes);
  if (!A || !R) return false;
  if (A.equals(Point.ZERO) || R.equals(Point.ZERO)) return false;
  if (!mulFull(A, L).equals(Point.ZERO)) return false;
  if (!mulFull(R, L).equals(Point.ZERO)) return false;
  const m = assertionMsg(d);
  const cat = new Uint8Array(32 + 32 + m.length);
  cat.set(rBytes, 0);
  cat.set(a, 32);
  cat.set(m, 64);
  const k = leInt(sha512(cat)) % L;
  const left = s === 0n ? Point.ZERO : Point.BASE.multiply(s);
  const right = R.add(k === 0n ? Point.ZERO : A.multiply(k));
  return left.equals(right);
}

export function signAssertion(sk: Uint8Array, d: Uint8Array): Uint8Array {
  return ed25519.sign(assertionMsg(d), sk);
}
