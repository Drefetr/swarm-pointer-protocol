/** RFC 8785 using ES NumberToString and UTF-16 charCodeAt key order.
 *
 * Iterative (explicit stack, no recursion): canonicalization depth is bounded
 * only by memory, per ┬º5.
 */

import type { JsonVal } from "./scan.ts";

export class CanonError extends Error {}

function jcsNumber(n: number): string {
  if (!Number.isFinite(n)) throw new CanonError("non-finite");
  if (Object.is(n, -0)) throw new CanonError("negative-zero");
  if (n === 0) return "0";
  return String(n);
}

function jcsString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const o = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (o < 0x20) out += `\\u${o.toString(16).padStart(4, "0")}`;
    else out += ch;
  }
  return out + '"';
}

function utf16Less(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = a.charCodeAt(i) - b.charCodeAt(i);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

class PopArr {
  static readonly INSTANCE = new PopArr();
}
class PopObj {
  static readonly INSTANCE = new PopObj();
}
class Comma {
  static readonly INSTANCE = new Comma();
}
class KeyMarker {
  constructor(readonly k: string) {}
}

type Item = JsonVal | PopArr | PopObj | Comma | KeyMarker;

export function jcs(value: JsonVal): string {
  const out: string[] = [];
  const stack: Item[] = [value];
  while (stack.length) {
    const item = stack.pop()!;
    if (item === PopArr.INSTANCE) {
      out.push("]");
      continue;
    }
    if (item === PopObj.INSTANCE) {
      out.push("}");
      continue;
    }
    if (item === Comma.INSTANCE) {
      out.push(",");
      continue;
    }
    if (item instanceof KeyMarker) {
      out.push(jcsString(item.k) + ":");
      continue;
    }
    const v = item as JsonVal;
    if (v === null) out.push("null");
    else if (v === true) out.push("true");
    else if (v === false) out.push("false");
    else if (typeof v === "number") out.push(jcsNumber(v));
    else if (typeof v === "string") out.push(jcsString(v));
    else if (Array.isArray(v)) {
      out.push("[");
      stack.push(PopArr.INSTANCE);
      for (let idx = v.length - 1; idx >= 0; idx--) {
        stack.push(v[idx]!);
        if (idx > 0) stack.push(Comma.INSTANCE);
      }
    } else {
      out.push("{");
      stack.push(PopObj.INSTANCE);
      const keys = Object.keys(v).sort(utf16Less);
      for (let idx = keys.length - 1; idx >= 0; idx--) {
        const k = keys[idx]!;
        stack.push(v[k]!);
        stack.push(new KeyMarker(k));
        if (idx > 0) stack.push(Comma.INSTANCE);
      }
    }
  }
  return out.join("");
}

export function jcsBytes(value: JsonVal): Uint8Array {
  return new TextEncoder().encode(jcs(value));
}
