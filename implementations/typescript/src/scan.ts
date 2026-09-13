/** Raw-byte JSON front end. Rejects duplicates, -0, surrogates, noncharacters.
 *
 * Iterative (explicit stack, no recursion): nesting depth is bounded only by
 * memory, per ┬º5 ΓÇö parser depth limits are transport policy, not validity.
 */

export class ScanError extends Error {
  reason: string;
  constructor(reason: string, detail = "") {
    super(detail ? `${reason}: ${detail}` : reason);
    this.reason = reason;
  }
}

function isNoncharacter(cp: number): boolean {
  if (cp >= 0xfdd0 && cp <= 0xfdef) return true;
  return (cp & 0xffff) === 0xfffe || (cp & 0xffff) === 0xffff;
}

export type JsonVal = null | boolean | number | string | JsonVal[] | { [k: string]: JsonVal };

export function scanUtf8(bytes: Uint8Array): JsonVal {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new ScanError("invalid-json", "bom");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new ScanError("invalid-utf8");
  }
  if (text.startsWith("\ufeff")) {
    throw new ScanError("invalid-json", "bom");
  }
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xd800 && cp <= 0xdfff) throw new ScanError("lone-surrogate");
    if (isNoncharacter(cp)) throw new ScanError("noncharacter");
  }
  return parseDocument(text);
}

export function scanObject(bytes: Uint8Array): { [k: string]: JsonVal } {
  const v = scanUtf8(bytes);
  if (v === null || typeof v !== "object" || Array.isArray(v)) {
    throw new ScanError("not-object");
  }
  return v;
}

type ObjFrame = { kind: 0; obj: { [k: string]: JsonVal }; key: string | null };
type ArrFrame = { kind: 1; arr: JsonVal[] };
type Frame = ObjFrame | ArrFrame;

const _VALUE = 0;
const _KEY = 1;
const _COLON = 2;
const _OBJ_NEXT = 3;
const _ARR_NEXT = 4;

function parseDocument(s: string): JsonVal {
  const n = s.length;
  const ws = (i: number): number => {
    while (i < n && (s[i] === " " || s[i] === "\t" || s[i] === "\n" || s[i] === "\r")) i++;
    return i;
  };

  let i = ws(0);
  if (i >= n) throw new ScanError("invalid-json", "empty");

  const stack: Frame[] = [];
  let phase = _VALUE;
  let value: JsonVal = null;

  const deliver = (pos: number): number => {
    // Deliver the completed `value` into the stack root or parent frame.
    if (stack.length === 0) {
      const j = ws(pos);
      if (j !== n) throw new ScanError("invalid-json", "trailing");
      return -1; // done
    }
    const top = stack[stack.length - 1]!;
    if (top.kind === 0) {
      const k = top.key!;
      if (Object.hasOwn(top.obj, k)) throw new ScanError("duplicate-member-name", k);
      top.obj[k] = value;
      return pos; // phase becomes _OBJ_NEXT
    }
    top.arr.push(value);
    return pos; // phase becomes _ARR_NEXT
  };

  for (;;) {
    if (phase === _VALUE) {
      i = ws(i);
      const c = s[i] ?? "";
      if (c === "{") {
        const obj: { [k: string]: JsonVal } = Object.create(null);
        i = ws(i + 1);
        if ((s[i] ?? "") === "}") {
          i++;
          value = obj;
          const d = deliver(i);
          if (d < 0) return value;
          phase = stack.length && stack[stack.length - 1]!.kind === 0 ? _OBJ_NEXT : _ARR_NEXT;
          continue;
        }
        if (i >= n || (s[i] ?? "") !== '"') throw new ScanError("invalid-json", "key");
        stack.push({ kind: 0, obj, key: null });
        phase = _KEY;
        continue;
      }
      if (c === "[") {
        const arr: JsonVal[] = [];
        i = ws(i + 1);
        if ((s[i] ?? "") === "]") {
          i++;
          value = arr;
          const d = deliver(i);
          if (d < 0) return value;
          phase = stack.length && stack[stack.length - 1]!.kind === 0 ? _OBJ_NEXT : _ARR_NEXT;
          continue;
        }
        stack.push({ kind: 1, arr });
        phase = _VALUE;
        continue;
      }
      if (c === '"') {
        const r = strAt(s, i);
        value = r[0];
        i = r[1];
        const d = deliver(i);
        if (d < 0) return value;
        phase = stack.length && stack[stack.length - 1]!.kind === 0 ? _OBJ_NEXT : _ARR_NEXT;
        continue;
      }
      if (c === "t") {
        if (s.slice(i, i + 4) !== "true") throw new ScanError("invalid-json", "true");
        i += 4;
        value = true;
      } else if (c === "f") {
        if (s.slice(i, i + 5) !== "false") throw new ScanError("invalid-json", "false");
        i += 5;
        value = false;
      } else if (c === "n") {
        if (s.slice(i, i + 4) !== "null") throw new ScanError("invalid-json", "null");
        i += 4;
        value = null;
      } else if (c === "-" || (c >= "0" && c <= "9")) {
        const r = numAt(s, i);
        value = r[0];
        i = r[1];
      } else {
        throw new ScanError("invalid-json");
      }
      const d = deliver(i);
      if (d < 0) return value;
      phase = stack.length && stack[stack.length - 1]!.kind === 0 ? _OBJ_NEXT : _ARR_NEXT;
      continue;
    }

    if (phase === _KEY) {
      const r = strAt(s, i);
      (stack[stack.length - 1] as ObjFrame).key = r[0];
      i = r[1];
      phase = _COLON;
      continue;
    }

    if (phase === _COLON) {
      i = ws(i);
      if ((s[i] ?? "") !== ":") throw new ScanError("invalid-json", "colon");
      i++;
      phase = _VALUE;
      continue;
    }

    if (phase === _OBJ_NEXT) {
      i = ws(i);
      const c = s[i] ?? "";
      if (c === ",") {
        i = ws(i + 1);
        if ((s[i] ?? "") !== '"') throw new ScanError("invalid-json", "key");
        phase = _KEY;
        continue;
      }
      if (c === "}") {
        i++;
        const frame = stack.pop() as ObjFrame;
        value = frame.obj;
        const d = deliver(i);
        if (d < 0) return value;
        phase = stack.length && stack[stack.length - 1]!.kind === 0 ? _OBJ_NEXT : _ARR_NEXT;
        continue;
      }
      throw new ScanError("invalid-json", "object");
    }

    // _ARR_NEXT
    i = ws(i);
    const c = s[i] ?? "";
    if (c === ",") {
      i++;
      phase = _VALUE;
      continue;
    }
    if (c === "]") {
      i++;
      const frame = stack.pop() as ArrFrame;
      value = frame.arr;
      const d = deliver(i);
      if (d < 0) return value;
      phase = stack.length && stack[stack.length - 1]!.kind === 0 ? _OBJ_NEXT : _ARR_NEXT;
      continue;
    }
    throw new ScanError("invalid-json", "array");
  }
}

function strAt(s: string, start: number): [string, number] {
  const n = s.length;
  let i = start + 1; // skip opening quote
  let out = "";
  while (i < n) {
    const c = s[i]!;
    if (c === '"') {
      checkText(out);
      return [out, i + 1];
    }
    if (c === "\\") {
      i++;
      const e = s[i++];
      if (e === '"') out += '"';
      else if (e === "\\") out += "\\";
      else if (e === "/") out += "/";
      else if (e === "b") out += "\b";
      else if (e === "f") out += "\f";
      else if (e === "n") out += "\n";
      else if (e === "r") out += "\r";
      else if (e === "t") out += "\t";
      else if (e === "u") {
        const hi = hex4(s, i);
        i += 4;
        if (hi >= 0xd800 && hi <= 0xdbff) {
          if (s.slice(i, i + 2) !== "\\u") throw new ScanError("lone-surrogate");
          i += 2;
          const lo = hex4(s, i);
          i += 4;
          if (lo < 0xdc00 || lo > 0xdfff) throw new ScanError("lone-surrogate");
          out += String.fromCodePoint(0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00));
        } else if (hi >= 0xdc00 && hi <= 0xdfff) {
          throw new ScanError("lone-surrogate");
        } else {
          out += String.fromCharCode(hi);
        }
      } else {
        throw new ScanError("invalid-json", "escape");
      }
      continue;
    }
    if (c.charCodeAt(0) <= 0x1f) throw new ScanError("invalid-json", "control");
    out += c;
    i++;
  }
  throw new ScanError("invalid-json", "string");
}

function hex4(s: string, i: number): number {
  const h = s.slice(i, i + 4);
  if (!/^[0-9a-fA-F]{4}$/.test(h)) throw new ScanError("invalid-json", "\\u");
  return parseInt(h, 16);
}

function numAt(s: string, start: number): [number, number] {
  const n = s.length;
  let i = start;
  if (s[i] === "-") i++;
  if ((s[i] ?? "") < "0" || (s[i] ?? "") > "9") throw new ScanError("invalid-json", "number");
  if (s[i] === "0") i++;
  else while (i < n && s[i]! >= "0" && s[i]! <= "9") i++;
  if (s[i] === ".") {
    i++;
    if ((s[i] ?? "") < "0" || (s[i] ?? "") > "9") throw new ScanError("invalid-json", "frac");
    while (i < n && s[i]! >= "0" && s[i]! <= "9") i++;
  }
  if (s[i] === "e" || s[i] === "E") {
    i++;
    if (s[i] === "+" || s[i] === "-") i++;
    if ((s[i] ?? "") < "0" || (s[i] ?? "") > "9") throw new ScanError("invalid-json", "exp");
    while (i < n && s[i]! >= "0" && s[i]! <= "9") i++;
  }
  const tok = s.slice(start, i);
  const v = Number(tok);
  if (!Number.isFinite(v)) throw new ScanError("non-finite-number", tok);
  if (Object.is(v, -0) || (v === 0 && tok.startsWith("-"))) {
    throw new ScanError("negative-zero", tok);
  }
  return [v, i];
}

function checkText(s: string): void {
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xd800 && cp <= 0xdfff) throw new ScanError("lone-surrogate");
    if (isNoncharacter(cp)) throw new ScanError("noncharacter");
  }
}
