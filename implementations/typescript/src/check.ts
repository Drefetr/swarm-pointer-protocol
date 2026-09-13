/** Schema, work, and the ┬º20 pipeline. */

import { sha256 } from "@noble/hashes/sha256";
import { jcs, jcsBytes } from "./canon.ts";
import { verifySppEd25519 } from "./curve.ts";
import { type JsonVal, ScanError, scanObject, scanUtf8 } from "./scan.ts";

export class Fail extends Error {
  stage: string;
  reason: string;
  constructor(stage: string, reason: string) {
    super(`${stage}:${reason}`);
    this.stage = stage;
    this.reason = reason;
  }
}

export class Unsupported extends Fail {}

const SHA256_ID = /^sha256:[0-9a-f]{64}$/;
const ACTOR = /^ed25519:[0-9a-f]{64}$/;
const SIG = /^[0-9a-f]{128}$/;
const NONCE = /^(0|[1-9][0-9]{0,19})$/;
const MAX_NONCE = (1n << 64n) - 1n;
const MAX_CREATED = 9007199254740991;
const MAX_JCS = 1048576;
const MAX_LOCS = 256;
const MAX_LOC_BYTES = 8192;
const MAX_PARENTS = 1024;
const SCALE = 65536n;
const MAXH = (1n << 256n) - 1n;
const CORE = new Set([
  "v",
  "type",
  "actor",
  "created",
  "nonce",
  "channel",
  "ref",
  "parents",
  "descriptor",
  "id",
  "sig",
  "ext",
]);

export function stripEnvelope(obj: { [k: string]: JsonVal }): { [k: string]: JsonVal } {
  const u: { [k: string]: JsonVal } = Object.create(null);
  for (const k of Object.keys(obj)) {
    if (k !== "id" && k !== "sig") u[k] = obj[k]!;
  }
  return u;
}

function isInt(n: JsonVal): n is number {
  return typeof n === "number" && Number.isFinite(n) && Number.isInteger(n);
}

function isFiniteNumber(n: JsonVal): n is number {
  return typeof n === "number" && Number.isFinite(n);
}

function shaId(bytes: Uint8Array): { id: string; d: Uint8Array } {
  const d = sha256(bytes);
  const hex = [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
  return { id: `sha256:${hex}`, d };
}

export function unitsOf(u: { [k: string]: JsonVal }, jcsLen: number): number {
  const t = u.type;
  let loc = 0;
  let parents = 0;
  let extra = 0;
  if (t === "pointer") {
    const ref = u.ref as { locators: string[] };
    loc = ref.locators.length;
    parents = Array.isArray(u.parents) ? u.parents.length : 0;
  } else if (t === "channel") {
    extra = 16;
    if (u.descriptor && typeof u.descriptor === "object" && !Array.isArray(u.descriptor)) {
      loc = (u.descriptor.locators as string[]).length;
    }
  } else {
    throw new Fail("schema", "unknown-type");
  }
  return 1 + Math.ceil(jcsLen / 1024) + loc + parents + extra;
}

export function targetOf(units: number): bigint {
  return MAXH / (BigInt(units) * SCALE);
}

export function workAccepts(h: bigint, units: number): boolean {
  return h <= targetOf(units);
}

function hex64(n: bigint): string {
  return n.toString(16).padStart(64, "0");
}

function needId(v: JsonVal): void {
  if (typeof v !== "string" || !SHA256_ID.test(v)) throw new Fail("identifier", "identifier");
}

function needRef(v: JsonVal): void {
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Fail("schema", "schema");
  const keys = Object.keys(v);
  if (keys.length !== 2 || !Object.hasOwn(v, "hash") || !Object.hasOwn(v, "locators")) throw new Fail("schema", "schema");
  needId(v.hash);
  if (!Array.isArray(v.locators)) throw new Fail("schema", "schema");
  if (v.locators.length > MAX_LOCS) throw new Fail("length", "too-many-locators");
  for (const loc of v.locators) {
    if (typeof loc !== "string") throw new Fail("schema", "schema");
    if (new TextEncoder().encode(loc).length > MAX_LOC_BYTES) {
      throw new Fail("length", "locator-too-long");
    }
  }
}

export function schemaOk(u: { [k: string]: JsonVal }): void {
  for (const k of Object.keys(u)) {
    if (!CORE.has(k)) throw new Fail("schema", "schema");
  }
  for (const req of ["v", "type", "actor", "created", "nonce"]) {
    if (!Object.hasOwn(u, req)) throw new Fail("schema", "schema");
  }
  if (!isFiniteNumber(u.v)) throw new Fail("schema", "schema");
  if (u.v !== 1) throw new Unsupported("version", "unknown-v");
  const t = u.type;
  if (t !== "channel" && t !== "pointer") throw new Fail("schema", "unknown-type");
  if (typeof u.actor !== "string" || !ACTOR.test(u.actor)) throw new Fail("identifier", "identifier");
  if (!isInt(u.created)) throw new Fail("created", "created");
  if (u.created < 0 || u.created > MAX_CREATED) throw new Fail("created", "created");
  if (typeof u.nonce !== "string" || !NONCE.test(u.nonce)) throw new Fail("nonce", "nonce");
  if (BigInt(u.nonce) > MAX_NONCE) throw new Fail("nonce", "nonce");
  if (Object.hasOwn(u, "ext") && (u.ext === null || typeof u.ext !== "object" || Array.isArray(u.ext))) {
    throw new Fail("schema", "schema");
  }
  if (t === "pointer") {
    if (Object.hasOwn(u, "descriptor") || !Object.hasOwn(u, "channel") || !Object.hasOwn(u, "ref")) throw new Fail("schema", "schema");
    needId(u.channel);
    needRef(u.ref);
    if (Object.hasOwn(u, "parents")) {
      if (!Array.isArray(u.parents)) throw new Fail("schema", "schema");
      if (u.parents.length > MAX_PARENTS) throw new Fail("length", "too-many-parents");
      for (const p of u.parents) needId(p);
    }
  } else {
    if (Object.hasOwn(u, "channel") || Object.hasOwn(u, "parents") || Object.hasOwn(u, "ref")) throw new Fail("schema", "schema");
    if (Object.hasOwn(u, "descriptor")) needRef(u.descriptor);
  }
}

export function validate(bytes: Uint8Array) {
  let obj: { [k: string]: JsonVal };
  try {
    obj = scanObject(bytes);
  } catch (e) {
    if (e instanceof ScanError) throw new Fail("json-input", e.reason);
    throw e;
  }
  return validateObj(obj);
}

export function validateObj(obj: { [k: string]: JsonVal }) {
  if (Object.hasOwn(obj, "v") && isFiniteNumber(obj.v) && obj.v !== 1) throw new Unsupported("version", "unknown-v");
  const u = stripEnvelope(obj);
  schemaOk(u);
  const jb = jcsBytes(u);
  if (jb.length > MAX_JCS) throw new Fail("length", "jcs-too-large");
  const { id, d } = shaId(jb);
  if (typeof obj.id !== "string") throw new Fail("identifier", "missing-id");
  if (obj.id !== id) throw new Fail("identity", "id-mismatch");
  const units = unitsOf(u, jb.length);
  let h = 0n;
  for (const b of d) h = (h << 8n) | BigInt(b);
  const target = targetOf(units);
  if (h > target) throw new Fail("work", "insufficient-work");
  if (typeof obj.sig !== "string" || !SIG.test(obj.sig)) throw new Fail("signature", "signature");
  const actor = Uint8Array.from((u.actor as string).slice(8).match(/../g)!.map((x) => parseInt(x, 16)));
  const sig = Uint8Array.from(obj.sig.match(/../g)!.map((x) => parseInt(x, 16)));
  if (!verifySppEd25519(actor, sig, d)) throw new Fail("signature", "signature");
  return {
    id,
    units,
    target_hex: hex64(target),
    jcs: jcs(u),
    sig: obj.sig,
  };
}

export function scanAny(bytes: Uint8Array): JsonVal {
  return scanUtf8(bytes);
}

export { hex64, shaId, jcs, jcsBytes, scanUtf8, ScanError };
