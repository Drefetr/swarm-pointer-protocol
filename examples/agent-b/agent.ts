#!/usr/bin/env npx tsx
/**
 * SPP v1 demo actor — Agent B (TypeScript).
 *
 * An acting SPP client, not a relay. It owns an Ed25519 identity and a
 * content-addressed object store, mines and signs pointer assertions (using
 * the independent `impl-b` stack), submits them to a relay, polls a capability
 * channel, independently validates every received assertion with the impl-b
 * verifier, fetches referenced objects from their locators, and accepts
 * payloads only after the §23 SHA-256 check.
 *
 * The relay is never trusted for validity.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash, createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { Fail, Unsupported, jcsBytes, targetOf, unitsOf, validate } from "../../implementations/typescript/src/check.ts";
import { signAssertion } from "../../implementations/typescript/src/curve.ts";
import type { JsonVal } from "../../implementations/typescript/src/scan.ts";

const SHA256_ID = /^sha256:[0-9a-f]{64}$/;
const MAX_FETCH_BYTES = 16 * 1024 * 1024;
const MAX_NONCE = (1n << 64n) - 1n;

type Env = { [k: string]: JsonVal };

// --------------------------------------------------------------------------- //
// small utilities
// --------------------------------------------------------------------------- //

function emit(obj: unknown): void {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(s: string): Uint8Array {
  return Uint8Array.from(s.match(/../g)!.map((x) => parseInt(x, 16)));
}

function sha256Id(data: Uint8Array): string {
  return "sha256:" + createHash("sha256").update(data).digest("hex");
}

/** Raw Ed25519 public key for a 32-byte seed, via node's own key handling. */
function publicFromSeed(seed: Uint8Array): Uint8Array {
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seed),
  ]);
  const priv = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const spki = createPublicKey(priv).export({ format: "der", type: "spki" });
  return new Uint8Array(spki.subarray(spki.length - 32));
}

function indexOfBytes(hay: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

interface Args {
  [k: string]: string | string[] | undefined;
}

function parseArgs(argv: string[]): Args {
  const out: Args = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith("--")) continue;
    const key = a.slice(2);
    const val = argv[++i];
    const prev = out[key];
    if (prev === undefined) out[key] = val;
    else if (Array.isArray(prev)) prev.push(val);
    else out[key] = [prev, val];
  }
  return out;
}

function optional(args: Args, key: string): string | undefined {
  const v = args[key];
  if (Array.isArray(v)) return v[v.length - 1];
  return v;
}

function required(args: Args, key: string): string {
  const v = optional(args, key);
  if (v === undefined) throw new Error(`missing --${key}`);
  return v;
}

/** Normalised, de-duplicated relay base URLs from a repeatable --relay. */
function relayList(args: Args): string[] {
  const v = args["relay"];
  if (v === undefined) throw new Error("missing --relay");
  const arr = Array.isArray(v) ? v : [v];
  const out: string[] = [];
  for (const raw of arr) {
    const base = raw.replace(/\/+$/, "");
    if (base.length > 0 && !out.includes(base)) out.push(base);
  }
  return out;
}

// --------------------------------------------------------------------------- //
// state
// --------------------------------------------------------------------------- //

interface State {
  actor: string;
  seen: string[];
  published: string[];
  objects: string[];
}

function paths(dir: string) {
  return {
    key: join(dir, "key.hex"),
    state: join(dir, "state.json"),
    objects: join(dir, "objects"),
    published: join(dir, "published"),
  };
}

function loadState(dir: string): { state: State; key: Uint8Array } {
  const p = paths(dir);
  if (!existsSync(p.key) || !existsSync(p.state)) {
    throw new Error(`agent B not initialised in ${dir} (run: init)`);
  }
  const key = fromHex(readFileSync(p.key, "utf8").trim());
  const state = JSON.parse(readFileSync(p.state, "utf8")) as State;
  return { state, key };
}

function saveState(dir: string, state: State): void {
  writeFileSync(paths(dir).state, JSON.stringify(state));
}

function objectStore(dir: string, data: Uint8Array): { hash: string; hex: string } {
  const h = createHash("sha256").update(data).digest("hex");
  const od = paths(dir).objects;
  mkdirSync(od, { recursive: true });
  const f = join(od, h);
  if (!existsSync(f)) writeFileSync(f, data);
  return { hash: "sha256:" + h, hex: h };
}

// --------------------------------------------------------------------------- //
// mining / signing
// --------------------------------------------------------------------------- //

function mine(U: Env, sk: Uint8Array): Env {
  const base: Env = { ...U };
  const enc = new TextEncoder();
  const marker = enc.encode('"nonce":"');
  for (let width = 1n; width <= 20n; width++) {
    const w = Number(width);
    let lo = width === 1n ? 0n : 10n ** (width - 1n);
    let hi = width === 1n ? 9n : 10n ** width - 1n;
    if (lo > MAX_NONCE) break;
    if (hi > MAX_NONCE) hi = MAX_NONCE;
    const placeholder = w === 1 ? "0" : "1" + "0".repeat(w - 1);
    const template = jcsBytes({ ...base, nonce: placeholder } as JsonVal);
    const off = indexOfBytes(template, marker) + marker.length;
    const units = unitsOf(base, template.length);
    const target = targetOf(units);
    const buf = new Uint8Array(template);
    for (let n = lo; n <= hi; n++) {
      const digits = w === 1 ? n.toString() : n.toString().padStart(w, "0");
      buf.set(enc.encode(digits), off);
      const d = new Uint8Array(createHash("sha256").update(buf).digest());
      let hv = 0n;
      for (const b of d) hv = (hv << 8n) | BigInt(b);
      if (hv <= target) {
        const env: Env = { ...base, nonce: digits, id: "sha256:" + hex(d), sig: hex(signAssertion(sk, d)) };
        validate(jcsBytes(env));
        return env;
      }
    }
  }
  throw new Error("nonce space exhausted");
}

// --------------------------------------------------------------------------- //
// http
// --------------------------------------------------------------------------- //

async function httpRaw(method: string, url: string, body?: Uint8Array, ctype?: string) {
  const headers: Record<string, string> = {};
  if (ctype) headers["Content-Type"] = ctype;
  const res = await fetch(url, { method, headers, body: body as BodyInit | undefined, redirect: "follow" });
  const raw = new Uint8Array(await res.arrayBuffer());
  return { status: res.status, raw };
}

async function fetchObject(locator: string): Promise<Uint8Array> {
  const u = new URL(locator);
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error(`refused scheme ${u.protocol}`);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 20000);
  try {
    const res = await fetch(locator, { signal: ctrl.signal, redirect: "follow" });
    if (!res.ok) throw new Error(`http ${res.status}`);
    const ab = new Uint8Array(await res.arrayBuffer());
    if (ab.length > MAX_FETCH_BYTES) throw new Error("object too large");
    return ab;
  } finally {
    clearTimeout(timer);
  }
}

function relayUrl(base: string, path: string): string {
  return base.replace(/\/+$/, "") + path;
}

// --------------------------------------------------------------------------- //
// commands
// --------------------------------------------------------------------------- //

function cmdInit(args: Args): number {
  const dir = required(args, "state");
  const p = paths(dir);
  mkdirSync(p.objects, { recursive: true });
  mkdirSync(p.published, { recursive: true });
  let created = false;
  let key: Uint8Array;
  if (existsSync(p.key)) {
    key = fromHex(readFileSync(p.key, "utf8").trim());
  } else {
    key = new Uint8Array(randomBytes(32));
    writeFileSync(p.key, hex(key));
    created = true;
  }
  const actor = "ed25519:" + hex(publicFromSeed(key));
  const state: State = existsSync(p.state)
    ? (JSON.parse(readFileSync(p.state, "utf8")) as State)
    : { actor, seen: [], published: [], objects: [] };
  state.actor = actor;
  saveState(dir, state);
  emit({ ok: true, command: "init", actor, state: dir, created });
  return 0;
}

function cmdStatus(args: Args): number {
  const { state } = loadState(required(args, "state"));
  emit({
    ok: true,
    command: "status",
    actor: state.actor,
    seen: state.seen,
    published: state.published,
    objects: state.objects,
  });
  return 0;
}

async function cmdPublish(args: Args): Promise<number> {
  const dir = required(args, "state");
  const relays = relayList(args);
  const channel = required(args, "channel");
  const file = required(args, "file");
  const objectBase = required(args, "object-base");
  const { state, key } = loadState(dir);
  if (!SHA256_ID.test(channel)) throw new Error(`invalid channel ${channel}`);

  const data = new Uint8Array(readFileSync(file));
  const { hash: objectHash, hex: objectHex } = objectStore(dir, data);
  const locator = objectBase.replace(/\/+$/, "") + "/objects/sha256/" + objectHex;
  const createdArg = optional(args, "created");
  const created = createdArg !== undefined ? Number(createdArg) : Math.floor(Date.now() / 1000);
  const U: Env = {
    v: 1,
    type: "pointer",
    actor: state.actor,
    channel,
    created,
    ref: { hash: objectHash, locators: [locator] },
  };
  const parentsArg = optional(args, "parents");
  if (parentsArg) {
    U.parents = parentsArg.split(",").filter((x) => x.length > 0);
  }

  const env = mine(U, key);
  const raw = jcsBytes(env);
  const id = env.id as string;
  const saved = join(paths(dir).published, id.slice(7) + ".json");
  writeFileSync(saved, Buffer.from(raw));

  const relayResults: Record<string, unknown>[] = [];
  let stored = false;
  let firstStatus: number | null = null;
  for (const base of relays) {
    let status = 0;
    let body: Record<string, unknown> = {};
    try {
      const res = await httpRaw("POST", relayUrl(base, "/v1/assertions"), raw, "application/json");
      status = res.status;
      try {
        body = JSON.parse(Buffer.from(res.raw).toString("utf8"));
      } catch {
        body = {};
      }
    } catch (e) {
      relayResults.push({ relay: base, status: 0, duplicate: false, error: e instanceof Error ? e.name : String(e) });
      continue;
    }
    relayResults.push({ relay: base, status, duplicate: Boolean(body.duplicate), error: body.error ?? null });
    if (firstStatus === null) firstStatus = status;
    if (status === 200) stored = true;
  }
  const accepted = relayResults.filter((r) => r.status === 200);
  if (stored) {
    if (!state.objects.includes(objectHash)) state.objects.push(objectHash);
    if (!state.published.includes(id)) state.published.push(id);
    saveState(dir, state);
  }
  emit({
    ok: stored,
    command: "publish",
    actor: state.actor,
    channel,
    assertion_id: id,
    object_hash: objectHash,
    file,
    status: firstStatus,
    duplicate: accepted.length > 0 ? accepted.every((r) => r.duplicate === true) : false,
    error: relayResults.find((r) => r.status !== 200)?.error ?? null,
    stored,
    saved,
    object_base: objectBase,
    relays: relayResults,
  });
  return 0;
}

async function cmdPublishChannel(args: Args): Promise<number> {
  const dir = required(args, "state");
  const relays = relayList(args);
  const { state, key } = loadState(dir);
  const createdArg = optional(args, "created");
  const created = createdArg !== undefined ? Number(createdArg) : Math.floor(Date.now() / 1000);
  const U: Env = { v: 1, type: "channel", actor: state.actor, created };
  const descriptorHash = optional(args, "descriptor-hash");
  if (descriptorHash) {
    U.descriptor = { hash: descriptorHash, locators: [] };
  }
  const env = mine(U, key);
  const raw = jcsBytes(env);
  const id = env.id as string;
  const saved = join(paths(dir).published, id.slice(7) + ".json");
  writeFileSync(saved, Buffer.from(raw));
  const relayResults: Record<string, unknown>[] = [];
  let stored = false;
  let firstStatus: number | null = null;
  for (const base of relays) {
    let status = 0;
    let body: Record<string, unknown> = {};
    try {
      const res = await httpRaw("POST", relayUrl(base, "/v1/assertions"), raw, "application/json");
      status = res.status;
      try {
        body = JSON.parse(Buffer.from(res.raw).toString("utf8"));
      } catch {
        body = {};
      }
    } catch (e) {
      relayResults.push({ relay: base, status: 0, duplicate: false, error: e instanceof Error ? e.name : String(e) });
      continue;
    }
    relayResults.push({ relay: base, status, duplicate: Boolean(body.duplicate), error: body.error ?? null });
    if (firstStatus === null) firstStatus = status;
    if (status === 200) stored = true;
  }
  const accepted = relayResults.filter((r) => r.status === 200);
  if (stored && !state.published.includes(id)) {
    state.published.push(id);
    saveState(dir, state);
  }
  emit({
    ok: stored,
    command: "publish-channel",
    actor: state.actor,
    assertion_id: id,
    status: firstStatus,
    duplicate: accepted.length > 0 ? accepted.every((r) => r.duplicate === true) : false,
    error: relayResults.find((r) => r.status !== 200)?.error ?? null,
    saved,
    relays: relayResults,
  });
  return 0;
}

async function cmdSubmit(args: Args): Promise<number> {
  const relays = relayList(args);
  const file = required(args, "file");
  const raw = new Uint8Array(readFileSync(file));
  let ident: unknown = null;
  try {
    ident = JSON.parse(Buffer.from(raw).toString("utf8")).id;
  } catch {
    ident = null;
  }
  const relayResults: Record<string, unknown>[] = [];
  let ok = false;
  let firstStatus: number | null = null;
  for (const base of relays) {
    let status = 0;
    let body: Record<string, unknown> = {};
    try {
      const res = await httpRaw("POST", relayUrl(base, "/v1/assertions"), raw, "application/json");
      status = res.status;
      try {
        body = JSON.parse(Buffer.from(res.raw).toString("utf8"));
      } catch {
        body = {};
      }
    } catch (e) {
      relayResults.push({ relay: base, status: 0, error: e instanceof Error ? e.name : String(e) });
      continue;
    }
    relayResults.push({ relay: base, status, error: body.error ?? null, response_id: body.id ?? null, duplicate: Boolean(body.duplicate) });
    if (firstStatus === null) firstStatus = status;
    if (status === 200) ok = true;
  }
  const accepted = relayResults.filter((r) => r.status === 200);
  emit({
    ok,
    command: "submit",
    status: firstStatus,
    error: relayResults.find((r) => r.status !== 200)?.error ?? null,
    assertion_id: ident,
    response_id: accepted[0]?.response_id ?? null,
    duplicate: accepted.length > 0 ? accepted.every((r) => r.duplicate === true) : false,
    relays: relayResults,
  });
  return 0;
}

async function cmdPoll(args: Args): Promise<number> {
  const dir = required(args, "state");
  const relays = relayList(args);
  const channel = required(args, "channel");
  if (!SHA256_ID.test(channel)) throw new Error(`invalid channel ${channel}`);
  const { state } = loadState(dir);

  const seen = [...state.seen];
  const seenSet = new Set(seen);
  const objects = [...state.objects];
  const objectSet = new Set(objects);
  const processed = new Set<string>();

  const basePath = `/v1/channels/sha256/${channel.slice(7)}/assertions`;
  let pages = 0;
  let discovered = 0;
  const results: Record<string, unknown>[] = [];
  const errors: string[] = [];
  const relayStatus: Record<string, unknown>[] = [];

  const consider = async (base: string, env: Env): Promise<void> => {
    discovered++;
    let info: { id: string };
    try {
      info = validate(jcsBytes(env));
    } catch (e) {
      const reason = e instanceof Unsupported ? `unsupported:${e.reason}` : e instanceof Fail ? `${e.stage}:${e.reason}` : String(e);
      results.push({ assertion_id: env.id ?? null, valid: false, new: false, reason, relay: base });
      return;
    }
    const aid = info.id;
    if (processed.has(aid)) return;
    processed.add(aid);
    if (seenSet.has(aid)) {
      results.push({ assertion_id: aid, valid: true, new: false, type: env.type, reason: "duplicate", relay: base });
      return;
    }
    seenSet.add(aid);
    seen.push(aid);

    const res: Record<string, unknown> = {
      assertion_id: aid,
      valid: true,
      new: true,
      type: env.type,
      actor: env.actor ?? null,
      object_hash: null,
      locator: null,
      fetched: false,
      hash_ok: false,
      stored: false,
      reason: null,
      relay: base,
    };
    if (env.type === "pointer") {
      const ref = env.ref as { hash: string; locators: string[] };
      const want = ref.hash;
      res.object_hash = want;
      for (const loc of ref.locators) {
        res.locator = loc;
        let data: Uint8Array;
        try {
          data = await fetchObject(loc);
        } catch (e) {
          res.reason = `fetch:${e instanceof Error ? e.name : String(e)}`;
          continue;
        }
        res.fetched = true;
        const got = sha256Id(data);
        if (got === want) {
          objectStore(dir, data);
          if (!objectSet.has(want)) {
            objectSet.add(want);
            objects.push(want);
          }
          res.hash_ok = true;
          res.stored = true;
          res.reason = null;
          break;
        }
        res.hash_ok = false;
        res.reason = "hash-mismatch";
      }
      if (!res.fetched && res.reason === null) res.reason = "no-usable-locator";
    }
    results.push(res);
  };

  // Query each relay separately. A relay is a local source of candidate
  // assertions, never the authority on identity: dedup is global by id.
  for (const base of relays) {
    let cursor: string | null = null;
    let relayPages = 0;
    const relayErrors: string[] = [];
    for (;;) {
      const url = relayUrl(base, basePath) + (cursor ? `?cursor=${cursor}` : "");
      let status = 0;
      let raw = new Uint8Array();
      try {
        const r = await httpRaw("GET", url);
        status = r.status;
        raw = r.raw;
      } catch (e) {
        const msg = `GET ${basePath} -> ${e instanceof Error ? e.name : String(e)}`;
        relayErrors.push(msg);
        errors.push(`${base}: ${msg}`);
        break;
      }
      if (status !== 200) {
        const msg = `GET ${basePath} -> ${status}`;
        relayErrors.push(msg);
        errors.push(`${base}: ${msg}`);
        break;
      }
      let page: { items: Env[]; next: string | null };
      try {
        page = JSON.parse(Buffer.from(raw).toString("utf8")) as { items: Env[]; next: string | null };
      } catch {
        const msg = `GET ${basePath} -> malformed-json`;
        relayErrors.push(msg);
        errors.push(`${base}: ${msg}`);
        break;
      }
      relayPages++;
      for (const env of page.items) await consider(base, env);
      cursor = page.next;
      if (!cursor) break;
    }
    pages += relayPages;
    relayStatus.push({ relay: base, pages: relayPages, errors: relayErrors });
  }

  state.seen = seen;
  state.objects = objects;
  saveState(dir, state);
  emit({
    ok: true,
    command: "poll",
    actor: state.actor,
    channel,
    pages,
    discovered,
    new: results.filter((r) => r.new).length,
    valid: results.filter((r) => r.valid).length,
    invalid: results.filter((r) => !r.valid).length,
    stored: results.filter((r) => r.stored).length,
    results,
    errors,
    relays: relayStatus,
  });
  return 0;
}

// --------------------------------------------------------------------------- //
// object server
// --------------------------------------------------------------------------- //

function cmdServe(args: Args): number {
  const dir = required(args, "state");
  const host = args.host ?? "127.0.0.1";
  const port = Number(required(args, "port"));
  const { state } = loadState(dir);
  const objectsDir = paths(dir).objects;
  mkdirSync(objectsDir, { recursive: true });

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", `http://${host}`);
    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      return res.end("ok");
    }
    const m = /^\/objects\/sha256\/([0-9a-f]{64})$/.exec(url.pathname);
    if (!m) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      return res.end("not found");
    }
    const file = join(objectsDir, m[1]!);
    if (!existsSync(file)) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      return res.end("not found");
    }
    const data = readFileSync(file);
    res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": data.length });
    res.end(data);
  });
  server.listen(port, host, () => {
    emit({ ok: true, command: "serve", actor: state.actor, host, port });
  });
  return 0;
}

// --------------------------------------------------------------------------- //

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const rest = argv.slice(1);
  const args = parseArgs(rest);
  switch (cmd) {
    case "init":
      return cmdInit(args);
    case "status":
      return cmdStatus(args);
    case "publish":
      return await cmdPublish(args);
    case "poll":
      return await cmdPoll(args);
    case "publish-channel":
      return await cmdPublishChannel(args);
    case "submit":
      return await cmdSubmit(args);
    case "serve":
      cmdServe(args);
      return await new Promise<number>(() => {});
    default:
      process.stderr.write("usage: agent.ts init|status|publish|poll|submit|serve ...\n");
      return 2;
  }
}

main().then((code) => process.exit(code));
