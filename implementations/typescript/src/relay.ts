/** Tiny ┬º28 HTTP relay. Uses TypeScript validation. Independent of implementations/python/relay.py. */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { jcsBytes } from "./canon.ts";
import { Fail, Unsupported, validate } from "./check.ts";
import { scanObject } from "./scan.ts";
import type { JsonVal } from "./scan.ts";

const MAXH = (1n << 256n) - 1n;
const multiplier = Math.max(1, Number(process.env.SPP_POW_MULTIPLIER ?? "1"));
const maxRecord = Number(process.env.SPP_MAX_RECORD_BYTES ?? "65536");
const pageSize = Math.max(1, Number(process.env.SPP_PAGE_SIZE ?? "2"));
const blockActor = process.env.SPP_BLOCK_ACTOR ?? "";
const blockChannel = process.env.SPP_BLOCK_CHANNEL ?? "";

type Env = { [k: string]: JsonVal };
const envelopes = new Map<string, Env>();
const advertised: string[] = [];
const channelOf = new Map<string, string[]>();
const objectOf = new Map<string, string[]>();

function push(map: Map<string, string[]>, key: string, id: string): void {
  const arr = map.get(key) ?? [];
  arr.push(id);
  map.set(key, arr);
}

function store(env: Env, ident: string): void {
  const hex = ident.slice(7);
  if (envelopes.has(hex)) return;
  envelopes.set(hex, env);
  const t = env.type;
  if (t === "channel") {
    advertised.push(hex);
    push(channelOf, hex, hex);
    const desc = env.descriptor;
    if (desc && typeof desc === "object" && !Array.isArray(desc) && typeof desc.hash === "string") {
      push(objectOf, desc.hash.slice(7), hex);
    }
  } else if (t === "pointer" && typeof env.channel === "string") {
    push(channelOf, env.channel.slice(7), hex);
    const ref = env.ref;
    if (ref && typeof ref === "object" && !Array.isArray(ref) && typeof ref.hash === "string") {
      push(objectOf, ref.hash.slice(7), hex);
    }
  }
}

function b64url(n: number): string {
  return Buffer.from(String(n), "utf8").toString("base64url");
}

function cursorOk(c: string | null): boolean {
  if (!c) return true;
  return /^[A-Za-z0-9_-]+$/.test(c);
}

function fromCursor(c: string | null): number {
  if (!c) return 0;
  const s = Buffer.from(c, "base64url").toString("utf8");
  const n = Number(s);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

function slicePage(ids: string[], cursor: string | null): { items: string[]; next: string | null } {
  const start = fromCursor(cursor);
  const chunk = ids.slice(start, start + pageSize);
  const end = start + chunk.length;
  return { items: chunk, next: end < ids.length ? b64url(end) : null };
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let n = 0;
    req.on("data", (c: Buffer) => {
      n += c.length;
      if (n > maxRecord) {
        reject(Object.assign(new Error("too_large"), { code: "too_large" }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function send(res: ServerResponse, code: number, body: unknown): void {
  const data = Buffer.from(JSON.stringify(body));
  res.writeHead(code, { "Content-Type": "application/json", "Content-Length": data.length });
  res.end(data);
}

function err(res: ServerResponse, code: number, error: string, message: string): void {
  send(res, code, { error, message });
}

function workOk(ident: string, units: number): boolean {
  const h = BigInt("0x" + ident.slice(7));
  return h <= MAXH / (BigInt(units) * 65536n * BigInt(multiplier));
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  const path = url.pathname;
  const cursor = url.searchParams.get("cursor");
  try {
    if (req.method === "GET" && path === "/.well-known/spp") {
      return send(res, 200, {
        v: 1,
        submit: "/v1/assertions",
        channels: "/v1/channels",
        assertion: "/v1/assertions/sha256/{hex}",
        channel: "/v1/channels/sha256/{hex}/assertions",
        object: "/v1/objects/sha256/{hex}/assertions",
        bootstrap_channels: [],
        policy: { pow_multiplier: multiplier, max_record_bytes: maxRecord },
      });
    }
    if (req.method === "GET" && path === "/v1/channels") {
      if (!cursorOk(cursor)) return err(res, 400, "bad_cursor", "cursor must match the base64url alphabet");
      const ids = advertised.map((h) => `sha256:${h}`);
      const page = slicePage(ids, cursor);
      return send(res, 200, { items: page.items, next: page.next });
    }
    let m = /^\/v1\/assertions\/sha256\/([0-9a-f]{64})$/.exec(path);
    if (req.method === "GET" && m) {
      const env = envelopes.get(m[1]!);
      if (!env) return err(res, 404, "not_found", "unknown assertion");
      return send(res, 200, JSON.parse(Buffer.from(jcsBytes(env)).toString("utf8")));
    }
    m = /^\/v1\/channels\/sha256\/([0-9a-f]{64})\/assertions$/.exec(path);
    if (req.method === "GET" && m) {
      if (!cursorOk(cursor)) return err(res, 400, "bad_cursor", "cursor must match the base64url alphabet");
      const page = slicePage(channelOf.get(m[1]!) ?? [], cursor);
      return send(res, 200, { items: page.items.map((h) => envelopes.get(h)), next: page.next });
    }
    m = /^\/v1\/objects\/sha256\/([0-9a-f]{64})\/assertions$/.exec(path);
    if (req.method === "GET" && m) {
      if (!cursorOk(cursor)) return err(res, 400, "bad_cursor", "cursor must match the base64url alphabet");
      const page = slicePage(objectOf.get(m[1]!) ?? [], cursor);
      return send(res, 200, { items: page.items.map((h) => envelopes.get(h)), next: page.next });
    }
    if (req.method === "POST" && path === "/v1/assertions") {
      const enc = (req.headers["content-encoding"] ?? "").toString();
      if (enc && enc.toLowerCase() !== "identity") return err(res, 400, "bad_encoding", "non-identity Content-Encoding");
      const ctype = (req.headers["content-type"] ?? "").toString().split(";")[0]!.trim();
      if (ctype !== "application/json" && ctype !== "application/spp+json") {
        return err(res, 400, "bad_type", "Content-Type");
      }
      const cl = Number(req.headers["content-length"] ?? "0");
      if (cl > maxRecord) return err(res, 400, "too_large", "max_record_bytes");
      const body = await readBody(req);
      if (body.length > maxRecord) return err(res, 400, "too_large", "max_record_bytes");
      let info: { id: string; units: number };
      try {
        info = validate(new Uint8Array(body));
      } catch (e) {
        if (e instanceof Unsupported) return err(res, 400, "unsupported_assertion", e.reason);
        if (e instanceof Fail) return err(res, 400, "invalid_assertion", `${e.stage}:${e.reason}`);
        throw e;
      }
      const env = scanObject(new Uint8Array(body)) as Env;
      if (blockActor && env.actor === blockActor) return err(res, 403, "policy", "actor blocked");
      if (blockChannel && env.channel === blockChannel) return err(res, 403, "policy", "channel blocked");
      if (!workOk(info.id, info.units)) return err(res, 403, "policy", "local proof-of-work multiplier");
      const existed = envelopes.has(info.id.slice(7));
      store(env, info.id);
      return send(res, 200, { id: info.id, duplicate: existed });
    }
    return err(res, 404, "not_found", "route");
  } catch (e) {
    if ((e as { code?: string }).code === "too_large") return err(res, 400, "too_large", "max_record_bytes");
    console.error(e);
    return err(res, 500, "internal", "error");
  }
});

const port = (() => {
  const i = process.argv.indexOf("--port");
  return i >= 0 ? Number(process.argv[i + 1]) : 18761;
})();

server.listen(port, "127.0.0.1", () => {
  console.log(`relay-b http://127.0.0.1:${port}`);
});
