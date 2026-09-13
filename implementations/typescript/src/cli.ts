#!/usr/bin/env npx tsx
import { readFileSync } from "node:fs";
import { Fail, ScanError, Unsupported, hex64, jcs, jcsBytes, scanUtf8, schemaOk, shaId, stripEnvelope, targetOf, unitsOf, validate, workAccepts } from "./check.ts";
import { verifySppEd25519 } from "./curve.ts";
import { type JsonVal, scanObject } from "./scan.ts";

type Case = {
  id: string;
  class: string;
  expect: string;
  input: Record<string, unknown>;
  want?: Record<string, unknown>;
};

function validText(info: { id: string; units: number; target_hex: string }): string {
  return `VALID\nid: ${info.id}\nunits: ${info.units}\ntarget: ${info.target_hex}\n`;
}

function invalidText(e: Fail): string {
  return `${e instanceof Unsupported ? "UNSUPPORTED" : "INVALID"}\nstage: ${e.stage}\nreason: ${e.reason}\n`;
}

function padU(inp: Record<string, unknown>): { [k: string]: JsonVal } {
  return {
    v: 1,
    type: "pointer",
    actor: inp.actor as string,
    channel: inp.channel as string,
    created: inp.created as number,
    ref: { hash: inp.hash as string, locators: [] },
    ext: { pad: "a".repeat(inp.pad_len as number) },
    nonce: String(inp.nonce),
  };
}

function deepU(inp: Record<string, unknown>): { [k: string]: JsonVal } {
  let inner: JsonVal = 1;
  for (let i = 0; i < (inp.depth as number); i++) {
    inner = { a: inner };
  }
  return {
    v: 1,
    type: "pointer",
    actor: inp.actor as string,
    channel: inp.channel as string,
    created: inp.created as number,
    ref: { hash: inp.hash as string, locators: [] },
    ext: { deep: inner },
    nonce: String(inp.nonce),
  };
}

function hexToBytes(h: string): Uint8Array {
  return Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
}

function runCase(c: Case): [boolean, string] {
  const want = c.want ?? {};
  const reasons = new Set((want.reasons as string[] | undefined) ?? []);
  const inp = c.input;
  const fail = (m: string): [boolean, string] => [false, `${c.id} FAIL ${m}`];
  try {
    if (c.class === "full-assertion") {
      const info = validate(new TextEncoder().encode(inp.utf8 as string));
      if (c.expect !== "valid") return fail(`expected ${c.expect}`);
      for (const k of ["id", "units", "target_hex", "jcs", "sig"] as const) {
        if (k in want && (info as Record<string, unknown>)[k] !== want[k]) return fail(`${k} mismatch`);
      }
      return [true, `${c.id} PASS`];
    }
    if (c.class === "json-input") {
      scanUtf8(new TextEncoder().encode(inp.utf8 as string));
      if (c.expect === "invalid") return fail("json-input accepted");
      return [true, `${c.id} PASS`];
    }
    if (c.class === "schema") {
      const obj = scanUtf8(new TextEncoder().encode(inp.utf8 as string));
      if (obj === null || typeof obj !== "object" || Array.isArray(obj)) throw new Fail("schema", "schema");
      const u = Object.hasOwn(obj, "id") || Object.hasOwn(obj, "sig") ? stripEnvelope(obj) : obj;
      schemaOk(u);
      if (c.expect === "invalid") return fail("schema accepted");
      return [true, `${c.id} PASS`];
    }
    if (c.class === "jcs") {
      const obj = scanUtf8(new TextEncoder().encode(inp.utf8 as string));
      const bytes = jcsBytes(obj);
      if (want.jcs_hex && Buffer.from(bytes).toString("hex") !== want.jcs_hex) {
        return fail(`jcs hex ${Buffer.from(bytes).toString("hex")}`);
      }
      if (want.jcs && new TextDecoder().decode(bytes) !== want.jcs) return fail("jcs mismatch");
      if (want.id && shaId(bytes).id !== want.id) return fail("id mismatch");
      return [true, `${c.id} PASS`];
    }
    if (c.class === "length") {
      const u =
        inp.kind === "construct-pad"
          ? padU(inp)
          : inp.kind === "construct-depth"
            ? deepU(inp)
            : (() => {
              const obj = scanUtf8(new TextEncoder().encode(inp.utf8 as string));
              if (obj === null || typeof obj !== "object" || Array.isArray(obj)) throw new Fail("schema", "schema");
              const body = Object.hasOwn(obj, "id") || Object.hasOwn(obj, "sig") ? stripEnvelope(obj) : obj;
              schemaOk(body);
              return body;
            })();
      const bytes = jcsBytes(u);
      if (typeof want.jcs_bytes === "number" && bytes.length !== want.jcs_bytes) {
        return fail(`jcs_bytes ${bytes.length}`);
      }
      if (c.expect === "invalid") {
        if (bytes.length > 1048576) throw new Fail("length", "jcs-too-large");
        schemaOk(u);
        return fail("length accepted");
      }
      schemaOk(u);
      if (typeof want.units === "number" && unitsOf(u, bytes.length) !== want.units) {
        return fail(`units ${unitsOf(u, bytes.length)}`);
      }
      return [true, `${c.id} PASS`];
    }
    if (c.class === "work") {
      const units = inp.units as number;
      const h = BigInt("0x" + (inp.H_hex as string));
      const ok = workAccepts(h, units);
      if (want.target_hex && hex64(targetOf(units)) !== want.target_hex) return fail("target");
      if (ok !== Boolean(want.accept ?? c.expect === "valid")) return fail(`accept=${ok}`);
      return [true, `${c.id} PASS`];
    }
    if (c.class === "spp-ed25519-1") {
      const ok = verifySppEd25519(hexToBytes(inp.A as string), hexToBytes(inp.sig as string), hexToBytes(inp.D as string));
      if (c.expect === "invalid" && ok) return fail("signature accepted");
      if (c.expect === "valid" && !ok) return fail("signature rejected");
      return [true, `${c.id} PASS`];
    }
    return fail(`unknown class ${c.class}`);
  } catch (e) {
    if (e instanceof ScanError) {
      if (c.expect === "invalid" && (reasons.size === 0 || reasons.has(e.reason))) return [true, `${c.id} PASS`];
      return fail(`json-input ${e.reason}`);
    }
    if (e instanceof Unsupported) {
      if (c.expect === "unsupported" && (reasons.size === 0 || reasons.has(e.reason))) return [true, `${c.id} PASS`];
      return fail(`unsupported ${e.reason}`);
    }
    if (e instanceof Fail) {
      if (c.expect === "invalid" && (reasons.size === 0 || reasons.has(e.reason))) return [true, `${c.id} PASS`];
      return fail(`${e.stage}:${e.reason}`);
    }
    return fail(String(e));
  }
}

function verdict(bytes: Uint8Array): Record<string, unknown> {
  try {
    const info = validate(bytes);
    return { status: "VALID", id: info.id, units: info.units, target_hex: info.target_hex };
  } catch (e) {
    if (e instanceof Unsupported) return { status: "UNSUPPORTED", stage: e.stage, reason: e.reason };
    if (e instanceof Fail) return { status: "INVALID", stage: e.stage, reason: e.reason };
    // Internal failure is not a validity claim; isolate it per record.
    return { status: "ERROR", stage: "internal", reason: e instanceof Error ? e.name : String(e) };
  }
}

function diagnostic(bytes: Uint8Array): string {
  const lines: string[] = [];
  const add = (label: string, value: unknown) => lines.push(`${label}: ${value}`);

  let obj: { [k: string]: JsonVal };
  try {
    obj = scanObject(bytes);
  } catch (e) {
    const reason = e instanceof ScanError ? e.reason : String(e);
    add("status", "INVALID"); add("stage", "json-input"); add("reason", reason);
    return lines.join("\n") + "\n";
  }

  try {
    if (Object.hasOwn(obj, "v") && isFiniteNumber(obj.v) && obj.v !== 1) throw new Unsupported("version", "unknown-v");

    const u = stripEnvelope(obj);
    add("v", obj.v);
    add("type", u.type);
    add("actor", u.actor);
    add("created", u.created);
    add("nonce", u.nonce);

    schemaOk(u);

    const jb = jcsBytes(u);
    add("JCS(U)", new TextDecoder().decode(jb));
    add("canonical_body_bytes", jb.length);

    if (jb.length > 1048576) throw new Fail("length", "jcs-too-large");

    const { id, d } = shaId(jb);
    add("D", [...d].map((b) => b.toString(16).padStart(2, "0")).join(""));
    add("id_computed", id);
    add("id_received", obj.id);

    let h = 0n;
    for (const b of d) h = (h << 8n) | BigInt(b);
    add("H", h.toString(16).padStart(64, "0"));

    if (typeof obj.id !== "string") throw new Fail("identifier", "missing-id");
    if (obj.id !== id) throw new Fail("identity", "id-mismatch");

    const t = u.type;
    let loc = 0, parents = 0, cdc = 0;
    if (t === "pointer") {
      const ref = u.ref as { locators: string[] };
      loc = ref.locators.length;
      parents = Array.isArray(u.parents) ? u.parents.length : 0;
    } else if (t === "channel") {
      cdc = 16;
      if (u.descriptor && typeof u.descriptor === "object" && !Array.isArray(u.descriptor)) {
        loc = (u.descriptor.locators as string[]).length;
      }
    }
    add("locator_count", loc);
    add("parent_count", parents);
    add("channel_description_cost", cdc);

    const units = unitsOf(u, jb.length);
    const target = targetOf(units);
    add("units", units);
    add("Wrequired", units * 65536);
    add("target", hex64(target));

    const powOk = workAccepts(h, units);
    add("PoW", powOk ? "PASS" : "FAIL");
    if (!powOk) throw new Fail("work", "insufficient-work");

    if (typeof obj.sig !== "string" || !/^[0-9a-f]{128}$/.test(obj.sig as string))
      throw new Fail("signature", "signature");
    const actor = Uint8Array.from(((u.actor as string).slice(8).match(/../g)!).map((x) => parseInt(x, 16)));
    const sig = Uint8Array.from(((obj.sig as string).match(/../g)!).map((x) => parseInt(x, 16)));
    const sigOk = verifySppEd25519(actor, sig, d);
    add("signature", sigOk ? "PASS" : "FAIL");
    if (!sigOk) throw new Fail("signature", "signature");

    add("status", "VALID");
    return lines.join("\n") + "\n";
  } catch (e) {
    if (e instanceof Unsupported) {
      add("status", "UNSUPPORTED"); add("stage", e.stage); add("reason", e.reason);
    } else if (e instanceof Fail) {
      add("status", "INVALID"); add("stage", e.stage); add("reason", e.reason);
    } else {
      add("status", "ERROR"); add("reason", String(e));
    }
    return lines.join("\n") + "\n";
  }
}

function isFiniteNumber(n: JsonVal): n is number {
  return typeof n === "number" && Number.isFinite(n);
}

function main(): number {
  const args = process.argv.slice(2);
  if (args[0] === "--batch" && args[1]) {
    const items = JSON.parse(readFileSync(args[1], "utf8")) as { name: string; utf8: string }[];
    for (const item of items) {
      const rec = verdict(new TextEncoder().encode(item.utf8));
      rec.name = item.name;
      console.log(JSON.stringify(rec));
    }
    return 0;
  }
  if (args[0] === "--jcs-batch" && args[1]) {
    const items = JSON.parse(readFileSync(args[1], "utf8")) as { name: string; utf8: string }[];
    for (const item of items) {
      try {
        const obj = scanUtf8(new TextEncoder().encode(item.utf8));
        const bytes = jcsBytes(obj);
        console.log(JSON.stringify({ name: item.name, status: "OK", jcs_hex: Buffer.from(bytes).toString("hex") }));
      } catch (e) {
        const reason = e instanceof ScanError ? e.reason : e instanceof Fail ? e.reason : e instanceof Error ? e.name : String(e);
        console.log(JSON.stringify({ name: item.name, status: "INVALID", reason }));
      }
    }
    return 0;
  }
  if (args[0] === "--ed-batch" && args[1]) {
    const items = JSON.parse(readFileSync(args[1], "utf8")) as {
      name: string;
      A: string;
      sig: string;
      D: string;
    }[];
    for (const item of items) {
      const ok = verifySppEd25519(hexToBytes(item.A), hexToBytes(item.sig), hexToBytes(item.D));
      console.log(JSON.stringify({ name: item.name, status: ok ? "VALID" : "INVALID" }));
    }
    return 0;
  }
  if (args[0] === "--suite" && args[1]) {
    const suite = JSON.parse(readFileSync(args[1], "utf8")) as { cases: Case[] };
    let failed = 0;
    for (const c of suite.cases) {
      const [ok, line] = runCase(c);
      console.log(line);
      if (!ok) failed++;
    }
    console.log(`${suite.cases.length - failed}/${suite.cases.length} passed`);
    return failed ? 1 : 0;
  }
  if (args[0] === "--diagnostic" && args[1]) {
    const bytes = readFileSync(args[1]);
    process.stdout.write(diagnostic(bytes));
    return 0;
  }
  if (args.length !== 1 || args[0] === "-h" || args[0] === "--help") {
    console.error("usage: spp-verify assertion.json | --suite suite.json | --diagnostic assertion.json");
    return 3;
  }
  try {
    const info = validate(readFileSync(args[0]));
    process.stdout.write(validText(info));
    return 0;
  } catch (e) {
    if (e instanceof Fail) {
      process.stdout.write(invalidText(e));
      return e instanceof Unsupported ? 2 : 1;
    }
    throw e;
  }
}

process.exit(main());

