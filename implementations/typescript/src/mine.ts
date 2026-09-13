import { readFileSync } from "node:fs";
import { schemaOk, stripEnvelope } from "./check.ts";
import { signAssertion } from "./curve.ts";
import { jcsBytes } from "./canon.ts";
import { sha256 } from "@noble/hashes/sha256";
import { scanObject } from "./scan.ts";
import type { JsonVal } from "./scan.ts";

const TEST_SK = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const MAXH = (1n << 256n) - 1n;

function hex(h: string): Uint8Array {
  return Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
}

function target(units: number): bigint {
  return MAXH / (BigInt(units) * 65536n);
}

function units(u: { [k: string]: JsonVal }, n: number): number {
  const t = u.type;
  const loc =
    t === "pointer"
      ? ((u.ref as { locators: string[] }).locators.length)
      : t === "channel" && u.descriptor
        ? ((u.descriptor as { locators: string[] }).locators.length)
        : 0;
  const parents = Array.isArray(u.parents) ? u.parents.length : 0;
  const extra = t === "channel" ? 16 : 0;
  return 1 + Math.ceil(n / 1024) + loc + parents + extra;
}

const args = process.argv.slice(2);
if (args.length < 1) {
  console.error("usage: mine.ts unsigned.json");
  process.exit(3);
}
const u = scanObject(readFileSync(args[0]));
const body = stripEnvelope(u);
let nonce = 0;
for (;;) {
  const cand = { ...body, nonce: nonce === 0 ? "0" : String(nonce) };
  schemaOk(cand);
  const jb = jcsBytes(cand);
  const d = sha256(jb);
  let h = 0n;
  for (const b of d) h = (h << 8n) | BigInt(b);
  const un = units(cand, jb.length);
  if (h <= target(un)) {
    const sig = signAssertion(TEST_SK, d);
    const id = `sha256:${[...d].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
    const env = { ...cand, id, sig: [...sig].map((b) => b.toString(16).padStart(2, "0")).join("") };
    process.stdout.write(JSON.stringify(env) + "\n");
    break;
  }
  nonce++;
}
