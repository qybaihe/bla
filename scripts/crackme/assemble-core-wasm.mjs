#!/usr/bin/env node
/** Rebuild challenge/v6/src/core.wasm (no wabt required). */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function uleb(v) {
  const out = [];
  v >>>= 0;
  do {
    let b = v & 0x7f;
    v >>>= 7;
    if (v) b |= 0x80;
    out.push(b);
  } while (v);
  return out;
}
function section(id, body) {
  return [id, ...uleb(body.length), ...body];
}
function name(s) {
  const u = [...Buffer.from(s)];
  return [...uleb(u.length), ...u];
}
function iconst(v) {
  v |= 0;
  const out = [0x41];
  while (true) {
    let b = v & 0x7f;
    v >>= 7;
    if ((v === 0 && (b & 0x40) === 0) || (v === -1 && (b & 0x40) !== 0)) {
      out.push(b);
      break;
    }
    out.push(b | 0x80);
  }
  return out;
}

const typeSec = section(1, [2, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 1, 0x7f, 1, 0x7f]);
const funcSec = section(3, [2, 0, 1]);
const exportSec = section(7, [2, ...name("mix"), 0x00, 0, ...name("seal"), 0x00, 1]);
const mixCode = [0, 0x20, 0, ...iconst(0x9e3779b1 | 0), 0x6c, 0x20, 1, ...iconst(0x85ebca6b | 0), 0x6c, 0x73, 0x20, 0, 0x20, 1, 0x6a, 0x73, ...iconst(13), 0x77, 0x0b];
const mixFunc = [...uleb(mixCode.length), ...mixCode];
const sealCode = [0, 0x20, 0, ...iconst(0xc0ffee01 | 0), 0x10, 0, ...iconst(0xbadc0ffe | 0), 0x10, 0, 0x0b];
const sealFunc = [...uleb(sealCode.length), ...sealCode];
const codeSec = section(10, [2, ...mixFunc, ...sealFunc]);
const bytes = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0, ...typeSec, ...funcSec, ...exportSec, ...codeSec]);
if (!WebAssembly.validate(bytes)) throw new Error("assembled wasm invalid");
const out = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "challenge", "v6", "src", "core.wasm");
writeFileSync(out, Buffer.from(bytes));
console.log("wrote", out, bytes.length);
