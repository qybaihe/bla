import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import {
  buildTestJsWasmHydrateDumpFootgun,
  intensityEnforcesJsWasmHydrateDumpRefusal,
  JS_WASM_HYDRATE_DUMP_SCHEMA,
  lintJsWasmHydrateDumpSource,
} from "../src/engine/js-wasm-hydrate-dump-lint.js";

/** R6-shaped host: arity-2 unlock in WASM; no salt/rounds/cipher layout dump. */
function buildUnlockInWasmHost(): string {
  return `
const fs = require("fs");
async function callUnlock(keyStr) {
  const bytes = fs.readFileSync("core.wasm");
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const exp = instance.exports;
  let memory = null;
  for (const v of Object.values(exp)) {
    if (v instanceof WebAssembly.Memory) { memory = v; break; }
  }
  let unlock = typeof exp.unlock === "function" && exp.unlock.length === 2 ? exp.unlock : null;
  if (!unlock) {
    for (const fn of Object.values(exp)) {
      if (typeof fn === "function" && fn.length === 2) { unlock = fn; break; }
    }
  }
  const u8 = new Uint8Array(memory.buffer);
  u8.set(Buffer.from(keyStr, "utf8"), 2048);
  const n = unlock(2048, 16) | 0;
  return Buffer.from(u8.subarray(4096, 4096 + n)).toString("utf8");
}
module.exports = { callUnlock };
`;
}

describe("js-wasm-hydrate-dump lint (red-blue round-5)", () => {
  it("flags R5-shaped memory.buffer + hydrate + salt/rounds/cipher as refuse", () => {
    const src = buildTestJsWasmHydrateDumpFootgun({});
    const report = lintJsWasmHydrateDumpSource(src, { path: "license.cjs" });
    expect(report.schema).toBe(JS_WASM_HYDRATE_DUMP_SCHEMA);
    expect(report.shouldRefuseBankrupt).toBe(true);
    expect(report.hasMemoryBufferRead).toBe(true);
    expect(report.hasHydrateCall).toBe(true);
    expect(report.hasParamLayoutDecode).toBe(true);
    expect(report.findings.some((f) => f.id === "js-wasm-hydrate-param-dump")).toBe(true);
    expect(intensityEnforcesJsWasmHydrateDumpRefusal("bankrupt")).toBe(true);
    expect(intensityEnforcesJsWasmHydrateDumpRefusal("maximum")).toBe(false);
  });

  it("does not refuse clean hashing code", () => {
    const src = `
      const crypto = require("crypto");
      function hash(s) {
        return crypto.createHash("sha256").update(s).digest("hex");
      }
      module.exports = { hash };
    `;
    const report = lintJsWasmHydrateDumpSource(src);
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.looksExposed).toBe(false);
  });

  it("warns on partial signals without full combo", () => {
    const noLayout = buildTestJsWasmHydrateDumpFootgun({ omitLayout: true });
    const report = lintJsWasmHydrateDumpSource(noLayout);
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.hasMemoryBufferRead).toBe(true);
  });

  it("does not refuse unlock-in-WASM host (R6 shape)", () => {
    const src = buildUnlockInWasmHost();
    const report = lintJsWasmHydrateDumpSource(src, { path: "license.cjs" });
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.hasParamLayoutDecode).toBe(false);
    expect(report.hasHydrateCall).toBe(false);
  });

  it("flags the round-5 cleartext license fixture when present", () => {
    const path = "/workspace/bla-redblue/round-5/target/license.cjs";
    if (!existsSync(path)) return; // optional dogfood fixture — absent on CI clones
    const src = readFileSync(path, "utf8");
    const report = lintJsWasmHydrateDumpSource(src, { path });
    expect(report.shouldRefuseBankrupt).toBe(true);
  });

  it("does not refuse the round-6 unlock-in-WASM license fixture when present", () => {
    const path = "/workspace/bla-redblue/round-6/target/license.cjs";
    if (!existsSync(path)) return;
    const src = readFileSync(path, "utf8");
    const report = lintJsWasmHydrateDumpSource(src, { path });
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.hasParamLayoutDecode).toBe(false);
    expect(report.hasHydrateCall).toBe(false);
  });
});
