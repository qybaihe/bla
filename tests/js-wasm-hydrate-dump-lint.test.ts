import { describe, expect, it } from "vitest";
import {
  buildTestJsWasmHydrateDumpFootgun,
  intensityEnforcesJsWasmHydrateDumpRefusal,
  JS_WASM_HYDRATE_DUMP_SCHEMA,
  lintJsWasmHydrateDumpSource,
} from "../src/engine/js-wasm-hydrate-dump-lint.js";
import { readFileSync } from "node:fs";

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

  it("flags the round-5 cleartext license fixture shape", () => {
    const path = "/workspace/bla-redblue/round-5/target/license.cjs";
    const src = readFileSync(path, "utf8");
    const report = lintJsWasmHydrateDumpSource(src, { path });
    expect(report.shouldRefuseBankrupt).toBe(true);
  });
});
