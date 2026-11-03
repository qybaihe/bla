import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  PACKAGING_GATES_SCHEMA,
  evaluateHardenProjectPackagingBlocks,
  formatPackagingGatesReport,
  scanPackagingGates,
} from "../src/engine/packaging-gates.js";
import { buildTestWasmWithXorMaskSidecar } from "../src/engine/wasm-xor-mask-sidecar-lint.js";

describe("packaging-gates (unified R1–R7 scan)", () => {
  it("reports clean on an empty project tree", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pg-clean-"));
    const report = scanPackagingGates({ directory: dir, intensity: "bankrupt" });
    expect(report.schema).toBe(PACKAGING_GATES_SCHEMA);
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.findings).toEqual([]);
    expect(report.honestyNote.length).toBeGreaterThan(20);
    expect(formatPackagingGatesReport(report)).toContain("no findings");
  });

  it("refuses bankrupt when a WASM XOR-mask sidecar is present", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pg-xor-"));
    writeFileSync(join(dir, "core.wasm"), buildTestWasmWithXorMaskSidecar());
    const report = scanPackagingGates({ directory: dir, intensity: "bankrupt" });
    expect(report.shouldRefuseBankrupt).toBe(true);
    expect(report.blocking.some((b) => b.gate === "wasm-xor-mask-sidecar")).toBe(
      true,
    );
    const blocks = evaluateHardenProjectPackagingBlocks({
      directory: dir,
      intensity: "bankrupt",
    });
    expect(blocks.blockingWasmXorMask.length).toBeGreaterThan(0);
  });

  it("allow_wasm_xor_mask_sidecar clears project-level refuse", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pg-allow-"));
    writeFileSync(join(dir, "core.wasm"), buildTestWasmWithXorMaskSidecar());
    const blocks = evaluateHardenProjectPackagingBlocks({
      directory: dir,
      intensity: "bankrupt",
      allowWasmXorMaskSidecar: true,
    });
    expect(blocks.blockingWasmXorMask).toEqual([]);
  });

  it("surfaces lane-independence when includeProtectTimeGates", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pg-lane-"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, "gate.js"),
      `
const lanes = [0x41, 0x42, 0x43, 0x44, 0x45];
function check(key) {
  return key.split("").every((ch, i) => ch.charCodeAt(0) === lanes[i]);
}
module.exports = { check };
`,
    );
    const report = scanPackagingGates({
      directory: dir,
      intensity: "bankrupt",
      includeProtectTimeGates: true,
    });
    expect(report.findings.some((f) => f.gate === "lane-independence")).toBe(true);
    expect(report.shouldRefuseBankrupt).toBe(true);
  });
});
