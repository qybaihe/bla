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

  it("panel-derive: every recorded finding carries a truthful refuseMessage", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pg-panel-msg-"));
    writeFileSync(
      join(dir, "local-only.js"),
      `function deriveLocal(k) { return k; }\nconsole.log(deriveLocal("x"));\n`,
    );
    writeFileSync(
      join(dir, "stable-only.js"),
      `globalThis.__vaultPanelDerive_r3 = (s) => s;\nexport function use(sb) { return sb.__vaultPanelDerive_r3("x"); }\n`,
    );
    const report = scanPackagingGates({ directory: dir, intensity: "bankrupt" });
    const panelFindings = report.findings.filter((f) => f.gate === "panel-derive");
    expect(panelFindings.length).toBeGreaterThanOrEqual(2);

    // Recorded panel-derive findings must all carry remediation text.
    for (const f of panelFindings) {
      expect(f.refuseMessage, `missing refuseMessage for ${f.path}`).toBeTruthy();
    }

    // Local-only and stable-only findings are rewrite findings, not blockers:
    // they must not claim a refusal that filterBlockingFindings will not honor.
    const localOnly = panelFindings.find((f) =>
      f.relativePath.includes("local-only"),
    )!;
    expect(localOnly.shouldRefuseBankrupt).toBe(false);
    expect(localOnly.refuseMessage).not.toContain("Refusing bankrupt");
    expect(localOnly.refuseMessage).toContain("deriveLocal");

    const stableOnly = panelFindings.find((f) =>
      f.relativePath.includes("stable-only"),
    )!;
    expect(stableOnly.shouldRefuseBankrupt).toBe(false);
    expect(stableOnly.refuseMessage).not.toContain("Refusing bankrupt");
    expect(stableOnly.refuseMessage).toContain("__vaultPanelDerive_r3");
  });

  it("panel-derive: offline oracle keeps its refusal message", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-pg-panel-oracle-"));
    writeFileSync(
      join(dir, "oracle.js"),
      `function deriveLocal(k) { return k; }\nconst panelTokenSha256 = "a".repeat(64);\nif (panelTokenSha256) console.log(deriveLocal("x"));\n`,
    );
    const report = scanPackagingGates({ directory: dir, intensity: "bankrupt" });
    const oracle = report.findings.find(
      (f) => f.gate === "panel-derive" && f.shouldRefuseBankrupt,
    );
    expect(oracle).toBeDefined();
    expect(oracle!.refuseMessage).toContain("Refusing bankrupt");
    expect(oracle!.refuseMessage).toContain("panel offline oracle");
  });
});
