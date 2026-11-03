import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  lintWasmParamCarrierBuffer,
  lintWasmParamCarrierFile,
  discoverAndLintWasmParamCarriers,
  buildTestWasmWithParamCarrier,
  wasmParamCarrierRefuseMessage,
  intensityEnforcesWasmParamRefusal,
  WASM_PARAM_CARRIER_SCHEMA,
} from "../src/engine/wasm-param-carrier-lint.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("wasm-param-carrier lint (red-blue round-3)", () => {
  it("flags R3PARM/R3CIPH clear carrier layout as error + refuse", () => {
    const buf = buildTestWasmWithParamCarrier({});
    const report = lintWasmParamCarrierBuffer(buf, { path: "/tmp/core.wasm" });
    expect(report.schema).toBe(WASM_PARAM_CARRIER_SCHEMA);
    expect(report.looksExposed).toBe(true);
    expect(report.shouldRefuseBankrupt).toBe(true);
    const ids = report.findings.map((f) => f.id);
    expect(ids).toContain("clear-wasm-param-magic");
    expect(ids).toContain("clear-wasm-cipher-carrier");
    expect(report.findings.some((f) => f.magic === "R3PARM")).toBe(true);
    expect(report.findings.some((f) => f.magic === "R3CIPH")).toBe(true);
    expect(intensityEnforcesWasmParamRefusal("bankrupt")).toBe(true);
    expect(intensityEnforcesWasmParamRefusal("balanced")).toBe(false);
    expect(wasmParamCarrierRefuseMessage(report, "/tmp/core.wasm")).toMatch(
      /allowWasmClearParamCarriers/,
    );
  });

  it("does not flag a minimal clean WASM module", () => {
    const clean = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    const report = lintWasmParamCarrierBuffer(clean);
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.findings).toHaveLength(0);
  });

  it("does not flag English prose containing SEAL as a substring", () => {
    const header = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    const prose = Buffer.from("under SEAL of approval for PARM farm sales", "utf8");
    const report = lintWasmParamCarrierBuffer(Buffer.concat([header, prose]));
    expect(report.findings).toHaveLength(0);
  });

  it("discovers .wasm under a tree and lints the round-3-shaped carrier", () => {
    const root = mkdtempSync(join(tmpdir(), "bla-wasm-parm-"));
    dirs.push(root);
    mkdirSync(join(root, "dist"));
    writeFileSync(join(root, "dist", "core.wasm"), buildTestWasmWithParamCarrier({}));
    writeFileSync(join(root, "dist", "app.js"), "export const x = 1;\n", "utf8");
    const reports = discoverAndLintWasmParamCarriers(root);
    expect(reports.length).toBeGreaterThanOrEqual(1);
    expect(reports.some((r) => r.shouldRefuseBankrupt)).toBe(true);
    const fileReport = lintWasmParamCarrierFile(join(root, "dist", "core.wasm"));
    expect(fileReport.shouldRefuseBankrupt).toBe(true);
  });

  it("flags the round-3 hardened fixture when present", () => {
    const fixture = "/workspace/bla-redblue/round-3/hardened/core.wasm";
    try {
      const report = lintWasmParamCarrierFile(fixture);
      expect(report.shouldRefuseBankrupt).toBe(true);
      expect(report.findings.some((f) => f.magic === "R3PARM")).toBe(true);
    } catch (err) {
      // Fixture may be absent in CI clones — skip rather than fail the gate.
      if (err instanceof Error && /not found/.test(err.message)) return;
      throw err;
    }
  });
});
