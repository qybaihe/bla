import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { protectTarget } from "../src/engine/protector.js";
import { hardenProject } from "../src/engine/harden.js";
import { buildTestWasmWithParamCarrier } from "../src/engine/wasm-param-carrier-lint.js";
import { rewriteStablePanelDeriveSymbols } from "../src/engine/panel-derive-abi-lint.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("red-blue round-3 residual gates", () => {
  it("bankrupt protect refuses clear WASM param carriers unless allowed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-wasm-gate-"));
    dirs.push(dir);
    const input = join(dir, "core.wasm");
    const output = join(dir, "core.out.wasm");
    writeFileSync(input, buildTestWasmWithParamCarrier({}));
    expect(() =>
      protectTarget({
        inputPath: input,
        outputPath: output,
        intensity: "bankrupt",
        seed: "r3-wasm-gate",
      }),
    ).toThrow(/allowWasmClearParamCarriers|clear WASM param/);
    const ok = protectTarget({
      inputPath: input,
      outputPath: output,
      intensity: "bankrupt",
      seed: "r3-wasm-gate",
      allowWasmClearParamCarriers: true,
    });
    expect(ok.detectedFormat).toBe("wasm");
  });

  it("bankrupt harden refuses project trees with clear WASM carriers", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-wasm-harden-"));
    dirs.push(dir);
    mkdirSync(join(dir, "dist"));
    writeFileSync(join(dir, "dist", "core.wasm"), buildTestWasmWithParamCarrier({}));
    writeFileSync(join(dir, "dist", "app.js"), "export const ok = 1;\n", "utf8");
    const report = hardenProject({
      directory: dir,
      intensity: "bankrupt",
      seed: "r3-harden-wasm",
      dryRun: true,
    });
    expect(report.overallSuccess).toBe(false);
    expect(report.artifacts.some((a) => /clear WASM param/i.test(a.error ?? ""))).toBe(true);
  });

  it("bankrupt protect rewrites stable panel derive ABI across JS seed roots", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-panel-rw-"));
    dirs.push(dir);
    const input = join(dir, "panel.js");
    const output = join(dir, "panel.out.js");
    writeFileSync(
      input,
      `globalThis.__vaultPanelDerive_r3 = (x) => x;\nexport const poke = (sb) => sb.__vaultPanelDerive_r3(1);\n`,
      "utf8",
    );
    const res = protectTarget({
      inputPath: input,
      outputPath: output,
      intensity: "bankrupt",
      seed: "r3-panel-seed",
      honeySourceMaps: false,
    });
    const out = readFileSync(res.outputPath, "utf8");
    expect(out).not.toContain("__vaultPanelDerive_r3");
    const expected = rewriteStablePanelDeriveSymbols(
      `globalThis.__vaultPanelDerive_r3 = (x) => x;`,
      "r3-panel-seed",
    ).renames[0]!.to;
    expect(out).toContain(expected);
  });

  it("harden recommends self_seal for multi-artifact trees without enabling it", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-selfseal-rec-"));
    dirs.push(dir);
    mkdirSync(join(dir, "dist"));
    // Clean minimal wasm (no param magic) + two JS files
    writeFileSync(
      join(dir, "dist", "core.wasm"),
      Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
    );
    writeFileSync(join(dir, "dist", "a.js"), "export const a = 1;\n", "utf8");
    writeFileSync(join(dir, "dist", "b.js"), "export const b = 2;\n", "utf8");
    const report = hardenProject({
      directory: dir,
      intensity: "bankrupt",
      seed: "r3-selfseal-rec",
      dryRun: true,
    });
    expect(report.selfSeal).toBe(false);
    expect(report.selfSealRecommended).toBe(true);
    expect(report.selfSealRecommendation).toMatch(/self_seal/);
  });

  it("single-file harden does not recommend self_seal", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-selfseal-single-"));
    dirs.push(dir);
    mkdirSync(join(dir, "dist"));
    writeFileSync(join(dir, "dist", "only.js"), "export const a = 1;\n", "utf8");
    const report = hardenProject({
      directory: dir,
      intensity: "bankrupt",
      seed: "r3-selfseal-single",
      dryRun: true,
    });
    expect(report.selfSealRecommended).toBe(false);
  });
});
