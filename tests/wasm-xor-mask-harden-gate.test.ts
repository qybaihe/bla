import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { protectTarget } from "../src/engine/protector.js";
import { hardenProject } from "../src/engine/harden.js";
import { buildTestWasmWithXorMaskSidecar } from "../src/engine/wasm-xor-mask-sidecar-lint.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("red-blue round-6 WASM XOR-mask sidecar gate", () => {
  it("bankrupt protect refuses XOR-mask sidecar unless allowed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-xor-gate-"));
    dirs.push(dir);
    const input = join(dir, "core.wasm");
    const output = join(dir, "core.out.wasm");
    writeFileSync(input, buildTestWasmWithXorMaskSidecar({}));
    expect(() =>
      protectTarget({
        inputPath: input,
        outputPath: output,
        intensity: "bankrupt",
        seed: "r6-xor-gate",
      }),
    ).toThrow(/allowWasmXorMaskSidecar|XOR-mask sidecar/);
    const ok = protectTarget({
      inputPath: input,
      outputPath: output,
      intensity: "bankrupt",
      seed: "r6-xor-gate",
      allowWasmXorMaskSidecar: true,
    });
    expect(ok.detectedFormat).toBe("wasm");
  });

  it("bankrupt harden refuses project trees with XOR-mask sidecar WASM", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-xor-harden-"));
    dirs.push(dir);
    mkdirSync(join(dir, "dist"));
    writeFileSync(join(dir, "dist", "core.wasm"), buildTestWasmWithXorMaskSidecar({}));
    writeFileSync(join(dir, "dist", "app.js"), "export const ok = 1;\n", "utf8");
    const report = hardenProject({
      directory: dir,
      intensity: "bankrupt",
      seed: "r6-harden-xor",
      dryRun: true,
    });
    expect(report.overallSuccess).toBe(false);
    expect(report.artifacts.some((a) => /XOR-mask sidecar/i.test(a.error ?? ""))).toBe(true);
  });
});
