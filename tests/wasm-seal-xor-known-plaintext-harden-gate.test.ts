import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { protectTarget } from "../src/engine/protector.js";
import { hardenProject } from "../src/engine/harden.js";
import { buildTestWasmWithSealXorKnownPlaintext } from "../src/engine/wasm-seal-xor-known-plaintext-lint.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("red-blue round-7 WASM seal.revision XOR known-plaintext gate", () => {
  it("bankrupt protect refuses seal.revision known-plaintext unless allowed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sealxor-gate-"));
    dirs.push(dir);
    const { wasm, seal } = buildTestWasmWithSealXorKnownPlaintext({});
    const input = join(dir, "core.wasm");
    const output = join(dir, "core.out.wasm");
    writeFileSync(input, wasm);
    writeFileSync(join(dir, "seal.json"), JSON.stringify(seal, null, 2));
    expect(() =>
      protectTarget({
        inputPath: input,
        outputPath: output,
        intensity: "bankrupt",
        seed: "r7-sealxor-gate",
      }),
    ).toThrow(/allowWasmSealXorKnownPlaintext|seal\.revision XOR known-plaintext/i);
    const ok = protectTarget({
      inputPath: input,
      outputPath: output,
      intensity: "bankrupt",
      seed: "r7-sealxor-gate",
      allowWasmSealXorKnownPlaintext: true,
    });
    expect(ok.detectedFormat).toBe("wasm");
  });

  it("bankrupt harden refuses project trees with seal.revision known-plaintext WASM", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sealxor-harden-"));
    dirs.push(dir);
    mkdirSync(join(dir, "dist"));
    const { wasm, seal } = buildTestWasmWithSealXorKnownPlaintext({});
    writeFileSync(join(dir, "dist", "core.wasm"), wasm);
    writeFileSync(join(dir, "dist", "seal.json"), JSON.stringify(seal, null, 2));
    writeFileSync(join(dir, "dist", "app.js"), "export const ok = 1;\n", "utf8");
    const report = hardenProject({
      directory: dir,
      intensity: "bankrupt",
      seed: "r7-harden-sealxor",
      dryRun: true,
    });
    expect(report.overallSuccess).toBe(false);
    expect(
      report.artifacts.some((a) => /seal\.revision XOR known-plaintext|allowWasmSealXorKnownPlaintext/i.test(a.error ?? "")),
    ).toBe(true);
  });
});
