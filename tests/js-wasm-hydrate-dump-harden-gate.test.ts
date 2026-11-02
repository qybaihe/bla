import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { protectTarget } from "../src/engine/protector.js";
import { hardenProject } from "../src/engine/harden.js";
import { buildTestJsWasmHydrateDumpFootgun } from "../src/engine/js-wasm-hydrate-dump-lint.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("red-blue round-5 JS WASM hydrate-dump gates", () => {
  it("bankrupt protect refuses hydrate dump footgun unless allowed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-hydrate-gate-"));
    dirs.push(dir);
    const input = join(dir, "license.cjs");
    const output = join(dir, "license.out.cjs");
    writeFileSync(input, buildTestJsWasmHydrateDumpFootgun({}), "utf8");
    expect(() =>
      protectTarget({
        inputPath: input,
        outputPath: output,
        intensity: "bankrupt",
        seed: "r5-hydrate-gate",
        honeySourceMaps: false,
      }),
    ).toThrow(/allowJsWasmHydrateDump|hydrate param-dump/);
    const ok = protectTarget({
      inputPath: input,
      outputPath: output,
      intensity: "bankrupt",
      seed: "r5-hydrate-gate",
      honeySourceMaps: false,
      allowJsWasmHydrateDump: true,
    });
    expect(ok.detectedFormat).toBe("javascript");
  });

  it("bankrupt harden refuses project trees with hydrate dump footguns", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-hydrate-harden-"));
    dirs.push(dir);
    mkdirSync(join(dir, "dist"));
    writeFileSync(join(dir, "dist", "license.cjs"), buildTestJsWasmHydrateDumpFootgun({}), "utf8");
    writeFileSync(
      join(dir, "dist", "core.wasm"),
      Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
    );
    const report = hardenProject({
      directory: dir,
      intensity: "bankrupt",
      seed: "r5-harden-hydrate",
      dryRun: true,
    });
    expect(report.overallSuccess).toBe(false);
    expect(
      report.artifacts.some((a) => /hydrate|allowJsWasmHydrateDump/i.test(a.error ?? "")),
    ).toBe(true);
  });
});
