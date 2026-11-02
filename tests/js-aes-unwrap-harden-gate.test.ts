import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { protectTarget } from "../src/engine/protector.js";
import { hardenProject } from "../src/engine/harden.js";
import { buildTestJsAesUnwrapFootgun } from "../src/engine/js-aes-unwrap-lint.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("red-blue round-4 JS AES unwrap gates", () => {
  it("bankrupt protect refuses JS AES unwrap footgun unless allowed", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-aes-gate-"));
    dirs.push(dir);
    const input = join(dir, "license.cjs");
    const output = join(dir, "license.out.cjs");
    writeFileSync(input, buildTestJsAesUnwrapFootgun({}), "utf8");
    expect(() =>
      protectTarget({
        inputPath: input,
        outputPath: output,
        intensity: "bankrupt",
        seed: "r4-aes-gate",
        honeySourceMaps: false,
      }),
    ).toThrow(/allowJsAesUnwrap|AES sealed-blob unwrap/);
    const ok = protectTarget({
      inputPath: input,
      outputPath: output,
      intensity: "bankrupt",
      seed: "r4-aes-gate",
      honeySourceMaps: false,
      allowJsAesUnwrap: true,
    });
    expect(ok.detectedFormat).toBe("javascript");
  });

  it("bankrupt harden refuses project trees with JS AES unwrap footguns", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-aes-harden-"));
    dirs.push(dir);
    mkdirSync(join(dir, "dist"));
    writeFileSync(join(dir, "dist", "license.cjs"), buildTestJsAesUnwrapFootgun({}), "utf8");
    writeFileSync(
      join(dir, "dist", "core.wasm"),
      Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
    );
    const report = hardenProject({
      directory: dir,
      intensity: "bankrupt",
      seed: "r4-harden-aes",
      dryRun: true,
    });
    expect(report.overallSuccess).toBe(false);
    expect(report.artifacts.some((a) => /AES|allowJsAesUnwrap/i.test(a.error ?? ""))).toBe(true);
  });
});
