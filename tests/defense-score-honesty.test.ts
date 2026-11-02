import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  applyDefenseScoreHonesty,
  collectDefenseScoreGaps,
  DEFENSE_SCORE_DISCLAIMER,
  formatDefenseScoreGapAnnotation,
} from "../src/engine/defense-score-honesty.js";
import { verifyTarget } from "../src/engine/verifier.js";
import { protectTarget } from "../src/engine/protector.js";
import { formatVerificationReport } from "../src/ui/reporter.js";

describe("Issue #40.6: defenseScore honesty", () => {
  it("exposes a fixed disclaimer that score ≠ preimage hardness", () => {
    expect(DEFENSE_SCORE_DISCLAIMER).toMatch(/not a preimage-hardness claim/i);
  });

  it("annotates wasm without export rename and soft-caps above 88", () => {
    const honesty = applyDefenseScoreHonesty(97, {
      detectedFormat: "wasm",
      wasmExportRenameApplied: false,
      selfSealEnabled: true,
    });
    expect(honesty.gaps.map((g) => g.id)).toContain("wasm-export-rename-pending");
    expect(honesty.rawScore).toBe(97);
    expect(honesty.cappedScore).toBe(88);
    expect(honesty.appliedCap).toBe(88);
    expect(formatDefenseScoreGapAnnotation(honesty)).toMatch(/Honesty cap applied/);
  });

  it("annotates JS without self-seal and soft-caps above 92", () => {
    const honesty = applyDefenseScoreHonesty(99, {
      detectedFormat: "javascript",
      selfSealEnabled: false,
    });
    expect(honesty.gaps.map((g) => g.id)).toContain("self-seal-not-enabled");
    expect(honesty.cappedScore).toBe(92);
  });

  it("does not raise a low raw score when gaps apply", () => {
    const honesty = applyDefenseScoreHonesty(40, {
      detectedFormat: "wasm",
      wasmExportRenameApplied: false,
    });
    expect(honesty.cappedScore).toBe(40);
    expect(honesty.appliedCap).toBeNull();
  });

  it("numeric-template leak flag soft-caps at 90", () => {
    const gaps = collectDefenseScoreGaps({
      detectedFormat: "directory",
      numericTemplateLeakKnown: true,
    });
    expect(gaps.some((g) => g.id === "numeric-template-hygiene-partial")).toBe(true);
    const honesty = applyDefenseScoreHonesty(95, {
      detectedFormat: "directory",
      numericTemplateLeakKnown: true,
    });
    expect(honesty.cappedScore).toBe(90);
  });

  it("verifyTarget attaches honesty fields and soft-caps wasm by default", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-honesty-"));
    try {
      // Minimal valid empty wasm module (magic + version)
      const wasm = Buffer.from([
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      ]);
      const input = join(dir, "mod.wasm");
      writeFileSync(input, wasm);
      const protectedRes = protectTarget({
        inputPath: input,
        intensity: "balanced",
        seed: "honesty-wasm-1",
      });
      const report = verifyTarget(protectedRes.outputPath);
      expect(report.defenseScoreDisclaimer).toBe(DEFENSE_SCORE_DISCLAIMER);
      expect(report.defenseScoreGaps?.some((g) => g.id === "wasm-export-rename-pending")).toBe(
        true,
      );
      expect(report.defenseScoreRaw).toBeGreaterThanOrEqual(report.defenseScore);
      if ((report.defenseScoreRaw ?? 0) > 88) {
        expect(report.defenseScore).toBeLessThanOrEqual(88);
      }
      const text = formatVerificationReport(report);
      expect(text).toMatch(/not a preimage-hardness claim/i);
      expect(text).toMatch(/wasm-export-rename-pending/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("verifyTarget skips wasm rename gap when wasmExportRenameApplied:true", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-honesty-ren-"));
    try {
      const wasm = Buffer.from([
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      ]);
      const input = join(dir, "mod.wasm");
      writeFileSync(input, wasm);
      const protectedRes = protectTarget({
        inputPath: input,
        intensity: "balanced",
        seed: "honesty-wasm-2",
      });
      const report = verifyTarget(protectedRes.outputPath, undefined, {
        wasmExportRenameApplied: true,
        selfSealEnabled: true,
      });
      expect(
        report.defenseScoreGaps?.some((g) => g.id === "wasm-export-rename-pending"),
      ).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
