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
      sidecarEntangleEnabled: true,
    });
    expect(honesty.gaps.map((g) => g.id)).toContain("self-seal-not-enabled");
    expect(honesty.cappedScore).toBe(92);
  });

  it("annotates formats without sidecarEntangle and soft-caps above 93", () => {
    const honesty = applyDefenseScoreHonesty(99, {
      detectedFormat: "javascript",
      selfSealEnabled: true,
      sidecarEntangleEnabled: false,
    });
    expect(honesty.gaps.map((g) => g.id)).toContain("sidecar-entangle-not-enabled");
    expect(honesty.cappedScore).toBe(93);
    const wasm = applyDefenseScoreHonesty(99, {
      detectedFormat: "wasm",
      wasmExportRenameApplied: true,
      sidecarEntangleEnabled: false,
    });
    expect(wasm.gaps.map((g) => g.id)).toContain("sidecar-entangle-not-enabled");
    expect(wasm.cappedScore).toBe(93);
    const on = applyDefenseScoreHonesty(99, {
      detectedFormat: "javascript",
      selfSealEnabled: true,
      sidecarEntangleEnabled: true,
    });
    expect(on.gaps.map((g) => g.id)).not.toContain("sidecar-entangle-not-enabled");
    expect(on.cappedScore).toBe(99);
  });

  it("keeps a .pyc host-only marshal trailer from closing the strip⇒fail gap", () => {
    const off = applyDefenseScoreHonesty(99, {
      detectedFormat: "python-pyc",
      sidecarEntangleEnabled: false,
    });
    expect(off.gaps.map((g) => g.id)).toContain("sidecar-entangle-not-enabled");
    expect(off.cappedScore).toBe(93);

    const hostOnly = applyDefenseScoreHonesty(99, {
      detectedFormat: "python-pyc",
      sidecarEntangleEnabled: true,
    });
    expect(hostOnly.gaps.map((g) => g.id)).toContain("pyc-sidecar-host-verify-only");
    expect(hostOnly.gaps.map((g) => g.id)).not.toContain("sidecar-entangle-not-enabled");
    expect(hostOnly.cappedScore).toBe(93);

    const hooked = applyDefenseScoreHonesty(99, {
      detectedFormat: "python-pyc",
      sidecarEntangleEnabled: true,
      pycSidecarLoaderHookApplied: true,
    });
    expect(hooked.gaps.map((g) => g.id)).not.toContain("pyc-sidecar-host-verify-only");
    expect(hooked.gaps.map((g) => g.id)).not.toContain("sidecar-entangle-not-enabled");
    expect(hooked.cappedScore).toBe(99);
  });

  it("keeps a GGUF host-only STRING metadata note from closing the strip⇒fail gap", () => {
    const off = applyDefenseScoreHonesty(99, {
      detectedFormat: "model-gguf",
      sidecarEntangleEnabled: false,
    });
    expect(off.gaps.map((g) => g.id)).toContain("sidecar-entangle-not-enabled");
    expect(off.cappedScore).toBe(93);

    const hostOnly = applyDefenseScoreHonesty(99, {
      detectedFormat: "model-gguf",
      sidecarEntangleEnabled: true,
    });
    expect(hostOnly.gaps.map((g) => g.id)).toContain("gguf-sidecar-host-verify-only");
    expect(hostOnly.gaps.map((g) => g.id)).not.toContain("sidecar-entangle-not-enabled");
    expect(hostOnly.cappedScore).toBe(93);

    const hooked = applyDefenseScoreHonesty(99, {
      detectedFormat: "model-gguf",
      sidecarEntangleEnabled: true,
      ggufSidecarLoaderHookApplied: true,
    });
    expect(hooked.gaps.map((g) => g.id)).not.toContain("gguf-sidecar-host-verify-only");
    expect(hooked.cappedScore).toBe(99);
  });

  it("keeps a SQLite host-only schema-comment note from closing the strip⇒fail gap", () => {
    const off = applyDefenseScoreHonesty(99, {
      detectedFormat: "sqlite",
      sidecarEntangleEnabled: false,
    });
    expect(off.gaps.map((g) => g.id)).toContain("sidecar-entangle-not-enabled");
    expect(off.gaps.find((g) => g.id === "sidecar-entangle-not-enabled")!.scoreCap).toBe(93);

    const hostOnly = applyDefenseScoreHonesty(99, {
      detectedFormat: "sqlite",
      sidecarEntangleEnabled: true,
    });
    expect(hostOnly.gaps.map((g) => g.id)).toContain("sqlite-sidecar-host-verify-only");
    expect(hostOnly.gaps.map((g) => g.id)).not.toContain("sidecar-entangle-not-enabled");
    expect(hostOnly.gaps.find((g) => g.id === "sqlite-sidecar-host-verify-only")!.scoreCap).toBe(93);
  });

  it("caps a SQLite database for what the shield does not do: hide the application's tables", () => {
    // Default output: decoy columns any client evaluates.
    const stock = applyDefenseScoreHonesty(99, { detectedFormat: "sqlite", sqliteTrapMode: "stock" });
    expect(stock.gaps.map((g) => g.id)).toEqual(
      expect.arrayContaining(["sqlite-business-data-readable", "sqlite-decoy-columns-evaluable"]),
    );
    expect(stock.cappedScore).toBe(68);
    expect(stock.gaps.find((g) => g.id === "sqlite-business-data-readable")!.summary).toMatch(
      /stored exactly as before: any SQLite client reads them/,
    );

    // Opt-in evaluation trap: an inspector's read of a honey table fails, the
    // application's own tables still do not.
    const evalTrap = applyDefenseScoreHonesty(99, { detectedFormat: "sqlite", sqliteTrapMode: "eval" });
    expect(evalTrap.gaps.map((g) => g.id)).toContain("sqlite-business-data-readable");
    expect(evalTrap.gaps.map((g) => g.id)).not.toContain("sqlite-decoy-columns-evaluable");
    expect(evalTrap.cappedScore).toBe(78);

    // A caller that does not know the mode gets the cautious answer.
    expect(applyDefenseScoreHonesty(99, { detectedFormat: "sqlite" }).cappedScore).toBe(68);
    // Other formats are untouched.
    expect(
      applyDefenseScoreHonesty(99, { detectedFormat: "model-gguf", sidecarEntangleEnabled: true }).gaps.map(
        (g) => g.id,
      ),
    ).not.toContain("sqlite-business-data-readable");
  });

  it("keeps a DEX host-only string-pool note from closing the strip⇒fail gap", () => {
    const off = applyDefenseScoreHonesty(99, {
      detectedFormat: "android-dex",
      sidecarEntangleEnabled: false,
    });
    expect(off.gaps.map((g) => g.id)).toContain("sidecar-entangle-not-enabled");
    expect(off.cappedScore).toBe(93);

    const hostOnly = applyDefenseScoreHonesty(99, {
      detectedFormat: "android-dex",
      sidecarEntangleEnabled: true,
    });
    expect(hostOnly.gaps.map((g) => g.id)).toContain("dex-sidecar-host-verify-only");
    expect(hostOnly.gaps.map((g) => g.id)).not.toContain("sidecar-entangle-not-enabled");
    expect(hostOnly.cappedScore).toBe(93);
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
        sidecarEntangleEnabled: true,
      });
      expect(
        report.defenseScoreGaps?.some((g) => g.id === "wasm-export-rename-pending"),
      ).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
