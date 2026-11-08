import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { initBlaConfig, loadBlaConfig, resolveProjectSeed } from "../src/core/config.js";

const tempDirs: string[] = [];
function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-config-validation-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe(".blarc/config validation", () => {
  it("loads a valid config", () => {
    const dir = createTempDir();
    writeFileSync(
      join(dir, ".blarc"),
      JSON.stringify({ intensity: "maximum", seed: "project-seed", emitManifest: true }),
      "utf8",
    );
    const loaded = loadBlaConfig(dir);
    expect(loaded.sourcePath).toBe(join(dir, ".blarc"));
    expect(loaded.config.intensity).toBe("maximum");
    expect(loaded.config.emitManifest).toBe(true);
  });

  it("fails loudly on malformed JSON instead of silently falling back", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".blarc"), "{ not json", "utf8");
    expect(() => loadBlaConfig(dir)).toThrow(/Invalid BLA config at .*\.blarc/);
  });

  it("fails loudly on an invalid intensity value", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".blarc"), JSON.stringify({ intensity: "nope" }), "utf8");
    expect(() => loadBlaConfig(dir)).toThrow(/intensity.*stealth, balanced, maximum, bankrupt/);
  });

  it("fails loudly on a non-boolean boolean field", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".blarc"), JSON.stringify({ selfSeal: "yes" }), "utf8");
    expect(() => loadBlaConfig(dir)).toThrow(/selfSeal.*boolean/);
    writeFileSync(join(dir, ".blarc"), JSON.stringify({ sidecarEntangle: "yes" }), "utf8");
    expect(() => loadBlaConfig(dir)).toThrow(/sidecarEntangle.*boolean/);
  });

  it("rejects config files above the size cap", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".blarc"), "{}\n" + " ".repeat(70 * 1024), "utf8");
    expect(() => loadBlaConfig(dir)).toThrow(/file is .* bytes/);
  });

  it("validates an explicit --config path and the package.json bla field", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "custom.json"), JSON.stringify({ intensity: "stealth" }), "utf8");
    expect(loadBlaConfig(dir, "custom.json").config.intensity).toBe("stealth");

    const pkgDir = createTempDir();
    writeFileSync(
      join(pkgDir, "package.json"),
      JSON.stringify({ name: "x", bla: { intensity: "nope" } }),
      "utf8",
    );
    expect(() => loadBlaConfig(pkgDir)).toThrow(/package\.json \(bla field\)/);
  });

  it("initBlaConfig writes valid starter config and validates existing config before updating", () => {
    const dir = createTempDir();
    const res = initBlaConfig(dir);
    expect(res.created).toBe(true);
    expect(res.config.sidecarEntangle).toBe(false);
    expect(res.config.seed).toMatch(/^bla-[0-9a-f]{32}$/);

    // Existing valid config without seed is updated safely
    writeFileSync(
      join(dir, "bla.config.json"),
      JSON.stringify({ intensity: "stealth", sidecarEntangle: true }),
      "utf8",
    );
    const updated = initBlaConfig(dir);
    expect(updated.created).toBe(false);
    expect(updated.config.intensity).toBe("stealth");
    expect(updated.config.sidecarEntangle).toBe(true);
    expect(updated.config.seed).toMatch(/^bla-[0-9a-f]{32}$/);

    // Corrupt existing config is rejected instead of corrupted
    writeFileSync(join(dir, "bla.config.json"), "{ invalid json", "utf8");
    expect(() => initBlaConfig(dir)).toThrow(/Invalid BLA config/);
  });

  it("resolveProjectSeed validates existing config file before persisting new seed", () => {
    const dir = createTempDir();
    writeFileSync(
      join(dir, ".blarc"),
      JSON.stringify({ intensity: "maximum", sidecarEntangle: "invalid" }),
      "utf8",
    );
    expect(() => resolveProjectSeed(dir)).toThrow(/sidecarEntangle.*boolean/);

    // With valid config, persists seed cleanly
    writeFileSync(
      join(dir, ".blarc"),
      JSON.stringify({ intensity: "maximum", sidecarEntangle: true }),
      "utf8",
    );
    const resolved = resolveProjectSeed(dir);
    expect(resolved.persisted).toBe(true);
    const onDisk = JSON.parse(readFileSync(resolved.sourcePath!, "utf8"));
    expect(onDisk.intensity).toBe("maximum");
    expect(onDisk.sidecarEntangle).toBe(true);
    expect(onDisk.seed).toBe(resolved.seed);
  });
});