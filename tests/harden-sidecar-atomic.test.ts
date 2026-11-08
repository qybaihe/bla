import { mkdtempSync, readdirSync, readFileSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { hardenProject } from "../src/engine/harden.js";

const tempDirs: string[] = [];

function makeProject(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-harden-sidecar-atomic-"));
  tempDirs.push(dir);
  mkdirSync(join(dir, "dist"), { recursive: true });
  writeFileSync(
    join(dir, "dist", "license.cjs"),
    "module.exports = { tier: 'pro', check() { return true; } };\n",
    "utf8",
  );
  writeFileSync(join(dir, "dist", "helper.cjs"), "module.exports = { helper: 1 };\n", "utf8");
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("harden sidecar entanglement report", () => {
  it("reports success without an entanglement error and leaves no atomic temp files", () => {
    const dir = makeProject();
    const report = hardenProject({
      directory: dir,
      intensity: "balanced",
      seed: "sidecar-atomic-seed",
      sidecarEntangle: true,
    });

    expect(report.overallSuccess).toBe(true);
    expect(report.sidecarEntangleError).toBeUndefined();
    expect(report.sidecarEntangle).toBe(true);

    const entry = report.artifacts.find((a) =>
      a.relativePath.replaceAll("\\", "/").endsWith("license.cjs"),
    );
    expect(entry?.success).toBe(true);
    expect(readFileSync(entry!.outputPath, "utf8")).toContain("integrity binding mismatch");

    // Atomic writes go through a uniquely named temp file; none may survive.
    const leftovers = readdirSync(report.outputDirectory).filter((name) =>
      name.includes(".bla-tmp-"),
    );
    expect(leftovers).toEqual([]);
  });
});