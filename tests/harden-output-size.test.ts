import { mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { formatByteSize, formatHardenProjectReport, hardenProject } from "../src/engine/harden.js";

/**
 * Decoys are the protection, and decoys are bytes. A user who ships to browsers
 * has to hear what hardening costs to download before choosing an intensity —
 * a 41-byte WASM module is megabytes at `bankrupt`.
 */

const tempDirs: string[] = [];
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function put(root: string, rel: string, content: string | Buffer): void {
  mkdirSync(dirname(join(root, rel)), { recursive: true });
  writeFileSync(join(root, rel), content);
}

/** (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add) */
const ADD_WASM = Buffer.from(
  "0061736d0100000001070160027f7f017f030201000707010361646400000a09010700200020016a0b",
  "hex",
);
const APP_JS = "export const greet = (name) => 'hello ' + name;\n";

function project(): string {
  const dir = tempDir("bla-size-");
  put(dir, "dist/app.mjs", APP_JS);
  put(dir, "dist/calc.wasm", ADD_WASM);
  return dir;
}

describe("harden reports what the output costs to ship", () => {
  it("states sizes per artifact and in total, measured on the files that ship", () => {
    const dir = project();
    const report = hardenProject({
      directory: dir,
      intensity: "balanced",
      seed: "size-seed",
      applyStateRoot: tempDir("bla-size-state-"),
    });
    expect(report.overallSuccess).toBe(true);
    for (const artifact of report.artifacts) {
      expect(artifact.inputBytes, artifact.relativePath).toBe(statSync(artifact.inputPath).size);
      expect(artifact.outputBytes, artifact.relativePath).toBe(statSync(artifact.outputPath).size);
    }
    expect(report.outputSize).toEqual({
      inputBytes: APP_JS.length + ADD_WASM.length,
      outputBytes: report.artifacts.reduce((sum, a) => sum + a.outputBytes!, 0),
      largestGrowth: {
        relativePath: expect.stringMatching(/^dist\//),
        growthBytes: expect.any(Number),
      },
    });
    expect(formatHardenProjectReport(report)).toMatch(/^Size: \d+ B → [\d.]+ (?:KB|MB) \(largest: dist\/\S+ \+[\d.]+ (?:KB|MB)\)$/m);
    // Well under a megabyte: no need to interrupt the user about it.
    expect(report.outputSize!.outputBytes - report.outputSize!.inputBytes).toBeLessThan(1024 * 1024);
    expect(report.nextSteps?.join("\n")).not.toMatch(/larger than the originals/);
  }, 240000);

  it("says so when bankrupt adds megabytes, and names the way out", () => {
    const dir = project();
    const report = hardenProject({
      directory: dir,
      intensity: "bankrupt",
      seed: "size-seed",
      applyStateRoot: tempDir("bla-size-state-"),
    });
    expect(report.overallSuccess).toBe(true);
    const size = report.outputSize!;
    expect(size.outputBytes - size.inputBytes).toBeGreaterThan(1024 * 1024);
    expect(size.largestGrowth?.relativePath).toBe("dist/calc.wasm");
    expect(report.nextSteps?.join("\n")).toMatch(
      /The hardened files are [\d.]+ MB larger than the originals \(\d+ B → [\d.]+ MB; dist\/calc\.wasm alone grew by [\d.]+ MB\)\. .* harden at a lower intensity \(maximum keeps string encoding and export renaming at a fraction of the size\), or leave the largest files out with "exclude"\./,
    );

    // The advice is true: maximum is a fraction of the size.
    const maximum = hardenProject({
      directory: dir,
      intensity: "maximum",
      seed: "size-seed",
      outputDirectory: join(dir, "out-maximum"),
      applyStateRoot: tempDir("bla-size-state-"),
    });
    expect(maximum.overallSuccess).toBe(true);
    expect(maximum.outputSize!.outputBytes).toBeLessThan(size.outputBytes / 4);
  }, 240000);

  it("a dry run reports input sizes only", () => {
    const report = hardenProject({
      directory: project(),
      intensity: "bankrupt",
      seed: "size-seed",
      dryRun: true,
      applyStateRoot: tempDir("bla-size-state-"),
    });
    expect(report.artifacts.every((a) => a.inputBytes !== undefined && a.outputBytes === undefined)).toBe(true);
    expect(report.outputSize).toBeUndefined();
  });

  it("formats byte counts for people", () => {
    expect(formatByteSize(0)).toBe("0 B");
    expect(formatByteSize(1023)).toBe("1023 B");
    expect(formatByteSize(1536)).toBe("1.5 KB");
    expect(formatByteSize(10 * 1024)).toBe("10 KB");
    expect(formatByteSize(6_879_944)).toBe("6.6 MB");
    expect(formatByteSize(3 * 1024 ** 3)).toBe("3.0 GB");
  });
});
