import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  buildInterleavedCoverageMatrix,
  discoverAndLintIntegrityCoverage,
} from "../src/engine/integrity-coverage.js";

const MATRIX = JSON.stringify(
  buildInterleavedCoverageMatrix({
    fileNodes: ["a.cjs"],
    checkerHosts: ["a.cjs"],
    expectedSha256: { "a.cjs": "0".repeat(64) },
  }),
);

function withScratch(fn: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "bla-coverage-read-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function canSymlink(): boolean {
  const probe = mkdtempSync(join(tmpdir(), "bla-symlink-probe-"));
  try {
    const target = join(probe, "target.txt");
    writeFileSync(target, "x", "utf8");
    symlinkSync(target, join(probe, "link.txt"), "file");
    return true;
  } catch {
    return false;
  } finally {
    rmSync(probe, { recursive: true, force: true });
  }
}

describe("integrity coverage matrix discovery stays inside the tree", () => {
  it("discovers a regular colocated matrix", () => {
    withScratch((dir) => {
      writeFileSync(join(dir, "integrity-coverage.json"), MATRIX, "utf8");
      const found = discoverAndLintIntegrityCoverage(dir);
      expect(found).toHaveLength(1);
      expect(found[0]!.path).toBe(join(dir, "integrity-coverage.json"));
    });
  });

  it("does not read a symlinked matrix that points outside the tree", () => {
    if (!canSymlink()) {
      return; // Windows without symlink privilege — skip.
    }
    withScratch((dir) => {
      const outside = mkdtempSync(join(tmpdir(), "bla-coverage-outside-"));
      try {
        const target = join(outside, "integrity-coverage.json");
        writeFileSync(target, MATRIX, "utf8");
        symlinkSync(target, join(dir, "integrity-coverage.json"), "file");
        expect(discoverAndLintIntegrityCoverage(dir)).toHaveLength(0);
      } finally {
        rmSync(outside, { recursive: true, force: true });
      }
    });
  });

  it("refuses a matrix past the read cap instead of parsing it", () => {
    withScratch((dir) => {
      writeFileSync(join(dir, "integrity-coverage.json"), Buffer.alloc(8 * 1024 * 1024 + 1, 0x20));
      const found = discoverAndLintIntegrityCoverage(dir);
      expect(found).toHaveLength(1);
      expect(found[0]!.parseError).toBe("matrix-too-large");
      expect(found[0]!.ok).toBe(false);
    });
  });
});
