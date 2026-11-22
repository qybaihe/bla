import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { auditTarget } from "../src/engine/auditor.js";
import { protectTarget } from "../src/engine/protector.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-audit-score-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * Plain, completely unprotected source. The only thing the auditor can latch
 * onto is a syntactic shape (a `+` chain with eight inline ternaries), which
 * used to be enough to publish the "partially shielded" band.
 */
const PLAIN_UNSHIELDED_JS = [
  "var c = 1;",
  "var s = (c > 0 ? 1 : 2) + (c > 0 ? 3 : 4) + (c > 0 ? 5 : 6) + (c > 0 ? 7 : 8) + (c > 0 ? 9 : 10) + (c > 0 ? 11 : 12) + (c > 0 ? 13 : 14) + (c > 0 ? 15 : 16);",
  "module.exports = { s };",
  "",
].join("\n");

describe("audit exposure score reflects real protection, not a syntactic shape", () => {
  it("does not report a plain unshielded file as partially shielded", () => {
    const dir = makeTempDir();
    const plainPath = join(dir, "plain.js");
    writeFileSync(plainPath, PLAIN_UNSHIELDED_JS, "utf8");

    const report = auditTarget(plainPath);
    expect(report.protectionStatus).toBe("UNPROTECTED");
    expect(report.exposureScore).toBeGreaterThan(50);
    expect(report.exposureScore).toBeGreaterThan(50);
  });

  it("still recognises a genuinely hardened artifact", () => {
    const dir = makeTempDir();
    const plainPath = join(dir, "plain.js");
    const hardenedPath = join(dir, "plain.hardened.cjs");
    writeFileSync(plainPath, PLAIN_UNSHIELDED_JS, "utf8");
    protectTarget({
      inputPath: plainPath,
      outputPath: hardenedPath,
      intensity: "balanced",
      seed: "audit-score-honesty",
    });

    expect(auditTarget(hardenedPath).protectionStatus).not.toBe("UNPROTECTED");
  });
});
