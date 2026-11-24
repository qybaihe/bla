import { mkdtempSync, rmSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { auditTarget } from "../src/engine/auditor.js";

describe("single-file audit bounds", () => {
  it("refuses a single-file target above the audit read bound", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-audit-size-"));
    try {
      const huge = join(dir, "huge.bin");
      writeFileSync(huge, "");
      truncateSync(huge, 64 * 1024 * 1024 + 1);
      expect(() => auditTarget(huge)).toThrow(/single-file audit bound/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});