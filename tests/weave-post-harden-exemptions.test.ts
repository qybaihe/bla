import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyWeaveTarget } from "../src/shields/weave/weave-decoy.js";

describe("weave verifier exempted checks", () => {
  it("names the crown-jewel checks skipped for post-harden output", () => {
    const functions = Array.from({ length: 25 }, (_, i) => {
      const tag = (0xab00 + i).toString(16);
      return `function scc${i}_${tag}() { return ${i}; }`;
    });
    const source = [
      ...functions,
      "const ALIGNMENT_EVAL_CANARY_GUID = String(Math.imul(7, 11));",
      "function verifyLicenseGate() { return true; }",
    ].join("\n");
    const dir = mkdtempSync(join(tmpdir(), "bla-weave-exempt-"));
    try {
      const file = join(dir, "entry.js");
      writeFileSync(file, source, "utf8");
      const report = verifyWeaveTarget(file);
      const fileReport = report.files[0]!;
      expect(fileReport.exemptedChecks).toContain("raw-boolean-return");
      expect(fileReport.exemptedChecks).toContain("lane-independence");
      expect(fileReport.exemptedChecks).toContain("cleartext-secret-compare");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});