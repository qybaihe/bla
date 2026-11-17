import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { auditTarget } from "../src/engine/auditor.js";
import {
  buildPackagingGatesSarif,
  scanPackagingGates,
} from "../src/engine/packaging-gates.js";
import { buildSarifReport } from "../src/core/sarif.js";

const OSC = "\u001b]0;pwned\u0007";

describe("SARIF output terminal hygiene", () => {
  it("does not carry escape sequences from artifact-derived audit text", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sarif-hygiene-"));
    try {
      const file = join(dir, "app.js");
      writeFileSync(file, `const flag = "FLAG{sarif_hygiene_fixture}";\n`, "utf8");
      const audit = auditTarget(file);
      const hostileItem = {
        id: "exposed-0",
        name: `mod${OSC}`,
        kind: "function" as const,
        location: `${OSC}/app.js:1`,
        riskLevel: "high" as const,
        reaToolUsed: "rea-test-probe",
        estimatedTokensToReconstruct: 100,
        estimatedCostUsd: 0.01,
        reason: `exposed ${OSC}`,
      };
      const hostile = {
        ...audit,
        targetPath: `${OSC}/project`,
        exposedItems: [hostileItem, ...audit.exposedItems],
      };
      // JSON.stringify escapes control characters, so a hostile name shows up
      // as a \u001b escape inside the emitted document rather than a raw byte.
      const sarif = JSON.stringify(buildSarifReport(hostile));
      expect(sarif).not.toContain("\\u001b");
      expect(sarif).not.toContain("\\u0007");
      expect(sarif).toContain("pwned");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not carry escape sequences from packaging-gate findings", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sarif-gates-"));
    try {
      writeFileSync(
        join(dir, "license.cjs"),
        `module.exports.unlock = function unlock(key) {\n  const flag = "FLAG{sarif_gate_fixture}";\n  return key === "ok" ? flag : null;\n};\n`,
        "utf8",
      );
      const report = scanPackagingGates({
        directory: dir,
        intensity: "bankrupt",
        includeProtectTimeGates: true,
      });
      expect(report.findings.length).toBeGreaterThan(0);
      const hostile = {
        ...report,
        findings: report.findings.map((f, i) =>
          i === 0
            ? { ...f, relativePath: `gate${OSC}.cjs`, oneLineAdvice: `advice ${OSC}` }
            : f,
        ),
      };
      const sarif = JSON.stringify(buildPackagingGatesSarif(hostile));
      expect(sarif).not.toContain("\\u001b");
      expect(sarif).not.toContain("\\u0007");
      expect(sarif).toContain("pwned");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
