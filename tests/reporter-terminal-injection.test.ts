import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { auditTarget } from "../src/engine/auditor.js";
import { formatPackagingGatesReport, scanPackagingGates } from "../src/engine/packaging-gates.js";
import { formatAuditReport, sanitizeTerminalText } from "../src/ui/reporter.js";

describe("reporter terminal hygiene", () => {
  it("strips escape sequences but keeps ordinary characters", () => {
    const cleaned = sanitizeTerminalText("app\u001b]0;pwned\u0007.js\nnext\tline");
    expect(cleaned).not.toContain("\u001b");
    expect(cleaned).not.toContain("\u0007");
    expect(cleaned).toContain("app");
    expect(cleaned).toContain(".js");
    expect(cleaned).toContain("next");
    expect(cleaned).toContain("\n");
    expect(cleaned).toContain("\t");
  });

  it("does not forward control characters from a target path into the report", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-report-injection-"));
    try {
      const target = join(dir, "x.py");
      writeFileSync(target, "x = 1\n", "utf8");

      // A hostile tree can produce such a name; the report must not carry it raw.
      const report = {
        ...auditTarget(target),
        targetPath: join(dir, "\u001b]0;pwned\u0007", "x.py"),
      };
      const text = formatAuditReport(report);

      expect(text).not.toContain("\u001b]0;");
      expect(text).not.toContain("\u0007");
      // BLA's own colouring is untouched.
      expect(text).toContain("\u001b[");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not forward control characters from packaging-gate paths", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-gate-injection-"));
    try {
      writeFileSync(
        join(dir, "license.cjs"),
        `module.exports.flag = "FLAG{gate_injection_fixture}";\n`,
        "utf8",
      );
      const report = scanPackagingGates({
        directory: dir,
        intensity: "bankrupt",
        includeProtectTimeGates: true,
      });
      expect(report.shouldRefuseBankrupt).toBe(true);

      // A hostile tree can produce such a name; the gate report must not carry it raw.
      const hostile = {
        ...report,
        directory: `${dir}\u001b]0;pwned\u0007`,
        findings: report.findings.map((f) => ({
          ...f,
          relativePath: `\u001b]0;pwned\u0007${f.relativePath}`,
        })),
        blocking: report.blocking.map((b) => ({
          ...b,
          relativePath: `\u001b]0;pwned\u0007${b.relativePath}`,
        })),
      };
      const text = formatPackagingGatesReport(hostile);

      expect(text).not.toContain("\u001b]0;");
      expect(text).not.toContain("\u0007");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});