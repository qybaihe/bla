import { describe, expect, it } from "vitest";
import { lintPlaintextSecretsSource } from "../src/engine/plaintext-secret-lint.js";

const MAX_SCAN_CHARS = 800_000;

describe("plaintext-secret lint names the characters it did not scan", () => {
  it("reports the truncation instead of silently ignoring the tail", () => {
    const oversized = "// padding\n".repeat(90_000); // ~990k chars, no sensitive literal
    expect(oversized.length).toBeGreaterThan(MAX_SCAN_CHARS);

    const report = lintPlaintextSecretsSource(oversized, { path: "bundle.js" });
    const truncation = report.findings.find((f) => f.id === "plaintext-scan-truncated");
    expect(truncation).toBeDefined();
    expect(truncation?.severity).toBe("warning");
    expect(truncation?.summary).toMatch(/not (?:been )?scanned|truncat/i);
    expect(report.oneLineAdvice).toMatch(/not inspected|truncat/i);
  });

  it("keeps a truncation notice from looking like exposure or a refusal", () => {
    const oversized = "// padding\n".repeat(90_000);
    const report = lintPlaintextSecretsSource(oversized, { path: "bundle.js" });
    expect(report.looksExposed).toBe(false);
    expect(report.shouldRefuseBankrupt).toBe(false);
  });

  it("does not add the notice for a source it fully scanned", () => {
    const small = "const x = 1;\n";
    const report = lintPlaintextSecretsSource(small, { path: "small.js" });
    expect(report.findings.some((f) => f.id === "plaintext-scan-truncated")).toBe(false);
    expect(report.oneLineAdvice).not.toMatch(/not inspected/i);
  });

  it("still refuses a small source that really ships a secret", () => {
    const report = lintPlaintextSecretsSource('const secretKey = "sk-live-abcdef123456";\n', {
      path: "license.cjs",
    });
    expect(report.shouldRefuseBankrupt).toBe(true);
    expect(report.looksExposed).toBe(true);
  });
});
