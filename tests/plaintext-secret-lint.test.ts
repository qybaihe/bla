import { describe, expect, it } from "vitest";
import {
  PLAINTEXT_SECRET_SCHEMA,
  classifySensitiveLiteral,
  extractStringLiterals,
  lintPlaintextSecretsSource,
  shannonEntropy,
} from "../src/engine/plaintext-secret-lint.js";

describe("plaintext-secret lint (Direction-2)", () => {
  it("flags FLAG{…} and high-entropy tokens as refuse", () => {
    const src = `
      const flag = "FLAG{bla_v8_aegis_demo_fixture_not_the_real_prize}";
      const token = "7f3a9c2e1b8d4f6a0e5c9b7d3a1f8e6c";
      module.exports = { flag, token };
    `;
    const report = lintPlaintextSecretsSource(src, { path: "license.cjs" });
    expect(report.schema).toBe(PLAINTEXT_SECRET_SCHEMA);
    expect(report.shouldRefuseBankrupt).toBe(true);
    expect(report.findings.some((f) => f.id === "plaintext-flag-literal")).toBe(
      true,
    );
    expect(report.findings.some((f) => f.id === "plaintext-high-entropy" || f.id === "plaintext-b64-or-hex")).toBe(
      true,
    );
  });

  it("does not refuse short UI copy (false-positive guard)", () => {
    const src = `
      const title = "Enter license";
      const hint = "16-char key";
      const btn = "Submit";
      module.exports = { title, hint, btn };
    `;
    const report = lintPlaintextSecretsSource(src, { path: "panel.html" });
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.findings.filter((f) => f.severity === "error")).toEqual([]);
  });

  it("flags a sensitive literal written with an escaped byte (bypass guard)", () => {
    // The raw source carries a backslash-n escape, so the unescaped literal
    // can never appear in the raw source. The "literal absent from source"
    // suppression must not hide a real secret just because it was written
    // with an escape sequence.
    const src = `const api = "sk_live_A1\\nB2C3D4E5F6G7H8";`;
    const report = lintPlaintextSecretsSource(src);
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.shouldRefuseBankrupt).toBe(true);
  });

  it("treats http(s) URLs as warning, not bankrupt refuse", () => {
    const src = `const ep = "https://enclave.internal/v1/slot/demo";`;
    const report = lintPlaintextSecretsSource(src);
    expect(report.findings.some((f) => f.id === "plaintext-url-endpoint")).toBe(
      true,
    );
    expect(report.shouldRefuseBankrupt).toBe(false);
  });

  it("allowPlaintextString clears refuse", () => {
    const src = `const flag = "FLAG{should_still_be_listed}";`;
    const report = lintPlaintextSecretsSource(src, {
      allowPlaintextString: true,
    });
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.shouldRefuseBankrupt).toBe(false);
  });

  it("shannonEntropy and classify helpers behave", () => {
    expect(shannonEntropy("aaaa")).toBe(0);
    expect(shannonEntropy("7f3a9c2e1b8d4f6a")).toBeGreaterThan(3.5);
    expect(classifySensitiveLiteral("hi")).toBeNull();
    expect(classifySensitiveLiteral("FLAG{abc_def_ghi}")).toBe(
      "plaintext-flag-literal",
    );
    expect(extractStringLiterals(`x("ab"); y('cd');`).sort()).toEqual([
      "ab",
      "cd",
    ]);
  });
});
