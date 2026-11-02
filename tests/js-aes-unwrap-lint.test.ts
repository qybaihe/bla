import { describe, expect, it } from "vitest";
import {
  buildTestJsAesUnwrapFootgun,
  intensityEnforcesJsAesUnwrapRefusal,
  JS_AES_UNWRAP_SCHEMA,
  lintJsAesUnwrapSource,
} from "../src/engine/js-aes-unwrap-lint.js";

describe("js-aes-unwrap lint (red-blue round-4)", () => {
  it("flags R4-shaped wrap-key + createDecipheriv + fixed hdr as refuse", () => {
    const src = buildTestJsAesUnwrapFootgun({});
    const report = lintJsAesUnwrapSource(src, { path: "license.cjs" });
    expect(report.schema).toBe(JS_AES_UNWRAP_SCHEMA);
    expect(report.shouldRefuseBankrupt).toBe(true);
    expect(report.hasWrapKeyMaterial).toBe(true);
    expect(report.hasCreateCipherIv).toBe(true);
    expect(report.hasFixedSealedHdr).toBe(true);
    expect(report.findings.some((f) => f.id === "js-aes-sealed-blob-unwrap")).toBe(true);
    expect(intensityEnforcesJsAesUnwrapRefusal("bankrupt")).toBe(true);
    expect(intensityEnforcesJsAesUnwrapRefusal("maximum")).toBe(false);
  });

  it("does not refuse clean code without key material", () => {
    const src = `
      const crypto = require("crypto");
      function hash(s) {
        return crypto.createHash("sha256").update(s).digest("hex");
      }
      module.exports = { hash };
    `;
    const report = lintJsAesUnwrapSource(src);
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.looksExposed).toBe(false);
  });

  it("warns on partial signals without full combo", () => {
    const noHdr = buildTestJsAesUnwrapFootgun({ omitHdr: true });
    const report = lintJsAesUnwrapSource(noHdr);
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.hasCreateCipherIv).toBe(true);
    expect(report.hasWrapKeyMaterial).toBe(true);
  });
});
