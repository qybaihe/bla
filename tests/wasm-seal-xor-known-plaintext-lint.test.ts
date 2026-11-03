import { describe, expect, it } from "vitest";
import {
  buildTestWasmWithSealXorKnownPlaintext,
  lintWasmSealXorKnownPlaintextBuffer,
  looksLikeSealRevisionKnownPlaintextPack,
} from "../src/engine/wasm-seal-xor-known-plaintext-lint.js";

describe("wasm-seal-xor-known-plaintext-lint", () => {
  it("flags fixture where seal.revision is XOR known-plaintext in pack", () => {
    const { wasm, seal, commit } = buildTestWasmWithSealXorKnownPlaintext({});
    const report = lintWasmSealXorKnownPlaintextBuffer(wasm, {
      path: "fixture.wasm",
      sealRaw: JSON.stringify(seal),
      sealPath: "seal.json",
    });
    expect(report.shouldRefuseBankrupt).toBe(true);
    expect(report.looksExposed).toBe(true);
    expect(report.findings.some((f) => f.id === "wasm-seal-revision-mask-oracle")).toBe(true);
    expect(commit.length).toBe(32);
  });

  it("does not refuse when embedded commit mismatches seal.revision", () => {
    const { wasm, seal } = buildTestWasmWithSealXorKnownPlaintext({ mismatchCommit: true });
    const report = lintWasmSealXorKnownPlaintextBuffer(wasm, {
      path: "mismatch.wasm",
      sealRaw: JSON.stringify(seal),
    });
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.findings).toHaveLength(0);
  });

  it("looksLike helper rejects empty buffer", () => {
    expect(looksLikeSealRevisionKnownPlaintextPack(Buffer.alloc(10), Buffer.alloc(32)).ok).toBe(false);
  });

  it("round-8 entropy pad under XOR (commit elsewhere) does not refuse", () => {
    // Product pattern: masked prefix holds entropy ≠ seal.revision; commitment is not under XOR.
    const { wasm, seal } = buildTestWasmWithSealXorKnownPlaintext({ mismatchCommit: true });
    const report = lintWasmSealXorKnownPlaintextBuffer(wasm, {
      path: "r8-style.wasm",
      sealRaw: JSON.stringify(seal),
    });
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.findings).toHaveLength(0);
  });
});
