import { describe, expect, it } from "vitest";
import {
  buildTestWasmWithXorMaskSidecar,
  lintWasmXorMaskSidecarBuffer,
  looksLikeXorMaskedEntitlementPack,
} from "../src/engine/wasm-xor-mask-sidecar-lint.js";

describe("wasm-xor-mask-sidecar-lint", () => {
  it("flags fixture entitlement pack with adjacent plaintext mask", () => {
    const wasm = buildTestWasmWithXorMaskSidecar({
      salt: -1378167267,
      rounds: 40,
      words: [1041213620, -2107783877, -126968763, -156377045],
    });
    const report = lintWasmXorMaskSidecarBuffer(wasm, { path: "fixture.wasm" });
    expect(report.shouldRefuseBankrupt).toBe(true);
    expect(report.looksExposed).toBe(true);
    expect(report.findings.some((f) => f.id === "wasm-xor-mask-entitlement-pack")).toBe(true);
  });

  it("does not flag empty WASM header", () => {
    const clean = Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]);
    const report = lintWasmXorMaskSidecarBuffer(clean);
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.findings).toHaveLength(0);
  });

  it("looksLikeXorMaskedEntitlementPack requires tight pack + entropy", () => {
    const wasm = buildTestWasmWithXorMaskSidecar({});
    const report = lintWasmXorMaskSidecarBuffer(wasm);
    expect(report.findings[0]?.blobLen).toBeGreaterThanOrEqual(40);
    expect(looksLikeXorMaskedEntitlementPack(Buffer.alloc(100)).ok).toBe(false);
  });

  it("does not refuse masked entitlement pack without adjacent plaintext mask (r7 key-dep style)", () => {
    const wasm = buildTestWasmWithXorMaskSidecar({ omitMaskSidecar: true });
    const report = lintWasmXorMaskSidecarBuffer(wasm, { path: "keydep.wasm" });
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.findings).toHaveLength(0);
  });
});
