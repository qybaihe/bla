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

  it("does not mistake a zero-filled region beside a small-integer table for a masked pack", () => {
    // Stock Go / Rust runtimes are full of little-endian u32 tables. With zeros
    // in front, "blob XOR table" is the table itself, and a table shaped
    // {x, 40, a, b, c, d, 57, y} satisfies the pack layout by construction:
    // rounds = 40, four non-zero words, clen = 57, blob length 26 + 57.
    const table = Buffer.alloc(32);
    [0x11, 40, 0x33, 0x44, 0x55, 0x66, 57, 0x77].forEach((value, i) => table.writeUInt32LE(value, i * 4));
    const blobLen = 26 + 57;
    const payload = Buffer.concat([Buffer.alloc(blobLen), table]);

    // The layout really does hold — only the entropy bars tell it apart.
    const plain = Buffer.from(payload.subarray(0, blobLen).map((byte, i) => byte ^ table[i % 32]!));
    expect([plain[4], plain[5], plain[6], plain[7], plain.readUInt16LE(24)]).toEqual([40, 0, 0, 0, 57]);

    expect(looksLikeXorMaskedEntitlementPack(payload).ok).toBe(false);
    // A real mask (32 key bytes) in the same position is still recognised.
    const wasm = buildTestWasmWithXorMaskSidecar({});
    expect(lintWasmXorMaskSidecarBuffer(wasm).shouldRefuseBankrupt).toBe(true);
  });

  it("does not refuse masked entitlement pack without adjacent plaintext mask (r7 key-dep style)", () => {
    const wasm = buildTestWasmWithXorMaskSidecar({ omitMaskSidecar: true });
    const report = lintWasmXorMaskSidecarBuffer(wasm, { path: "keydep.wasm" });
    expect(report.shouldRefuseBankrupt).toBe(false);
    expect(report.findings).toHaveLength(0);
  });
});
