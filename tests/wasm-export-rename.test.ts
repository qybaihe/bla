import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import {
  inspectWasmBinary,
  looksLikeInternalWasmExport,
  parseWasmExportSectionPayload,
  protectWasmBinary,
  renameWasmExports,
} from "../src/shields/formats/wasm.js";

/** Minimal WASM exporting compute_score(i32)->i32 = x*42+7 */
function fixtureComputeScore(): Buffer {
  return Buffer.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x11, 0x01, 0x0d, 0x63, 0x6f, 0x6d, 0x70,
    0x75, 0x74, 0x65, 0x5f, 0x73, 0x63, 0x6f, 0x72,
    0x65, 0x00, 0x00,
    0x0a, 0x0c, 0x01, 0x0a, 0x00, 0x20, 0x00, 0x41,
    0x2a, 0x6c, 0x41, 0x07, 0x6a, 0x0b,
  ]);
}

describe("WASM export rename / semantic preservation (#40.3)", () => {
  it("looksLikeInternalWasmExport matches debug/internal prefixes only", () => {
    expect(looksLikeInternalWasmExport("__heap_base")).toBe(true);
    expect(looksLikeInternalWasmExport("debug_dump")).toBe(true);
    expect(looksLikeInternalWasmExport("compute_score")).toBe(false);
    expect(looksLikeInternalWasmExport("main")).toBe(false);
  });

  it("renameWasmExports preserves listed ABI and rewrites others", () => {
    // Craft a tiny export section: 2 func exports
    // count=2, name "keep_me" (kind0 idx0), name "__dbg" (kind0 idx0)
    const keep = Buffer.from("keep_me", "utf8");
    const dbg = Buffer.from("__dbg", "utf8");
    const encodeName = (b: Buffer) => Buffer.concat([Buffer.from([b.length]), b]);
    const payload = Buffer.concat([
      Buffer.from([0x02]),
      encodeName(keep),
      Buffer.from([0x00, 0x00]),
      encodeName(dbg),
      Buffer.from([0x00, 0x00]),
    ]);
    const parsed = parseWasmExportSectionPayload(payload);
    expect(parsed.map((e) => e.name)).toEqual(["keep_me", "__dbg"]);

    const prng = new SeededPrng("wasm-rename-unit");
    const { payload: out, renames } = renameWasmExports(payload, prng, {
      preserveExports: ["keep_me"],
      onlyInternal: false,
    });
    expect(renames).toHaveLength(1);
    expect(renames[0]!.from).toBe("__dbg");
    expect(renames[0]!.to).not.toBe("__dbg");
    const after = parseWasmExportSectionPayload(out);
    expect(after.map((e) => e.name)).toContain("keep_me");
    expect(after.map((e) => e.name)).not.toContain("__dbg");
    expect(after.map((e) => e.name)).toContain(renames[0]!.to);
  });

  it("balanced keeps public ABI; bankrupt renames non-preserved by default", () => {
    const raw = fixtureComputeScore();
    const balanced = protectWasmBinary(raw, {
      intensity: "balanced",
      seed: "wasm-rename-bal",
    });
    expect(balanced.exportsRenamed).toHaveLength(0);
    expect(inspectWasmBinary(balanced.buffer).exportNames).toContain("compute_score");
    expect(WebAssembly.validate(new Uint8Array(balanced.buffer))).toBe(true);

    const bankrupt = protectWasmBinary(raw, {
      intensity: "bankrupt",
      seed: "wasm-rename-bankrupt-default",
    });
    expect(bankrupt.exportsRenamed.length).toBeGreaterThanOrEqual(1);
    expect(bankrupt.exportsRenamed[0]!.from).toBe("compute_score");
    const names = inspectWasmBinary(bankrupt.buffer).exportNames;
    expect(names).not.toContain("compute_score");
    expect(names).toContain(bankrupt.exportsRenamed[0]!.to);
    expect(WebAssembly.validate(new Uint8Array(bankrupt.buffer))).toBe(true);

    const mod = new WebAssembly.Module(new Uint8Array(bankrupt.buffer));
    const inst = new WebAssembly.Instance(mod);
    const fn = inst.exports[bankrupt.exportsRenamed[0]!.to] as (x: number) => number;
    expect(fn(10)).toBe(427);
  });

  it("preserveExports keeps the named public ABI under bankrupt rename", () => {
    const raw = fixtureComputeScore();
    const res = protectWasmBinary(raw, {
      intensity: "bankrupt",
      seed: "wasm-rename-preserve",
      preserveExports: ["compute_score"],
    });
    expect(res.exportsRenamed).toHaveLength(0);
    expect(inspectWasmBinary(res.buffer).exportNames).toContain("compute_score");
    expect(WebAssembly.validate(new Uint8Array(res.buffer))).toBe(true);
  });

  it("renameInternalOnly:true keeps public names even at bankrupt", () => {
    const raw = fixtureComputeScore();
    const res = protectWasmBinary(raw, {
      intensity: "bankrupt",
      seed: "wasm-rename-internal-only",
      renameInternalOnly: true,
    });
    expect(res.exportsRenamed).toHaveLength(0);
    expect(inspectWasmBinary(res.buffer).exportNames).toContain("compute_score");
  });
});
