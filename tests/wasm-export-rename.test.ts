import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import {
  inspectWasmBinary,
  looksLikeInternalWasmExport,
  parseWasmExportSectionPayload,
  protectWasmBinary,
  renameWasmExports,
  shuffleWasmExportSectionPayload,
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

describe("WASM export decoy arity-2 hygiene (red/blue round-10)", () => {
  /** Two arity-2 func exports (idx 0 junk, idx 1 unlock) + memory — decoys must not all alias 0. */
  function fixtureTwoFuncs(): Buffer {
    // types: (i32,i32)->i32 only; funcs type0+type0; mem; exports junk/unlock/memory
    // junk returns 0; unlock returns a+b
    return Buffer.from([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01,
      0x7f, 0x03, 0x03, 0x02, 0x00, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x1a, 0x03, 0x04, 0x6a,
      0x75, 0x6e, 0x6b, 0x00, 0x00, 0x06, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x00, 0x01, 0x06, 0x6d,
      0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x0a, 0x0e, 0x02, 0x04, 0x00, 0x41, 0x00, 0x0b, 0x07,
      0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
    ]);
  }

  it("bankrupt decoy aliases spread across exported function indices", () => {
    const raw = fixtureTwoFuncs();
    expect(WebAssembly.validate(new Uint8Array(raw))).toBe(true);
    const res = protectWasmBinary(raw, {
      intensity: "bankrupt",
      seed: "r10-arity2-hygiene-spread",
      // keep names so we can map decoy→index via parse of protected export section
      preserveExports: ["junk", "unlock", "memory"],
    });
    expect(res.exportDecoysInjected).toBe(250);
    expect(WebAssembly.validate(new Uint8Array(res.buffer))).toBe(true);

    // Locate export section payload and count decoy aliases per func index.
    const bytes = res.buffer;
    let offset = 8;
    let decoyIdx0 = 0;
    let decoyIdx1 = 0;
    while (offset < bytes.length) {
      const sectionId = bytes[offset++]!;
      let size = 0;
      let shift = 0;
      while (true) {
        const b = bytes[offset++]!;
        size |= (b & 0x7f) << shift;
        if ((b & 0x80) === 0) break;
        shift += 7;
      }
      const sectionEnd = offset + size;
      if (sectionId === 7) {
        const payload = bytes.subarray(offset, sectionEnd);
        const entries = parseWasmExportSectionPayload(payload);
        for (const e of entries) {
          if (e.kind !== 0) continue;
          if (!e.name.startsWith("enclave_export_")) continue;
          if (e.index === 0) decoyIdx0++;
          else if (e.index === 1) decoyIdx1++;
        }
        break;
      }
      offset = sectionEnd;
    }
    expect(decoyIdx0 + decoyIdx1).toBe(250);
    // Hygiene: both indices get a non-trivial share (not 250/0 pile-on).
    expect(decoyIdx0).toBeGreaterThan(40);
    expect(decoyIdx1).toBeGreaterThan(40);
  });
});

describe("WASM export-order shuffle (red/blue round-11)", () => {
  /** unlock (idx1) exported FIRST among funcs, then junk (idx0), then memory. */
  function fixtureUnlockFirst(): Buffer {
    // Both funcs arity-2 (R12 prefer-arity-2); unlock exported first (R10 footgun).
    // junk returns 0; unlock returns a+b
    return Buffer.from([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01,
      0x7f, 0x03, 0x03, 0x02, 0x00, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x1a, 0x03, 0x06, 0x75,
      0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x00, 0x01, 0x04, 0x6a, 0x75, 0x6e, 0x6b, 0x00, 0x00, 0x06, 0x6d,
      0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x0a, 0x0e, 0x02, 0x04, 0x00, 0x41, 0x00, 0x0b, 0x07,
      0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
    ]);
  }

  function firstFuncExportIndex(bytes: Buffer): number | null {
    let offset = 8;
    while (offset < bytes.length) {
      const sectionId = bytes[offset++]!;
      let size = 0;
      let shift = 0;
      while (true) {
        const b = bytes[offset++]!;
        size |= (b & 0x7f) << shift;
        if ((b & 0x80) === 0) break;
        shift += 7;
      }
      const sectionEnd = offset + size;
      if (sectionId === 7) {
        const entries = parseWasmExportSectionPayload(bytes.subarray(offset, sectionEnd));
        for (const e of entries) {
          if (e.kind === 0) return e.index;
        }
        return null;
      }
      offset = sectionEnd;
    }
    return null;
  }

  it("shuffleWasmExportSectionPayload permutes entry order without changing set", () => {
    const keep = Buffer.from("a", "utf8");
    const dbg = Buffer.from("b", "utf8");
    const encodeName = (b: Buffer) => Buffer.concat([Buffer.from([b.length]), b]);
    const payload = Buffer.concat([
      Buffer.from([0x02]),
      encodeName(keep),
      Buffer.from([0x00, 0x00]),
      encodeName(dbg),
      Buffer.from([0x00, 0x01]),
    ]);
    const before = parseWasmExportSectionPayload(payload);
    let changed = false;
    for (const seed of ["r11-u0", "r11-u1", "r11-u2", "r11-u3", "r11-u4", "r11-u5", "r11-u6", "r11-u7"]) {
      const out = shuffleWasmExportSectionPayload(payload, new SeededPrng(seed));
      const after = parseWasmExportSectionPayload(out);
      expect(after).toHaveLength(2);
      expect(new Set(after.map((e) => e.name))).toEqual(new Set(before.map((e) => e.name)));
      if (after.map((e) => e.name).join(",") !== before.map((e) => e.name).join(",")) changed = true;
    }
    expect(changed).toBe(true);
  });

  it("bankrupt protect shuffles export order so first func ≠ cleartext-first unlock", () => {
    const raw = fixtureUnlockFirst();
    expect(WebAssembly.validate(new Uint8Array(raw))).toBe(true);
    expect(firstFuncExportIndex(raw)).toBe(1); // unlock idx1 first in cleartext

    // Across several seeds, first func export index after protect must not
    // *always* remain unlock (idx 1). At least one seed yields a different first.
    const firsts = new Set<number>();
    for (const seed of [
      "r11-export-shuffle-a",
      "r11-export-shuffle-b",
      "r11-export-shuffle-c",
      "r11-export-shuffle-d",
      "r11-export-shuffle-e",
      "r11-export-shuffle-f",
      "r11-export-shuffle-g",
      "r11-export-shuffle-h",
    ]) {
      const res = protectWasmBinary(raw, {
        intensity: "bankrupt",
        seed,
        preserveExports: ["unlock", "junk", "memory"],
      });
      expect(res.exportsOrderShuffled).toBe(true);
      expect(WebAssembly.validate(new Uint8Array(res.buffer))).toBe(true);
      const idx = firstFuncExportIndex(res.buffer);
      expect(idx === 0 || idx === 1).toBe(true);
      firsts.add(idx!);
    }
    expect(firsts.has(0)).toBe(true); // at least one seed puts junk/decoy-of-junk first
    expect(firsts.size).toBeGreaterThan(1);
  });
});

describe("WASM alias budget prefers arity-2 (red/blue round-12)", () => {
  /** arity-1 seal (idx0) + arity-2 junk (idx1) + arity-2 unlock (idx2) + memory */
  function fixtureArityMix(): Buffer {
    // types: (i32)->i32, (i32,i32)->i32
    // funcs: seal=type0, junk=type1, unlock=type1
    // code: seal returns 0; junk returns 0; unlock returns a+b
    return Buffer.from([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x0c, 0x02, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
      0x03, 0x04, 0x03, 0x00, 0x01, 0x01,
      0x05, 0x03, 0x01, 0x00, 0x01,
      0x07, 0x21, 0x04,
      0x04, 0x73, 0x65, 0x61, 0x6c, 0x00, 0x00,
      0x04, 0x6a, 0x75, 0x6e, 0x6b, 0x00, 0x01,
      0x06, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x00, 0x02,
      0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00,
      0x0a, 0x13, 0x03,
      0x04, 0x00, 0x41, 0x00, 0x0b,
      0x04, 0x00, 0x41, 0x00, 0x0b,
      0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
    ]);
  }

  it("bankrupt decoy aliases skip arity-1 when arity-2 exports exist", () => {
    const raw = fixtureArityMix();
    expect(WebAssembly.validate(new Uint8Array(raw))).toBe(true);
    const res = protectWasmBinary(raw, {
      intensity: "bankrupt",
      seed: "r12-arity1-budget-tighten",
      preserveExports: ["seal", "junk", "unlock", "memory"],
    });
    expect(res.exportDecoysInjected).toBe(250);
    expect(WebAssembly.validate(new Uint8Array(res.buffer))).toBe(true);

    const bytes = res.buffer;
    let offset = 8;
    let decoySeal = 0;
    let decoyJunk = 0;
    let decoyUnlock = 0;
    while (offset < bytes.length) {
      const sectionId = bytes[offset++]!;
      let size = 0;
      let shift = 0;
      while (true) {
        const b = bytes[offset++]!;
        size |= (b & 0x7f) << shift;
        if ((b & 0x80) === 0) break;
        shift += 7;
      }
      const sectionEnd = offset + size;
      if (sectionId === 7) {
        const entries = parseWasmExportSectionPayload(bytes.subarray(offset, sectionEnd));
        for (const e of entries) {
          if (e.kind !== 0) continue;
          if (!e.name.startsWith("enclave_export_")) continue;
          if (e.index === 0) decoySeal++;
          else if (e.index === 1) decoyJunk++;
          else if (e.index === 2) decoyUnlock++;
        }
        break;
      }
      offset = sectionEnd;
    }
    expect(decoySeal + decoyJunk + decoyUnlock).toBe(250);
    // Round-12: arity-1 seal must not receive alias budget when arity-2 exist.
    expect(decoySeal).toBe(0);
    expect(decoyJunk).toBeGreaterThan(40);
    expect(decoyUnlock).toBeGreaterThan(40);
  });
});
