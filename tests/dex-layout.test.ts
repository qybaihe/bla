import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { REA_INTERNAL_LIMITS } from "../src/identity.js";
import { generateAndroidDexXrefCounter } from "../src/shields/formats/android-dex-xref.js";
import { protectAndroidDexBuffer } from "../src/shields/formats/mobile-game.js";
import {
  DEX_SIDECAR_STRING_KEY,
  compareDexUtf16,
  dexChecksumsValid,
  dropDexSidecarStrings,
  insertDexString,
  parseDexLayout,
  readDexStringPool,
  rebuildDex,
  stripDexSidecarPrefix,
} from "../src/shields/formats/dex-layout.js";

function codeItemDigests(bytes: Buffer): string[] {
  const layout = parseDexLayout(bytes);
  if (!layout) return [];
  return layout.codeItems.map((item) =>
    createHash("sha256").update(item.raw.subarray(16)).digest("hex"),
  );
}

describe("dex-layout", () => {
  it("catalogues REA #10227 DEX array-dimension admission cap (honesty only)", () => {
    expect(REA_INTERNAL_LIMITS.DEX_ARRAY_DIMENSIONS).toBe(255);
  });

  it("parses a structurally valid xref DEX and accepts checksums", () => {
    const dex = generateAndroidDexXrefCounter(new SeededPrng("dex-layout-1"), "stealth").dexBuffer;
    expect(dexChecksumsValid(dex)).toBe(true);
    const layout = parseDexLayout(dex);
    expect(layout).not.toBeNull();
    expect(layout!.strings.length).toBeGreaterThan(8);
    expect(layout!.classDefs.length).toBe(layout!.classData.length);
    expect(layout!.codeItems.length).toBe(layout!.classDefs.length);
    expect(layout!.trailer.length).toBe(0);
  });

  it("returns null for a header-only stub", () => {
    const stub = Buffer.alloc(112, 0);
    stub.write("dex\n035\0", 0, "ascii");
    stub.writeUInt32LE(112, 32);
    stub.writeUInt32LE(112, 36);
    stub.writeUInt32LE(0x12345678, 40);
    expect(parseDexLayout(stub)).toBeNull();
  });

  it("inserts a sort-last string without changing existing indices or insn bytes", () => {
    const original = generateAndroidDexXrefCounter(new SeededPrng("dex-layout-2"), "stealth").dexBuffer;
    const before = parseDexLayout(original)!;
    const insnBefore = codeItemDigests(original);
    const typesBefore = before.typeIds.slice();
    const methodsBefore = before.methodIds.map((m) => ({ ...m }));

    const bound = insertDexString(original, `${DEX_SIDECAR_STRING_KEY}{"digest":"abc"}`);
    expect(bound).not.toBeNull();
    expect(dexChecksumsValid(bound!)).toBe(true);

    const after = parseDexLayout(bound!);
    expect(after).not.toBeNull();
    expect(after!.strings.length).toBe(before.strings.length + 1);
    expect(after!.strings.slice(0, before.strings.length).map((s) => s.text)).toEqual(
      before.strings.map((s) => s.text),
    );
    const added = after!.strings[after!.strings.length - 1]!.text;
    expect(stripDexSidecarPrefix(added)).toBe('{"digest":"abc"}');
    for (const existing of before.strings) {
      expect(compareDexUtf16(existing.text, added) < 0).toBe(true);
    }

    expect(after!.typeIds).toEqual(typesBefore);
    expect(after!.methodIds).toEqual(methodsBefore);
    expect(after!.classDefs.map((c) => c.classIdx)).toEqual(before.classDefs.map((c) => c.classIdx));
    expect(codeItemDigests(bound!)).toEqual(insnBefore);
  });

  it("rebuild without changes stays parse-equivalent and checksum-valid", () => {
    const original = generateAndroidDexXrefCounter(new SeededPrng("dex-layout-3"), "stealth").dexBuffer;
    const layout = parseDexLayout(original)!;
    const rebuilt = rebuildDex(layout);
    expect(dexChecksumsValid(rebuilt)).toBe(true);
    const again = parseDexLayout(rebuilt)!;
    expect(again.strings.map((s) => s.text)).toEqual(layout.strings.map((s) => s.text));
    expect(again.typeIds).toEqual(layout.typeIds);
    expect(again.methodIds).toEqual(layout.methodIds);
    expect(codeItemDigests(rebuilt)).toEqual(codeItemDigests(original));
  });

  it("drop is idempotent and restores the pre-insert string pool", () => {
    const original = generateAndroidDexXrefCounter(new SeededPrng("dex-layout-4"), "stealth").dexBuffer;
    const pool0 = readDexStringPool(original)!;
    const inserted = insertDexString(original, `${DEX_SIDECAR_STRING_KEY}note`)!;
    expect(readDexStringPool(inserted)!.length).toBe(pool0.length + 1);
    const stripped = dropDexSidecarStrings(inserted)!;
    expect(dexChecksumsValid(stripped)).toBe(true);
    expect(readDexStringPool(stripped)).toEqual(pool0);
    const again = dropDexSidecarStrings(stripped)!;
    expect(readDexStringPool(again)).toEqual(pool0);
  });

  it("preserves a protectAndroidDexBuffer trailer after insert", () => {
    const original = generateAndroidDexXrefCounter(new SeededPrng("dex-layout-5"), "stealth").dexBuffer;
    const protected_ = protectAndroidDexBuffer(original, {
      intensity: "stealth",
      seed: "dex-trailer",
    });
    expect(protected_.buffer.toString("latin1")).toContain("[BLA-DEX-SHIELD-V1]");
    const layout = parseDexLayout(protected_.buffer);
    expect(layout).not.toBeNull();
    expect(layout!.trailer.length).toBeGreaterThan(0);
    const inserted = insertDexString(protected_.buffer, `${DEX_SIDECAR_STRING_KEY}trail`)!;
    expect(dexChecksumsValid(inserted)).toBe(true);
    expect(inserted.toString("latin1")).toContain("[BLA-DEX-SHIELD-V1]");
    const after = parseDexLayout(inserted)!;
    expect(after.trailer.equals(layout!.trailer)).toBe(true);
    expect(after.strings.slice(0, layout!.strings.length).map((s) => s.text)).toEqual(
      layout!.strings.map((s) => s.text),
    );
  });
});
