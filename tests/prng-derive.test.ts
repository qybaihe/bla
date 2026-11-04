import { describe, expect, it } from "vitest";
import { SeededPrng, deriveSeedLabel } from "../src/core/prng.js";

describe("SeededPrng.derive / deriveSeedLabel", () => {
  it("deriveSeedLabel is deterministic and label-sensitive", () => {
    const a = deriveSeedLabel("root-seed", "wasm.export-order");
    const b = deriveSeedLabel("root-seed", "wasm.export-order");
    const c = deriveSeedLabel("root-seed", "js.identifiers");
    const d = deriveSeedLabel("other-root", "wasm.export-order");
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).not.toBe(c);
    expect(a).not.toBe(d);
  });

  it("rejects empty labels", () => {
    expect(() => deriveSeedLabel("root", "")).toThrow(/non-empty/);
  });

  it("child streams are independent of parent draws", () => {
    const root = new SeededPrng("independence-root");
    const before = root.derive("child").nextUint32();
    // Advance parent — must not change the child's first draw.
    root.nextUint32();
    root.nextUint32();
    expect(root.derive("child").nextUint32()).toBe(before);
  });

  it("same seed + label → identical shuffle; different label → different", () => {
    const items = ["a", "b", "c", "d", "e", "f", "g", "h"];
    const s1 = new SeededPrng("poly-root").derive("lane").shuffle(items);
    const s2 = new SeededPrng("poly-root").derive("lane").shuffle(items);
    const s3 = new SeededPrng("poly-root").derive("other").shuffle(items);
    expect(s1).toEqual(s2);
    expect(s1).not.toEqual(s3);
  });

  it("different roots with same label diverge", () => {
    const items = Array.from({ length: 16 }, (_, i) => `x${i}`);
    const a = new SeededPrng("seed-A").derive("export").shuffle(items);
    const b = new SeededPrng("seed-B").derive("export").shuffle(items);
    expect(a).not.toEqual(b);
  });
});
