import { describe, expect, it } from "vitest";
import { emitCompileTimeNativeHeader } from "../src/shields/formats/headers.js";
import type { NativeHeaderLanguage } from "../src/shields/formats/headers.js";

const GOLDEN = /0x9e37_?79b9/i;
const GOLDEN_DEC = /\b2654435769\b/;
const LANGS: NativeHeaderLanguage[] = ["c", "rust", "go"];

describe("Issue #40: emit-headers native tarpit never ships golden-ratio probe", () => {
  it("C/Rust/Go headers scrub 0x9e3779b9 across seeds and intensities", () => {
    for (const lang of LANGS) {
      for (const seed of ["hdr-a", "hdr-b", "hdr-c", "bankrupt-hdr"]) {
        for (const intensity of ["balanced", "maximum", "bankrupt"] as const) {
          const out = emitCompileTimeNativeHeader(lang, { seed, intensity });
          expect(out.content, `${lang}/${seed}/${intensity}`).not.toMatch(GOLDEN);
          expect(out.content, `${lang}/${seed}/${intensity}`).not.toMatch(GOLDEN_DEC);
        }
      }
    }
  });

  it("emitted mixing multiply is still present (odd-constant avalanche preserved)", () => {
    const c = emitCompileTimeNativeHeader("c", { seed: "hdr-mix", intensity: "balanced" });
    // multiply-xor-shift mixer survives, just with a seed-derived odd constant.
    expect(c.content).toMatch(/acc = \(acc \* 0x[0-9a-f]+u\) \^ \(acc >> 13\)/i);
  });
});
