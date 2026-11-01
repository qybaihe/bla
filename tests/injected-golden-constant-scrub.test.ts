import { describe, expect, it } from "vitest";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import { generateShadowHeapChurnShield } from "../src/shields/runtime/memory-diff-shield.js";
import { generateFridaCaptureSaturation } from "../src/shields/exhaustion/frida-capture-saturation.js";
import { generateChaffPayloads } from "../src/shields/chaff/chaff-generator.js";
import { SeededPrng } from "../src/core/prng.js";

const GOLDEN_HEX = /0x9e3779b9/i;
const GOLDEN_DEC = /\b2654435769\b/;

describe("Issue #40: scrub BLA-injected golden constant templates", () => {
  it("memory-diff / frida / chaff generators never emit 0x9e3779b9 bit-identically", () => {
    for (const seed of [
      "issue-40-template-hygiene",
      "golden-probe-a",
      "golden-probe-b",
      "bankrupt-scrub-1",
    ]) {
      const prng = new SeededPrng(seed);
      const heap = generateShadowHeapChurnShield(prng, "bankrupt");
      expect(heap.code).not.toMatch(GOLDEN_HEX);
      expect(heap.code).not.toMatch(GOLDEN_DEC);

      const frida = generateFridaCaptureSaturation(new SeededPrng(seed), "bankrupt");
      expect(frida.code).not.toMatch(GOLDEN_HEX);
      expect(frida.code).not.toMatch(GOLDEN_DEC);

      const chaff = generateChaffPayloads(new SeededPrng(seed), "bankrupt");
      for (const payload of chaff) {
        expect(payload.rawText).not.toMatch(GOLDEN_HEX);
        expect(payload.rawText).not.toMatch(GOLDEN_DEC);
      }
    }
  });

  it("bankrupt harden of customer code without the probe does not reintroduce it via injections", () => {
    const source = `
      function schedule(x) {
        const SALT = 109551763;
        return (Math.imul(x ^ 7, SALT) >>> 0) + 640 + 1;
      }
      module.exports = { schedule };
    `;
    const result = transformJavaScriptWithBlaShield(source, {
      intensity: "bankrupt",
      seed: "issue-40-injected-scrub",
      sourceType: "commonjs",
    });
    expect(result.code).not.toMatch(GOLDEN_HEX);
    expect(result.code).not.toMatch(GOLDEN_DEC);
  });
});
