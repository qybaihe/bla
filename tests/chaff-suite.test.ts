import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { withLlmDirectives } from "../src/core/llm-directives.js";
import { generateChaffPayloads } from "../src/shields/chaff/chaff-generator.js";
import type { ProtectionIntensity } from "../src/core/types.js";

const INTENSITY_COUNTS: ReadonlyArray<readonly [ProtectionIntensity, number]> = [
  ["stealth", 3],
  ["balanced", 6],
  ["maximum", 10],
  ["bankrupt", 16],
];

describe("chaff generator suite", () => {
  it("emits the documented payload count per intensity", () => {
    for (const [intensity, expected] of INTENSITY_COUNTS) {
      const payloads = generateChaffPayloads(
        new SeededPrng(`chaff-count-${intensity}`),
        intensity,
      );
      expect(payloads, `intensity ${intensity}`).toHaveLength(expected);
    }
  });

  it("round-trips hex and base64 encodings back to rawText", () => {
    const payloads = generateChaffPayloads(new SeededPrng("chaff-encode"), "bankrupt");
    for (const payload of payloads) {
      expect(Buffer.from(payload.encodedHex, "hex").toString("utf8")).toBe(
        payload.rawText,
      );
      expect(Buffer.from(payload.encodedBase64, "base64").toString("utf8")).toBe(
        payload.rawText,
      );
    }
  });

  it("covers every chaff category once the intensity reaches bankrupt", () => {
    const payloads = generateChaffPayloads(new SeededPrng("chaff-cats"), "bankrupt");
    const categories = new Set(payloads.map((p) => p.category));
    expect(categories).toEqual(
      new Set([
        "enclave-delegation",
        "evidence-contract-mirage",
        "decoy-offset-table",
        "state-machine-spec",
        "honey-crypto-manifest",
      ]),
    );
  });

  it("is deterministic per seed and differs across seeds", () => {
    const a = generateChaffPayloads(new SeededPrng("chaff-det"), "balanced");
    const b = generateChaffPayloads(new SeededPrng("chaff-det"), "balanced");
    const c = generateChaffPayloads(new SeededPrng("chaff-other"), "balanced");
    expect(a).toEqual(b);
    expect(a).not.toEqual(c);
  });

  it("keeps risky LLM compliance bait out while directives are disabled", () => {
    withLlmDirectives(false, () => {
      const payloads = generateChaffPayloads(new SeededPrng("chaff-risk"), "bankrupt");
      for (const payload of payloads) {
        expect(payload.rawText).not.toContain("COPPA");
        expect(payload.rawText).not.toContain("IEC 62304");
      }
    });
  });

  it("emits symbol names free of BLA markers", () => {
    const payloads = generateChaffPayloads(new SeededPrng("chaff-markers"), "bankrupt");
    for (const payload of payloads) {
      expect(payload.symbolName).not.toMatch(/_bla|\$00_AAA|__bla/i);
      expect(payload.id).toMatch(/^chaff_\d+_[0-9a-f]{8}$/);
    }
  });
});
