import vm from "node:vm";
import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import {
  computeContainmentCorpusDigest,
  generateCognitiveArmorTrigger,
  LEGACY_DIGEST_MIX_CONSTANT,
} from "../src/shields/deception/cognitive-armor-trigger.js";

/**
 * Static de-blinding tools key on BLA's cognitive-armor digest function by its
 * fixed seed constant — the old build emitted `((seedInput | 0) ^ 0x26b5c67b)`
 * (the numeric twin of the canary GUID) in every artifact. That constant is now
 * seed-derived per build. The anti-strip digest ENTANGLEMENT must survive
 * unchanged: the TS-side `expectedDigest` and the emitted runtime digest
 * function must agree (so untampered programs run), which they only do when the
 * per-build constant is woven into both. The canary GUID string itself stays
 * fixed by design — its anti-strip protection is the entanglement proven by the
 * redteam-adversarial-bypass "redact the GUID ⇒ program breaks" test, and its
 * anti-REA function requires a recognizable literal.
 */

function runEmittedDigest(code: string, fnName: string): number {
  return vm.runInNewContext(`${code}; ${fnName}(0);`, { Uint32Array, Math, Array }) as number;
}

describe("anti static de-blinding: cognitive-armor digest mixing constant is seed-derived", () => {
  it("drops the fixed 0x26b5c67b seed and keeps TS/runtime digest entanglement intact", () => {
    for (let n = 0; n < 6; n++) {
      const armor = generateCognitiveArmorTrigger(new SeededPrng(`digest-mix-${n}`), "bankrupt");
      // The emitted digest function must not carry the fixed BLA constant.
      expect(armor.code).not.toContain("0x26b5c67b");
      // Entanglement: TS expectedDigest == runtime digest == recompute with the
      // threaded per-build constant.
      const runtime = runEmittedDigest(armor.code, armor.digestFunctionName);
      expect(runtime).toBe(armor.expectedDigest);
      expect(
        computeContainmentCorpusDigest(armor.triggersInjected, 0, armor.digestMixConstant),
      ).toBe(armor.expectedDigest);
    }
  });

  it("varies the digest mixing constant across seeds", () => {
    const mixes = new Set<number>();
    for (let n = 0; n < 24; n++) {
      mixes.add(
        generateCognitiveArmorTrigger(new SeededPrng(`digest-vary-${n}`), "bankrupt")
          .digestMixConstant >>> 0,
      );
    }
    expect(mixes.size).toBeGreaterThan(20);
  });

  it("is reproducible for a given seed", () => {
    const a = generateCognitiveArmorTrigger(new SeededPrng("digest-repro"), "bankrupt");
    const b = generateCognitiveArmorTrigger(new SeededPrng("digest-repro"), "bankrupt");
    expect(a.digestMixConstant).toBe(b.digestMixConstant);
    expect(a.code).toBe(b.code);
  });

  it("legacy default constant still reproduces the pre-change digest", () => {
    const entries = generateCognitiveArmorTrigger(
      new SeededPrng("digest-legacy"),
      "bankrupt",
    ).triggersInjected;
    // Calling with the explicit legacy constant equals the two-arg default call.
    expect(computeContainmentCorpusDigest(entries, 0, LEGACY_DIGEST_MIX_CONSTANT)).toBe(
      computeContainmentCorpusDigest(entries, 0),
    );
  });
});
