import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";

export interface DecompilerIllusionResult {
  readonly code: string;
  readonly illusionPatternsInjected: number;
}

/**
 * Generates control-flow and array-aliasing illusions that exploit static
 * decompiler & AST constant-propagation simplifications:
 * - Static analyzers see two distinct variable names (`_apparentRate`, `_effectiveRate`)
 *   and assume `_apparentRate` controls the return value, whereas runtime TypedArray
 *   buffer sharing (`Int32Array` view over the same `ArrayBuffer`) aliases them!
 */
export function generateDecompilerPseudocodeIllusion(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): DecompilerIllusionResult {
  const count =
    intensity === "stealth"
      ? 1
      : intensity === "balanced"
        ? 2
        : intensity === "maximum"
          ? 3
          : 4;
  const tag = prng.hex(3);
  const blocks: string[] = [];

  for (let i = 0; i < count; i++) {
    const fnName = `aliasedBufferIllusion_${tag}_${i}`;
    const c1 = 100 + prng.nextInt(1, 50);
    const c2 = 200 + prng.nextInt(1, 50);
    blocks.push(
      `function ${fnName}(inputVal = 1) {`,
      `  const _rawBuf = new ArrayBuffer(8);`,
      `  const _viewA = new Int32Array(_rawBuf);`,
      `  const _viewB = new Int32Array(_rawBuf);`,
      `  _viewA[0] = inputVal * ${c1};`,
      `  _viewB[0] = inputVal ^ ${c2};`,
      `  return _viewA[0];`,
      `}`,
    );
  }

  return {
    code: blocks.join("\n\n"),
    illusionPatternsInjected: count,
  };
}
