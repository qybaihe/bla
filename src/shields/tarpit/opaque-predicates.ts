import { SeededPrng } from "../../core/prng.js";

/**
 * Generates JavaScript/TypeScript number-theoretic opaque predicate expressions
 * that always evaluate to `false` or `true` at runtime in O(1), but cannot be
 * constant-folded by static AST analyzers (`indexJavaScriptBindingsWithReceiversSteps`).
 */
export function generateJsOpaqueFalseExpression(prng: SeededPrng, seedVar = "k"): string {
  const k = prng.nextInt(3, 97);
  const variant = prng.nextInt(0, 3);
  switch (variant) {
    case 0:
      // 7 * x^2 - 1 === y^2 has no integer solutions mod 7 (since -1 is not a quadratic residue mod 7)
      return `(Math.imul(7, Math.imul(${seedVar} | ${k}, ${seedVar} | ${k})) - 1 === Math.imul(${seedVar} ^ ${k + 1}, ${seedVar} ^ ${k + 1}))`;
    case 1:
      // (x ^ y) + ((x & y) << 1) is ALWAYS equal to (x + y) for 32-bit integers
      return `((((${seedVar} ^ ${k}) + (((${seedVar} & ${k}) << 1) | 0)) | 0) !== (((${seedVar} + ${k}) | 0)))`;
    case 2:
      // x * (x + 1) is ALWAYS even, so bit 0 is never 1
      return `((Math.imul(${seedVar} | ${k}, ((${seedVar} | ${k}) + 1) | 0) & 1) === 1)`;
    default:
      // (x | ~x) is always -1 in two's complement
      return `(((${seedVar} | ~${seedVar}) | 0) !== -1)`;
  }
}

export function generateJsOpaqueTrueExpression(prng: SeededPrng, seedVar = "k"): string {
  const k = prng.nextInt(5, 89);
  const variant = prng.nextInt(0, 2);
  switch (variant) {
    case 0:
      return `((Math.imul(${seedVar} | ${k}, ((${seedVar} | ${k}) + 1) | 0) & 1) === 0)`;
    case 1:
      return `((((${seedVar} ^ ${k}) + (((${seedVar} & ${k}) << 1) | 0)) | 0) === (((${seedVar} + ${k}) | 0)))`;
    default:
      return `(((${seedVar} | ~${seedVar}) | 0) === -1)`;
  }
}

export function generatePythonOpaqueFalseExpression(prng: SeededPrng, seedVar = "k"): string {
  const k = prng.nextInt(3, 97);
  return `(((7 * ((${seedVar} | ${k}) ** 2) - 1) & 0xFFFFFFFF) == (((${seedVar} ^ ${k + 3}) ** 2) & 0xFFFFFFFF) and ((${seedVar} * (${seedVar} + 1)) & 1) == 1)`;
}

/**
 * Recommended opaque-seed binding strength (issue #40.4).
 * Callers should draw >= 28 bits of PRNG material and reserve bit0 for
 * integrity entanglement — never Date.now / hrtime / constant bit0.
 */
export function recommendOpaqueSeedBinding(): {
  readonly minEntropyBits: number;
  readonly forbid: readonly string[];
  readonly reserveLowBitForIntegrity: boolean;
} {
  return {
    minEntropyBits: 28,
    forbid: ["Date.now", "performance.now", "process.hrtime", "Math.random"],
    reserveLowBitForIntegrity: true,
  };
}
