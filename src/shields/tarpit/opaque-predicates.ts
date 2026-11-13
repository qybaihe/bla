import { SeededPrng } from "../../core/prng.js";
import { modInverseUint32 } from "./mba-substitutions.js";

function deriveInlineAffineTuple(k: number): {
  readonly m: number;
  readonly m2: number;
  readonly mInv: number;
  readonly c: number;
  readonly d: number;
} {
  const m = ((Math.imul(k ^ 0x9e3779b1, 0x85ebca6b) | 1) >>> 0) || 3;
  const m2 = Math.imul(m, 2) >>> 0;
  const mInv = modInverseUint32(m);
  const c = (Math.imul(k + 0x517cc1b7, 0xc2b2ae35) >>> 0) || 0x27d4eb2f;
  const d = (-Math.imul(mInv, c)) >>> 0;
  return { m, m2, mInv, c, d };
}

/**
 * Generates JavaScript/TypeScript number-theoretic & Mixed Boolean-Arithmetic (MBA)
 * opaque predicate expressions that always evaluate to `false` or `true` at runtime
 * in O(1), while defeating both static AST folding and canonical MBA rule tables:
 * - Variant 0: Quadratic non-residue modulo 7 (`7 * x^2 - 1 !== y^2`)
 * - Variant 1: Parameterized affine MBA over Z_{2^32} (`mInv * (m*(x^k) + 2m*(x&k) + c) + d === x+k`)
 * - Variant 2: Unsigned-domain MBA inequality (`(u | (u - 1)) >= (u ^ (u - 1))` over uint32,
 *   exploiting signed-vs-unsigned bit-31 misjudgment in LLM static reasoning)
 * - Variant 3: Parameterized affine OR-XOR-AND MBA identity (`mInv * (m*(x|k) - m*(x&k) + c) + d === x^k`)
 */
export function generateJsOpaqueFalseExpression(prng: SeededPrng, seedVar = "k"): string {
  const k = prng.nextInt(3, 97);
  const variant = prng.nextInt(0, 3);
  switch (variant) {
    case 0:
      // 7 * x^2 - 1 === y^2 has no integer solutions mod 7 (since -1 is not a quadratic residue mod 7)
      return `(Math.imul(7, Math.imul(${seedVar} | ${k}, ${seedVar} | ${k})) - 1 === Math.imul(${seedVar} ^ ${k + 1}, ${seedVar} ^ ${k + 1}))`;
    case 1: {
      const { m, m2, mInv, c, d } = deriveInlineAffineTuple(k);
      return `(((Math.imul(${mInv}, (Math.imul(${m}, (${seedVar} ^ ${k})) + Math.imul(${m2}, (${seedVar} & ${k})) + ${c}) | 0) + ${d}) | 0) !== ((${seedVar} + ${k}) | 0))`;
    }
    case 2: {
      const u = `(((${seedVar} ^ ${k * 0x045d9f3b}) >>> 0))`;
      const u1 = `(((${u} - 1) >>> 0))`;
      return `(((${u} | ${u1}) >>> 0) < ((${u} ^ ${u1}) >>> 0))`;
    }
    default: {
      const { m, mInv, c, d } = deriveInlineAffineTuple(k ^ 0x5a);
      return `(((Math.imul(${mInv}, (Math.imul(${m}, (${seedVar} | ${k})) - Math.imul(${m}, (${seedVar} & ${k})) + ${c}) | 0) + ${d}) | 0) !== ((${seedVar} ^ ${k}) | 0))`;
    }
  }
}

export function generateJsOpaqueTrueExpression(prng: SeededPrng, seedVar = "k"): string {
  const k = prng.nextInt(5, 89);
  const variant = prng.nextInt(0, 2);
  switch (variant) {
    case 0: {
      const u = `(((${seedVar} ^ ${k * 0x045d9f3b}) >>> 0))`;
      const u1 = `(((${u} - 1) >>> 0))`;
      return `(((${u} | ${u1}) >>> 0) >= ((${u} ^ ${u1}) >>> 0))`;
    }
    case 1: {
      const { m, m2, mInv, c, d } = deriveInlineAffineTuple(k);
      return `(((Math.imul(${mInv}, (Math.imul(${m}, (${seedVar} ^ ${k})) + Math.imul(${m2}, (${seedVar} & ${k})) + ${c}) | 0) + ${d}) | 0) === ((${seedVar} + ${k}) | 0))`;
    }
    default: {
      const { m, mInv, c, d } = deriveInlineAffineTuple(k ^ 0x33);
      return `(((Math.imul(${mInv}, (Math.imul(${m}, (${seedVar} & ${k})) + Math.imul(${m}, (${seedVar} ^ ${k})) + ${c}) | 0) + ${d}) | 0) === ((${seedVar} | ${k}) | 0))`;
    }
  }
}

export function generatePythonOpaqueFalseExpression(prng: SeededPrng, seedVar = "k"): string {
  const k = prng.nextInt(3, 97);
  const { m, m2, mInv, c, d } = deriveInlineAffineTuple(k);
  const u = `(((${seedVar} ^ ${k * 0x119de1f3}) & 0xFFFFFFFF))`;
  return `(((${u} | ((${u} - 1) & 0xFFFFFFFF)) < (${u} ^ ((${u} - 1) & 0xFFFFFFFF))) or (((${mInv} * ((${m} * (${seedVar} ^ ${k})) + (${m2} * (${seedVar} & ${k})) + ${c}) + ${d}) & 0xFFFFFFFF) != ((${seedVar} + ${k}) & 0xFFFFFFFF)))`;
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
