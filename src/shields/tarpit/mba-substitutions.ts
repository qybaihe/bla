import * as t from "@babel/types";
import { SeededPrng } from "../../core/prng.js";

export type MbaBitwiseOp = "+" | "-" | "^" | "|" | "&";

export interface ParameterizedMbaParams {
  readonly m: number;
  readonly m2: number;
  readonly mInv: number;
  readonly c: number;
  readonly d: number;
}

/**
 * Computes the multiplicative inverse of an odd 32-bit integer modulo 2^32
 * via 5 Newton-Raphson iterations: m * mInv === 1 (mod 2^32).
 */
export function modInverseUint32(oddValue: number): number {
  const m = (oddValue | 1) >>> 0;
  let inv = 1;
  for (let i = 0; i < 5; i++) {
    inv = Math.imul(inv, (2 - Math.imul(m, inv)) | 0) >>> 0;
  }
  return inv >>> 0;
}

/**
 * Draws a non-canonical 63-bit parameterized affine key tuple over Z_{2^32}
 * so MBA instruction substitutions escape fixed canonical rule tables
 * (e.g. D810G's 96-rule simplifier) while remaining exact O(1) identities.
 *
 * Identity:
 *   mInv * (m * termA +/- (k * m) * termB + c) + d === termA +/- k * termB (mod 2^32)
 * where d = -(mInv * c) mod 2^32.
 */
export function deriveParameterizedMbaParams(prng: SeededPrng): ParameterizedMbaParams {
  let m = (prng.nextUint32() | 1) >>> 0;
  if (m === 1 || m === 0xffffffff || m === 0x9e3779b9) {
    m = (m ^ 0x5bd1e995) | 1;
    m >>>= 0;
  }
  const m2 = (Math.imul(m, 2) >>> 0);
  const mInv = modInverseUint32(m);
  let c = prng.nextUint32() >>> 0;
  if (c === 0) c = 0x27d4eb2f;
  const d = (-Math.imul(mInv, c)) >>> 0;
  return { m, m2, mInv, c, d };
}

function imulAst(lhs: t.Expression, rhs: t.Expression): t.CallExpression {
  return t.callExpression(
    t.memberExpression(t.identifier("Math"), t.identifier("imul")),
    [lhs, rhs],
  );
}

function uint32Literal(val: number): t.NumericLiteral {
  return t.numericLiteral(val >>> 0);
}

/**
 * Builds a Babel AST expression over 32-bit signed/unsigned integers equivalent to
 * `(lhs <op> rhs) | 0` using parameterized affine Mixed Boolean-Arithmetic (MBA):
 *
 * - `a + b` -> `(imul(mInv, imul(m, a ^ b) + imul(2*m, a & b) + c) + d) | 0`
 * - `a - b` -> `(imul(mInv, imul(m, a ^ b) - imul(2*m, ~a & b) + c) + d) | 0`
 * - `a ^ b` -> `(imul(mInv, imul(m, a | b) - imul(m, a & b) + c) + d) | 0`
 * - `a | b` -> `(imul(mInv, imul(m, a & b) + imul(m, a ^ b) + c) + d) | 0`
 * - `a & b` -> `(imul(mInv, imul(m, a | b) - imul(m, a ^ b) + c) + d) | 0`
 *
 * Note: Callers must ensure `lhs` and `rhs` are pure/duplicable (e.g. identifiers,
 * numeric literals, or side-effect-free temps) since both operands appear twice.
 */
export function buildParameterizedMbaBinaryAst(
  op: MbaBitwiseOp,
  lhs: t.Expression,
  rhs: t.Expression,
  prng: SeededPrng,
): t.Expression {
  const { m, m2, mInv, c, d } = deriveParameterizedMbaParams(prng);
  const a1 = t.cloneNode(lhs, true);
  const b1 = t.cloneNode(rhs, true);
  const a2 = t.cloneNode(lhs, true);
  const b2 = t.cloneNode(rhs, true);

  let inner: t.Expression;
  switch (op) {
    case "+": {
      const xorTerm = imulAst(uint32Literal(m), t.binaryExpression("^", a1, b1));
      const andTerm = imulAst(uint32Literal(m2), t.binaryExpression("&", a2, b2));
      inner = t.binaryExpression("+", t.binaryExpression("+", xorTerm, andTerm), uint32Literal(c));
      break;
    }
    case "-": {
      const xorTerm = imulAst(uint32Literal(m), t.binaryExpression("^", a1, b1));
      const notAAndB = t.binaryExpression("&", t.unaryExpression("~", a2), b2);
      const borrowTerm = imulAst(uint32Literal(m2), notAAndB);
      inner = t.binaryExpression("+", t.binaryExpression("-", xorTerm, borrowTerm), uint32Literal(c));
      break;
    }
    case "^": {
      const orTerm = imulAst(uint32Literal(m), t.binaryExpression("|", a1, b1));
      const andTerm = imulAst(uint32Literal(m), t.binaryExpression("&", a2, b2));
      inner = t.binaryExpression("+", t.binaryExpression("-", orTerm, andTerm), uint32Literal(c));
      break;
    }
    case "|": {
      const andTerm = imulAst(uint32Literal(m), t.binaryExpression("&", a1, b1));
      const xorTerm = imulAst(uint32Literal(m), t.binaryExpression("^", a2, b2));
      inner = t.binaryExpression("+", t.binaryExpression("+", andTerm, xorTerm), uint32Literal(c));
      break;
    }
    case "&": {
      const orTerm = imulAst(uint32Literal(m), t.binaryExpression("|", a1, b1));
      const xorTerm = imulAst(uint32Literal(m), t.binaryExpression("^", a2, b2));
      inner = t.binaryExpression("+", t.binaryExpression("-", orTerm, xorTerm), uint32Literal(c));
      break;
    }
  }

  const unmasked = t.binaryExpression("+", imulAst(uint32Literal(mInv), inner), uint32Literal(d));
  return t.binaryExpression("|", unmasked, t.numericLiteral(0));
}

/**
 * Emits a C `uint32_t` inline expression implementing the same parameterized
 * affine MBA identity for compile-time native headers (`bla emit-headers`).
 */
export function formatCParameterizedMbaExpr(
  op: MbaBitwiseOp,
  lhsExpr: string,
  rhsExpr: string,
  prng: SeededPrng,
): string {
  const { m, m2, mInv, c, d } = deriveParameterizedMbaParams(prng);
  const mh = `0x${m.toString(16)}u`;
  const m2h = `0x${m2.toString(16)}u`;
  const mInvh = `0x${mInv.toString(16)}u`;
  const ch = `0x${c.toString(16)}u`;
  const dh = `0x${d.toString(16)}u`;
  const a = `((uint32_t)(${lhsExpr}))`;
  const b = `((uint32_t)(${rhsExpr}))`;

  switch (op) {
    case "+":
      return `((uint32_t)(${mInvh} * ((${mh} * (${a} ^ ${b})) + (${m2h} * (${a} & ${b})) + ${ch}) + ${dh}))`;
    case "-":
      return `((uint32_t)(${mInvh} * ((${mh} * (${a} ^ ${b})) - (${m2h} * ((~${a}) & ${b})) + ${ch}) + ${dh}))`;
    case "^":
      return `((uint32_t)(${mInvh} * ((${mh} * (${a} | ${b})) - (${mh} * (${a} & ${b})) + ${ch}) + ${dh}))`;
    case "|":
      return `((uint32_t)(${mInvh} * ((${mh} * (${a} & ${b})) + (${mh} * (${a} ^ ${b})) + ${ch}) + ${dh}))`;
    case "&":
      return `((uint32_t)(${mInvh} * ((${mh} * (${a} | ${b})) - (${mh} * (${a} ^ ${b})) + ${ch}) + ${dh}))`;
  }
}

/**
 * Unsigned-domain MBA opaque predicates that exploit signed vs. unsigned
 * semantic confusion in LLM static reasoning:
 *
 * Identity: `(u | (u - 1)) - (u ^ (u - 1)) == (u & (u - 1))` in Z_{2^32}.
 * Over unsigned `uint32_t` (`>>> 0`), `(u | (u - 1)) >= (u ^ (u - 1))` ALWAYS holds
 * for every u in [0, 2^32 - 1] (including u = 0 and u = 0xC0000000), whereas
 * signed interpretation falsely predicts negativity when bit 31 is set.
 */
export function generateUnsignedMbaOpaqueTrueJs(prng: SeededPrng, seedVar = "k"): string {
  const k = prng.nextUint32() >>> 0;
  const u = `(((${seedVar} ^ 0x${k.toString(16)}) >>> 0))`;
  const uMinus1 = `(((${u} - 1) >>> 0))`;
  return `(((${u} | ${uMinus1}) >>> 0) >= ((${u} ^ ${uMinus1}) >>> 0))`;
}

export function generateUnsignedMbaOpaqueFalseJs(prng: SeededPrng, seedVar = "k"): string {
  const k = prng.nextUint32() >>> 0;
  const u = `(((${seedVar} ^ 0x${k.toString(16)}) >>> 0))`;
  const uMinus1 = `(((${u} - 1) >>> 0))`;
  return `(((${u} | ${uMinus1}) >>> 0) < ((${u} ^ ${uMinus1}) >>> 0))`;
}

export function generateUnsignedMbaOpaqueFalseC(prng: SeededPrng, seedExpr = "seed"): string {
  const k = prng.nextUint32() >>> 0;
  const u = `(((uint32_t)(${seedExpr})) ^ 0x${k.toString(16)}u)`;
  return `((uint32_t)(${u} | (uint32_t)(${u} - 1u)) < (uint32_t)(${u} ^ (uint32_t)(${u} - 1u)))`;
}
