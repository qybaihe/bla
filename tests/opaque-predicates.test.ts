import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import {
  generateJsOpaqueFalseExpression,
  generateJsOpaqueTrueExpression,
} from "../src/shields/tarpit/opaque-predicates.js";

function evalExpr(expr: string, k: number): boolean {
  return new Function("k", `return (${expr});`)(k) as boolean;
}

const INPUTS = [-1_000_000, -1, 0, 1, 2, 3, 5, 42, 127, 255, 1_000_000] as const;

describe("opaque predicates evaluate to their claimed invariant", () => {
  it("false variants never evaluate to true across many seeds and inputs", () => {
    for (let s = 0; s < 40; s++) {
      const prng = new SeededPrng(`opaque-false-${s}`);
      const expr = generateJsOpaqueFalseExpression(prng, "k");
      for (const k of INPUTS) {
        expect(evalExpr(expr, k), `seed variant ${s}, k=${k}, expr=${expr}`).toBe(false);
      }
    }
  });

  it("true variants always evaluate to true across many seeds and inputs", () => {
    for (let s = 0; s < 40; s++) {
      const prng = new SeededPrng(`opaque-true-${s}`);
      const expr = generateJsOpaqueTrueExpression(prng, "k");
      for (const k of INPUTS) {
        expect(evalExpr(expr, k), `seed variant ${s}, k=${k}, expr=${expr}`).toBe(true);
      }
    }
  });

  it("generation is deterministic per seed and differs across seeds", () => {
    const a = generateJsOpaqueFalseExpression(new SeededPrng("det"), "k");
    const b = generateJsOpaqueFalseExpression(new SeededPrng("det"), "k");
    const c = generateJsOpaqueFalseExpression(new SeededPrng("other"), "k");
    expect(a).toBe(b);
    expect(c).not.toBe(a);
  });
});
