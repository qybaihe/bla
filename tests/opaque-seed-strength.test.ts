import { describe, expect, it } from "vitest";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import { recommendOpaqueSeedBinding } from "../src/shields/tarpit/opaque-predicates.js";

describe("opaque-predicate seed strength (#40.4)", () => {
  it("recommendOpaqueSeedBinding forbids hrtime/Date.now and asks for >=28 bits", () => {
    const rec = recommendOpaqueSeedBinding();
    expect(rec.minEntropyBits).toBeGreaterThanOrEqual(28);
    expect(rec.reserveLowBitForIntegrity).toBe(true);
    expect(rec.forbid).toEqual(
      expect.arrayContaining(["Date.now", "process.hrtime", "Math.random"]),
    );
  });

  it("AST shield opaque seed is a wide deterministic integer, not hrtime/bit0-only", () => {
    const src = "export function f(n){ return n + 1; }\n";
    const out = transformJavaScriptWithBlaShield(src, {
      intensity: "balanced",
      seed: "opaque-strength-1",
    });
    expect(out.code).not.toMatch(/hrtime/);
    expect(out.code).not.toMatch(/Date\.now\s*\(/);
    expect(out.code).not.toMatch(/performance\.now\s*\(/);
    // Opaque seed is a wide deterministic integer OR'd with integrity bit (not 0/1-only).
    const seedLit = out.code.match(
      /const\s+\w+\s*=\s*(?:\(\()?(\d{3,})\s*(?:\)|\|)/,
    );
    expect(seedLit).toBeTruthy();
    const n = Number(seedLit![1]);
    expect(n).toBeGreaterThan(0xff);
    // Deterministic across runs
    const out2 = transformJavaScriptWithBlaShield(src, {
      intensity: "balanced",
      seed: "opaque-strength-1",
    });
    expect(out2.code).toBe(out.code);
  });
});
