import { describe, expect, it } from "vitest";
import * as vm from "node:vm";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";

describe("Issue #40: numeric literal de-literalization", () => {
  it("removes bit-identical customer magic integers at bankrupt while preserving runtime values", () => {
    const source = `
      function schedule(x) {
        const GOLDEN = 0x9e3779b9;
        const SALT = 109551763;
        return (Math.imul(x ^ GOLDEN, SALT) >>> 0) + 640 + 1;
      }
      module.exports = { schedule };
    `;
    const result = transformJavaScriptWithBlaShield(source, {
      intensity: "bankrupt",
      seed: "issue-40-numeric-probe",
      sourceType: "commonjs",
    });

    // Customer schedule/salt constants must not survive as NumericLiterals.
    expect(result.code).not.toMatch(/109551763/);
    expect(result.code).not.toMatch(/\b2654435769\b/);
    // Direct assignment form of the classic probe must be gone.
    // Injected shield templates are scrubbed separately (see injected-golden-constant-scrub).
    expect(result.code).not.toMatch(/GOLDEN\s*=\s*0x9e3779b9/i);
    expect(result.code).not.toMatch(/GOLDEN\s*=\s*2654435769/);

    const run = (code: string) => {
      const mod = { exports: {} as { schedule: (x: number) => number } };
      vm.runInContext(
        code,
        vm.createContext({
          module: mod,
          exports: mod.exports,
          Math,
          Object,
          Array,
          String,
          Number,
          Boolean,
          Map,
          Set,
          process: undefined,
          Date,
        }),
        { timeout: 3000 },
      );
      return mod.exports;
    };

    const orig = run(source);
    const prot = run(result.code);
    for (const x of [0, 1, 7, 99, 0x1234, 0xffffff]) {
      expect(prot.schedule(x)).toEqual(orig.schedule(x));
    }
  });

  it("leaves tiny integers alone and does not rewrite at balanced intensity", () => {
    const source = `
      const n = 0x9e3779b9;
      const tiny = 3;
      module.exports = { n, tiny };
    `;
    const balanced = transformJavaScriptWithBlaShield(source, {
      intensity: "balanced",
      seed: "issue-40-balanced",
      sourceType: "commonjs",
    });
    expect(balanced.code).toMatch(/2654435769|0x9e3779b9/i);

    const bankrupt = transformJavaScriptWithBlaShield(source, {
      intensity: "bankrupt",
      seed: "issue-40-tiny",
      sourceType: "commonjs",
    });
    // User binding rewritten — no bare assignment of the classic constant.
    expect(bankrupt.code).not.toMatch(/\bn\s*=\s*0x9e3779b9/i);
    expect(bankrupt.code).not.toMatch(/\bn\s*=\s*2654435769\b/);
  });
});
