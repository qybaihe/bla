import { describe, expect, it } from "vitest";
import * as vm from "node:vm";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";

function runCommonJs<T extends Record<string, unknown>>(
  code: string,
): T {
  const mod = { exports: {} as T };
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
      WeakMap,
      WeakSet,
      Promise,
      Error,
      TypeError,
      RangeError,
      JSON,
      Date,
      parseInt,
      parseFloat,
      isNaN,
      isFinite,
      undefined,
      NaN,
      Infinity,
      console,
      process: undefined,
      Buffer: undefined,
      require: undefined,
      globalThis: {},
    }),
    { timeout: 5000 },
  );
  return mod.exports;
}

describe("Issue #40: class/new rename consistency + deterministic opaque seed", () => {
  it("keeps ClassDeclaration name in sync with new/identifier refs at bankrupt", () => {
    const source = `
      class Foo {
        value() { return 42; }
        static self() { return Foo; }
      }
      function make() {
        return new Foo().value();
      }
      function sameRef() {
        return Foo.self() === Foo;
      }
      module.exports = { make, sameRef };
    `;
    const result = transformJavaScriptWithBlaShield(source, {
      intensity: "bankrupt",
      seed: "issue-40-class-rename",
      sourceType: "commonjs",
    });

    expect(result.code).not.toMatch(/\bclass\s+Foo\b/);
    expect(result.code).not.toMatch(/\bnew\s+Foo\b/);
    expect(result.code).not.toMatch(/hrtime/);
    expect(result.code).not.toMatch(/Date\.now\s*\(/);

    const orig = runCommonJs<{ make: () => number; sameRef: () => boolean }>(source);
    const prot = runCommonJs<{ make: () => number; sameRef: () => boolean }>(
      result.code,
    );
    expect(prot.make()).toBe(orig.make());
    expect(prot.sameRef()).toBe(true);
  });

  it("keeps nested ClassDeclaration usable via new after rename", () => {
    const source = `
      function factory(n) {
        class Bar {
          constructor(x) { this.x = x; }
          twice() { return this.x * 2; }
        }
        return new Bar(n).twice();
      }
      module.exports = { factory };
    `;
    const result = transformJavaScriptWithBlaShield(source, {
      intensity: "bankrupt",
      seed: "issue-40-nested-class",
      sourceType: "commonjs",
    });
    const orig = runCommonJs<{ factory: (n: number) => number }>(source);
    const prot = runCommonJs<{ factory: (n: number) => number }>(result.code);
    for (const n of [0, 1, 7, 99]) {
      expect(prot.factory(n)).toBe(orig.factory(n));
    }
  });

  it("emits a deterministic opaque-predicate seed for the same harden seed", () => {
    const source = `
      function id(x) { return x ^ 1; }
      module.exports = { id };
    `;
    const a = transformJavaScriptWithBlaShield(source, {
      intensity: "maximum",
      seed: "issue-40-opaque-seed-stable",
      sourceType: "commonjs",
    });
    const b = transformJavaScriptWithBlaShield(source, {
      intensity: "maximum",
      seed: "issue-40-opaque-seed-stable",
      sourceType: "commonjs",
    });
    expect(a.code).toBe(b.code);
    expect(a.code).not.toMatch(/hrtime/);
    expect(a.code).not.toMatch(/Date\.now\s*\(/);
    // Seed initializer: deterministic numeric base OR'd with digest-check bit (Babel may drop parens).
    expect(a.code).toMatch(
      /const\s+\w+\s*=\s*\d+\s*\|\s*\(typeof\s+\w+\s*===\s*"function"/,
    );

    const orig = runCommonJs<{ id: (x: number) => number }>(source);
    const prot = runCommonJs<{ id: (x: number) => number }>(a.code);
    expect(prot.id(41)).toBe(orig.id(41));
  });
});
