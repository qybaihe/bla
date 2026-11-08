import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runInNewContext } from "node:vm";
import { afterEach, describe, expect, it } from "vitest";
import {
  transformJavaScriptWithBlaShield,
  InvalidJavaScriptCarrierError,
} from "../src/shields/javascript/ast-shield.js";
import { protectTarget } from "../src/engine/protector.js";
import { verifyTarget } from "../src/engine/verifier.js";
import { formatVerificationReport } from "../src/ui/reporter.js";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function executeCjs(source: string, args: readonly unknown[] = []): unknown {
  const module = { exports: undefined as unknown };
  const context = {
    module,
    exports: {},
    Math,
    Date,
    Array,
    Object,
    Number,
    String,
    Boolean,
    Map,
    Set,
    JSON,
  };
  runInNewContext(source, context, { timeout: 3500 });
  const exported = module.exports;
  if (typeof exported !== "function") throw new Error("expected function export");
  return exported(...args);
}

const fixtures = [
  {
    name: "direct eval reads local bindings",
    source: `function calculate() {
      const secretValue = 40;
      return eval("secretValue + 2");
    }
    module.exports = calculate;`,
    expected: 42,
  },
  {
    name: "direct eval updates local bindings",
    source: `function calculate() {
      let value = 99;
      eval("value += 3");
      return value;
    }
    module.exports = calculate;`,
    expected: 102,
  },
  {
    name: "direct eval accesses an outer closure",
    source: `function outer() {
      const outside = 20;
      return function inner() { return eval("outside * 2 + 2"); };
    }
    module.exports = outer();`,
    expected: 42,
  },
  {
    name: "user-defined Math parameter does not capture injected predicates",
    source: `function calculate(Math) {
      const salt = 123456;
      return salt + 1;
    }
    module.exports = calculate;`,
    args: [{}],
    expected: 123457,
  },
  {
    name: "user-defined module-level Math does not cause injected TDZ",
    source: `const Math = { custom: 5 };
    function calculate() {
      const salt = 123456;
      return salt + 1;
    }
    module.exports = calculate;`,
    expected: 123457,
  },
  {
    name: "function names remain observable",
    source: `function licenceValidator() {}
    module.exports = () => licenceValidator.name;`,
    expected: "licenceValidator",
  },
  {
    name: "class names remain observable",
    source: `class LocalStore {}
    module.exports = () => (new LocalStore()).constructor.name;`,
    expected: "LocalStore",
  },
  {
    name: "inferred names on function expressions remain observable",
    source: `const validateLicense = function () {};
    module.exports = () => validateLicense.name;`,
    expected: "validateLicense",
  },
  {
    name: "inferred names on arrow functions remain observable",
    source: `const performAudit = () => 1;
    module.exports = () => performAudit.name;`,
    expected: "performAudit",
  },
  {
    name: "computed function name reflection remains observable",
    source: `function verifyPolicy() {}
    module.exports = () => verifyPolicy["name"];`,
    expected: "verifyPolicy",
  },
  {
    name: "alias function name reflection retains original declaration name",
    source: `function tokenAudit() {}
    const alias = tokenAudit;
    module.exports = () => alias.name;`,
    expected: "tokenAudit",
  },
  {
    name: "constructor name through an instance binding remains observable",
    source: `class PrivateStore {}
    const instance = new PrivateStore();
    module.exports = () => instance.constructor.name;`,
    expected: "PrivateStore",
  },
  {
    name: "getOwnPropertyDescriptor name reflection is preserved",
    source: `function verifySeat() {}
    module.exports = () => Object.getOwnPropertyDescriptor(verifySeat, "name").value;`,
    expected: "verifySeat",
  },
] as const;

describe("issue #154: protected JS must preserve runtime behaviour", () => {
  for (const intensity of ["balanced", "bankrupt"] as const) {
    for (const fixture of fixtures) {
      it(`${fixture.name} (${intensity})`, () => {
        const original = executeCjs(fixture.source, "args" in fixture ? fixture.args : []);
        expect(original).toBe(fixture.expected);
        const result = transformJavaScriptWithBlaShield(fixture.source, {
          intensity,
          sourceType: "commonjs",
          seed: "issue-154-runtime-equivalence",
        });
        expect(executeCjs(result.code, "args" in fixture ? fixture.args : [])).toBe(original);
      });
    }
  }

  it("refuses an imported Math binding that cannot safely be rewritten", () => {
    expect(() =>
      transformJavaScriptWithBlaShield(
        'import { createMagic as Math } from "some-math"; export const result = Math;',
        { intensity: "balanced", sourceType: "module", seed: "issue-154-math-import" },
      ),
    ).toThrow(InvalidJavaScriptCarrierError);
  });

  it("public protectTarget leaves no output for unsupported imported Math", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-issue154-math-"));
    dirs.push(dir);
    const source = join(dir, "original.mjs");
    const output = join(dir, "protected.mjs");
    writeFileSync(source, 'import { createMagic as Math } from "some-math"; export const result = Math;\n');
    expect(() =>
      protectTarget({ inputPath: source, outputPath: output, intensity: "balanced", seed: "issue-154-import" }),
    ).toThrow(InvalidJavaScriptCarrierError);
    expect(existsSync(output)).toBe(false);
  });

  it("refuses a direct eval scope whose Math binding cannot be renamed", () => {
    const source = 'function f(Math) { return eval("Math.custom + 1"); } module.exports = f;';
    expect(executeCjs(source, [{ custom: 9 }])).toBe(10);
    expect(() =>
      transformJavaScriptWithBlaShield(source, {
        intensity: "bankrupt",
        sourceType: "commonjs",
        seed: "issue-154-eval-math",
      }),
    ).toThrow(InvalidJavaScriptCarrierError);
  });
});

describe("issue #154: verifier is explicit about absence of executable parity evidence", () => {
  it("never claims functional integrity from static parsing of a protected artifact", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-issue154-"));
    dirs.push(dir);
    const source = join(dir, "original.cjs");
    const output = join(dir, "protected.cjs");
    writeFileSync(source, "module.exports = () => 3 + 4;\n");
    protectTarget({
      inputPath: source,
      outputPath: output,
      intensity: "balanced",
      seed: "issue-154-verify-honesty",
    });
    expect(readFileSync(output, "utf8").length).toBeGreaterThan(0);

    const report = verifyTarget(output, source);
    expect(report.overallPassed).toBe(true);
    expect(report.functionalIntegrityVerified).toBe(false);
    expect(report.runtimeEquivalence?.status).toBe("not-tested");
    expect(report.verificationScope).toBe("counter-rea-structural");
    expect(formatVerificationReport(report)).toContain("NOT VERIFIED");
  });
});
