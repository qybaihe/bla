/**
 * Functional-equivalence regressions for the JavaScript shield.
 *
 * Every case here is a program whose hardened form once behaved differently
 * from the original (QA differential fuzzing of bla-agents 3.4.3). Each test
 * runs the original and the hardened program the way its host would — as a
 * CommonJS module, as classic scripts sharing one realm, or as ES modules under
 * `node` — and compares what they produce.
 *
 * A few groups also pin what must (or must not) be in the hardened text:
 * licence notices stay, strings inside template substitutions do not, and a
 * bundle-sized input has to harden in time proportional to its size.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { parse } from "@babel/parser";
import ts from "typescript";
import { afterAll, describe, expect, it } from "vitest";
import {
  InvalidJavaScriptCarrierError,
  transformJavaScriptWithBlaShield,
  type JsCarrierType,
} from "../src/shields/javascript/ast-shield.js";
import type { ProtectionIntensity } from "../src/core/types.js";

const SEED = "fuzz-regression-js";
const ALL: readonly ProtectionIntensity[] = ["stealth", "balanced", "maximum", "bankrupt"];
/** Literal rewriting (strings, templates, integers, `&|^`) only exists at these two. */
const LITERAL_REWRITING: readonly ProtectionIntensity[] = ["maximum", "bankrupt"];

const nodeRequire = createRequire(import.meta.url);
const tempDirs: string[] = [];
afterAll(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

interface HardenOptions {
  readonly filename?: string;
  readonly sourceType?: JsCarrierType;
  readonly seed?: string;
}

function harden(source: string, intensity: ProtectionIntensity, options: HardenOptions = {}) {
  return transformJavaScriptWithBlaShield(source, {
    intensity,
    seed: options.seed ?? SEED,
    ...(options.filename !== undefined ? { filename: options.filename } : {}),
    ...(options.sourceType !== undefined ? { sourceType: options.sourceType } : {}),
  });
}

/** Evaluate `code` the way Node's CommonJS loader does: as the body of the module wrapper. */
function runCommonJs(code: string): unknown {
  const module = { exports: {} as unknown };
  const wrapper = new Function("exports", "require", "module", "__filename", "__dirname", code);
  wrapper.call(module.exports, module.exports, nodeRequire, module, "/virtual/fixture.js", "/virtual");
  return module.exports;
}

/** Load classic scripts into one realm, like consecutive `<script>` tags of a page. */
function loadScripts(...scripts: readonly string[]): vm.Context {
  const context = vm.createContext({});
  for (const script of scripts) vm.runInContext(script, context);
  return context;
}

/** Write an ES module graph to a scratch directory and run its entry with `node`. */
function runEsm(files: Readonly<Record<string, string>>, entry: string): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-fuzz-regression-"));
  tempDirs.push(dir);
  for (const [name, code] of Object.entries(files)) {
    mkdirSync(join(dir, name, ".."), { recursive: true });
    writeFileSync(join(dir, name), code, "utf8");
  }
  const run = spawnSync(process.execPath, [entry], { cwd: dir, encoding: "utf8", timeout: 20_000 });
  return `${run.stdout}[exit ${run.status}]${run.status === 0 ? "" : run.stderr.split("\n").find((line) => /Error/.test(line)) ?? ""}`;
}

const json = (value: unknown): string => JSON.stringify(value);

describe("06 template literals keep ToString semantics", () => {
  const source = `
    class Money {
      constructor(cents) { this.cents = cents; }
      valueOf() { return this.cents; }
      toString() { return '$' + (this.cents / 100).toFixed(2); }
    }
    const hints = [];
    const spy = { [Symbol.toPrimitive](hint) { hints.push(hint); return 'spy'; } };
    const order = [];
    const tap = (label, value) => { order.push(label); return value; };
    const tag = (strings, ...values) => strings.raw.join('|') + '#' + values.length;
    const sequence = \`\${tap('first', 1)} then \${tap('second', 2)} and finally \${tap('third', 3)}\`;
    module.exports = {
      total: \`Total due: \${new Money(1999)}\`,
      elapsed: \`Elapsed: \${{ valueOf: () => 90061000, toString: () => '1d 1h 1m 1s' }} (approx)\`,
      spied: \`spy says \${spy} and again \${spy}!\`,
      hints,
      sequence,
      order,
      tagged: tag\`raw \\n text \${1} and more \${2}\`,
      raw: String.raw\`C:\\new\\table \${'x'}\`,
      nested: \`outer \${\`inner \${new Money(5)} done\`} end\`,
      symbol: (() => { try { return \`sym \${Symbol('s')}\`; } catch (e) { return e.name; } })(),
      multiline: \`line one
line two \${1 + 1}
line three\`,
      escapes: \`tab\\there \\u00e9 \\x41 \${'q'} \\\${not} \\\`tick\\\`\`,
    };
  `;
  const expected = json(runCommonJs(source));

  for (const intensity of LITERAL_REWRITING) {
    it(`value objects print through toString, in order (${intensity})`, () => {
      expect(expected).toContain("Total due: $19.99");
      const result = harden(source, intensity, { sourceType: "commonjs" });
      expect(json(runCommonJs(result.code))).toBe(expected);
      // The static text is still encoded, not left in a backtick chunk.
      expect(result.code).not.toContain("Total due");
    });
  }
});

describe("02 classic scripts keep their globals", () => {
  const vendor = `
    var MyLib = (function () {
      function greet(who) { return 'hello ' + who; }
      return { greet: greet };
    })();
    const LIB_VERSION = '1.2.3';
    let libCounter = 41;
    class Widget { render() { return '<widget/>'; } }
    function helper(n) { return n * 2; }
    for (var loopIndex = 0; loopIndex < 3; loopIndex++) { libCounter += 0; }
  `;
  const probe = `[typeof MyLib, typeof LIB_VERSION, typeof libCounter, typeof Widget, typeof helper,
    typeof loopIndex, MyLib.greet('page'), LIB_VERSION, ++libCounter, new Widget().render(),
    helper(21), Widget.name, helper.name].join(' | ')`;
  const expected = vm.runInContext(probe, loadScripts(vendor));

  const dualMode = `
    function MyLib(name) { return 'hello ' + name; }
    MyLib.version = '1.2.3';
    if (typeof module !== 'undefined' && module.exports) { module.exports = MyLib; }
  `;
  const umd = `
    (function (root, factory) {
      if (typeof define === 'function' && define.amd) { define([], factory); }
      else if (typeof module === 'object' && module.exports) { module.exports = factory(); }
      else { root.UmdLib = factory(); }
    }(typeof self !== 'undefined' ? self : this, function () {
      function greet(name) { return 'umd ' + name; }
      return { greet: greet };
    }));
    var umdTopLevel = 'still a global';
  `;
  const dualProbe = `typeof MyLib === 'function' ? MyLib('page') + ' v' + MyLib.version : 'MyLib is not defined'`;
  const umdProbe = `[typeof UmdLib === 'object' ? UmdLib.greet('page') : 'UmdLib is not defined', typeof umdTopLevel].join(' | ')`;

  for (const intensity of ALL) {
    it(`var / let / const / class / function stay reachable from the next script (${intensity})`, () => {
      expect(expected).toContain("hello page");
      const result = harden(vendor, intensity, { filename: "vendor.js" });
      expect(result.carrierType).toBe("script");
      expect(vm.runInContext(probe, loadScripts(result.code))).toBe(expected);
    });

    it(`a UMD / dual-mode file works as a script and as a module (${intensity})`, () => {
      const dual = harden(dualMode, intensity, { filename: "mylib.js" });
      expect(dual.carrierType).toBe("script");
      expect(vm.runInContext(dualProbe, loadScripts(dual.code))).toBe("hello page v1.2.3");
      expect((runCommonJs(dual.code) as (name: string) => string)("node")).toBe("hello node");

      const wrapped = harden(umd, intensity, { filename: "umd.js" });
      expect(wrapped.carrierType).toBe("script");
      expect(vm.runInContext(umdProbe, loadScripts(wrapped.code))).toBe("umd page | string");
      expect((runCommonJs(wrapped.code) as { greet(name: string): string }).greet("node")).toBe("umd node");
    });
  }

  it("unguarded require / module / exports, .cjs and a top-level return still mean CommonJS", () => {
    const carrier = (source: string, filename: string): string =>
      harden(source, "stealth", { filename }).carrierType;
    expect(carrier("const fs = require('fs');\nvar x = fs.constants;\n", "a.js")).toBe("commonjs");
    expect(carrier("function f() { return 1; }\nmodule.exports = f;\n", "b.js")).toBe("commonjs");
    expect(carrier("exports.answer = 42;\n", "c.js")).toBe("commonjs");
    expect(carrier("var onlyGlobals = 1;\n", "d.cjs")).toBe("commonjs");
    expect(carrier("if (globalThis.skip) return;\nvar late = 1;\n", "e.js")).toBe("commonjs");
    // A real top-level require wins over an environment check elsewhere in the file.
    expect(
      carrier(
        "const path = require('path');\nif (typeof module !== 'undefined') module.exports = path.sep;\n",
        "f.js",
      ),
    ).toBe("commonjs");
    // `require` / `module` / `exports` as wrapper parameters are not the CommonJS free variables.
    expect(
      carrier(
        "var bundle = (function (require, module, exports) { module.exports = require('x'); });\n",
        "g.js",
      ),
    ).toBe("script");
    // AMD's page-level loader is not CommonJS either.
    expect(carrier("var App = {};\nrequire(['dep'], function (dep) { App.dep = dep; });\n", "h.js")).toBe(
      "script",
    );
  });
});

describe("05 hardened classic scripts can share a realm", () => {
  const vendor = "function vendorHelper(n) { return n * 2; }\n";
  const app = "function appMain() { return vendorHelper(21); }\n";

  for (const intensity of ALL) {
    it(`two scripts hardened with one seed load side by side (${intensity})`, () => {
      const first = harden(vendor, intensity, { filename: "vendor.js" });
      const second = harden(app, intensity, { filename: "app.js" });
      const context = loadScripts(first.code, second.code);
      expect(vm.runInContext("appMain()", context)).toBe(42);
      // The same script twice is legal un-hardened (it only has `var` / function
      // declarations), so it has to stay legal.
      expect(vm.runInContext("vendorHelper(4)", loadScripts(first.code, first.code))).toBe(8);
      // No lexical declaration is left at program level to collide on.
      const topLevel = parse(first.code, { sourceType: "script" }).program.body;
      expect(
        topLevel.filter((stmt) => stmt.type === "VariableDeclaration" && stmt.kind !== "var"),
      ).toEqual([]);
      expect(topLevel.filter((stmt) => stmt.type === "ClassDeclaration")).toEqual([]);
    });
  }

  it("output stays deterministic for one (source, seed) and is named per source", () => {
    const a = harden(vendor, "balanced", { filename: "vendor.js" });
    expect(harden(vendor, "balanced", { filename: "vendor.js" }).code).toBe(a.code);
    const b = harden(app, "balanced", { filename: "app.js" });
    const declared = (code: string): string[] =>
      parse(code, { sourceType: "script" }).program.body.flatMap((stmt) =>
        stmt.type === "FunctionDeclaration" && stmt.id
          ? [stmt.id.name]
          : stmt.type === "VariableDeclaration"
            ? stmt.declarations.flatMap((d) => (d.id.type === "Identifier" ? [d.id.name] : []))
            : [],
      );
    const namesA = new Set(declared(a.code));
    const namesB = declared(b.code);
    expect(namesB.length).toBeGreaterThan(40);
    // With one seed these used to be the same names in every file. A few short
    // tags may still coincide; that is harmless now that none is lexical.
    const shared = namesB.filter((name) => namesA.has(name));
    expect(shared.length).toBeLessThan(namesB.length / 10);
  });
});

describe("01 a function's source text can be evaluated elsewhere", () => {
  const source = `
    'use strict';
    const vm = require('node:vm');
    function double(n) { return n * 2; }
    const label = (n) => 'value-is-' + n;
    const sumTo = function (n) { let s = 0; for (let i = 1; i <= n; i++) s += i; return s; };
    const withDefault = function (greeting = 'default-greeting', n = 4096) { return greeting + ':' + n; };
    class Counter { step = 'step-label-'; next(n) { return this.step + (n + 1); } }
    function outer(k) { function inner(v) { return 'inner:' + v; } return inner.toString(); }
    const elsewhere = (text) => new Function('return (' + text + ')')();
    module.exports = {
      direct: [double(21), label(7), sumTo(100), withDefault(), new Counter().next(1)],
      cloned: [
        elsewhere(double.toString())(21),
        elsewhere(label.toString())(7),
        elsewhere(sumTo.toString())(100),
        elsewhere(withDefault.toString())(),
        new (elsewhere(Counter.toString()))().next(1),
        elsewhere(outer(1))('nested'),
      ],
      sandboxed: vm.runInNewContext('(' + sumTo.toString() + ')(10)'),
      indirect: (0, eval)('(' + double.toString() + ')')(4),
    };
  `;
  const expected = json(runCommonJs(source));

  for (const intensity of ALL) {
    it(`new Function / vm / indirect eval of fn.toString() still work (${intensity})`, () => {
      expect(expected).toContain("default-greeting:4096");
      const result = harden(source, intensity, { sourceType: "commonjs" });
      expect(json(runCommonJs(result.code))).toBe(expected);
    });
  }
});

describe("03 / 16 ES modules: import cycles and lazy chunks", () => {
  const files = {
    "a.mjs": `
      import { early, earlyList } from './b.mjs';
      export function helperFromA(x, label = 'default-label-from-a') {
        const fmt = (v) => 'formatted<' + v + '>';
        if (x === 'boom') { return 'never-taken-branch'; }
        return 'A(' + fmt(x) + ':' + label + ':' + 4242 + ')';
      }
      export function listFromA(n = 3) { return Array.from({ length: n }, (_, i) => \`item-\${i}-of-\${n}\`); }
      function privateHelper(v) { return 'private:' + v; }
      export function viaPrivate(v) { return privateHelper(v) + '|' + privateHelper.name; }
      export async function load() { const mod = await import('./lazy.mjs'); return mod.default; }
      console.log(early);
      console.log(earlyList.join(','));
      console.log(helperFromA('late call'), viaPrivate('late'), await load());
    `,
    "b.mjs": `
      import { helperFromA, listFromA, viaPrivate } from './a.mjs';
      export const early = helperFromA('called before the body of a.mjs ran') + ' / ' + viaPrivate('early').split('|')[0];
      export const earlyList = listFromA();
    `,
    "lazy.mjs": `export default 'lazy chunk loaded';\n`,
  };
  const expected = runEsm(files, "a.mjs");

  for (const intensity of ALL) {
    it(`a hoisted export called through a cycle runs before its module body (${intensity})`, () => {
      expect(expected).toContain("A(formatted<called before the body of a.mjs ran>:default-label-from-a:4242)");
      expect(expected).toContain("lazy chunk loaded");
      const hardened = Object.fromEntries(
        Object.entries(files).map(([name, code]) => [name, harden(code, intensity, { filename: name }).code]),
      );
      expect(runEsm(hardened, "a.mjs")).toBe(expected);
      // 16: the import() specifier is still a literal a bundler can follow.
      let literalSpecifiers = 0;
      const stack: unknown[] = [parse(hardened["a.mjs"]!, { sourceType: "module" }).program];
      while (stack.length > 0) {
        const node = stack.pop();
        if (node === null || typeof node !== "object") continue;
        const record = node as Record<string, unknown>;
        if (record.type === "ImportExpression") {
          const specifier = record.source as { type?: string; value?: string };
          if (specifier.type === "StringLiteral" && specifier.value === "./lazy.mjs") literalSpecifiers++;
        }
        for (const [key, child] of Object.entries(record)) {
          if (key === "loc" || key === "leadingComments" || key === "trailingComments") continue;
          if (Array.isArray(child)) stack.push(...child);
          else if (child !== null && typeof child === "object") stack.push(child);
        }
      }
      expect(literalSpecifiers).toBe(1);
    });
  }
});

describe("07 / 13 bitwise operators on values that are not int32 Numbers", () => {
  const bigint = `
    'use strict';
    function lowestSetBit(mask) { return mask & -mask; }
    function withFlag(mask, flag) { return mask | flag; }
    function toggled(mask, flag) { return mask ^ flag; }
    function masked(mask, flag) { return mask & flag; }
    const buf = Buffer.alloc(8);
    buf.writeUInt32LE(40, 0);
    const wide = buf.readBigUInt64LE(0);
    const attempt = (fn) => { try { return String(fn()); } catch (e) { return e.name; } };
    module.exports = [
      lowestSetBit(40), withFlag(40, 1), toggled(40, 8), masked(-1, 255),
      attempt(() => lowestSetBit(wide)), attempt(() => withFlag(wide, wide)),
      attempt(() => toggled(wide, wide)), attempt(() => masked(wide, wide)),
      attempt(() => withFlag(wide, 1)), attempt(() => toggled(1, wide)),
      withFlag('9', 6), toggled(null, 3), masked(undefined, 1), withFlag(2.9, 1.2),
      toggled(NaN, 5), masked(2 ** 40 + 7, 15), withFlag(-0, -0), toggled(Infinity, 1),
    ].map(String);
  `;
  const coercion = `
    'use strict';
    function probe() {
      let reads = 0;
      const sensor = { valueOf() { reads++; return 12; } };
      const first = sensor ^ 5;
      let seq = 0;
      const next = { valueOf() { return ++seq; } };
      const second = [next | 4, next & 6];
      const order = [];
      const left = { valueOf() { order.push('L'); return 6; } };
      const right = { valueOf() { order.push('R'); return 3; } };
      const third = [left ^ right, left | right, left & right];
      return { first, reads, second, seq, third, order: order.join('') };
    }
    module.exports = probe();
  `;
  const expectedBigint = json(runCommonJs(bigint));
  const expectedCoercion = json(runCommonJs(coercion));

  for (const intensity of LITERAL_REWRITING) {
    it(`BigInt operands that come from an API keep working (${intensity})`, () => {
      expect(expectedBigint).toContain('"40"');
      const result = harden(bigint, intensity, { sourceType: "commonjs" });
      expect(json(runCommonJs(result.code))).toBe(expectedBigint);
    });

    it(`each operand is converted exactly once, left to right (${intensity})`, () => {
      expect(expectedCoercion).toContain('"reads":1');
      const result = harden(coercion, intensity, { sourceType: "commonjs" });
      expect(json(runCommonJs(result.code))).toBe(expectedCoercion);
    });
  }
});

describe("09 numeric member keys", () => {
  const source = `
    'use strict';
    const handlers = {
      200() { return 'OK'; },
      get 404() { return 'Not Found'; },
      set 500(value) { this.last = value; },
      301: 'Moved',
      [600 + 6]: 'computed',
    };
    class Opcodes { static 32 = 'space'; 65() { return 'A'; } static 100() { return 'd'; } 255 = 'field'; }
    handlers[500] = 'stored';
    module.exports = [handlers[200](), handlers[404], handlers.last, handlers[301], handlers[606],
      Opcodes[32], new Opcodes()[65](), Opcodes[100](), new Opcodes()[255], Object.keys(handlers).join(',')];
  `;
  const expected = json(runCommonJs(source));

  for (const intensity of LITERAL_REWRITING) {
    it(`integer keys of methods, accessors and class fields are left alone (${intensity})`, () => {
      expect(expected).toContain("Not Found");
      const result = harden(source, intensity, { sourceType: "commonjs" });
      expect(json(runCommonJs(result.code))).toBe(expected);
    });
  }
});

describe("10 string module export names", () => {
  const files = {
    "lib.mjs": `
      function impl(n) { return n * 21; }
      const answer = 'forty-two';
      export { impl as "module.exports", impl as "kebab-case-name", answer as "the answer" };
      export * as "name space" from './other.mjs';
    `,
    "other.mjs": `export const marker = 'other-module-marker';\n`,
    "main.mjs": `
      import { "kebab-case-name" as kebab, "the answer" as answer, "name space" as ns } from './lib.mjs';
      import * as all from './lib.mjs';
      console.log(kebab(2), answer, ns.marker, Object.keys(all).sort().join(','));
    `,
  };
  const expected = runEsm(files, "main.mjs");

  for (const intensity of LITERAL_REWRITING) {
    it(`export { x as "…" } / import { "…" as y } / export * as "…" survive (${intensity})`, () => {
      expect(expected).toContain("42 forty-two other-module-marker");
      const hardened = Object.fromEntries(
        Object.entries(files).map(([name, code]) => [name, harden(code, intensity, { filename: name }).code]),
      );
      expect(runEsm(hardened, "main.mjs")).toBe(expected);
    });
  }
});

describe("11 CommonJS top-level return", () => {
  const gated = `
    'use strict';
    const log = globalThis.__fuzzLog;
    log.push('start');
    function later(tag) { return 'called-later:' + tag; }
    module.exports = { later };
    if (!globalThis.__fuzzFeature) {
      log.push('feature disabled, leaving the module early');
      return;
    }
    log.push('feature enabled');
    module.exports.extra = 'only-when-enabled';
  `;
  // No require / module / exports at all: the return alone decides the carrier.
  const bare = `
    'use strict';
    globalThis.__fuzzLog.push('bare start');
    if (!globalThis.__fuzzFeature) { return; }
    globalThis.__fuzzLog.push('bare end');
  `;
  const scope = globalThis as { __fuzzLog?: string[]; __fuzzFeature?: boolean };
  const observe = (code: string, feature: boolean): string => {
    scope.__fuzzLog = [];
    scope.__fuzzFeature = feature;
    try {
      const exported = runCommonJs(code) as { later?: (tag: string) => string; extra?: string };
      // A function exported before the early return is called after it.
      return json([scope.__fuzzLog, exported.later?.("x"), exported.extra]);
    } finally {
      delete scope.__fuzzLog;
      delete scope.__fuzzFeature;
    }
  };

  for (const intensity of ALL) {
    it(`both sides of the early return behave like the original (${intensity})`, () => {
      const result = harden(gated, intensity, { filename: "gate.cjs" });
      expect(result.carrierType).toBe("commonjs");
      expect(observe(result.code, false)).toBe(observe(gated, false));
      expect(observe(result.code, true)).toBe(observe(gated, true));
      expect(observe(gated, false)).toContain("leaving the module early");

      const plain = harden(bare, intensity, { filename: "bare.js" });
      expect(plain.carrierType).toBe("commonjs");
      expect(observe(plain.code, false)).toBe(observe(bare, false));
      expect(observe(plain.code, true)).toBe(observe(bare, true));
    });
  }

  it("is still refused where no runtime accepts it", () => {
    expect(() => harden("export const a = 1;\nif (a) return;\n", "stealth")).toThrow(
      InvalidJavaScriptCarrierError,
    );
    expect(() => harden("if (self.skip) return;\n", "stealth", { sourceType: "script" })).toThrow(
      InvalidJavaScriptCarrierError,
    );
  });
});

describe("08 renamed identifiers stay identifiers", () => {
  const source = `
    'use strict';
    const swap = (s) => s.replace(/(\\w+)@(\\w+)/, ($0, $1, $2) => $2 + ' at ' + $1);
    function pad($1, width) { return String($1).padStart(width, '0'); }
    function mix(_0x1f2e, _0, $, π2, $$9lives, _$1) { return [_0x1f2e, _0, $, π2, $$9lives, _$1].join('-'); }
    module.exports = [swap('user@example'), pad(7, 3), mix(1, 2, 3, 4, 5, 6)];
  `;
  const expected = json(runCommonJs(source));

  for (const intensity of ["stealth", "balanced"] as const) {
    it(`names such as $1, _0x1f and π2 are renamed to valid identifiers (${intensity})`, () => {
      expect(expected).toContain("example at user");
      const result = harden(source, intensity, { sourceType: "commonjs" });
      expect(() => parse(result.code, { sourceType: "script" })).not.toThrow();
      expect(json(runCommonJs(result.code))).toBe(expected);
    });
  }
});

describe("04 / 14 / 15 sloppy-mode scoping", () => {
  const annexB = `
    function outer(flag) {
      if (flag) { function inner() { return 'inner-from-block'; } }
      return typeof inner === 'function' ? inner() : 'inner missing';
    }
    if (typeof process !== 'undefined') { function report(msg) { return 'report:' + msg; } }
    if (process.argv.length > 99) { function pick() { return 'A'; } } else { function pick() { return 'B'; } }
    switch (1) { case 1: function fromCase() { return 'case-level'; } }
    module.exports = [outer(true), outer(false), report('visible outside the block'), pick(), fromCase()];
  `;
  const duplicateParams = `
    function pick(a, a, b) { return a + ':' + b; }
    function shadowed(value, value) { var value; return typeof value + ':' + value; }
    module.exports = [pick(1, 2, 3), shadowed('first', 'second')];
  `;
  const catchVar = `
    function probe() {
      try { throw 'thrown'; } catch (e) { var e = 'assigned-in-catch'; }
      return typeof e + ':' + e;
    }
    function loop() {
      try { throw { k: 1 }; } catch (err) { for (var err in { fromLoop: 1 }) { } }
      return typeof err;
    }
    module.exports = [probe(), loop()];
  `;
  const withScope = `
    function lookup(scopeObject) {
      var title = 'local-title';
      var missing = 'local-missing';
      with (scopeObject) { return title + '/' + missing; }
    }
    module.exports = lookup({ title: 'object-title' });
  `;
  const cases: ReadonlyArray<readonly [string, string, string]> = [
    ["04 a block-level function is visible after its block (Annex B.3.3)", annexB, "report:visible outside the block"],
    ["14 the last duplicate parameter wins", duplicateParams, "2:3"],
    ["15 var inside catch (e) assigns the catch parameter (Annex B.3.5)", catchVar, "undefined:undefined"],
    ["names looked up through `with` are not renamed", withScope, "object-title/local-missing"],
  ];

  for (const [title, source, marker] of cases) {
    const expected = json(runCommonJs(source));
    for (const intensity of ALL) {
      it(`${title} (${intensity})`, () => {
        expect(expected).toContain(marker);
        const result = harden(source, intensity, { sourceType: "commonjs" });
        expect(json(runCommonJs(result.code))).toBe(expected);
      });
    }
  }
});

describe("23 program-level bindings named like globals the runtime uses", () => {
  // Neither file mentions require / module / exports, so both are classified as
  // scripts — and both also have to work when Node loads them as CommonJS,
  // where the hoisted `var` is still undefined while the injected preamble runs.
  const lodashStyle = `
    'use strict';
    var root = typeof globalThis === 'object' ? globalThis : Function('return this')();
    var Array = root.Array;
    var JSON = root.JSON;
    function check(list) { return Array.isArray(list) + ':' + JSON.stringify(list); }
    globalThis.__fuzzOut = check([1, 2, 3]);
  `;
  const standIn = `
    'use strict';
    var Object = { keys: function (o) { return ['only-keys-is-implemented']; } };
    globalThis.__fuzzOut = Object.keys({ a: 1 }).join();
  `;
  const lexical = `
    'use strict';
    const Map = function FakeMap() { this.fake = 'fake-map'; };
    let String = (value) => 'wrapped:' + value;
    class Boolean { static check() { return 'own-boolean'; } }
    module.exports = [new Map().fake, String(1), Boolean.check()];
  `;
  const scope = globalThis as { __fuzzOut?: unknown };
  const observeCommonJs = (code: string): string => {
    try {
      const exported = runCommonJs(code);
      return json([scope.__fuzzOut, exported]);
    } finally {
      delete scope.__fuzzOut;
    }
  };
  const observeScript = (code: string): string => {
    const context = vm.createContext({});
    vm.runInContext(code, context);
    return String(vm.runInContext("globalThis.__fuzzOut", context));
  };

  for (const intensity of ALL) {
    it(`var Array = root.Array / var Object = {…} / lexical stand-ins (${intensity})`, () => {
      for (const source of [lodashStyle, standIn]) {
        const result = harden(source, intensity, { filename: "vendor.js" });
        expect(observeCommonJs(result.code)).toBe(observeCommonJs(source));
        expect(observeScript(result.code)).toBe(observeScript(source));
      }
      expect(observeCommonJs(lodashStyle)).toContain("true:[1,2,3]");
      expect(observeScript(standIn)).toBe("only-keys-is-implemented");
      const moduleScoped = harden(lexical, intensity, { sourceType: "commonjs" });
      expect(observeCommonJs(moduleScoped.code)).toBe(observeCommonJs(lexical));
    });
  }

  it("fails loudly when the real globals cannot be reached at all", () => {
    expect(() =>
      harden("var globalThis = {};\nvar Array = [];\nvar out = Array.length;\n", "stealth", {
        filename: "odd.js",
      }),
    ).toThrow(InvalidJavaScriptCarrierError);
  });
});

describe("17 the completion value of a script", () => {
  const scripts: ReadonlyArray<readonly [string, string]> = [
    [
      "an object expression in last position",
      `var registry = { name: 'plugin', version: 3 };
       function activate(host) { return 'activated on ' + host; }
       ({ name: registry.name, version: registry.version, activate: activate });`,
    ],
    [
      "a block whose only additions are name restorations",
      `'last expression value';
       { class Inner { } var made = new Inner().constructor.name; }
       if (made) { function tail() { return 1; } var kept = tail.name; }`,
    ],
    [
      "a strict script ending in blocks that declare classes and functions",
      `'use strict';
       'strict last value';
       { class Inner { } var made = new Inner().constructor.name; }
       { function tail() { return 1; } var kept = tail.name + made; }`,
    ],
    ["declarations only", `var counter = 1; function bump() { return ++counter; }`],
  ];
  const describeValue = (value: unknown): string => {
    if (value !== null && typeof value === "object") {
      const record = value as { name?: unknown; version?: unknown; activate?: (host: string) => unknown };
      return json([record.name, record.version, typeof record.activate === "function" ? record.activate("host") : null]);
    }
    // (V8 yields the function itself for a sloppy block-level declaration.)
    if (typeof value === "function") return `function:${(value as { name: string }).name}`;
    return `${typeof value}:${String(value)}`;
  };

  for (const intensity of ALL) {
    it(`vm.runInNewContext returns what the original script returns (${intensity})`, () => {
      for (const [label, source] of scripts) {
        const expected = describeValue(vm.runInNewContext(source, {}));
        const result = harden(source, intensity, { filename: "plugin.js" });
        expect(describeValue(vm.runInNewContext(result.code, {})), label).toBe(expected);
      }
      expect(describeValue(vm.runInNewContext(scripts[0]![1], {}))).toBe('["plugin",3,"activated on host"]');
    });
  }
});

describe("expression-bodied arrow functions", () => {
  // Predicates woven into `x => expr` need a frame seed, and an expression body
  // has no block to declare it in.
  const source = `
    'use strict';
    const formatTotal = (l) => 'total=' + l.total;
    const asyncLabel = async (n) => \`value:\${n}:done\`;
    const nested = (a) => (b) => (c) => 'nested-' + a + '-' + b + '-' + c + '-end';
    const makeRecord = (id) => ({ id, kind: 'record-kind', tags: ['alpha-tag', 'beta-tag'], weight: 4096 });
    const withDefault = (cb = (x) => 'default-arrow:' + x, sep = 'separator') => cb(sep);
    const curried = (prefix = 'prefix-default') => (value) => ({ label: prefix + ':' + value, size: 65536 });
    const numbers = [3, 1, 2].map((n) => n * 1000).filter((n) => n > 1500).map((n) => 'n=' + n);
    class Box { fmt = (v) => 'boxed:' + v; static make = () => new Box(); }
    const table = { render: (row) => 'row<' + row + '>', deep: () => () => 'deep-result' };
    module.exports = (async () => [
      formatTotal({ total: 5 }), await asyncLabel(7), nested(1)(2)(3), makeRecord(9),
      withDefault(), withDefault((x) => x.length), curried()('v'), curried('given')('w'),
      numbers, Box.make().fmt(3), table.render(1), table.deep()(),
      new Function('return (' + formatTotal.toString() + ')')()({ total: 6 }),
      new Function('return (' + nested.toString() + ')')()(4)(5)(6),
      new Function('return (' + makeRecord.toString() + ')')()(1),
    ])();
  `;

  it("plain, async, nested, object-returning and default-parameter arrows", async () => {
    const expected = json(await (runCommonJs(source) as Promise<unknown>));
    expect(expected).toContain("total=5");
    expect(expected).toContain("default-arrow:separator");
    for (const intensity of LITERAL_REWRITING) {
      for (const seed of ["contract-seed", "alpha", "s2"]) {
        const result = harden(source, intensity, { sourceType: "commonjs", seed });
        const actual = json(await (runCommonJs(result.code) as Promise<unknown>));
        expect(actual, `${intensity} / ${seed}`).toBe(expected);
      }
    }
  });
});

describe("licence notices in comments", () => {
  const source = `/*! vendor v1.2.3 | (c) 2019 Jane Doe | MIT License */
'use strict';
// TODO: internal note about the licence check algorithm
/** @license Apache-2.0 */
function split(total) {
  // SPDX-License-Identifier: MIT
  return [Math.floor(total * 0.7), Math.ceil(total * 0.3)];
}
/** Computes the royalty split. */
module.exports = split(1000);
`;
  const notices = [
    "/*! vendor v1.2.3 | (c) 2019 Jane Doe | MIT License */",
    "/** @license Apache-2.0 */",
    "// SPDX-License-Identifier: MIT",
  ];

  for (const intensity of ["stealth", "bankrupt"] as const) {
    it(`legal notices ship verbatim, ordinary comments are still scrambled (${intensity})`, () => {
      const result = harden(source, intensity, { filename: "vendor.cjs" });
      for (const notice of notices) expect(result.code).toContain(notice);
      expect(result.code).not.toContain("internal note about the licence check algorithm");
      expect(result.code).not.toContain("Computes the royalty split");
      expect(json(runCommonJs(result.code))).toBe(json(runCommonJs(source)));
      expect(json(runCommonJs(source))).toBe("[700,300]");
    });
  }
});

describe("19 renaming a binding reaches every site of it, in one pass", () => {
  // Every kind of place a rename has to follow: shorthand properties and
  // patterns, assignment targets, loops heads, redeclarations, self-references,
  // computed keys and switch discriminants read in the enclosing scope.
  const shapes = `
    var out = [];
    var alpha = 1, beta = 2, gamma = 3;
    var shorthand = { alpha, beta, gamma: gamma, "alpha2": alpha };
    var { alpha: renamedAlpha, beta: [firstBeta = 7] = [], ...restOfIt } = { alpha: 10, beta: [], x: 1, y: 2 };
    out.push(shorthand, renamedAlpha, firstBeta, restOfIt);
    function takesPattern({ alpha, beta = alpha + 1, nested: { gamma: innerGamma = 5 } = {} }, [first, , third = first] = [1, 2]) {
      return [alpha, beta, innerGamma, first, third].join('/');
    }
    out.push(takesPattern({ alpha: 4 }), takesPattern({ alpha: 1, beta: 9, nested: { gamma: 8 } }, [5, 6, 7]));
    var swapA = 'left', swapB = 'right';
    [swapA, swapB] = [swapB, swapA];
    ({ swapA: swapB, swapB: swapA } = { swapA, swapB });
    out.push(swapA, swapB);
    var counter = 0, key, total = 0, maybe = null;
    for (key in { one: 1, two: 2 }) counter++;
    for (key of ['p', 'q', 'r']) total += key.charCodeAt(0);
    counter++; counter += 2; counter **= 2; counter ||= 5; counter &&= counter + 1; maybe ??= 'set';
    out.push(counter, key, total, maybe);
    var dup = 1; var dup = dup + 1; { var dup = dup * 10; }
    function twice() { return 'first'; } function twice() { return 'second'; }
    out.push(dup, twice());
    var named = function selfRef(n) { return n <= 1 ? 1 : n * selfRef(n - 1); };
    var Klass = class Inner { static make() { return new Inner(); } who() { return Inner === Klass; } };
    class Declared { static create() { return new Declared(); } get me() { return Declared; } static #count = 0; static bump() { return ++Declared.#count; } }
    out.push(named(5), Klass.make().who(), Declared.create().me === Declared, Declared.bump(), Declared.bump());
    try { null.x; } catch ({ message, name: errName }) { out.push(errName, typeof message); }
    label: for (var label = 0; label < 3; label++) { for (;;) { if (label === 1) continue label; break label; } }
    out.push(label);
    var x = 'outer-x';
    class Keyed { [x]() { let x = 'inner-x'; return x; } static [x + '!'] = x; }
    out.push(new Keyed()['outer-x'](), Keyed['outer-x!']);
    switch (x) { case 'outer-x': { let x = 'case-x'; out.push(x); } }
    switch (x.length) { case 7: let scoped = x + '?'; out.push(scoped); break; default: out.push('no'); }
    function defaults(a, b = a + 1, c = () => a + b, d = x) { var a2 = c(); return [a, b, a2, d].join(','); }
    out.push(defaults(1), defaults(1, 5));
    var obj = { x: x, alpha, method() { return x; }, get beta() { return beta; }, set beta(v) { beta = v; }, [alpha + 'k']: gamma, x2: { x } };
    obj.beta = 20; out.push(obj.x, obj.method(), obj.beta, obj['1k'], obj.x2.x, beta);
    var fns = []; for (let i = 0; i < 3; i++) fns.push(() => i * 2); out.push(fns.map((f) => f()).join(''));
    var arr = [1, 2]; [arr[1], arr[0]] = arr; var target = {}; ({ a: target.first, b: target['second'] } = { a: 1, b: 2 }); out.push(arr, target);
    (function () { var alpha = 'shadow'; out.push(alpha, typeof beta); function inner() { return alpha; } out.push(inner()); })();
    function sameAsParam(sameAsParam) { return sameAsParam + 1; } out.push(sameAsParam(1));
    class WithStatic { static value; static { let local = 5; const helper = () => local * 2; WithStatic.value = helper(); } } out.push(WithStatic.value);
    module.exports = out;
  `;
  const moduleShapes = {
    "main.mjs": `import entry, { Shape, helper, liveCounter, bump, viaInternal, constantLength, firstChar } from "./mod.mjs";
import Default from "./klass.mjs";
bump();
console.log(entry(), entry.name, Shape.of(3, 4).area, Shape.name, JSON.stringify(helper(1)), liveCounter, viaInternal, constantLength, firstChar, Default.make().tag(), Default.name);
`,
    "mod.mjs": `import { basename as base } from "node:path";
const local = base("/a/b/c.txt");
export default function mainEntry(n = 2) { return n > 0 ? mainEntry(n - 1) + local.length : 0; }
export class Shape { static of(...a) { return new Shape(...a); } constructor(w = 1, h = w) { this.area = w * h; } }
export const constant = mainEntry(1), { length: constantLength, [0]: firstChar = "?" } = local;
function privateHelper(value) { return { value, constant, self: privateHelper.name.length > 0 }; }
let counter = 0;
export function bump() { return ++counter; }
export { privateHelper as helper, counter as liveCounter };
const internal = { privateHelper, mainEntry, Shape };
export const viaInternal = internal.mainEntry(1) + internal.Shape.of(2).area + internal.privateHelper(3).value;
`,
    "klass.mjs": `export default class DefaultKlass { static make() { return new DefaultKlass(); } tag() { return DefaultKlass.name + ":" + helperValue; } }
const helperValue = (() => { const inner = 5; return inner * 2; })();
`,
  };

  for (const intensity of ALL) {
    it(`shorthand, patterns, assignment targets and shadowing (${intensity})`, () => {
      const expected = json(runCommonJs(shapes));
      expect(expected).toContain('"inner-x","outer-x","case-x","outer-x?"');
      const result = harden(shapes, intensity, { filename: "shapes.cjs" });
      expect(json(runCommonJs(result.code))).toBe(expected);
    });

    it(`export default declarations and renamed export lists (${intensity})`, () => {
      const expected = runEsm(moduleShapes, "main.mjs");
      expect(expected).toContain("[exit 0]");
      const hardened: Record<string, string> = { "main.mjs": moduleShapes["main.mjs"] };
      for (const name of ["mod.mjs", "klass.mjs"] as const) {
        hardened[name] = harden(moduleShapes[name], intensity, { filename: name }).code;
      }
      expect(runEsm(hardened, "main.mjs")).toBe(expected);
    });
  }

  it("a scope-hoisted bundle of 1,800 top-level functions hardens in seconds, not minutes", () => {
    // Renaming used to walk the whole program once per binding: about 40 s for
    // this input, against about 1 s now. The bound sits far from both.
    let source = "'use strict';\n";
    const functions = 900;
    for (let i = 0; i < functions; i++) {
      source += `function compute${i}(a, b) {\n  const total = a + b * ${i % 13};\n  if (total > 10) {\n    return helper${i}(total) + 'x';\n  }\n  return total;\n}\nfunction helper${i}(value) {\n  let sum = 0;\n  for (let k = 0; k < 3; k++) {\n    sum += value * k;\n  }\n  return sum;\n}\nexports.compute${i} = compute${i};\n`;
    }
    source += `exports.summary = [exports.compute0(1, 2), exports.compute${functions - 1}(20, 3), Object.keys(exports).length];\n`;
    const expected = json((runCommonJs(source) as { summary: unknown }).summary);
    const started = performance.now();
    const result = harden(source, "stealth", { filename: "bundle.cjs" });
    const elapsed = performance.now() - started;
    expect(json((runCommonJs(result.code) as { summary: unknown }).summary)).toBe(expected);
    expect(result.code).not.toMatch(/\bfunction compute\d+\(/);
    expect(elapsed).toBeLessThan(15_000);
  }, 60_000);
});

describe("JSX source keeps meaning the same elements", () => {
  // The hardened file is still JSX; the customer's compiler runs after us.
  const shim = `const render = (type, props, children) => {
  if (typeof type === "function") return type.prototype && type.prototype.render ? new type({ ...props, children }).render() : type({ ...props, children });
  const attrs = props ? Object.keys(props).filter((k) => k !== "children").map((k) => " " + k + "=" + JSON.stringify(props[k])).join("") : "";
  return "<" + type + attrs + ">" + children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false).join("") + "</" + type + ">";
};
export class Component { constructor(props) { this.props = props; } }
export const Fragment = ({ children }) => children.flat(Infinity).join("");
export const createElement = (type, props, ...children) => render(type, props, children);
`;
  const source = `import { Component, createElement, Fragment } from "./react-shim.mjs";
const React = { createElement, Fragment };
const div = "a-local-named-like-a-tag", span = 7;
function Button({ label, kind = "primary" }) { return <button className={"btn btn-" + kind} title="Press &amp; hold &quot;here&quot;" data-count={span}>{label}</button>; }
const Card = ({ title, children, footer: Footer }) => <section aria-label='single "quoted"'><h2>{title}</h2>{children}{Footer ? <Footer note="foot-note" /> : null}</section>;
const Kit = { Row: ({ cells }) => <tr>{cells.map((cell, index) => <td key={index}>{cell}</td>)}</tr>, nested: { Cell: ({ v }) => <td>{v}</td> } };
class Panel extends Component { render() { const Inner = this.props.inner ?? Button; return <Card title="panel-title" footer={Note}><Inner label="ok-label" /><Kit.Row cells={["x", "y"]} /><Kit.nested.Cell v={div} /></Card>; } }
function Note({ note }) { return <small>{note}</small>; }
const _Private = () => <i>private-component</i>;
const lowerHelper = () => "plain-helper";
export default function App({ items }) {
  const Row = Kit.Row;
  return <><Panel /><Panel inner={Note} /><ul>{items.map((item) => <li key={item}><Button label={item} kind="ghost" /></li>)}</ul><_Private /><Row cells={[lowerHelper(), div.length, span]} /><div id="real-div">{div}</div></>;
}
`;
  const main = `import App from "./app.mjs";\nconsole.log(App({ items: ["first", "second"] }));\n`;
  const compileJsx = (code: string): string =>
    ts.transpileModule(code, {
      fileName: "app.jsx",
      compilerOptions: {
        allowJs: true,
        jsx: ts.JsxEmit.React,
        module: ts.ModuleKind.ESNext,
        target: ts.ScriptTarget.ES2022,
      },
    }).outputText;
  const render = (code: string): string =>
    runEsm({ "react-shim.mjs": shim, "app.mjs": compileJsx(code), "main.mjs": main }, "main.mjs");

  for (const intensity of ALL) {
    it(`components stay components and attribute strings stay attributes (${intensity})`, () => {
      const expected = render(source);
      expect(expected).toContain('title="Press & hold \\"here\\""');
      expect(expected).toContain("[exit 0]");
      const result = harden(source, intensity, { filename: "app.jsx" });
      expect(render(result.code)).toBe(expected);
      // Where strings are encoded at all, attribute strings are too.
      if (LITERAL_REWRITING.includes(intensity)) expect(result.code).not.toContain("foot-note");
    });
  }
});

describe("strings inside template substitutions are encoded like any other string", () => {
  // The template rewrite used to stop the walk at the template, so everything
  // inside `${…}` stayed readable while the text around it was encoded.
  const source = `
    'use strict';
    function endpoint(isDev, path) {
      return \`\${isDev ? "http://localhost:3000" : "https://api.internal.example.com"}/v1/\${path}?k=\${encodeURIComponent("partner-key-ALPHA-7781")}\`;
    }
    function label(ok) { return \`tier=\${ok ? "pro-unlimited-seats" : "free-three-seats"}\`; }
    const plain = "https://billing.internal.example.com/hooks";
    const nested = [\`a\${[\`b\${"deep-nested-literal-0042"}\`].join("")}\`];
    const order = [];
    const tap = (name, value) => { order.push(name); return value; };
    class Money {
      constructor(cents) { this.cents = cents; }
      valueOf() { order.push('valueOf'); return this.cents; }
      toString() { order.push('toString'); return '$' + (this.cents / 100).toFixed(2); }
    }
    const greet = (user) => \`Hello \${user ? \`dear \${user.name ?? "anonymous-visitor"} (\${user.roles.map((role) => "role:" + role).join(", ")})\` : "stranger-at-the-gate"}, total \${new Money(123456)} for \${tap('count', 65536)} items\${tap('tail', '!!')}\`;
    const rows = (list) => \`<table class="\${list.length > 2 ? "table-large-variant" : "table-small-variant"}">\${list.map((row, index) => \`<tr data-index="\${index * 1000}">\${row}</tr>\`).join('')}</table>\`;
    function withDefaults(prefix = \`pre-\${"default-prefix-value"}\`, fmt = (v) => \`[\${v ?? "missing-value-text"}]\`) { return \`\${prefix}:\${fmt()}:\${fmt('given')}\`; }
    class Report { static title = \`Report \${"static-title-text"} v\${4096}\`; line = \`line \${"instance-field-text"}\`; }
    const tag = (strings, ...values) => strings.raw.join('|') + '#' + values.join(',');
    function* steps() { yield \`step \${yield "yielded-first-value"} done \${"generator-tail-text"}\`; }
    const walk = steps();
    module.exports = (async () => [
      endpoint(true, 'users'), endpoint(false, 'orders'), label(true), label(false), plain, nested,
      greet({ name: 'Ada', roles: ['admin', 'billing'] }), greet({ roles: [] }), greet(null), order.join('>'),
      rows(['a', 'b', 'c']), rows([]), withDefaults(), withDefaults('explicit'),
      Report.title, new Report().line, tag\`raw \${"tagged-hole-string"} and \${\`inner \${"inner-hole-string"} text\`}\`,
      walk.next().value, walk.next('sent').value,
      \`async \${await Promise.resolve("awaited-string-value")} \${await (async () => \`inner \${"async-inner-text"}\`)()}\`,
      new Function('return (' + label.toString() + ')')()(true),
      new Function('return (' + endpoint.toString() + ')')()(false, 'again'),
    ])();
  `;
  const secrets = [
    "http://localhost:3000",
    "api.internal.example.com",
    "partner-key-ALPHA-7781",
    "pro-unlimited-seats",
    "free-three-seats",
    "billing.internal.example.com",
    "deep-nested-literal-0042",
    "anonymous-visitor",
    "stranger-at-the-gate",
    "table-large-variant",
    "default-prefix-value",
    "static-title-text",
    "instance-field-text",
    "tagged-hole-string",
    "inner-hole-string",
    "yielded-first-value",
    "generator-tail-text",
    "awaited-string-value",
    "async-inner-text",
  ];

  for (const intensity of LITERAL_REWRITING) {
    it(`no substitution string survives and the program prints the same (${intensity})`, async () => {
      const expected = json(await (runCommonJs(source) as Promise<unknown>));
      expect(expected).toContain("https://api.internal.example.com/v1/orders?k=partner-key-ALPHA-7781");
      // ToString runs right after each substitution is evaluated, in source order.
      expect(expected).toContain("toString>count>tail");
      for (const seed of [SEED, "alpha", "s2"]) {
        const result = harden(source, intensity, { sourceType: "commonjs", seed });
        for (const secret of secrets) expect(result.code, `${seed}: ${secret}`).not.toContain(secret);
        const actual = json(await (runCommonJs(result.code) as Promise<unknown>));
        expect(actual, seed).toBe(expected);
      }
    });
  }
});

describe("TypeScript string enums stay string enums", () => {
  // tsc keeps `A = "a"` one-way only while the initializer is a literal; an
  // encoded initializer is a computed member and gains a reverse mapping.
  const source = `export enum Color { Red = "red-value", Green = "green-value" }
export enum Level { Low = 100, High = 200 }
const describeEnum = (e: object): string => Object.keys(e).join(",") + "=" + Object.values(e).join(",");
export const report = [describeEnum(Color), describeEnum(Level), Color.Green, Level[200], "a-plain-string-outside-the-enum"].join(" | ");
`;
  const run = (code: string): string =>
    runEsm(
      {
        "mod.mjs": ts.transpileModule(code, {
          compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
        }).outputText,
        "main.mjs": `import { report } from "./mod.mjs";\nconsole.log(report);\n`,
      },
      "main.mjs",
    );

  for (const intensity of LITERAL_REWRITING) {
    it(`Object.keys / Object.values of an enum are unchanged (${intensity})`, () => {
      const expected = run(source);
      // (A numeric enum does have its reverse mapping; a string enum must not gain one.)
      expect(expected).toContain("Red,Green=red-value,green-value | 100,200,Low,High=");
      const result = harden(source, intensity, { filename: "colors.ts" });
      expect(run(result.code)).toBe(expected);
      expect(result.code).not.toContain("a-plain-string-outside-the-enum");
    });
  }
});

describe("strings that name a file relative to the module stay literal", () => {
  // Bundlers, packagers and deploy-time file tracers follow these to decide
  // what ships. Encoding them still runs — and silently drops the file later.
  const files = {
    "main.mjs": `
      import { createRequire } from 'node:module';
      import { readFileSync } from 'node:fs';
      const require = createRequire(import.meta.url);
      const viaRequireResolve = require.resolve('./data/keys.json');
      const viaMetaResolve = import.meta.resolve('./data/token-table.json');
      const viaUrl = new URL('./data/license-notes.txt', import.meta.url);
      const viaTemplateUrl = new URL(\`./data/keys.json\`, import.meta.url);
      const unrelated = new URL('/v1/an-ordinary-route-string', 'https://example.invalid');
      console.log([
        JSON.parse(readFileSync(viaRequireResolve, 'utf8')).name,
        viaMetaResolve.endsWith('/data/token-table.json'),
        readFileSync(viaUrl, 'utf8').trim(),
        viaTemplateUrl.pathname.endsWith('/data/keys.json'),
        unrelated.pathname,
      ].join(' | '));
    `,
    "data/keys.json": `{ "name": "keys-file" }\n`,
    "data/token-table.json": `{}\n`,
    "data/license-notes.txt": `notes-file\n`,
  };
  const expected = runEsm(files, "main.mjs");

  for (const intensity of ALL) {
    it(`require.resolve / import.meta.resolve / new URL(…, import.meta.url) (${intensity})`, () => {
      expect(expected).toBe("keys-file | true | notes-file | true | /v1/an-ordinary-route-string\n[exit 0]");
      const result = harden(files["main.mjs"], intensity, { filename: "main.mjs" });
      expect(runEsm({ ...files, "main.mjs": result.code }, "main.mjs")).toBe(expected);

      const found = { requireResolve: 0, metaResolve: 0, url: 0 };
      const firstArgValue = (node: Record<string, any>): string | undefined => {
        const arg = node.arguments?.[0];
        if (arg?.type === "StringLiteral") return arg.value;
        if (arg?.type === "TemplateLiteral" && arg.expressions.length === 0) return arg.quasis[0].value.cooked;
        return undefined;
      };
      const stack: unknown[] = [parse(result.code, { sourceType: "module" }).program];
      while (stack.length > 0) {
        const node = stack.pop();
        if (node === null || typeof node !== "object") continue;
        const record = node as Record<string, any>;
        const value = firstArgValue(record);
        if (record.type === "CallExpression" && value === "./data/keys.json") found.requireResolve++;
        if (record.type === "CallExpression" && value === "./data/token-table.json") found.metaResolve++;
        if (record.type === "NewExpression" && value?.startsWith("./data/")) found.url++;
        for (const [key, child] of Object.entries(record)) {
          if (key === "loc" || key === "leadingComments" || key === "trailingComments") continue;
          if (Array.isArray(child)) stack.push(...child);
          else if (child !== null && typeof child === "object") stack.push(child);
        }
      }
      expect(found).toEqual({ requireResolve: 1, metaResolve: 1, url: 2 });
      // A URL that is not relative to the module is an ordinary string.
      if (LITERAL_REWRITING.includes(intensity)) {
        expect(result.code).not.toContain("an-ordinary-route-string");
      }
    });
  }
});
