/**
 * An ES module imports names from a CommonJS file — `import { x } from
 * "./lib.cjs"` — only if Node can find them by scanning that file's text
 * (cjs-module-lexer). The shapes it looks for are what TypeScript, Babel and
 * esbuild emit; a hardened file has to keep them, or the importer fails to link
 * with "Named export 'x' not found" before a line of the program runs.
 *
 * These tests run the real thing: Node importing the hardened files.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ProtectionIntensity } from "../src/core/types.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";

const digestOf = (label: string): string => createHash("sha256").update(label).digest("hex");
const LITERAL_DIGEST = digestOf("cjs-named-exports/literal");

/** What `tsc --module commonjs` writes for a file with a named re-export and `export *`. */
const TS_STYLE = `"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.greet = exports.VERSION = exports.lazyValue = void 0;
const dep_1 = require("./dep.cjs");
Object.defineProperty(exports, "lazyValue", { enumerable: true, get: function () { return dep_1.lazyValue; } });
__exportStar(require("./star.cjs"), exports);
exports.VERSION = "1.2.3-build";
function greet(name) { return "hello " + name; }
exports.greet = greet;
exports["quoted-name"] = "q";
`;

/** What Babel writes for `export * from "./star"` next to an export of its own. */
const BABEL_STYLE = `"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
var _exportNames = {
  own: true
};
exports.own = own;
var _star = require("./star.cjs");
Object.keys(_star).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (Object.prototype.hasOwnProperty.call(_exportNames, key)) return;
  if (key in exports && exports[key] === _star[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function () {
      return _star[key];
    }
  });
});
function own() { return "own"; }
`;

/** A hand-written module: two names Node finds, then values it stops at. */
const LITERAL = `function alpha() { return 'a'; }
function beta() { return 'b'; }
module.exports = { alpha, beta, label: 'object-literal', port: 8080, digest: '${LITERAL_DIGEST}' };
`;

/** What `esbuild --format=cjs` writes, with its annotation for this very scanner. */
const ESBUILD_STYLE = `"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var entry_exports = {};
__export(entry_exports, {
  compute: () => compute,
  LIMIT: () => LIMIT
});
module.exports = __toCommonJS(entry_exports);
var LIMIT = 4096;
function compute(n) { return n * 2 + LIMIT; }
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  LIMIT,
  compute
});
`;

const STAR = `"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.starValue = exports.starFn = void 0;
exports.starValue = "from-star";
function starFn(n) { return n + 1; }
exports.starFn = starFn;
`;

const DEP = `"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.lazyValue = 42;
`;

const COMMONJS_FILES: Readonly<Record<string, string>> = {
  "ts-style.cjs": TS_STYLE,
  "babel-style.cjs": BABEL_STYLE,
  "literal.cjs": LITERAL,
  "esbuild-style.cjs": ESBUILD_STYLE,
  "star.cjs": STAR,
  "dep.cjs": DEP,
};

/** The importer is never hardened: it stands for the customer of a hardened package. */
const ESM_IMPORTER = `import { greet, VERSION, lazyValue, starValue, starFn } from './ts-style.cjs';
import * as ts from './ts-style.cjs';
import * as babel from './babel-style.cjs';
import { own, starValue as viaBabel } from './babel-style.cjs';
import * as literal from './literal.cjs';
import * as bundled from './esbuild-style.cjs';
import { compute, LIMIT } from './esbuild-style.cjs';
// ('module.exports' is a namespace key only in newer Node releases.)
const names = (ns) => Object.keys(ns).filter((name) => name !== 'module.exports').sort().join(',');
console.log('ts      ', names(ts), '|', greet('x'), VERSION, lazyValue, starValue, starFn(1), ts['quoted-name']);
console.log('babel   ', names(babel), '|', own(), viaBabel);
console.log('literal ', names(literal), '|', literal.alpha(), literal.default.label, literal.default.port, literal.default.digest);
console.log('esbuild ', names(bundled), '|', compute(1), LIMIT);
`;

const SEED = "cjs-named-exports";

function harden(code: string, filename: string, intensity: ProtectionIntensity): string {
  return transformJavaScriptWithBlaShield(code, { intensity, seed: SEED, filename }).code;
}

let workDir = "";

function runImporter(label: string, files: Readonly<Record<string, string>>): string {
  const dir = join(workDir, label);
  mkdirSync(dir, { recursive: true });
  for (const [name, code] of Object.entries(files)) writeFileSync(join(dir, name), code, "utf8");
  writeFileSync(join(dir, "main.mjs"), ESM_IMPORTER, "utf8");
  const run = spawnSync(process.execPath, ["main.mjs"], { cwd: dir, encoding: "utf8" });
  // A link error is the failure this file is about: show it instead of an empty diff.
  return run.status === 0 ? run.stdout : `exit ${String(run.status)}\n${run.stderr}`;
}

beforeAll(() => {
  workDir = mkdtempSync(join(tmpdir(), "bla-cjs-named-exports-"));
});
afterAll(() => {
  rmSync(workDir, { recursive: true, force: true });
});

describe("an ES module importing names from a hardened CommonJS file", () => {
  it("the fixtures export what the comments say, before any hardening", () => {
    expect(runImporter("original", COMMONJS_FILES)).toBe(
      [
        "ts       VERSION,__esModule,default,greet,lazyValue,quoted-name,starFn,starValue | hello x 1.2.3-build 42 from-star 2 q",
        "babel    __esModule,default,own,starFn,starValue | own from-star",
        `literal  alpha,beta,default | a object-literal 8080 ${LITERAL_DIGEST}`,
        "esbuild  LIMIT,compute,default | 4098 4096",
        "",
      ].join("\n"),
    );
  });

  it.each(["stealth", "balanced", "maximum", "bankrupt"] as const)(
    "%s: the same names link, the same names are listed, the same values come back",
    (intensity) => {
      const hardened = Object.fromEntries(
        Object.entries(COMMONJS_FILES).map(([name, code]) => [name, harden(code, name, intensity)]),
      );
      expect(runImporter(intensity, hardened)).toBe(runImporter("original", COMMONJS_FILES));
    },
    120_000,
  );
});

describe("a UMD bundle, which Node loads as CommonJS", () => {
  /** What `rollup --format umd` writes for a re-export next to an export of its own. */
  const UMD = `(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('./dep.cjs')) :
  typeof define === 'function' && define.amd ? define(['exports', './dep.cjs'], factory) :
  (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.Lib = {}, global.Dep));
})(this, (function (exports, dep) { 'use strict';
  function own() { return 'own'; }
  Object.defineProperty(exports, 'lazyValue', {
    enumerable: true,
    get: function () { return dep.lazyValue; }
  });
  exports.own = own;
  Object.defineProperty(exports, '__esModule', { value: true });
}));
`;
  const IMPORTER = `import * as ns from './umd.js';
import { own, lazyValue } from './umd.js';
console.log(Object.keys(ns).filter((name) => name !== 'module.exports').sort().join(','), '|', own(), lazyValue);
`;

  function runUmd(label: string, umd: string, dep: string): string {
    const dir = join(workDir, label);
    mkdirSync(dir, { recursive: true });
    // `.js` is CommonJS here whatever sits above the temporary directory.
    writeFileSync(join(dir, "package.json"), '{ "type": "commonjs" }\n', "utf8");
    writeFileSync(join(dir, "umd.js"), umd, "utf8");
    writeFileSync(join(dir, "dep.cjs"), dep, "utf8");
    writeFileSync(join(dir, "main.mjs"), IMPORTER, "utf8");
    const run = spawnSync(process.execPath, ["main.mjs"], { cwd: dir, encoding: "utf8" });
    return run.status === 0 ? run.stdout : `exit ${String(run.status)}\n${run.stderr}`;
  }

  it("exports the same names from inside its factory function at every intensity", () => {
    const original = runUmd("umd-original", UMD, DEP);
    expect(original).toBe("__esModule,default,lazyValue,own | own 42\n");

    for (const intensity of ["stealth", "balanced", "maximum", "bankrupt"] as const) {
      const hardened = runUmd(
        `umd-${intensity}`,
        harden(UMD, "umd.js", intensity),
        harden(DEP, "dep.cjs", intensity),
      );
      expect(hardened, intensity).toBe(original);
    }
  }, 120_000);
});

describe("what is left as written, and what is not", () => {
  it("keeps an export's name, its re-export getter and the star helper's name", () => {
    const out = harden(TS_STYLE, "ts-style.cjs", "bankrupt");

    expect(out).toContain('Object.defineProperty(exports, "__esModule", {');
    expect(out).toContain('Object.defineProperty(exports, "lazyValue", {');
    expect(out).toContain('exports["quoted-name"] =');
    expect(out).toContain('__exportStar(require("./star.cjs"), exports)');
    // The getter is still one `return <module>.<name>;`, whatever the module is called now.
    expect(out).toMatch(/get: function \(\) \{\s*return \w+\.lazyValue;\s*\}/);
    // Everything else in the file is hardened as before.
    expect(out).not.toContain('"1.2.3-build"');
    expect(out).not.toMatch(/function greet\(name\) \{\s*return/);
  });

  it("keeps Babel's export-star loop readable as that loop", () => {
    const out = harden(BABEL_STYLE, "babel-style.cjs", "bankrupt");

    expect(out).toMatch(
      /Object\.keys\((\w+)\)\.forEach\(function \((\w+)\) \{\s*if \(\2 === "default" \|\| \2 === "__esModule"\) return;/,
    );
    expect(out).toMatch(/get: function \(\) \{\s*return \w+\[\w+\];\s*\}/);
  });

  it("still encodes a secret that is the value of an exported property", () => {
    const digest = digestOf("cjs-named-exports/value");
    const source = `"use strict";
Object.defineProperty(exports, "LICENSE_DIGEST", { value: "${digest}" });
exports["quoted-digest"] = "${digest}";
`;
    const out = harden(source, "license.cjs", "bankrupt");

    expect(out).toContain('Object.defineProperty(exports, "LICENSE_DIGEST", {');
    expect(out).toContain('exports["quoted-digest"] =');
    expect(out).not.toContain(digest);
    expect(out).not.toContain(digest.slice(0, 16));
  });

  it("hardens a getter that does more than return a module's member", () => {
    const digest = digestOf("cjs-named-exports/getter");
    const source = `"use strict";
const crypto_1 = require("node:crypto");
Object.defineProperty(exports, "token", { enumerable: true, get: function () {
  const seed = "${digest}";
  return crypto_1.createHash("sha256").update(seed).digest("hex");
} });
`;
    const out = harden(source, "token.cjs", "bankrupt");

    expect(out).toContain('Object.defineProperty(exports, "token", {');
    expect(out).not.toContain(digest);
    const loaded = runModule(out, "token.cjs");
    expect(loaded).toBe(digestOf(digest));
  });

  it("hardens a loop over keys that is the program's own code", () => {
    const digest = digestOf("cjs-named-exports/loop");
    const source = `"use strict";
const table = { a: 1, b: 2 };
const seen = [];
Object.keys(table).forEach(function (key) {
  seen.push(key);
  seen.push("${digest}");
  seen.push(key.length);
  seen.push(table[key]);
  seen.push(key + key);
  seen.push(String(table[key]));
  exports[key] = table[key];
});
exports.seen = seen;
`;
    const out = harden(source, "table.cjs", "bankrupt");

    expect(out).not.toContain(digest);
  });

  it("writes a rewritten value of a module.exports literal in parentheses", () => {
    const out = harden(LITERAL, "literal.cjs", "bankrupt");

    // `label: function (s, m, c) {…}(…)` is the same expression, and one more
    // named export to Node's scanner.
    expect(out).toMatch(/label: \(function \(s, m, c\) \{/);
    expect(out).not.toMatch(/label: function\b/);
    expect(out).toMatch(/port: \(/);
    expect(out).not.toContain(LITERAL_DIGEST);
  });

  it("keeps the parentheses that end Node's scan of a module.exports literal", () => {
    // `{ first: (inner) }` exports nothing by name: the scan stops at `(`.
    // Printed without them, `first` and `second` both become named exports.
    const source = `const inner = 1;\nmodule.exports = { first: (inner), second: inner };\n`;
    const out = harden(source, "paren.cjs", "stealth");

    expect(out).toMatch(/first: \(\w+\),/);
    expect(namesNodeFinds(source, "paren-original")).toBe("default");
    expect(namesNodeFinds(out, "paren-hardened")).toBe("default");
  });

  it("leaves an ES module and a classic script as they were handled before", () => {
    const esm = harden(
      `export const label = "module-scope label";\nexport function f() { return label; }\n`,
      "lib.mjs",
      "bankrupt",
    );
    expect(esm).toMatch(/\(function \(s, m, c\) \{/);

    const script = transformJavaScriptWithBlaShield(
      `var exportsLike = {};\nObject.defineProperty(exportsLike, "name-in-a-script", { value: 1 });\n`,
      { intensity: "bankrupt", seed: SEED, sourceType: "script" },
    ).code;
    expect(script).not.toContain('"name-in-a-script"');
  });
});

/** The names an ES module gets from `import * as ns` of this CommonJS source. */
function namesNodeFinds(code: string, label: string): string {
  const dir = join(workDir, label);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "lib.cjs"), code, "utf8");
  const run = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      "import * as ns from './lib.cjs'; process.stdout.write(Object.keys(ns).filter((name) => name !== 'module.exports').sort().join(','));",
    ],
    { cwd: dir, encoding: "utf8" },
  );
  return run.status === 0 ? run.stdout : `exit ${String(run.status)}\n${run.stderr}`;
}

function runModule(code: string, filename: string): string {
  const dir = join(workDir, `run-${filename}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, filename), code, "utf8");
  const run = spawnSync(
    process.execPath,
    ["-e", `process.stdout.write(String(require(${JSON.stringify(`./${filename}`)}).token))`],
    { cwd: dir, encoding: "utf8" },
  );
  return run.status === 0 ? run.stdout : `exit ${String(run.status)}\n${run.stderr}`;
}
