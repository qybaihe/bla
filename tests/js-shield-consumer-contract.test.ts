import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { hardenProject } from "../src/engine/harden.js";

/**
 * What code *outside* a hardened module can still rely on. Renaming is free
 * inside a file; across the module boundary a caller sees `fn.name`,
 * `error.name`, `instance.constructor.name`, `instanceof` and the export list —
 * and logging, DI containers, ORMs and test frameworks all read them.
 */

const tempDirs: string[] = [];
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function put(root: string, rel: string, content: string): void {
  mkdirSync(dirname(join(root, rel)), { recursive: true });
  writeFileSync(join(root, rel), content, "utf8");
}
function node(cwd: string, args: string[]) {
  const run = spawnSync(process.execPath, args, { cwd, encoding: "utf8", timeout: 60000 });
  return { status: run.status, stdout: run.stdout, stderr: run.stderr.slice(0, 600) };
}

const LIB_CJS = `class Ledger { constructor() { this.total = 0; } add(n) { this.total += n; return this; } }
class AuditedLedger extends Ledger { constructor(tag) { super(); this.tag = tag; } add(n) { super.add(n); return this; } }
class LicenseError extends Error { constructor(msg) { super(msg); this.name = new.target.name; } }
function verifyLicense(key) { if (typeof key !== 'string') throw new LicenseError('bad key'); return key.length === 4; }
const formatTotal = (l) => 'total=' + l.total;
module.exports = { Ledger, AuditedLedger, LicenseError, verifyLicense, formatTotal };
`;
const MOD_MJS = `export function verifyToken(t) { return t === 'ok'; }
export class Session { constructor(id) { this.id = id; } }
export default class Client extends Session { constructor() { super('c1'); } }
export const helper = function namedHelper() { return 1; };
`;
const INDEX_MJS = `export * as api from './mod.mjs';
export { default as Client } from './mod.mjs';
`;
const TYPED_TS = `export interface Opts { n: number }
export function double(o: Opts): number { return o.n * 2; }
export class Box<T> { constructor(public value: T) {} }
`;

const CJS_PROBE = `const m = require('./lib.cjs');
const a = new m.AuditedLedger('t').add(2).add(3);
let err; try { m.verifyLicense(1); } catch (e) { err = e; }
console.log(JSON.stringify({
  classNames: [m.Ledger.name, m.AuditedLedger.name, a.constructor.name],
  total: a.total,
  inherits: a instanceof m.Ledger,
  fnName: m.verifyLicense.name,
  arrowName: m.formatTotal.name,
  verdict: m.verifyLicense('abcd'),
  formatted: m.formatTotal(a),
  error: [err.name, err.message, err instanceof m.LicenseError, err instanceof Error],
  exports: Object.keys(m).sort(),
}));`;
const ESM_PROBE = `import { api, Client } from './esm/index.mjs';
const c = new Client();
console.log(JSON.stringify({
  names: [api.verifyToken.name, api.Session.name, Client.name, api.helper.name],
  verdict: api.verifyToken('ok'),
  id: c.id,
  inherits: c instanceof api.Session,
  exports: Object.keys(api).sort(),
}));`;

describe.each(["stealth", "balanced", "maximum", "bankrupt"] as const)(
  "hardened JS keeps its contract with callers (%s)",
  (intensity) => {
    it("names, inheritance and the export list survive", () => {
      const dir = tempDir("bla-js-contract-");
      put(dir, "package.json", JSON.stringify({ name: "n", version: "1.0.0" }));
      put(dir, "dist/lib.cjs", LIB_CJS);
      put(dir, "dist/esm/mod.mjs", MOD_MJS);
      put(dir, "dist/esm/index.mjs", INDEX_MJS);
      put(dir, "dist/typed.ts", TYPED_TS);

      const report = hardenProject({
        directory: dir,
        intensity,
        seed: "contract-seed",
        applyStateRoot: tempDir("bla-js-contract-state-"),
      });
      expect(report.artifacts.map((a) => [a.relativePath, a.error])).toEqual([
        ["dist/esm/index.mjs", undefined],
        ["dist/esm/mod.mjs", undefined],
        ["dist/lib.cjs", undefined],
        ["dist/typed.ts", undefined],
      ]);
      expect(report.overallSuccess).toBe(true);
      const out = join(dir, ".bla-hardened", "dist");

      const cjs = node(out, ["-e", CJS_PROBE]);
      expect(cjs.stderr).toBe("");
      expect(JSON.parse(cjs.stdout)).toEqual({
        classNames: ["Ledger", "AuditedLedger", "AuditedLedger"],
        total: 5,
        inherits: true,
        fnName: "verifyLicense",
        arrowName: "formatTotal",
        verdict: true,
        formatted: "total=5",
        error: ["LicenseError", "bad key", true, true],
        exports: ["AuditedLedger", "Ledger", "LicenseError", "formatTotal", "verifyLicense"],
      });

      const esm = node(out, ["--input-type=module", "-e", ESM_PROBE]);
      expect(esm.stderr).toBe("");
      expect(JSON.parse(esm.stdout)).toEqual({
        names: ["verifyToken", "Session", "Client", "namedHelper"],
        verdict: true,
        id: "c1",
        inherits: true,
        exports: ["Session", "default", "helper", "verifyToken"],
      });

      // Hardened TypeScript is still TypeScript: its types stay, and the
      // injected code is not held to the project's `strict` settings.
      const typed = readFileSync(join(out, "typed.ts"), "utf8");
      expect(typed.startsWith("// @ts-nocheck\n")).toBe(true);
      expect(typed).toMatch(/\binterface Opts\b/);
      expect(typed).toMatch(/\bexport function double\b/);
      expect(typed).toMatch(/\bexport class Box\b/);
    }, 240000);
  },
);
