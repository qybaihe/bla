import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import generate from "@babel/generator";
import * as t from "@babel/types";
import { describe, expect, it } from "vitest";
import { assertNoForbiddenMarkers } from "../src/core/identifiers.js";
import { SeededPrng } from "../src/core/prng.js";
import { hardenProject } from "../src/engine/harden.js";
import { scanPackagingGates } from "../src/engine/packaging-gates.js";
import {
  generateCounterReaDeceptionSuite,
  generateHypothesisRevisionDecoy,
} from "../src/shields/deception/index.js";
import { emitCompileTimeNativeHeader } from "../src/shields/formats/headers.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import {
  buildParameterizedMbaBinaryAst,
  deriveParameterizedMbaParams,
  generateUnsignedMbaOpaqueFalseJs,
  generateUnsignedMbaOpaqueTrueJs,
  type MbaBitwiseOp,
} from "../src/shields/tarpit/mba-substitutions.js";

const babelGenerate: typeof generate =
  typeof generate === "function"
    ? generate
    : (generate as unknown as { default: typeof generate }).default;

const BOUNDARY_VALUES = [
  0,
  1,
  -1,
  2,
  0x7fffffff,
  -0x80000000,
  0xc0000000 | 0,
  0xbaaad0bf | 0,
  0x12345678,
  -42,
] as const;

describe("Kanxue thread-293217 Counter-REA Reinforcements", () => {
  it("proves 32-bit parameterized affine MBA identities and unsigned-domain MBA predicates across boundary values", () => {
    const prng = new SeededPrng("kanxue-mba-identities");
    for (let i = 0; i < 32; i++) {
      const p = deriveParameterizedMbaParams(prng);
      expect(Math.imul(p.m, p.mInv) >>> 0).toBe(1);
      expect(((Math.imul(p.mInv, p.c) + p.d) >>> 0)).toBe(0);
    }

    const ops: MbaBitwiseOp[] = ["+", "-", "^", "|", "&"];
    for (const op of ops) {
      const astExpr = buildParameterizedMbaBinaryAst(
        op,
        t.identifier("a"),
        t.identifier("b"),
        prng,
      );
      const code = babelGenerate(astExpr).code;
      const fn = new Function("a", "b", `return (${code});`) as (
        a: number,
        b: number,
      ) => number;
      const ref = new Function("a", "b", `return ((a ${op} b) | 0);`) as (
        a: number,
        b: number,
      ) => number;

      for (const a of BOUNDARY_VALUES) {
        for (const b of BOUNDARY_VALUES) {
          expect(fn(a, b), `op=${op}, a=${a}, b=${b}`).toBe(ref(a, b));
        }
      }
    }

    for (let s = 0; s < 20; s++) {
      const seedPrng = new SeededPrng(`unsigned-mba-${s}`);
      const tExpr = generateUnsignedMbaOpaqueTrueJs(seedPrng, "k");
      const fExpr = generateUnsignedMbaOpaqueFalseJs(seedPrng, "k");
      const evalT = new Function("k", `return (${tExpr});`) as (k: number) => boolean;
      const evalF = new Function("k", `return (${fExpr});`) as (k: number) => boolean;
      for (const v of BOUNDARY_VALUES) {
        expect(evalT(v)).toBe(true);
        expect(evalF(v)).toBe(false);
      }
    }
  });

  it("applies parameterized MBA instruction substitution in JS AST shield while preserving exact function semantics", () => {
    const src = `
      function targetFunction(n) {
        const u = n >>> 0;
        const m = u & 3;
        if (m === 0) return (Math.imul(u | 0xBAAAD0BF, 2 ^ u)) >>> 0;
        if (m === 1) return (Math.imul(u & 0xBAAAD0BF, (3 + u) | 0)) >>> 0;
        if (m === 2) return (Math.imul(u ^ 0xBAAAD0BF, 4 | u)) >>> 0;
        return (Math.imul((u + 0xBAAAD0BF) >>> 0, 5 & u)) >>> 0;
      }
      module.exports = { targetFunction };
    `;

    const protectedRes = transformJavaScriptWithBlaShield(src, {
      intensity: "bankrupt",
      seed: "kanxue-promon-fn",
    });
    assertNoForbiddenMarkers(protectedRes.code);
    // Neither raw 0xBAAAD0BF decimal/hex nor trivial x*(x+1)&1 parity template survives
    expect(protectedRes.code.toLowerCase()).not.toContain("baaad0bf");
    expect(protectedRes.code).not.toContain("3131756735");
    expect(protectedRes.code).not.toMatch(/\+\s*1\)\s*&\s*1/);

    const runMod = (code: string) => {
      const mod = { exports: {} as { targetFunction: (n: number) => number } };
      vm.runInNewContext(code, {
        module: mod,
        exports: mod.exports,
        Math,
        process: { pid: 1001, env: {}, versions: { node: "24.0.0" } },
        Buffer,
      });
      return mod.exports.targetFunction;
    };
    const origFn = runMod(src);
    const protFn = runMod(protectedRes.code);

    for (const input of [0, 1, 2, 3, 4, 7, 42, 0x1337, 0x80000001, 0xffffffff]) {
      expect(protFn(input)).toBe(origFn(input));
    }
  });

  it("upgrades C, Rust, and Go compile-time native headers with parameterized MBA and unsigned-domain MBA predicates", () => {
    const cHdr = emitCompileTimeNativeHeader("c", {
      intensity: "balanced",
      seed: "kanxue-hdr",
    });
    const rsHdr = emitCompileTimeNativeHeader("rust", {
      intensity: "balanced",
      seed: "kanxue-hdr",
    });
    const goHdr = emitCompileTimeNativeHeader("go", {
      intensity: "balanced",
      seed: "kanxue-hdr",
    });

    expect(cHdr.content).toContain("- 1u)) < (uint32_t)(");
    expect(rsHdr.content).toContain("(u | u.wrapping_sub(1)) < (u ^ u.wrapping_sub(1))");
    expect(goHdr.content).toContain("(u|(u-1)) < (u^(u-1))");
    expect(goHdr.content).not.toContain("(((seed|1)*((seed|1)+1))&1)");
  });

  it("executes multi-round hypothesis-revision decoys and auditor attention sinks cleanly without crashing or leaking markers", () => {
    const prng = new SeededPrng("kanxue-deception-coevolution");
    const decoy = generateHypothesisRevisionDecoy(prng, "bankrupt");
    assertNoForbiddenMarkers(decoy.code);
    expect(decoy.revisionChains).toHaveLength(4);
    expect(decoy.auditorAttentionSinks).toHaveLength(8);

    const primary = decoy.revisionChains[0]!.primaryLureSymbol;
    const sink = decoy.auditorAttentionSinks[0]!;
    const out = vm.runInNewContext(
      `${decoy.code}\n({ envelope: ${primary}(12345), sinkVal: ${sink}(9) });`,
      { Math, process: { pid: 4242 } },
    ) as {
      envelope: { code: number; status: string; lease: number; ok: boolean };
      sinkVal: number;
    };

    expect(out.envelope.code).toBe(200);
    expect(["active", "verified", "calibrated"]).toContain(out.envelope.status);
    expect(out.envelope.ok).toBe(false);
    expect(typeof out.sinkVal).toBe("number");

    const suite = generateCounterReaDeceptionSuite(
      new SeededPrng("suite-check"),
      "balanced",
    );
    expect(suite.hypothesisRevision.revisionChains.length).toBeGreaterThanOrEqual(2);
  });

  it("blocks leaked SOLUTION.txt, .env secrets, private keys, and debug symbols via release-hygiene packaging gate", async () => {
    const tmp = mkdtempSync(join(tmpdir(), "bla-kanxue-hygiene-"));
    try {
      writeFileSync(
        join(tmp, "entry.cjs"),
        `"use strict"; module.exports = { run: (x) => (x ^ 7) >>> 0 };\n`,
      );
      // Benign template & public key must NOT trigger false positives
      writeFileSync(join(tmp, ".env.example"), "API_SECRET=replace_me\n");
      writeFileSync(
        join(tmp, "verify-pub.pem"),
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA1234\n-----END PUBLIC KEY-----\n",
      );

      const cleanScan = scanPackagingGates({ directory: tmp, intensity: "bankrupt" });
      expect(cleanScan.gateCounts["release-hygiene"]).toBe(0);

      // Plant Quarkslab Defect 1 environment leaks
      writeFileSync(join(tmp, "SOLUTION.txt"), "flag is 1234\n");
      writeFileSync(join(tmp, ".env"), "SIGNING_SECRET=prod_live_998877\n");
      writeFileSync(
        join(tmp, "deploy.pem"),
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF\n-----END PRIVATE KEY-----\n",
      );
      mkdirSync(join(tmp, "lib native.so.dSYM", "Contents", "Resources", "DWARF"), {
        recursive: true,
      });
      writeFileSync(
        join(tmp, "lib native.so.dSYM", "Contents", "Resources", "DWARF", "libnative.so"),
        Buffer.from([0xcf, 0xfa, 0xed, 0xfe]),
      );

      const dirtyScan = scanPackagingGates({ directory: tmp, intensity: "bankrupt" });
      expect(dirtyScan.gateCounts["release-hygiene"]).toBe(4);
      expect(dirtyScan.shouldRefuseBankrupt).toBe(true);

      const outDir = join(tmp, "out-blocked");
      const blockedReport = await hardenProject({
        directory: tmp,
        outputDirectory: outDir,
        intensity: "bankrupt",
      });
      expect(blockedReport.overallSuccess).toBe(false);
      expect(blockedReport.hardenedCount).toBe(0);

      // Lab escape allows explicit override
      const allowedOut = join(tmp, "out-allowed");
      const allowedReport = await hardenProject({
        directory: tmp,
        outputDirectory: allowedOut,
        intensity: "bankrupt",
        allowReleaseHygieneLeak: true,
      });
      expect(allowedReport.overallSuccess).toBe(true);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
