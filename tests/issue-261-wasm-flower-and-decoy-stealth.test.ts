import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as vm from "node:vm";
import { afterEach, describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { lintPlaintextSecretsSource } from "../src/engine/plaintext-secret-lint.js";
import { protectTarget } from "../src/engine/protector.js";
import { verifyTarget } from "../src/engine/verifier.js";
import { generateBpeTokenAmplifier } from "../src/shields/exhaustion/bpe-token-amplifier.js";
import {
  createWasmCustomSection,
  injectWasmBytecodeFlowerInstructions,
  protectWasmBinary,
} from "../src/shields/formats/wasm.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-issue261-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * Builds a valid multi-function WebAssembly 1.0 module with:
 *   func 0: add32(i32, i32) -> i32  (returns (a + b) ^ 0x5a)
 *   func 1: mix64(i64) -> i64       (returns x + 7n)
 *   func 2: constZero() -> i32      (declares 1 local i32, sets it to 42, returns it)
 */
function buildMultiSigWasmModule(): Buffer {
  const typeSection = Buffer.from([
    0x01, 0x10, 0x03,
    0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // type 0: (i32, i32) -> i32
    0x60, 0x01, 0x7e, 0x01, 0x7e,       // type 1: (i64) -> i64
    0x60, 0x00, 0x01, 0x7f,             // type 2: () -> i32
  ]);
  const funcSection = Buffer.from([0x03, 0x04, 0x03, 0x00, 0x01, 0x02]);
  const expAdd = Buffer.from([0x05, ...Buffer.from("add32"), 0x00, 0x00]);
  const expMix = Buffer.from([0x05, ...Buffer.from("mix64"), 0x00, 0x01]);
  const expConst = Buffer.from([0x09, ...Buffer.from("constZero"), 0x00, 0x02]);
  const expBody = Buffer.concat([Buffer.from([0x03]), expAdd, expMix, expConst]);
  const exportSection = Buffer.concat([Buffer.from([0x07, expBody.length]), expBody]);

  // Body 0: 0 locals; local.get 0; local.get 1; i32.add; i32.const 0x5a; i32.xor; end
  const body0 = Buffer.from([0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x41, 0xda, 0x00, 0x73, 0x0b]);
  // Body 1: 0 locals; local.get 0; i64.const 7; i64.add; end
  const body1 = Buffer.from([0x00, 0x20, 0x00, 0x42, 0x07, 0x7c, 0x0b]);
  // Body 2: 1 local decl (1 x i32); i32.const 42; local.set 0; local.get 0; end
  const body2 = Buffer.from([0x01, 0x01, 0x7f, 0x41, 0x2a, 0x21, 0x00, 0x20, 0x00, 0x0b]);

  const codePayload = Buffer.concat([
    Buffer.from([0x03]),
    Buffer.from([body0.length]),
    body0,
    Buffer.from([body1.length]),
    body1,
    Buffer.from([body2.length]),
    body2,
  ]);
  const codeSection = Buffer.concat([Buffer.from([0x0a, codePayload.length]), codePayload]);

  return Buffer.concat([
    Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
    typeSection,
    funcSection,
    exportSection,
    codeSection,
  ]);
}

describe("Issue #261: WASM Code-section flower bytecode injection", () => {
  it("injects valid parameter-coupled opaque-false flower blocks across i32, i64, and 0-param functions while preserving exact runtime behavior", async () => {
    const rawWasm = buildMultiSigWasmModule();
    expect(WebAssembly.validate(new Uint8Array(rawWasm))).toBe(true);

    const intensities = [
      ["stealth", 1],
      ["balanced", 2],
      ["maximum", 3],
      ["bankrupt", 4],
    ] as const;

    for (const [intensity, expectedBlocksPerFn] of intensities) {
      const flowerOnly = injectWasmBytecodeFlowerInstructions(rawWasm, {
        intensity,
        seed: `flower-${intensity}`,
      });
      expect(flowerOnly.functionsHardened).toBe(3);
      expect(flowerOnly.flowerBlocksInjected).toBe(3 * expectedBlocksPerFn);
      expect(flowerOnly.addedCodeBytes).toBeGreaterThan(120 * expectedBlocksPerFn);
      expect(WebAssembly.validate(new Uint8Array(flowerOnly.buffer))).toBe(true);

      const protectedRes = protectWasmBinary(rawWasm, {
        intensity,
        seed: `protect-${intensity}`,
        preserveExports: ["add32", "mix64", "constZero"],
      });
      expect(protectedRes.codeFunctionsHardened).toBe(3);
      expect(protectedRes.bytecodeFlowerBlocksInjected).toBe(3 * expectedBlocksPerFn);
      expect(WebAssembly.validate(new Uint8Array(protectedRes.buffer))).toBe(true);

      // Execute the hardened WASM module in V8 and verify 100% bit-exact outputs across boundary inputs
      const { instance } = await WebAssembly.instantiate(new Uint8Array(protectedRes.buffer));
      const add32 = instance.exports.add32 as (a: number, b: number) => number;
      const mix64 = instance.exports.mix64 as (x: bigint) => bigint;
      const constZero = instance.exports.constZero as () => number;

      const i32Cases: readonly [number, number][] = [
        [0, 0],
        [-1, 1],
        [0x7fffffff, 1],
        [-0x80000000, -1],
        [12345, 67890],
        [0x55aa55aa | 0, 0xaa55aa55 | 0],
      ];
      for (const [a, b] of i32Cases) {
        expect(add32(a, b)).toBe(((a + b) | 0) ^ 0x5a);
      }

      const i64Cases: readonly bigint[] = [
        0n,
        1n,
        -1n,
        42n,
        0x7fffffffffffffffn,
        -0x8000000000000000n,
      ];
      for (const x of i64Cases) {
        expect(mix64(x)).toBe(BigInt.asIntN(64, x + 7n));
      }

      expect(constZero()).toBe(42);
    }
  });

  it("skips Code-section mutation safely when reloc.* custom sections exist or input is malformed", () => {
    const rawWasm = buildMultiSigWasmModule();
    const withReloc = Buffer.concat([
      rawWasm,
      createWasmCustomSection("reloc.CODE", Buffer.from([0x0a, 0x00])),
    ]);
    const relocRes = injectWasmBytecodeFlowerInstructions(withReloc, {
      intensity: "bankrupt",
      seed: "reloc-skip",
    });
    expect(relocRes.functionsHardened).toBe(0);
    expect(relocRes.buffer.equals(withReloc)).toBe(true);

    const badMagic = injectWasmBytecodeFlowerInstructions(Buffer.from("not-wasm"));
    expect(badMagic.functionsHardened).toBe(0);

    const truncated = injectWasmBytecodeFlowerInstructions(rawWasm.subarray(0, rawWasm.length - 4));
    expect(truncated.functionsHardened).toBe(0);
  });
});

describe("Issue #261: Decoy identifier stealth, rare-CJK BPE amplification & plausible comments", () => {
  it("removes self-revealing decoy names/comments and trivial `&& false` tells from hardened JS while preserving execution & verify", () => {
    const source = `
      function verifyLicenseCode(code) {
        if (typeof code !== "string" || code.length < 4) return false;
        let sum = 0;
        for (let i = 0; i < code.length; i++) sum = (sum + code.charCodeAt(i)) & 0xff;
        return sum === 0x9e;
      }
      module.exports = { verifyLicenseCode };
    `;

    const res = transformJavaScriptWithBlaShield(source, {
      intensity: "bankrupt",
      seed: "issue-261-stealth",
    });

    // Zero self-revealing decoy/deception identifiers or comments in emitted output
    expect(res.code).not.toMatch(/registerDecoyIpc/i);
    expect(res.code).not.toMatch(/initRuntimeDeception/i);
    expect(res.code).not.toMatch(/stepShadowHeap|shadowHeap/i);
    expect(res.code).not.toMatch(/bpeSink_|tokenSink_/i);
    expect(res.code).not.toContain("inverted shadow invariant");
    expect(res.code).not.toContain("bla.enterprise.billing.v4");
    expect(res.code).not.toContain("[HONEY-CRYPTO-MANIFEST]");
    expect(res.code).not.toContain("Boolean(token) && false");

    // Contains plausible engineering maintenance comments + rare CJK Extension A characters (U+3400..U+343F)
    expect(res.code).toMatch(/[\u3400-\u343f]{4,}/);
    expect(res.code).toContain("CJK Extension A collation");

    // Hardened program still runs identically
    const mod = { exports: {} as { verifyLicenseCode?: (c: string) => boolean } };
    const ctx = vm.createContext({
      module: mod,
      exports: mod.exports,
      Math,
      Object,
      Array,
      String,
      Number,
      Boolean,
      Map,
      RegExp,
      JSON,
      Date,
      Int32Array,
      Uint8Array,
      Uint32Array,
      ArrayBuffer,
      DataView,
    });
    vm.runInContext(res.code, ctx, { timeout: 3000 });
    expect(mod.exports.verifyLicenseCode!("AAAA")).toBe(false);
    // '!' (33) + '!' (33) + '!' (33) + ';' (59) = 158 = 0x9e
    expect(mod.exports.verifyLicenseCode!("!!!;")).toBe(true);

    // End-to-end protectTarget + verifyTarget passes cleanly
    const dir = makeTempDir();
    const inPath = join(dir, "app.cjs");
    const outPath = join(dir, "app.hardened.cjs");
    writeFileSync(inPath, source, "utf8");
    protectTarget({
      inputPath: inPath,
      outputPath: outPath,
      intensity: "bankrupt",
      seed: "issue-261-verify",
    });
    expect(verifyTarget(outPath, inPath).overallPassed).toBe(true);
  });

  it("amplifies BPE token density with rare CJK Extension A tables & plausible comments across all intensities", () => {
    for (const intensity of ["stealth", "balanced", "maximum", "bankrupt"] as const) {
      const bpe = generateBpeTokenAmplifier(new SeededPrng(`cjk-${intensity}`), intensity);
      expect(bpe.rareCjkCharsInjected).toBeGreaterThanOrEqual(32);
      expect(bpe.plausibleCommentsInjected).toBeGreaterThanOrEqual(2);
      expect(bpe.tokensPerByteRatio).toBeGreaterThanOrEqual(0.64);
      expect(bpe.code).not.toMatch(/bpeSink_|tokenSink_/);
      expect(bpe.code).toMatch(/[\u3400-\u343f]/);
      // Rare CJK comments/tables must not trigger false-positive plaintext-secret findings
      expect(
        lintPlaintextSecretsSource(bpe.code).findings.filter((f) => f.severity === "error"),
      ).toEqual([]);
      // Must remain valid executable JavaScript
      expect(() => new Function(`${bpe.code}; return true;`)()).not.toThrow();
    }
  });
});
