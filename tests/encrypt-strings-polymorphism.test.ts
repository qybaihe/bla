import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import vm from "node:vm";
import { describe, expect, it } from "vitest";
import {
  buildKeystream,
  deriveEntryKeystream,
  encryptStrings,
  xorEncodeToBytes,
} from "../src/engine/encrypt-strings.js";
import {
  DECODER_VARIANT_COUNT,
  LEGACY_DECODER_MIX,
  deriveDecoderMix,
  matchesDecoderFunction,
  renderDecoderFunction,
  type DecoderMix,
} from "../src/engine/string-decoder-stub.js";
import { protectTarget } from "../src/engine/protector.js";
import { SeededPrng } from "../src/core/prng.js";

const require = createRequire(import.meta.url);

const NAMES = { fnName: "dec", tableName: "T", ksName: "K" } as const;

/** Encode strings into a table under `mix` using the production encode path. */
function encodeTable(
  strings: readonly string[],
  mix: DecoderMix,
): { table: number[][]; ks: number[] } {
  const prng = new SeededPrng(`poly-${mix.s1}-${mix.s2}-${mix.a}-${mix.b}`).derive(
    "string.encrypt",
  );
  const maxLen = Math.max(...strings.map((s) => Buffer.byteLength(s, "utf8")), 32);
  const keystream = buildKeystream(prng, Math.max(64, maxLen));
  const table = strings.map((u, idx) =>
    xorEncodeToBytes(u, deriveEntryKeystream(keystream, idx, Buffer.byteLength(u, "utf8"), mix)),
  );
  return { table, ks: Array.from(keystream) };
}

/** Evaluate an emitted decoder shape against a table and return the decoded rows. */
function runDecoder(
  table: readonly number[][],
  ks: readonly number[],
  mix: DecoderMix,
): string[] {
  const fnText = renderDecoderFunction(NAMES, mix);
  const sandbox: Record<string, unknown> = {
    [NAMES.tableName]: table,
    [NAMES.ksName]: ks,
    Buffer,
    Uint8Array,
    Array,
    TextDecoder,
    String,
  };
  vm.runInNewContext(`${fnText}\nglobalThis.__out=${NAMES.fnName};`, sandbox);
  const decode = sandbox.__out as (i: number) => string;
  return table.map((_, i) => decode(i));
}

describe("string-decrypt stub structural polymorphism (anti static de-blinding)", () => {
  const SAMPLE = [
    "FLAG{polymorphic_decoder_round_trip}",
    "https://license.example.com/v1/activate",
    "7f3a9c2e1b8d4f6a0e5c9b7d3a1f8e6c",
    "héllo — unïcode ✓ 日本語",
    "",
  ];

  it("every decoder shape is the exact inverse of the encode pad, for arbitrary seed-derived constants", () => {
    for (let n = 0; n < 40; n++) {
      const prng = new SeededPrng(`equiv-seed-${n}`).derive("string.encrypt");
      const mix = deriveDecoderMix(prng);
      const { table, ks } = encodeTable(SAMPLE, mix);
      // Decode with each structural shape — all shapes share the same math,
      // so any shape must recover the plaintext encoded under `mix`.
      for (let variant = 0; variant < DECODER_VARIANT_COUNT; variant++) {
        const decoded = runDecoder(table, ks, { ...mix, variant });
        expect(decoded).toEqual(SAMPLE.slice());
      }
    }
  });

  it("the legacy fixed constants still round-trip (back-compatible default)", () => {
    const { table, ks } = encodeTable(SAMPLE, LEGACY_DECODER_MIX);
    expect(runDecoder(table, ks, LEGACY_DECODER_MIX)).toEqual(SAMPLE.slice());
    // deriveEntryKeystream with no mix argument must equal the legacy mix.
    const prng = new SeededPrng("legacy-default").derive("string.encrypt");
    const keystream = buildKeystream(prng, 64);
    const withDefault = deriveEntryKeystream(keystream, 3, 20);
    const withLegacy = deriveEntryKeystream(keystream, 3, 20, LEGACY_DECODER_MIX);
    expect(Buffer.compare(withDefault, withLegacy)).toBe(0);
  });

  it("carries no build-invariant arithmetic signature: constants and shape vary across seeds", () => {
    const tuples = new Set<string>();
    const variantsSeen = new Set<number>();
    for (let n = 0; n < 80; n++) {
      const prng = new SeededPrng(`drift-seed-${n}`).derive("string.encrypt");
      const mix = deriveDecoderMix(prng);
      tuples.add(`${mix.s1}|${mix.s2}|${mix.a}|${mix.b}`);
      variantsSeen.add(mix.variant);
      // Strides are odd (coprime-friendly with the even keystream length).
      expect(mix.s1 % 2).toBe(1);
      expect(mix.s2 % 2).toBe(1);
    }
    // High entropy: the old build emitted ONE invariant tuple for every build.
    expect(tuples.size).toBeGreaterThan(40);
    // Both structural shapes actually occur.
    expect(variantsSeen.size).toBe(DECODER_VARIANT_COUNT);
    // The historical signature is not what most builds emit now.
    const legacyTuple = `${LEGACY_DECODER_MIX.s1}|${LEGACY_DECODER_MIX.s2}|${LEGACY_DECODER_MIX.a}|${LEGACY_DECODER_MIX.b}`;
    expect(tuples.has(legacyTuple)).toBe(false);
  });

  it("the shared recognizer matches every emitted shape and rejects near-misses", () => {
    for (let variant = 0; variant < DECODER_VARIANT_COUNT; variant++) {
      const prng = new SeededPrng(`match-seed-${variant}`).derive("string.encrypt");
      const mix = { ...deriveDecoderMix(prng), variant };
      const fnText = renderDecoderFunction(NAMES, mix);
      expect(matchesDecoderFunction(fnText, NAMES)).toBe(true);
      // Wrong binding names must not match.
      expect(
        matchesDecoderFunction(fnText, { ...NAMES, tableName: "OTHER" }),
      ).toBe(false);
      // A one-operator tamper (XOR → OR) must not match.
      const tampered = fnText.replace("^", "|");
      expect(matchesDecoderFunction(tampered, NAMES)).toBe(false);
    }
    // An unrelated user function must never be mistaken for the stub.
    expect(
      matchesDecoderFunction("function dec(i){return T[i]+K;}", NAMES),
    ).toBe(false);
  });

  it("the JS AST shield still recognizes and scrubs the polymorphic stub, and hardened output runs — for both shapes", () => {
    const covered = new Map<number, boolean>();
    const plain = "FLAG{harden_scrub_both_shapes}";
    const token = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
    for (let n = 0; n < 60 && covered.size < DECODER_VARIANT_COUNT; n++) {
      const seed = `scrub-seed-${n}`;
      const dir = mkdtempSync(join(tmpdir(), "bla-poly-"));
      const file = join(dir, "license.cjs");
      writeFileSync(
        file,
        [
          '"use strict";',
          `function unlock(key){return key==="k"?${JSON.stringify(plain)}:${JSON.stringify(token)};}`,
          "module.exports={unlock};",
          "",
        ].join("\n"),
        "utf8",
      );
      const enc = encryptStrings({ path: dir, seed });
      expect(enc.status).toBe("ok");
      const stage2 = readFileSync(file, "utf8");
      // Local-variable layout tells the two emitted shapes apart.
      const variant = stage2.includes("p=new Uint8Array(") ? 1 : 0;
      if (covered.has(variant)) continue;
      covered.set(variant, true);

      // The intermediate stub carries the transient markers …
      expect(stage2).toContain("_blaS");
      // … but the final hardened artifact must not expose them.
      const outFile = join(dir, "license.hardened.cjs");
      protectTarget({ inputPath: file, outputPath: outFile, intensity: "bankrupt", seed });
      const hardened = readFileSync(outFile, "utf8");
      expect(hardened).not.toMatch(/\b_bla[ST]\b/);
      expect(hardened).not.toContain(plain);
      expect(hardened).not.toContain(token);

      // Equivalence: the scrubbed module still decodes its strings.
      const mod = require(outFile) as { unlock: (k: string) => string };
      expect(mod.unlock("k")).toBe(plain);
      expect(mod.unlock("x")).toBe(token);
    }
    // Both structural shapes were exercised end-to-end.
    expect(covered.size).toBe(DECODER_VARIANT_COUNT);
  });
});
