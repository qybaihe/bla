/**
 * Structural polymorphism for the string-decrypt stub (anti static de-blinding).
 *
 * Before v3.6.2 the runtime decoder emitted by `encrypt-strings.ts` was
 * byte-for-byte identical across every build apart from its (already seeded)
 * identifier names. Its decode loop baked in the fixed mixing constants
 * `i*31`, `i*7+(j>>2)` and `ks+i*73+j*19`, so the whole function body was a
 * build-invariant signature. A static de-blinding tool that recognizes BLA
 * "by structure, not by name" (e.g. LASIK-class strippers) can key on exactly
 * that shape, locate every decoder, and either evaluate it to recover the
 * plaintext table or excise the protection wholesale.
 *
 * This module removes that invariant signature. For each file the mixing
 * constants are derived from the seed (an independent `SeededPrng` substream,
 * so keystream bytes and decoy identifiers stay bit-for-bit reproducible), and
 * one of several arithmetically-equivalent decoder *shapes* is selected. The
 * emitter (`renderDecoderFunction`) and the JS AST shield's marker recognizer
 * (`decoderFunctionPatterns`) are generated from the same source so they can
 * never drift apart.
 *
 * Honesty constraints (unchanged from `encrypt-strings.ts`):
 *   - XOR keystream only — NOT JS AES, no JS-held wrap-key + createDecipheriv.
 *   - The decode is the exact inverse of the encode pad; equivalence is proven
 *     by executing the hardened output in tests, never by a strength claim.
 *   - Polymorphism raises the cost of a *structural* recognizer; it is not a
 *     cryptographic guarantee and is not represented as one.
 */

import type { SeededPrng } from "../core/prng.js";

/** Seed-derived mixing parameters + structural shape selector for one file. */
export interface DecoderMix {
  /** Keystream stride for the per-byte base pad (odd). */
  readonly s1: number;
  /** Keystream stride for the per-entry salt pad (odd). */
  readonly s2: number;
  /** Per-entry additive mixer. */
  readonly a: number;
  /** Per-byte additive mixer. */
  readonly b: number;
  /** Decoder emission shape in `[0, DECODER_VARIANT_COUNT)`. */
  readonly variant: number;
}

/**
 * The constants emitted before structural polymorphism landed. Kept as the
 * default so the standalone `deriveEntryKeystream` export stays
 * backward-compatible for callers that pass no mix.
 */
export const LEGACY_DECODER_MIX: DecoderMix = {
  s1: 31,
  s2: 7,
  a: 73,
  b: 19,
  variant: 0,
};

/** Number of arithmetically-equivalent decoder shapes the emitter chooses from. */
export const DECODER_VARIANT_COUNT = 2;

/**
 * Derive the per-file mix from an independent substream of the file PRNG.
 * `SeededPrng.derive` keys the child off the root seed without advancing the
 * parent, so the keystream and decoy identifiers a file already draws from
 * `prng` stay reproducible for a given seed.
 */
export function deriveDecoderMix(prng: SeededPrng): DecoderMix {
  const mix = prng.derive("string.encrypt.mix");
  const s1 = mix.nextInt(5, 124) * 2 + 1; // odd in [11, 249]
  const s2 = mix.nextInt(1, 48) * 2 + 1; // odd in [3, 97]
  const a = mix.nextInt(17, 251);
  const b = mix.nextInt(5, 97);
  const variant = mix.nextInt(0, DECODER_VARIANT_COUNT - 1);
  return { s1, s2, a, b, variant };
}

/**
 * The single pad byte XORed onto plaintext byte `j` of entry `entryIndex`.
 * Both the encode side (`deriveEntryKeystream`) and every emitted decoder
 * shape compute this same value, so decode is the exact inverse of encode.
 */
export function entryPadByte(
  keystream: Buffer,
  entryIndex: number,
  j: number,
  mix: DecoderMix,
): number {
  const kLen = keystream.length;
  const kBase = keystream[(j + entryIndex * mix.s1) % kLen]!;
  const kSalt = keystream[(entryIndex * mix.s2 + (j >> 2)) % kLen]!;
  return (kBase ^ ((kSalt + entryIndex * mix.a + j * mix.b) & 0xff)) & 0xff;
}

export interface DecoderNames {
  readonly fnName: string;
  readonly tableName: string;
  readonly ksName: string;
}

/**
 * Render the decoder function `function <fn>(i){…}` for the chosen shape.
 * The shapes are arithmetically identical (addition and XOR commute) but use
 * different statement forms, operand orders and local identifiers, so no
 * single structural pattern matches every build.
 */
export function renderDecoderFunction(names: DecoderNames, mix: DecoderMix): string {
  const { fnName, tableName, ksName } = names;
  const { s1, s2, a, b } = mix;
  if (mix.variant === 1) {
    // Temp-for-pad shape: read salt before base, fold the additive group with
    // a reassociated sum, and XOR the pad onto the ciphertext last.
    return (
      `function ${fnName}(i){` +
      `var r=${tableName}[i],m=${ksName},ml=m.length,p=new Uint8Array(r.length);` +
      `for(var t=0;t<r.length;t++){` +
      `var s=m[(i*${s2}+(t>>2))%ml],c=m[(t+i*${s1})%ml];` +
      `var g=((i*${a}+s+t*${b})&255)^c;` +
      `p[t]=(g^r[t])&255;` +
      `}` +
      `return typeof Buffer!=="undefined"?Buffer.from(p).toString("utf8"):` +
      `(typeof TextDecoder!=="undefined"?new TextDecoder().decode(p):` +
      `String.fromCharCode.apply(null,Array.from(p)));` +
      `}`
    );
  }
  // Inline shape (historical layout, now with seed-derived constants).
  return (
    `function ${fnName}(i){` +
    `var e=${tableName}[i],k=${ksName},kl=k.length,o=new Uint8Array(e.length);` +
    `for(var j=0;j<e.length;j++){` +
    `var kb=k[(j+i*${s1})%kl],ks=k[(i*${s2}+(j>>2))%kl];` +
    `o[j]=(e[j]^(kb^((ks+i*${a}+j*${b})&255)))&255;` +
    `}` +
    `return typeof Buffer!=="undefined"?Buffer.from(o).toString("utf8"):` +
    `(typeof TextDecoder!=="undefined"?new TextDecoder().decode(o):` +
    `String.fromCharCode.apply(null,Array.from(o)));` +
    `}`
  );
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Distinct large sentinels standing in for the four seed-derived constants.
// They never collide with the decoder's own literal constants (2, 255) or
// index arithmetic, so replacing them with `\d+` after escaping yields a
// pattern that matches any build's constants while pinning everything else.
const MIX_SENTINELS = { s1: 811111, s2: 822222, a: 833333, b: 844444 } as const;

/**
 * One anchored `RegExp` per decoder shape that recognizes a BLA string-decrypt
 * function with the given binding names, treating the seed-derived mix
 * constants as wildcards. Generated from `renderDecoderFunction` so the
 * recognizer always tracks whatever the emitter produces.
 */
export function decoderFunctionPatterns(names: DecoderNames): readonly RegExp[] {
  const patterns: RegExp[] = [];
  for (let variant = 0; variant < DECODER_VARIANT_COUNT; variant++) {
    const rendered = renderDecoderFunction(names, { ...MIX_SENTINELS, variant });
    const body = escapeRegExp(rendered).replace(/8(?:1{5}|2{5}|3{5}|4{5})/g, "\\d+");
    patterns.push(new RegExp(`^${body}$`));
  }
  return patterns;
}

/** True when `decoderSource` is a BLA string-decrypt function of any shape. */
export function matchesDecoderFunction(
  decoderSource: string,
  names: DecoderNames,
): boolean {
  return decoderFunctionPatterns(names).some((re) => re.test(decoderSource));
}
