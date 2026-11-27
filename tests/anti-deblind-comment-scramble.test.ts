import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import {
  ATTESTATION_BANNER_PHRASES,
  deriveAttestationBanner,
  looksLikeAttestationBanner,
  LEGACY_ATTESTATION_BANNER,
  scrambleCommentText,
} from "../src/shields/deception/comment-scramble.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import { generatePythonTarpit } from "../src/shields/tarpit/tarpit-generator.js";

/**
 * LASIK (pktq/lasik src/js/fingerprints.ts) bulk-strips BLA comments matching:
 *   /^\s*(?:(?:reconcile session epoch|derive ledger digest|normalize envelope
 *   frame|hydrate runtime cache|project quota policy) \([0-9a-f]{6}\)|runtime
 *   attestation boundary|decorative shadow runtime signal\b.*)\s*$/
 * Both the overwrite comments and the attestation banner are now seed-derived.
 */

// Transcribed from the adversary.
const LASIK_SCRAMBLED_COMMENT =
  /^\s*(?:(?:reconcile session epoch|derive ledger digest|normalize envelope frame|hydrate runtime cache|project quota policy) \([0-9a-f]{6}\)|runtime attestation boundary|decorative shadow runtime signal\b.*)\s*$/;

describe("anti static de-blinding: scrambled comments and attestation banner are seed-derived", () => {
  it("overwrite comments never match LASIK's SCRAMBLED_COMMENT and vary across seeds", () => {
    const seen = new Set<string>();
    for (let n = 0; n < 200; n++) {
      const text = scrambleCommentText(new SeededPrng(`sc-${n}`));
      // LASIK matches the comment *value* (framing stripped); test both the bare
      // text and the block/line framed forms.
      expect(LASIK_SCRAMBLED_COMMENT.test(text)).toBe(false);
      expect(LASIK_SCRAMBLED_COMMENT.test(` ${text} `)).toBe(false);
      expect(LASIK_SCRAMBLED_COMMENT.test(` ${text}`)).toBe(false);
      seen.add(text);
    }
    expect(seen.size).toBeGreaterThan(50);
  });

  it("scrambles real JS comments into non-fingerprinted, plausible text", () => {
    const src = [
      "// 原始中文注释：计算授权",
      "/* proprietary licence check below */",
      "function f(x){ return x + 1; } // trailing note",
      "module.exports = { f };",
    ].join("\n");
    const out = transformJavaScriptWithBlaShield(src, {
      intensity: "bankrupt",
      seed: "comment-scramble-js",
      sourceType: "commonjs",
    }).code;
    // Original comment content is destroyed.
    expect(out).not.toContain("原始中文注释");
    expect(out).not.toContain("proprietary licence check");
    // And no comment line matches the adversary's fixed pattern.
    for (const line of out.split("\n")) {
      const m = /^\s*\/\/(.*)$/.exec(line) ?? /^\s*\/\*(.*?)\*\/\s*$/.exec(line);
      if (m) expect(LASIK_SCRAMBLED_COMMENT.test(m[1]!)).toBe(false);
    }
  });

  it("attestation banner pool is recognized but excludes the legacy fixed phrase", () => {
    expect(ATTESTATION_BANNER_PHRASES).not.toContain(LEGACY_ATTESTATION_BANNER);
    for (const phrase of ATTESTATION_BANNER_PHRASES) {
      expect(looksLikeAttestationBanner(`# ${phrase}`)).toBe(true);
    }
    // Back-compat: legacy phrase still recognized for pre-existing artifacts.
    expect(looksLikeAttestationBanner(`/* ${LEGACY_ATTESTATION_BANNER} */`)).toBe(true);
    expect(looksLikeAttestationBanner("// ordinary developer comment")).toBe(false);
  });

  it("python tarpit emits a seed-derived banner BLA recognizes but LASIK's literal misses", () => {
    const banners = new Set<string>();
    for (let n = 0; n < 24; n++) {
      const prng = new SeededPrng(`py-tarpit-${n}`);
      const code = generatePythonTarpit(prng, "bankrupt", []).code;
      expect(looksLikeAttestationBanner(code)).toBe(true);
      expect(code.includes(LEGACY_ATTESTATION_BANNER)).toBe(false);
      const m = /#\s*(.+)/.exec(code);
      if (m) banners.add(m[1]!.trim());
    }
    expect(banners.size).toBeGreaterThan(1);
  });

  it("deriveAttestationBanner is reproducible for a given seed", () => {
    expect(deriveAttestationBanner(new SeededPrng("b"))).toBe(
      deriveAttestationBanner(new SeededPrng("b")),
    );
  });
});
