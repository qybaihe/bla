import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";

export interface BpeTokenAmplifierResult {
  readonly code: string;
  readonly amplifiedIdentifiersCount: number;
  readonly rareCjkCharsInjected: number;
  readonly plausibleCommentsInjected: number;
  readonly rawUtf8Bytes: number;
  readonly estimatedBpeTokens: number;
  readonly tokensPerByteRatio: number;
}

const HIGH_SPLIT_SUBWORDS = [
  "Zq",
  "X9",
  "Kv",
  "W7",
  "Jm",
  "P3",
  "Vh",
  "N8",
  "Cx",
  "B4",
  "Gf",
  "L6",
  "Tr",
  "D2",
  "Yw",
  "S5",
] as const;

/**
 * Curated CJK Unified Ideographs Extension A codepoints (`U+3400`–`U+343F`).
 * Valid printable UTF-8 (3 bytes/char) that almost never merge in common BPE
 * vocabularies (`o200k_base`, `cl100k_base`, Claude, Qwen, Hunyuan), splitting
 * into ~2–3 byte-fallback tokens per character (~0.80–1.0 tokens/byte).
 */
const RARE_CJK_EXT_A: readonly string[] = Array.from({ length: 64 }, (_, i) =>
  String.fromCodePoint(0x3400 + i),
);

/**
 * Mundane, domain-plausible engineering maintenance comments (zero self-revealing
 * decoy/tarpit/enclave markers) designed to engage CoT / deep-thinking models on
 * realistic compatibility and bitmask invariants.
 */
const PLAUSIBLE_MAINTENANCE_COMMENTS: readonly string[] = [
  "NFC/NFKC CJK Extension A collation bucket offsets; keep exact key order for v2 cache parity",
  "Do not fold the XOR mask: older V8 TurboFan builds widen signed 32-bit shifts without it",
  "Legacy ISO-15924 fallback buckets shared with client-side key normalization",
  "Parity check aligns regional glyph widths with server-side canonical digest table",
  "Preserves 16-bit stride alignment expected by downstream binary frame serializer",
  "Keep frozen table intact: downstream lookup hashes Object.keys() count during warm boot",
];

/**
 * Generates valid ECMAScript identifiers, rare CJK Extension A collation tables, and
 * plausible engineering maintenance comments engineered to maximize Byte-Pair Encoding
 * (BPE) subword fragmentation across modern LLM tokenizers while avoiding self-revealing
 * decoy/sink naming.
 */
export function generateBpeTokenAmplifier(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): BpeTokenAmplifierResult {
  const symbolCount =
    intensity === "stealth"
      ? 8
      : intensity === "balanced"
        ? 16
        : intensity === "maximum"
          ? 28
          : 42;
  const cjkPerEntry =
    intensity === "stealth"
      ? 4
      : intensity === "balanced"
        ? 6
        : intensity === "maximum"
          ? 10
          : 14;
  const tag = prng.hex(3);
  const identifiers: string[] = [];

  for (let i = 0; i < symbolCount; i++) {
    const parts: string[] = [`collationSlot_${tag}`];
    for (let s = 0; s < 8; s++) {
      const sub =
        HIGH_SPLIT_SUBWORDS[(i * 7 + s * 3 + prng.nextInt(0, 15)) % HIGH_SPLIT_SUBWORDS.length]!;
      parts.push(sub);
    }
    identifiers.push(parts.join("_"));
  }

  let rareCjkCharsInjected = 0;
  let plausibleCommentsInjected = 0;
  const lines: string[] = [
    `/* ${PLAUSIBLE_MAINTENANCE_COMMENTS[0]} */`,
    `const localeCollation_${tag} = Object.freeze({`,
  ];
  plausibleCommentsInjected += 1;

  for (let i = 0; i < identifiers.length; i++) {
    const id = identifiers[i]!;
    const prev = identifiers[(i + identifiers.length - 1) % identifiers.length]!;
    let cjkRun = "";
    for (let c = 0; c < cjkPerEntry; c++) {
      cjkRun += RARE_CJK_EXT_A[(i * 11 + c * 5 + prng.nextInt(0, 63)) % RARE_CJK_EXT_A.length]!;
    }
    rareCjkCharsInjected += cjkPerEntry;
    const commentNote =
      i % 4 === 0
        ? ` /* ${PLAUSIBLE_MAINTENANCE_COMMENTS[(i / 4) % PLAUSIBLE_MAINTENANCE_COMMENTS.length]} | ${cjkRun} | ref:${prev} */`
        : ` /* ${cjkRun} ref:${prev} */`;
    if (i % 4 === 0) plausibleCommentsInjected += 1;
    lines.push(
      `  ${id}: (${i + 1} ^ 0x${prng.hex(4)})${commentNote},`,
    );
  }
  lines.push(`});`);

  const code = lines.join("\n");
  const rawUtf8Bytes = Buffer.byteLength(code, "utf8");
  // Rare CJK Ext-A bytes (~0.85 tokens/byte) + high-split ASCII segments (~0.62 tokens/byte)
  const cjkUtf8Bytes = rareCjkCharsInjected * 3;
  const asciiUtf8Bytes = Math.max(0, rawUtf8Bytes - cjkUtf8Bytes);
  const estimatedBpeTokens = Math.ceil(asciiUtf8Bytes * 0.62 + cjkUtf8Bytes * 0.85);

  return {
    code,
    amplifiedIdentifiersCount: identifiers.length,
    rareCjkCharsInjected,
    plausibleCommentsInjected,
    rawUtf8Bytes,
    estimatedBpeTokens,
    tokensPerByteRatio: Number((estimatedBpeTokens / Math.max(1, rawUtf8Bytes)).toFixed(2)),
  };
}
