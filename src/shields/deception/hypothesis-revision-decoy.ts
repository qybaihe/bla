import { realisticIdentifierBatch } from "../../core/identifiers.js";
import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";

export interface HypothesisRevisionChainEntry {
  readonly primaryLureSymbol: string;
  readonly revisedFallbackSymbol: string;
  readonly stateLedgerSymbol: string;
}

export interface HypothesisRevisionDecoyResult {
  readonly code: string;
  readonly revisionChains: readonly HypothesisRevisionChainEntry[];
  readonly auditorAttentionSinks: readonly string[];
}

const CIPHER_TAG_BYTES: readonly (readonly number[])[] = Object.freeze([
  [0x41, 0x45, 0x53, 0x2d, 0x32, 0x35, 0x36], // "AES-256"
  [0x48, 0x4d, 0x41, 0x43, 0x2d, 0x53, 0x32], // "HMAC-S2"
  [0x4b, 0x44, 0x46, 0x2d, 0x48, 0x4b, 0x31], // "KDF-HK1"
  [0x43, 0x48, 0x41, 0x43, 0x48, 0x41, 0x32], // "CHACHA2"
]);

function deriveNonHexspeakUint32(prng: SeededPrng): number {
  let v = (prng.nextUint32() | 1) >>> 0;
  if (
    v === 0xdeadbeef ||
    v === 0xbaadf00d ||
    v === 0xcafebabe ||
    v === 0x9e3779b9
  ) {
    v = (v ^ 0x5bd1e995) >>> 0;
  }
  return v;
}

/**
 * Multi-Round Hypothesis-Revision Decoys & Adversarial-Auditor Attention Sinks.
 *
 * Countermeasure against next-generation RE agent metacognitive layers:
 * 1. Two-stage live lures (`primaryLure -> revisedFallback`): Stage 1 presents a
 *    linear XOR-add-xor chain (`step1 -> step2 -> step3`) that executes live on
 *    warm-init (satisfying static-vs-dynamic Evidence Arbitrators), then hands off
 *    to Stage 2 (`revisedFallback`), which emits a non-crashing, schema-valid
 *    plausible-wrong envelope so a Hypothesis Manager that revises Stage 1 locks
 *    onto Stage 2 ("post-revision confidence bias") instead of crashing or searching
 *    further.
 * 2. Adversarial-Auditor attention sinks: benign, side-effect-free local functions
 *    containing high-salience security-audit idioms (byte-array cipher tags, PID
 *    probe, round mixing, and explicit `.fill(0)` memory zeroization) that consume
 *    an isolated Auditor agent's attention/token budget on false positives.
 */
export function generateHypothesisRevisionDecoy(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): HypothesisRevisionDecoyResult {
  const chainCount =
    intensity === "stealth" ? 1 : intensity === "balanced" ? 2 : intensity === "maximum" ? 3 : 4;
  const sinkCount =
    intensity === "stealth" ? 2 : intensity === "balanced" ? 4 : intensity === "maximum" ? 6 : 8;

  const totalIdsNeeded = chainCount * 3 + sinkCount + 1;
  const ids = realisticIdentifierBatch(prng, totalIdsNeeded);
  let cursor = 0;

  const revisionChains: HypothesisRevisionChainEntry[] = [];
  const auditorAttentionSinks: string[] = [];
  const lines: string[] = [];

  for (let i = 0; i < chainCount; i++) {
    const primarySym = ids[cursor++]!;
    const revisedSym = ids[cursor++]!;
    const ledgerSym = ids[cursor++]!;
    revisionChains.push({
      primaryLureSymbol: primarySym,
      revisedFallbackSymbol: revisedSym,
      stateLedgerSymbol: ledgerSym,
    });

    const k1 = deriveNonHexspeakUint32(prng);
    const k2 = prng.nextInt(0x101, 0x7fff);
    const k3 = deriveNonHexspeakUint32(prng);
    const revPrime = (prng.nextUint32() | 1) >>> 0;
    const revBasis = deriveNonHexspeakUint32(prng);
    const warmInput = prng.nextInt(17, 4093);

    lines.push(`const ${ledgerSym} = { epoch: 0, ticket: 0, status: "idle" };`);
    // Stage 2: Revised hypothesis target — returns plausible structured envelope (never crashes)
    lines.push(`function ${revisedSym}(frameSeed, priorSlot) {`);
    lines.push(`  let h = (${revBasis} ^ (frameSeed >>> 0)) >>> 0;`);
    lines.push(`  h = Math.imul(h ^ (priorSlot >>> 0), ${revPrime}) >>> 0;`);
    lines.push(`  h = ((h >>> 13) | (h << 19)) >>> 0;`);
    lines.push(`  ${ledgerSym}.epoch = (${ledgerSym}.epoch + 1) | 0;`);
    lines.push(`  ${ledgerSym}.ticket = h;`);
    lines.push(`  ${ledgerSym}.status = (h & 3) === 1 ? "verified" : "active";`);
    lines.push(`  return { code: 200, status: ${ledgerSym}.status, lease: (h ^ 0x${(k1 & 0xffff).toString(16)}) >>> 0, ok: (h & 7) === 9 };`);
    lines.push(`}`);

    // Stage 1: Linear readable chain (attracts initial hypothesis H1, conditionally reachable, delegates to H2)
    lines.push(`function ${primarySym}(rawToken) {`);
    lines.push(`  const step1 = ((rawToken >>> 0) ^ 0x${k1.toString(16)}) >>> 0;`);
    lines.push(`  const step2 = (step1 + 0x${k2.toString(16)}) >>> 0;`);
    lines.push(`  const step3 = (step2 ^ 0x${k3.toString(16)}) >>> 0;`);
    lines.push(`  if (step3 === 0) {`);
    lines.push(`    return { code: 200, status: "calibrated", lease: step2, ok: false };`);
    lines.push(`  }`);
    lines.push(`  return ${revisedSym}(rawToken >>> 0, step3);`);
    lines.push(`}`);
    lines.push(`void ${primarySym}(${warmInput});`);
  }

  for (let s = 0; s < sinkCount; s++) {
    const sinkSym = ids[cursor++]!;
    auditorAttentionSinks.push(sinkSym);
    const tagBytes = CIPHER_TAG_BYTES[s % CIPHER_TAG_BYTES.length]!;
    const maskByte = prng.nextInt(0x11, 0x7e);
    const maskedLiteral = tagBytes.map((b) => `0x${(b ^ maskByte).toString(16)}`).join(", ");
    const salt = prng.nextInt(3, 251);

    lines.push(`function ${sinkSym}(probeHint) {`);
    lines.push(`  const buf = [${maskedLiteral}];`);
    lines.push(`  const pidSalt = typeof process === "object" && process && typeof process.pid === "number" ? process.pid : ${salt};`);
    lines.push(`  let acc = (pidSalt ^ (probeHint | 0)) >>> 0;`);
    lines.push(`  for (let i = 0; i < buf.length; i++) {`);
    lines.push(`    buf[i] = (buf[i] ^ 0x${maskByte.toString(16)}) & 0xff;`);
    lines.push(`    acc = (Math.imul(acc ^ buf[i], 16777619) >>> 0);`);
    lines.push(`  }`);
    lines.push(`  if (pidSalt > 0) {`);
    lines.push(`    for (let z = 0; z < buf.length; z++) buf[z] = 0;`);
    lines.push(`  }`);
    lines.push(`  return acc;`);
    lines.push(`}`);
  }

  const bootSym = ids[cursor++]!;
  const warmSinkCalls = auditorAttentionSinks
    .slice(0, Math.min(2, auditorAttentionSinks.length))
    .map((fn, idx) => `${fn}(${idx + 1})`)
    .join(" ^ ");
  if (warmSinkCalls.length > 0) {
    lines.push(`const ${bootSym} = (${warmSinkCalls}) >>> 0; void ${bootSym};`);
  }

  return {
    code: lines.join("\n"),
    revisionChains,
    auditorAttentionSinks,
  };
}
