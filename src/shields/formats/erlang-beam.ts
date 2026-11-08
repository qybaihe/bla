import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

const FOR1 = Buffer.from("FOR1", "latin1");
const BEAM = Buffer.from("BEAM", "latin1");

function u32be(value: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(value >>> 0);
  return b;
}

function pad4(bytes: Buffer): Buffer {
  const pad = (4 - (bytes.length % 4)) % 4;
  return pad === 0 ? bytes : Buffer.concat([bytes, Buffer.alloc(pad)]);
}

function encodeChunk(name: string, payload: Buffer): Buffer {
  if (name.length !== 4) throw new Error(`BEAM chunk name must be 4 chars: ${name}`);
  return Buffer.concat([
    Buffer.from(name, "latin1"),
    u32be(payload.length),
    pad4(payload),
  ]);
}

/** Non-compact AtU8 atom table (positive count, 1-byte lengths). */
function encodeAtU8(names: readonly string[]): Buffer {
  const parts: Buffer[] = [u32be(names.length)];
  for (const name of names) {
    const encoded = Buffer.from(name, "utf8");
    if (encoded.length > 255) {
      throw new Error(`BEAM atom name too long for non-compact encoding: ${name}`);
    }
    parts.push(Buffer.from([encoded.length]), encoded);
  }
  return encodeChunk("AtU8", Buffer.concat(parts));
}

export interface BeamChunkView {
  readonly name: string;
  readonly payload: Buffer;
}

export interface ErlangBeamInspection {
  readonly validMagic: boolean;
  readonly formSize: number;
  readonly chunkCount: number;
  readonly chunkNames: readonly string[];
  readonly atomCount: number;
  readonly blaProtected: boolean;
}

function parseBeamChunks(bytes: Buffer): {
  readonly valid: boolean;
  readonly formSize: number;
  readonly chunks: BeamChunkView[];
} {
  if (
    bytes.length < 12 ||
    bytes.subarray(0, 4).toString("latin1") !== "FOR1" ||
    bytes.subarray(8, 12).toString("latin1") !== "BEAM"
  ) {
    return { valid: false, formSize: 0, chunks: [] };
  }
  const formSize = bytes.readUInt32BE(4);
  const formEnd = 8 + formSize;
  if (formEnd > bytes.length) return { valid: false, formSize, chunks: [] };
  const chunks: BeamChunkView[] = [];
  let at = 12;
  while (at + 8 <= formEnd) {
    const name = bytes.subarray(at, at + 4).toString("latin1");
    const size = bytes.readUInt32BE(at + 4);
    const payloadOffset = at + 8;
    const padded = payloadOffset + size + ((4 - (size % 4)) % 4);
    if (padded > formEnd || payloadOffset + size > bytes.length) break;
    chunks.push({
      name,
      payload: Buffer.from(bytes.subarray(payloadOffset, payloadOffset + size)),
    });
    at = padded;
  }
  return { valid: true, formSize, chunks };
}

/** OTP 28+ compact unsigned `u` tag encoder (mirrors REA BeamParser). */
function encodeCompactU(value: number): Buffer {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`compact u value must be a non-negative integer: ${value}`);
  }
  if (value < 16) return Buffer.from([(value << 4) & 0xff]);
  if (value < 0x800) {
    return Buffer.from([0x08 | (((value >> 8) & 0x07) << 5), value & 0xff]);
  }
  if (value <= 0xffff) {
    return Buffer.from([0x18, (value >> 8) & 0xff, value & 0xff]);
  }
  if (value <= 0xffffff) {
    return Buffer.from([
      0x38,
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff,
    ]);
  }
  throw new Error(`compact u value too large for atom length: ${value}`);
}

function decodeCompactU(
  payload: Buffer,
  at: number,
): { value: number; next: number } | null {
  if (at >= payload.length) return null;
  const first = payload[at]!;
  if ((first & 0x07) !== 0) return null;
  if ((first & 0x08) === 0) {
    return { value: first >> 4, next: at + 1 };
  }
  if ((first & 0x10) === 0) {
    if (at + 1 >= payload.length) return null;
    return {
      value: ((first >> 5) << 8) | payload[at + 1]!,
      next: at + 2,
    };
  }
  const byteCountCode = first >> 5;
  if (byteCountCode === 7) return null;
  const byteCount = byteCountCode + 2;
  const start = at + 1;
  if (start + byteCount > payload.length) return null;
  let value = 0;
  for (let i = 0; i < byteCount; i++) {
    value = (value << 8) | payload[start + i]!;
  }
  return { value, next: start + byteCount };
}

function decodeAtU8Table(payload: Buffer): {
  readonly names: string[];
  readonly compact: boolean;
} {
  if (payload.length < 4) return { names: [], compact: false };
  const declared = payload.readInt32BE(0);
  const compact = declared < 0;
  const count = Math.abs(declared);
  if (count === 0) return { names: [], compact };
  const names: string[] = [];
  let at = 4;
  for (let i = 0; i < count; i++) {
    if (at >= payload.length) break;
    let length: number;
    let next: number;
    if (compact) {
      const decoded = decodeCompactU(payload, at);
      if (decoded === null) break;
      length = decoded.value;
      next = decoded.next;
    } else {
      length = payload[at]!;
      next = at + 1;
    }
    at = next;
    if (at + length > payload.length) break;
    names.push(payload.subarray(at, at + length).toString("utf8"));
    at += length;
  }
  return { names, compact };
}

/** Encode AtU8 body (not wrapped in IFF chunk) in compact or classic form. */
function encodeAtU8Body(
  names: readonly string[],
  compact: boolean,
): Buffer {
  if (compact) {
    const parts: Buffer[] = [Buffer.alloc(4)];
    parts[0]!.writeInt32BE(-names.length);
    for (const name of names) {
      const enc = Buffer.from(name, "utf8");
      parts.push(encodeCompactU(enc.length), enc);
    }
    return Buffer.concat(parts);
  }
  const parts: Buffer[] = [u32be(names.length)];
  for (const name of names) {
    const enc = Buffer.from(name, "utf8");
    if (enc.length > 255) continue;
    parts.push(Buffer.from([enc.length]), enc);
  }
  return Buffer.concat(parts);
}

export function inspectErlangBeam(bytes: Buffer): ErlangBeamInspection {
  const parsed = parseBeamChunks(bytes);
  let atomCount = 0;
  for (const chunk of parsed.chunks) {
    if (chunk.name === "AtU8" || chunk.name === "Atom") {
      if (chunk.payload.length >= 4) {
        atomCount = Math.abs(chunk.payload.readInt32BE(0));
      }
    }
  }
  const text = bytes.toString("latin1");
  return {
    validMagic: parsed.valid,
    formSize: parsed.formSize,
    chunkCount: parsed.chunks.length,
    chunkNames: parsed.chunks.map((c) => c.name),
    atomCount,
    blaProtected:
      text.includes("[BLA-BEAM-SHIELD]") ||
      parsed.chunks.some((c) => c.name.startsWith("Bla")),
  };
}

function rebuildBeam(chunks: readonly BeamChunkView[]): Buffer {
  const body = Buffer.concat([
    BEAM,
    ...chunks.map((c) => encodeChunk(c.name, c.payload)),
  ]);
  return Buffer.concat([FOR1, u32be(body.length), body]);
}

/**
 * Protects an Erlang BEAM IFF container:
 * - Preserves original chunk order and non-AtU8 payloads (Code/ExpT/ImpT stay intact).
 * - Appends canary atoms onto AtU8 tables (classic or OTP28+ compact), preserving
 *   original atom indices and compact/classic encoding style.
 * - Appends decoy IFF chunks past REA's default `max_chunks` (64) budget.
 */
export function protectErlangBeamBuffer(
  input: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string;
  } = {},
): {
  readonly buffer: Buffer;
  readonly chunksInjected: number;
  readonly atomsInjected: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
  readonly exceedsDefaultChunkBudget: boolean;
  readonly exceedsDefaultAtomBudget: boolean;
} {
  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-beam-shield");
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  const parsed = parseBeamChunks(input);
  if (!parsed.valid) {
    throw new Error(
      "Invalid or truncated BEAM module: expected an IFF FOR1/BEAM container; refusing to synthesize a replacement module.",
    );
  }
  const baseChunks: BeamChunkView[] = parsed.chunks.map((c) => ({
    name: c.name,
    payload: Buffer.from(c.payload),
  }));

  // Expand non-compact AtU8 in place (keep original atom indices).
  let atomsInjected = 0;
  let exceedsDefaultAtomBudget = false;
  const atomExtraTarget =
    intensity === "bankrupt" || intensity === "maximum"
      ? REA_INTERNAL_LIMITS.BEAM_DEFAULT_MAX_ATOMS + 64
      : 48;

  for (let i = 0; i < baseChunks.length; i++) {
    const chunk = baseChunks[i]!;
    if (chunk.name !== "AtU8") continue;
    const table = decodeAtU8Table(chunk.payload);
    if (table.names.length === 0 && chunk.payload.length >= 4) {
      // Empty or undecodable — skip atom mutation; decoy chunks still apply.
      break;
    }
    const existing = table.names;
    const extras: string[] = [
      "bla_beam_canary",
      `[BLA-BEAM-SHIELD]`,
      ...deception.textRecords
        .map((r) => r.replace(/[^\w.:/=+-]/g, "_").slice(0, 200))
        .filter((r) => r.length > 0)
        .slice(0, 16),
    ];
    while (existing.length + extras.length < atomExtraTarget) {
      extras.push(`bla_tarpit_atom_${extras.length}_${prng.hex(4)}`);
    }
    const merged = [...existing, ...extras];
    atomsInjected = extras.length;
    exceedsDefaultAtomBudget =
      merged.length > REA_INTERNAL_LIMITS.BEAM_DEFAULT_MAX_ATOMS;
    baseChunks[i] = {
      name: "AtU8",
      payload: encodeAtU8Body(merged, table.compact),
    };
    break;
  }

  // Decoy chunks: push past default max_chunks (64); bankrupt approaches hard 256.
  const targetChunks =
    intensity === "bankrupt"
      ? REA_INTERNAL_LIMITS.BEAM_MAX_CHUNKS + 4
      : intensity === "maximum"
        ? REA_INTERNAL_LIMITS.BEAM_DEFAULT_MAX_CHUNKS + 32
        : REA_INTERNAL_LIMITS.BEAM_DEFAULT_MAX_CHUNKS + 8;

  const decoyPayload = Buffer.from(
    [
      "[BLA-BEAM-SHIELD]",
      ...deception.textRecords.slice(0, 8),
      `BLA_BEAM_CANARY=${prng.hex(16)}`,
    ].join("\0") + "\0",
    "utf8",
  );

  let chunksInjected = 0;
  while (baseChunks.length < targetChunks) {
    const idx = chunksInjected;
    // 4-char IFF names; "Bla0".."Bla9" then "Bl10"+ via hex
    const name =
      idx < 10
        ? `Bla${idx}`
        : idx < 36
          ? `Bl${idx.toString(36).padStart(2, "0")}`.slice(0, 4)
          : `B${idx.toString(36).padStart(3, "0")}`.slice(0, 4);
    baseChunks.push({
      name: name.padEnd(4, "x").slice(0, 4),
      payload: Buffer.concat([
        decoyPayload,
        Buffer.from(`\nchunk=${idx}\n`, "utf8"),
      ]),
    });
    chunksInjected++;
  }

  const buffer = rebuildBeam(baseChunks);
  return {
    buffer,
    chunksInjected,
    atomsInjected,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
    exceedsDefaultChunkBudget:
      baseChunks.length > REA_INTERNAL_LIMITS.BEAM_DEFAULT_MAX_CHUNKS,
    exceedsDefaultAtomBudget,
  };
}
