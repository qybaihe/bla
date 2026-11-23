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
  if (formEnd !== bytes.length) return { valid: false, formSize, chunks: [] };

  // BLA's older synthetic callers (including the doctor probe) omit all IFF
  // padding. Accept that layout only if every chunk consumes the exact form,
  // then rebuild with standard padding.
  const chunks = readBeamChunks(bytes, true) ?? readBeamChunks(bytes, false);
  return { valid: chunks !== null, formSize, chunks: chunks ?? [] };
}

function readBeamChunks(bytes: Buffer, padded: boolean): BeamChunkView[] | null {
  const chunks: BeamChunkView[] = [];
  let at = 12;
  while (at < bytes.length) {
    if (at + 8 > bytes.length) return null;
    const name = bytes.subarray(at, at + 4).toString("latin1");
    const size = bytes.readUInt32BE(at + 4);
    const payloadOffset = at + 8;
    const end = payloadOffset + size;
    const next = end + (padded ? (4 - size % 4) % 4 : 0);
    if (next > bytes.length) return null;
    chunks.push({
      name,
      payload: bytes.subarray(payloadOffset, end),
    });
    at = next;
  }
  return chunks;
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
    value = value * 256 + payload[start + i]!;
    if (!Number.isSafeInteger(value)) return null;
  }
  return { value, next: start + byteCount };
}

function decodeAtomTable(chunk: BeamChunkView): {
  readonly names: string[];
  readonly compact: boolean;
} | null {
  const { payload } = chunk;
  if (payload.length < 4) return null;
  const isUtf8 = chunk.name === "AtU8";
  const declared = payload.readInt32BE(0);
  const compact = isUtf8 && declared < 0;
  const count = compact ? -declared : declared;
  // Every atom needs at least a length byte.
  if (count < 0 || count > payload.length - 4) return null;
  const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  const names: string[] = [];
  let at = 4;
  for (let i = 0; i < count; i++) {
    if (at >= payload.length) return null;
    const size = compact
      ? decodeCompactU(payload, at)
      : { value: payload[at]!, next: at + 1 };
    if (!size || size.value > payload.length - size.next) return null;
    at = size.next + size.value;
    const atom = payload.subarray(size.next, at);
    try {
      names.push(isUtf8 ? utf8.decode(atom) : atom.toString("latin1"));
    } catch {
      return null;
    }
  }
  return at === payload.length ? { names, compact } : null;
}

export function inspectErlangBeam(bytes: Buffer): ErlangBeamInspection {
  const parsed = parseBeamChunks(bytes);
  const exactFraming = parsed.valid && 8 + parsed.formSize === bytes.length;
  const marker = Buffer.from("[BLA-BEAM-SHIELD]", "utf8");
  let atomCount = 0;
  let validAtoms = true;
  let decoyChunkCount = 0;
  for (const chunk of parsed.chunks) {
    if (chunk.name === "AtU8" || chunk.name === "Atom") {
      const table = decodeAtomTable(chunk);
      if (table) atomCount = table.names.length;
      else validAtoms = false;
    }
    if (chunk.payload.includes(marker)) {
      decoyChunkCount += 1;
    }
  }
  return {
    validMagic: exactFraming,
    formSize: parsed.formSize,
    chunkCount: parsed.chunks.length,
    chunkNames: parsed.chunks.map((c) => c.name),
    atomCount,
    blaProtected: exactFraming && validAtoms && decoyChunkCount >= 4,
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
 * - Appends canary atoms onto Atom or AtU8 tables (classic or OTP28+ compact), preserving
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

  let atomsInjected = 0;
  let exceedsDefaultAtomBudget = false;
  const atomExtraTarget =
    intensity === "bankrupt" || intensity === "maximum"
      ? REA_INTERNAL_LIMITS.BEAM_DEFAULT_MAX_ATOMS + 64
      : 48;

  for (let i = 0; i < baseChunks.length; i++) {
    const chunk = baseChunks[i]!;
    if (chunk.name !== "AtU8" && chunk.name !== "Atom") continue;
    const table = decodeAtomTable(chunk);
    if (!table) throw new Error(`Malformed BEAM ${chunk.name} atom table`);
    if (atomsInjected > 0) continue;
    const existing = table.names;
    const extras: string[] = [
      "bla_beam_canary",
      `[BLA-BEAM-SHIELD]`,
      ...deception.textRecords
        .map((r) => r.replace(/[^\w.:/=+-]/g, "_").slice(0, 200))
        .filter((r) => r.length > 0)
        .slice(0, 16),
    ];
    const used = new Set(existing);
    const uniqueExtras = extras.filter((name) => {
      if (used.has(name)) return false;
      used.add(name);
      return true;
    });
    let serial = 0;
    while (existing.length + uniqueExtras.length < atomExtraTarget) {
      const name = `bla_tarpit_atom_${serial++}_${prng.hex(4)}`;
      if (used.has(name)) continue;
      uniqueExtras.push(name);
      used.add(name);
    }

    atomsInjected = uniqueExtras.length;
    const atomCount = existing.length + atomsInjected;
    exceedsDefaultAtomBudget = atomCount > REA_INTERNAL_LIMITS.BEAM_DEFAULT_MAX_ATOMS;
    const count = Buffer.alloc(4);
    count.writeInt32BE(table.compact ? -atomCount : atomCount);
    const appended = uniqueExtras.flatMap((name) => {
      // Extra names are restricted to ASCII for both atom encodings.
      const text = Buffer.from(name, "ascii");
      return [table.compact ? encodeCompactU(text.length) : Buffer.from([text.length]), text];
    });
    baseChunks[i] = {
      name: chunk.name,
      payload: Buffer.concat([count, chunk.payload.subarray(4), ...appended]),
    };
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
