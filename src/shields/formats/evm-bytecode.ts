import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

function cborHeader(major: number, length: number): Buffer {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length < 256) return Buffer.from([(major << 5) | 24, length]);
  if (length < 65536) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(length, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(length, 1);
  return b;
}

function cborText(value: string): Buffer {
  const body = Buffer.from(value, "utf8");
  return Buffer.concat([cborHeader(3, body.length), body]);
}

function cborBytes(value: Buffer): Buffer {
  return Buffer.concat([cborHeader(2, value.length), value]);
}

function cborMap(entries: readonly (readonly [Buffer, Buffer])[]): Buffer {
  return Buffer.concat([
    cborHeader(5, entries.length),
    ...entries.flatMap(([k, v]) => [k, v]),
  ]);
}

/** Build Solidity terminal metadata CBOR + 2-byte big-endian length trailer. */
export function buildSolidityMetadataTrailer(
  entries: readonly (readonly [string, string | Buffer])[],
): Buffer {
  const encoded = cborMap(
    entries.map(([key, value]) => [
      cborText(key),
      typeof value === "string" ? cborText(value) : cborBytes(value),
    ]),
  );
  if (encoded.length > 0xffff) {
    throw new Error("Solidity metadata CBOR exceeds uint16 length");
  }
  const len = Buffer.alloc(2);
  len.writeUInt16BE(encoded.length);
  return Buffer.concat([encoded, len]);
}

export interface EvmBytecodeInspection {
  readonly byteLength: number;
  readonly hasSolidityMetadata: boolean;
  readonly metadataBytes: number;
  readonly blaProtected: boolean;
}

/** Reads the definite-length map of text keys and scalar Solidity metadata values. */
function readTerminalMetadata(bytes: Buffer): {
  offset: number;
  length: number;
  hasBlaFields: boolean;
} | null {
  if (bytes.length < 3) return null;
  const end = bytes.length - 2;
  const length = bytes.readUInt16BE(end);
  const offset = end - length;
  if (length === 0 || offset < 0 || bytes[offset]! >> 5 !== 5) return null;
  let cursor = offset;
  const readLength = (major: number): number => {
    if (cursor >= end) throw new Error("truncated CBOR item");
    const head = bytes[cursor++]!;
    if (head >> 5 !== major) throw new Error("unexpected CBOR item type");
    const size = head & 31;
    if (size < 24) return size;
    const width = size === 24 ? 1 : size === 25 ? 2 : size === 26 ? 4 : 0;
    if (width === 0 || cursor + width > end) throw new Error("invalid CBOR length");
    const value = bytes.readUIntBE(cursor, width);
    cursor += width;
    return value;
  };
  const readString = (major: number): Buffer => {
    const size = readLength(major);
    if (size > end - cursor) throw new Error("truncated CBOR string");
    const value = bytes.subarray(cursor, cursor + size);
    cursor += size;
    return value;
  };
  const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  const fields = new Map<string, string | Buffer | boolean>();
  try {
    const count = readLength(5);
    for (let i = 0; i < count; i++) {
      const key = utf8.decode(readString(3));
      if (fields.has(key) || cursor >= end) return null;
      const head = bytes[cursor]!;
      if (head === 0xf4 || head === 0xf5) {
        fields.set(key, head === 0xf5);
        cursor++;
      } else if (head >> 5 === 3) {
        fields.set(key, utf8.decode(readString(3)));
      } else {
        fields.set(key, readString(2));
      }
    }
  } catch {
    return null;
  }
  if (cursor !== end) return null;
  const canary = fields.get("bla_evm_canary");
  return {
    offset,
    length,
    hasBlaFields: fields.get("bla") === "[BLA-EVM-SHIELD]" &&
      typeof canary === "string" && /^[0-9a-f]{16}$/.test(canary),
  };
}

export function inspectEvmBytecode(bytes: Buffer): EvmBytecodeInspection {
  const trailer = readTerminalMetadata(bytes);
  return {
    byteLength: bytes.length,
    hasSolidityMetadata: trailer !== null,
    metadataBytes: trailer?.length ?? 0,
    blaProtected: trailer !== null && trailer.length >= 96 && trailer.hasBlaFields,
  };
}

/**
 * Strips a prior BLA terminal Solidity metadata CBOR (if present) so a fresh
 * adversarial trailer can be appended without nesting length suffixes, while
 * never stripping original bytecode or non-BLA compiler metadata.
 */
function stripTerminalMetadata(bytes: Buffer): Buffer {
  const trailer = readTerminalMetadata(bytes);
  return trailer && trailer.offset > 0 && trailer.hasBlaFields
    ? bytes.subarray(0, trailer.offset)
    : bytes;
}

const EIP_170_MAX_CODE_BYTES = 24_576;

/**
 * Protects EVM contract bytecode by appending Solidity-compatible terminal
 * CBOR metadata packed with canary/diagnostic strings. Optional bankrupt
 * padding inserts JUMPDEST filler before the metadata (runtime-equivalent for
 * contracts that never fall through into the padding). Pass `enforceEip170Cap: true`
 * when deploying on networks that enforce the 24,576-byte EIP-170 runtime code ceiling.
 */
export function protectEvmBytecodeBuffer(
  input: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string;
    readonly enforceEip170Cap?: boolean;
  } = {},
): {
  readonly buffer: Buffer;
  readonly metadataBytes: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
  readonly paddingBytes: number;
  readonly approachesInputBudget: boolean;
  readonly exceedsEip170Limit: boolean;
} {
  if (input.length === 0) {
    throw new Error(
      "Refusing to synthesize EVM bytecode: input buffer is empty.",
    );
  }
  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-evm-shield");
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  const base = stripTerminalMetadata(input);

  const metaEntries: [string, string | Buffer][] = [
    ["solc", Buffer.from([0x00, 0x08, 0x1e])], // 0.8.30
    ["bla", "[BLA-EVM-SHIELD]"],
    ["bla_evm_canary", prng.hex(16)],
  ];
  for (const rec of deception.textRecords.slice(0, 12)) {
    const key = `bla_${metaEntries.length}`;
    metaEntries.push([key, rec.slice(0, 200)]);
  }

  const metadata = buildSolidityMetadataTrailer(metaEntries);
  if (options.enforceEip170Cap && base.length + metadata.length > EIP_170_MAX_CODE_BYTES) {
    throw new Error("EIP-170 deployment limit (24,576 bytes) leaves insufficient room for protection metadata");
  }

  let padding = Buffer.alloc(0);
  if (intensity === "bankrupt") {
    // Full approach of REA's 4 MiB `inputBytes` budget (leave a small slack
    // so the artifact still fits under the hard ceiling after metadata).
    const target = options.enforceEip170Cap
      ? EIP_170_MAX_CODE_BYTES
      : REA_INTERNAL_LIMITS.EVM_INPUT_BYTES - 4096;
    const need = Math.max(0, target - base.length - metadata.length);
    // 0x5b = JUMPDEST; inert when never jumped to (runtime-equivalent).
    padding = Buffer.alloc(need, 0x5b);
  } else if (intensity === "maximum") {
    const rawNeed = 64 * 1024;
    const need = options.enforceEip170Cap
      ? Math.max(0, Math.min(rawNeed, EIP_170_MAX_CODE_BYTES - base.length - metadata.length))
      : rawNeed;
    padding = Buffer.alloc(need, 0x5b);
  }
  // balanced stays lean: metadata only, no JUMPDEST padding.

  const buffer = Buffer.concat([base, padding, metadata]);
  return {
    buffer,
    metadataBytes: metadata.length - 2,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
    paddingBytes: padding.length,
    approachesInputBudget:
      buffer.length >= REA_INTERNAL_LIMITS.EVM_INPUT_BYTES - 8192,
    exceedsEip170Limit: buffer.length > EIP_170_MAX_CODE_BYTES,
  };
}
