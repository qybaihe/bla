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

export function inspectEvmBytecode(bytes: Buffer): EvmBytecodeInspection {
  let hasSolidityMetadata = false;
  let metadataBytes = 0;
  if (bytes.length >= 3) {
    const length = bytes[bytes.length - 2]! * 256 + bytes[bytes.length - 1]!;
    const offset = bytes.length - 2 - length;
    if (length > 0 && offset >= 0 && bytes[offset]! >> 5 === 5) {
      hasSolidityMetadata = true;
      metadataBytes = length;
    }
  }
  const text = bytes.toString("utf8");
  return {
    byteLength: bytes.length,
    hasSolidityMetadata,
    metadataBytes,
    blaProtected:
      text.includes("[BLA-EVM-SHIELD]") || text.includes("bla_evm_canary"),
  };
}

/**
 * Strips a prior BLA terminal Solidity metadata CBOR (if present) so a fresh
 * adversarial trailer can be appended without nesting length suffixes, while
 * never stripping original bytecode or non-BLA compiler metadata.
 */
function stripTerminalMetadata(bytes: Buffer): Buffer {
  if (bytes.length < 3) return bytes;
  const length = bytes[bytes.length - 2]! * 256 + bytes[bytes.length - 1]!;
  const offset = bytes.length - 2 - length;
  if (length > 0 && offset > 0 && bytes[offset]! >> 5 === 5) {
    const trailerText = bytes.subarray(offset, bytes.length - 2).toString("utf8");
    if (
      trailerText.includes("[BLA-EVM-SHIELD]") ||
      trailerText.includes("bla_evm_canary")
    ) {
      return bytes.subarray(0, offset);
    }
  }
  return bytes;
}

/**
 * Protects EVM contract bytecode by appending Solidity-compatible terminal
 * CBOR metadata packed with canary/diagnostic strings. Optional bankrupt
 * padding inserts JUMPDEST filler before the metadata (runtime-equivalent for
 * contracts that never fall through into the padding).
 */
export function protectEvmBytecodeBuffer(
  input: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string;
  } = {},
): {
  readonly buffer: Buffer;
  readonly metadataBytes: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
  readonly paddingBytes: number;
  readonly approachesInputBudget: boolean;
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

  let padding = Buffer.alloc(0);
  if (intensity === "bankrupt") {
    // Full approach of REA's 4 MiB `inputBytes` budget (leave a small slack
    // so the artifact still fits under the hard ceiling after metadata).
    const target = REA_INTERNAL_LIMITS.EVM_INPUT_BYTES - 4096;
    const need = Math.max(0, target - base.length - metadata.length);
    // 0x5b = JUMPDEST; inert when never jumped to (runtime-equivalent).
    padding = Buffer.alloc(need, 0x5b);
  } else if (intensity === "maximum") {
    const need = 64 * 1024;
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
  };
}
