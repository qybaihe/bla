/**
 * Alignment-safe GGUF v2/v3 layout parser + rewriter.
 *
 * GGUF tensor-info `offset` fields are RELATIVE to the tensor-data section,
 * whose absolute start is `align(endOfTensorInfos, general.alignment)`
 * (default 32). Inserting or removing metadata KV bytes shifts the end of the
 * tensor infos, so the data section MUST be re-padded to the new aligned
 * start — otherwise every tensor offset resolves to the wrong bytes and the
 * model silently loads corrupted weights while still "parsing".
 *
 * `rebuildGguf` keeps tensor infos and the tensor-data region byte-exact and
 * recomputes only the padding, so tensor bytes are preserved bit-for-bit.
 *
 * DEFENSIVE ONLY. Format-preserving; no tensor bytes are ever modified.
 */

/** GGUF metadata value type ids (gguf spec). */
export const GGUF_TYPE_UINT32 = 4;
export const GGUF_TYPE_STRING = 8;
export const GGUF_TYPE_ARRAY = 9;

/** Spec default when `general.alignment` is absent. */
export const GGUF_DEFAULT_ALIGNMENT = 32;

/** Bounds that keep parsing cheap on hostile / malformed input. */
const MAX_KV_COUNT = 100_000n;
const MAX_TENSOR_COUNT = 1_000_000n;
const MAX_TENSOR_DIMS = 4;
const MAX_KV_KEY_BYTES = 65_535n;
const MAX_SIGNED_DIM = (1n << 63n) - 1n;
const GGUF_SCALAR_BYTES = [1, 1, 2, 2, 4, 4, 4, 1, 0, 0, 8, 8, 8] as const;
// GGML on-disk types: [elements per block, bytes per block].
// Type IDs and block layouts follow ggml.h and ggml-common.h.
const GGML_BLOCK_LAYOUT: Readonly<Record<number, readonly [bigint, bigint]>> = {
  0: [1n, 4n],      // F32
  1: [1n, 2n],      // F16
  2: [32n, 18n],    // Q4_0
  3: [32n, 20n],    // Q4_1
  6: [32n, 22n],    // Q5_0
  7: [32n, 24n],    // Q5_1
  8: [32n, 34n],    // Q8_0
  9: [32n, 36n],    // Q8_1
  10: [256n, 84n],  // Q2_K
  11: [256n, 110n], // Q3_K
  12: [256n, 144n], // Q4_K
  13: [256n, 176n], // Q5_K
  14: [256n, 210n], // Q6_K
  15: [256n, 292n], // Q8_K
  16: [256n, 66n],  // IQ2_XXS
  17: [256n, 74n],  // IQ2_XS
  18: [256n, 98n],  // IQ3_XXS
  19: [256n, 50n],  // IQ1_S
  20: [32n, 18n],   // IQ4_NL
  21: [256n, 110n], // IQ3_S
  22: [256n, 82n],  // IQ2_S
  23: [256n, 136n], // IQ4_XS
  24: [1n, 1n],     // I8
  25: [1n, 2n],     // I16
  26: [1n, 4n],     // I32
  27: [1n, 8n],     // I64
  28: [1n, 8n],     // F64
  29: [256n, 56n],  // IQ1_M
  30: [1n, 2n],     // BF16
  34: [256n, 54n],  // TQ1_0
  35: [256n, 66n],  // TQ2_0
  39: [32n, 17n],   // MXFP4
  40: [64n, 36n],   // NVFP4
  41: [128n, 18n],  // Q1_0
  42: [64n, 18n],   // Q2_0
  43: [1n, 1n],     // F8_E4M3
};
/**
 * Upper bound on `general.alignment`. Real GGUF writers use 32 (some use 64 or
 * 128). A hostile file can claim up to 2^31, which makes `alignUp` request a
 * multi-gigabyte zeroed pad and pushes `dataStart` past the end of the file —
 * dropping every tensor while still producing a parseable container.
 */
const MAX_ALIGNMENT = 1_048_576;

export interface GgufKvEntry {
  readonly key: string;
  /** Absolute offset of the KV record (start of the key length prefix). */
  readonly start: number;
  /** Absolute offset one past the end of the KV record. */
  readonly end: number;
  readonly valueStart: number;
  readonly valueType: number;
}

export interface GgufLayout {
  readonly version: number;
  readonly tensorCount: bigint;
  readonly kvCount: bigint;
  readonly kvs: readonly GgufKvEntry[];
  readonly kvEnd: number;
  /** Absolute offset one past the last tensor-info record. */
  readonly tensorInfoEnd: number;
  readonly alignment: number;
  /** Absolute aligned start of the tensor-data section. */
  readonly dataStart: number;
  /** True when bytes exist beyond the tensor infos (padding and/or data). */
  readonly hasDataRegion: boolean;
}

function skipValue(
  bytes: Buffer,
  offset: number,
  valType: number,
): number | null {
  if (offset > bytes.length) return null;
  switch (valType) {
    case 0:
    case 1:
    case 7:
      return offset + 1 <= bytes.length ? offset + 1 : null;
    case 2:
    case 3:
      return offset + 2 <= bytes.length ? offset + 2 : null;
    case 4:
    case 5:
    case 6:
      return offset + 4 <= bytes.length ? offset + 4 : null;
    case 10:
    case 11:
    case 12:
      return offset + 8 <= bytes.length ? offset + 8 : null;
    case GGUF_TYPE_STRING: {
      if (offset + 8 > bytes.length) return null;
      const len = bytes.readBigUInt64LE(offset);
      const end = BigInt(offset) + 8n + len;
      return end <= BigInt(bytes.length) ? Number(end) : null;
    }
    case GGUF_TYPE_ARRAY: {
      if (offset + 12 > bytes.length) return null;
      const elemType = bytes.readUInt32LE(offset);
      const count = bytes.readBigUInt64LE(offset + 4);
      if (elemType === GGUF_TYPE_ARRAY || elemType > 12) return null;
      let cur = offset + 12;
      if (elemType !== GGUF_TYPE_STRING) {
        const end = BigInt(cur) + count * BigInt(GGUF_SCALAR_BYTES[elemType]!);
        return end <= BigInt(bytes.length) ? Number(end) : null;
      }
      if (count * 8n > BigInt(bytes.length - cur)) return null;
      for (let i = 0n; i < count; i++) {
        const next = skipValue(bytes, cur, elemType);
        if (next === null) return null;
        cur = next;
      }
      return cur;
    }
    default:
      return null;
  }
}

function alignUp(value: number, alignment: number): number {
  const rem = value % alignment;
  return rem === 0 ? value : value + (alignment - rem);
}

/**
 * Parse the GGUF v2/v3 container layout. Returns null for non-GGUF input,
 * unsupported versions (v1 uses u32 counts), or any malformed / truncated
 * structure. Never throws on hostile input.
 */
export function parseGgufLayout(input: Uint8Array): GgufLayout | null {
  const bytes = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  if (
    bytes.length < 24 ||
    bytes[0] !== 0x47 ||
    bytes[1] !== 0x47 ||
    bytes[2] !== 0x55 ||
    bytes[3] !== 0x46
  ) {
    return null;
  }
  const version = bytes.readUInt32LE(4);
  if (version !== 2 && version !== 3) return null;
  const tensorCount = bytes.readBigUInt64LE(8);
  const kvCount = bytes.readBigUInt64LE(16);
  if (kvCount > MAX_KV_COUNT || tensorCount > MAX_TENSOR_COUNT) return null;

  let offset = 24;
  const kvs: GgufKvEntry[] = [];
  const keys = new Set<string>();
  let alignment = GGUF_DEFAULT_ALIGNMENT;
  for (let i = 0n; i < kvCount; i++) {
    const start = offset;
    if (offset + 8 > bytes.length) return null;
    const keyLen = bytes.readBigUInt64LE(offset);
    const keyEnd = BigInt(offset) + 8n + keyLen;
    if (keyLen === 0n || keyLen > MAX_KV_KEY_BYTES || keyEnd + 4n > BigInt(bytes.length)) return null;
    const keyEndN = Number(keyEnd);
    const key = bytes.subarray(offset + 8, keyEndN).toString("utf8");
    const valueType = bytes.readUInt32LE(keyEndN);
    const valueStart = keyEndN + 4;
    if (keys.has(key)) return null;
    keys.add(key);
    const next = skipValue(bytes, valueStart, valueType);
    if (next === null) return null;
    if (key === "general.alignment") {
      if (valueType !== GGUF_TYPE_UINT32) return null;
      const a = bytes.readUInt32LE(valueStart);
      if (a === 0 || a % 8 !== 0 || a > MAX_ALIGNMENT) return null;
      alignment = a;
    }
    kvs.push({ key, start, end: next, valueStart, valueType });
    offset = next;
  }
  const kvEnd = offset;

  const fileEnd = BigInt(bytes.length);
  let maxTensorEnd = 0n;
  for (let t = 0n; t < tensorCount; t++) {
    if (offset + 8 > bytes.length) return null;
    const nameLen = bytes.readBigUInt64LE(offset);
    const nameEnd = BigInt(offset) + 8n + nameLen;
    if (nameEnd + 4n > BigInt(bytes.length)) return null;
    offset = Number(nameEnd);
    const nDims = bytes.readUInt32LE(offset);
    if (nDims > MAX_TENSOR_DIMS) return null;
    offset += 4;
    const tail = nDims * 8 + 4 + 8; // dims (u64 each) + ggml_type (u32) + offset (u64)
    if (offset + tail > bytes.length) return null;
    const dimensions = offset;
    offset += tail;
    const [blockElements, blockBytes] = GGML_BLOCK_LAYOUT[bytes.readUInt32LE(offset - 12)] ?? [0n, 0n];
    if (blockElements === 0n) return null;
    const firstDim = nDims === 0 ? 1n : bytes.readBigUInt64LE(dimensions);
    if (firstDim > MAX_SIGNED_DIM || firstDim % blockElements !== 0n) return null;
    let size = (firstDim / blockElements) * blockBytes;
    for (let d = 1; d < nDims; d++) {
      const dimension = bytes.readBigUInt64LE(dimensions + d * 8);
      if (dimension > MAX_SIGNED_DIM) return null;
      size *= dimension;
    }
    const tensorOffset = bytes.readBigUInt64LE(offset - 8);
    if (tensorOffset % BigInt(alignment) !== 0n) return null;
    const end = tensorOffset + size;
    if (end > fileEnd) return null;
    if (end > maxTensorEnd) maxTensorEnd = end;
  }
  const tensorInfoEnd = offset;
  const hasDataRegion = bytes.length > tensorInfoEnd;
  const dataStart = alignUp(tensorInfoEnd, alignment);
  if (tensorCount > 0n && BigInt(dataStart) + maxTensorEnd > fileEnd) return null;

  return {
    version,
    tensorCount,
    kvCount,
    kvs,
    kvEnd,
    tensorInfoEnd,
    alignment,
    dataStart,
    hasDataRegion,
  };
}

/** Encode a GGUF string (u64 LE length + UTF-8 bytes). */
export function encodeGgufString(str: string): Buffer {
  const utf8 = Buffer.from(str, "utf8");
  const len = Buffer.alloc(8);
  len.writeBigUInt64LE(BigInt(utf8.length), 0);
  return Buffer.concat([len, utf8]);
}

/** Encode a full STRING-typed GGUF metadata KV record. */
export function encodeGgufStringKv(key: string, value: string): Buffer {
  const type = Buffer.alloc(4);
  type.writeUInt32LE(GGUF_TYPE_STRING, 0);
  return Buffer.concat([encodeGgufString(key), type, encodeGgufString(value)]);
}

export interface GgufRebuildOptions {
  /** Existing KV keys to drop (e.g. a stale sidecar note for idempotent re-bind). */
  readonly dropKeys?: ReadonlySet<string>;
  /** Fully encoded KV records to append after the retained KVs. */
  readonly appendKvs?: readonly Buffer[];
}

/**
 * Rebuild a GGUF container with modified metadata while keeping tensor infos
 * and the tensor-data region byte-exact. The data section is re-padded to the
 * new `align(tensorInfoEnd, alignment)` so every relative tensor offset still
 * resolves to the original bytes.
 */
export function rebuildGguf(
  input: Uint8Array,
  layout: GgufLayout,
  options: GgufRebuildOptions = {},
): Buffer {
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input);
  const drop = options.dropKeys ?? new Set<string>();
  const append = options.appendKvs ?? [];
  const kept = layout.kvs.filter((kv) => !drop.has(kv.key));
  if (BigInt(kept.length + append.length) > MAX_KV_COUNT) {
    throw new Error("Refusing to rebuild GGUF: metadata count exceeds the supported limit");
  }

  const header = Buffer.alloc(24);
  header.write("GGUF", 0, "ascii");
  header.writeUInt32LE(layout.version, 4);
  header.writeBigUInt64LE(layout.tensorCount, 8);
  header.writeBigUInt64LE(BigInt(kept.length + append.length), 16);

  const tensorInfos = bytes.subarray(layout.kvEnd, layout.tensorInfoEnd);
  const metaAndInfos = Buffer.concat([
    header,
    ...kept.map((kv) => bytes.subarray(kv.start, kv.end)),
    ...append,
    tensorInfos,
  ]);
  if (!layout.hasDataRegion) return metaAndInfos;

  // A declared data section that starts past the end of the input means the
  // tensor bytes cannot be preserved. Fail closed instead of emitting a
  // container whose tensors silently resolve to nothing.
  if (layout.dataStart > bytes.length) {
    throw new Error(
      `Refusing to rebuild GGUF: declared tensor-data start ${layout.dataStart} exceeds the ${bytes.length}-byte input`,
    );
  }

  const newDataStart = alignUp(metaAndInfos.length, layout.alignment);
  const pad = Buffer.alloc(newDataStart - metaAndInfos.length, 0);
  const data = bytes.subarray(layout.dataStart);
  return Buffer.concat([metaAndInfos, pad, data]);
}

/** Read a STRING-typed KV value by key, or null when absent / not a string. */
export function readGgufStringKv(
  input: Uint8Array,
  layout: GgufLayout,
  key: string,
): string | null {
  const bytes = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  const kv = layout.kvs.find((k) => k.key === key);
  if (!kv || kv.valueType !== GGUF_TYPE_STRING) return null;
  return bytes.subarray(kv.valueStart + 8, kv.end).toString("utf8");
}
