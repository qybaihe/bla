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
const MAX_TENSOR_DIMS = 8;
const MAX_VALUE_DEPTH = 64;

export interface GgufKvEntry {
  readonly key: string;
  /** Absolute offset of the KV record (start of the key length prefix). */
  readonly start: number;
  /** Absolute offset one past the end of the KV record. */
  readonly end: number;
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
  depth: number,
): number | null {
  if (depth > MAX_VALUE_DEPTH || offset > bytes.length) return null;
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
      // Each element consumes >= 1 byte, so a count larger than the remaining
      // bytes is necessarily malformed (also bounds the loop).
      if (count > BigInt(bytes.length - (offset + 12))) return null;
      let cur = offset + 12;
      for (let i = 0n; i < count; i++) {
        const next = skipValue(bytes, cur, elemType, depth + 1);
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
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input);
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
  let alignment = GGUF_DEFAULT_ALIGNMENT;
  for (let i = 0n; i < kvCount; i++) {
    const start = offset;
    if (offset + 8 > bytes.length) return null;
    const keyLen = bytes.readBigUInt64LE(offset);
    const keyEnd = BigInt(offset) + 8n + keyLen;
    if (keyEnd + 4n > BigInt(bytes.length)) return null;
    const keyEndN = Number(keyEnd);
    const key = bytes.subarray(offset + 8, keyEndN).toString("utf8");
    const valueType = bytes.readUInt32LE(keyEndN);
    const valueStart = keyEndN + 4;
    const next = skipValue(bytes, valueStart, valueType, 0);
    if (next === null) return null;
    if (key === "general.alignment" && valueType === GGUF_TYPE_UINT32) {
      const a = bytes.readUInt32LE(valueStart);
      // Spec: a non-zero multiple of 8. Ignore nonsensical values.
      if (a > 0 && a % 8 === 0) alignment = a;
    }
    kvs.push({ key, start, end: next, valueType });
    offset = next;
  }
  const kvEnd = offset;

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
    offset += tail;
  }
  const tensorInfoEnd = offset;
  const hasDataRegion = bytes.length > tensorInfoEnd;
  const dataStart = alignUp(tensorInfoEnd, alignment);

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

  const newDataStart = alignUp(metaAndInfos.length, layout.alignment);
  const pad = Buffer.alloc(newDataStart - metaAndInfos.length, 0);
  const data = bytes.subarray(Math.min(layout.dataStart, bytes.length));
  return Buffer.concat([metaAndInfos, pad, data]);
}

/** Read a STRING-typed KV value by key, or null when absent / not a string. */
export function readGgufStringKv(
  input: Uint8Array,
  layout: GgufLayout,
  key: string,
): string | null {
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input);
  const kv = layout.kvs.find((k) => k.key === key);
  if (!kv || kv.valueType !== GGUF_TYPE_STRING) return null;
  const keyLen = Number(bytes.readBigUInt64LE(kv.start));
  const valueStart = kv.start + 8 + keyLen + 4;
  const len = Number(bytes.readBigUInt64LE(valueStart));
  return bytes.subarray(valueStart + 8, valueStart + 8 + len).toString("utf8");
}
