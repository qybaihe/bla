import { parseGgufLayout, rebuildGguf } from "./gguf-layout.js";
import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

export interface ModelInspectionSummary {
  readonly validModel: boolean;
  readonly format: "safetensors" | "gguf" | "unknown";
  readonly tensorCount: number;
  readonly metadataCount: number;
  readonly exceedsReaNestingLimit: boolean;
  readonly blaProtected: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Invalid or unsupported input is never replaced with synthetic weights. */
export class InvalidSafetensorsError extends Error {
  constructor(reason: string) {
    super(`Invalid or unsupported Safetensors input: ${reason}`);
    this.name = "InvalidSafetensorsError";
  }
}

// Conservative supported dtype subset. Unknown/new dtypes fail closed.
const DTYPE_BYTES: Readonly<Record<string, number>> = Object.freeze({
  BOOL: 1, U8: 1, I8: 1, I16: 2, U16: 2, F16: 2, BF16: 2,
  I32: 4, U32: 4, F32: 4, I64: 8, U64: 8, F64: 8,
});

/** Structural validation only: this does not run model inference. */
export function validateSafetensorsBuffer(bytes: Buffer): {
  header: Record<string, unknown>; tensorData: Buffer;
} {
  const fail = (reason: string): never => { throw new InvalidSafetensorsError(reason); };
  if (bytes.length < 10) fail("truncated header");
  const length = bytes.readBigUInt64LE(0);
  if (length > 100_000_000n || length > BigInt(bytes.length - 8) || length < 2n) {
    fail("invalid header length");
  }
  const end = 8 + Number(length);
  let text: string;
  let header: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes.subarray(8, end));
    if (!text.startsWith("{")) fail("header must start with an object");
    header = JSON.parse(text);
    // JSON.parse otherwise silently loses duplicate fields, including tensor names.
    const stack: Array<Set<string> | null> = [];
    const tokens = /"(?:[^"\\]|\\.)*"|[{}\[\]]|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
    for (const token of text.matchAll(tokens)) {
      const value = token[0];
      if (value === "{") stack.push(new Set());
      else if (value === "[") stack.push(null);
      else if (value === "}" || value === "]") stack.pop();
      else if (!value.startsWith('"')) {
        // JSON.parse rounds before Number.isSafeInteger can inspect the value.
        // The supported header subset requires integer lexical tokens, not
        // fractions/exponents even when they would round to an integer.
        if (value.length > 16 || !/^\d+$/.test(value) || BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)) {
          fail("unsupported numeric token: require nonnegative safe integer notation");
        }
      } else {
        const decoded = JSON.parse(value) as string;
        if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(decoded)) {
          fail("invalid Unicode string");
        }
        if (text.slice(token.index! + value.length).trimStart().startsWith(":")) {
          const keys = stack.at(-1);
          if (keys?.has(decoded)) fail("duplicate JSON field");
          keys?.add(decoded);
        }
      }
    }
  } catch (error) {
    if (error instanceof InvalidSafetensorsError) throw error;
    return fail("invalid UTF-8 or JSON header");
  }
  if (!isRecord(header)) return fail("header must be an object");
  if (Object.hasOwn(header, "__metadata__") &&
      (!isRecord(header.__metadata__) || Object.values(header.__metadata__).some(v => typeof v !== "string"))) {
    fail("metadata must be a string-to-string object");
  }
  const ranges: Array<[number, number]> = [];
  for (const [name, descriptor] of Object.entries(header)) {
    if (name === "__metadata__") continue;
    if (!isRecord(descriptor)) return fail("invalid tensor descriptor");
    const { dtype, shape, data_offsets: offsets } = descriptor;
    if (typeof dtype !== "string" || !Object.hasOwn(DTYPE_BYTES, dtype)) fail("unsupported tensor dtype");
    if (!Array.isArray(shape) || !shape.every(n => Number.isSafeInteger(n) && n >= 0)) {
      return fail("invalid tensor shape");
    }
    if (!Array.isArray(offsets) || offsets.length !== 2 || !offsets.every(n => Number.isSafeInteger(n) && n >= 0)) {
      return fail("invalid tensor offsets");
    }
    const [start, stop] = offsets as [number, number];
    let size = shape.includes(0) ? 0n : BigInt(DTYPE_BYTES[dtype as string]!);
    if (size !== 0n) {
      for (const dimension of shape) {
        size *= BigInt(dimension);
        if (size > BigInt(Number.MAX_SAFE_INTEGER)) fail("unsupported tensor size beyond safe range");
      }
    }
    if (stop < start || stop > bytes.length - end || size !== BigInt(stop - start)) fail("tensor byte size mismatch");
    ranges.push([start, stop]);
  }
  ranges.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  let cursor = 0;
  for (const [start, stop] of ranges) {
    if (start !== cursor) fail("overlapping or incomplete tensor data");
    cursor = stop;
  }
  if (cursor !== bytes.length - end) fail("unreferenced tensor data");
  return { header, tensorData: bytes.subarray(end) };
}

/**
 * Serializes a Safetensors header and data buffer (does not validate caller input) (`.safetensors`) from a header object and raw data bytes.
 */
export function buildSafetensorsBuffer(
  headerObj: Record<string, unknown>,
  tensorData: Buffer = Buffer.alloc(16, 0),
): Buffer {
  const rawJson = Buffer.from(JSON.stringify(headerObj), "utf8");
  const jsonBytes = Buffer.alloc(Math.ceil(rawJson.length / 8) * 8, 0x20);
  rawJson.copy(jsonBytes);
  const lenPrefix = Buffer.alloc(8);
  lenPrefix.writeBigUInt64LE(BigInt(jsonBytes.length), 0);
  return Buffer.concat([lenPrefix, jsonBytes, tensorData]);
}

/**
 * Inspects a `.safetensors` or `.gguf` AI model artifact buffer.
 */
export function inspectModelBuffer(bytes: Buffer): ModelInspectionSummary {
  // Check GGUF magic (`GGUF`)
  if (
    bytes.length >= 24 &&
    bytes[0] === 0x47 &&
    bytes[1] === 0x47 &&
    bytes[2] === 0x55 &&
    bytes[3] === 0x46
  ) {
    const tensorCount = Number(bytes.readBigUInt64LE(8));
    const metadataCount = Number(bytes.readBigUInt64LE(16));
    const textLatin1 = bytes.toString("latin1");
    const blaProtected =
      textLatin1.includes("enclave.delegation") ||
      textLatin1.includes("BLA-MODEL-SHIELD") ||
      textLatin1.includes("bla.sidecar.v1");
    return {
      validModel: true,
      format: "gguf",
      tensorCount,
      metadataCount,
      exceedsReaNestingLimit: textLatin1.includes("enclave.nesting.breaker"),
      blaProtected,
    };
  }

  // Check Safetensors (8-byte LE uint64 header size + JSON starting with '{')
  if (bytes.length >= 10 && bytes[8] === 0x7b) {
    try {
      const { header: parsed } = validateSafetensorsBuffer(bytes);
      const meta = Object.keys((parsed.__metadata__ ?? {}) as Record<string, string>);
      const exceedsReaNestingLimit = Object.entries(parsed).some(([name, desc]) => {
        if (name === "__metadata__" || !isRecord(desc)) return false;
        return Object.hasOwn(desc, "enclave_topology_seal");
      });
      return {
        validModel: true,
        format: "safetensors",
        tensorCount: Object.keys(parsed).filter(k => k !== "__metadata__").length,
        metadataCount: meta.length,
        exceedsReaNestingLimit,
        blaProtected:
          exceedsReaNestingLimit ||
          meta.some(k => k.startsWith("bla.") || k.startsWith("enclave.")),
      };
    } catch {
      // Fallthrough
    }
  }

  return {
    validModel: false,
    format: "unknown",
    tensorCount: 0,
    metadataCount: 0,
    exceedsReaNestingLimit: false,
    blaProtected: false,
  };
}

/**
 * Protect a Safetensors artifact without changing tensor bytes or required
 * descriptor fields (`dtype` / `shape` / `data_offsets`).
 *
 * Counter-REA: attaches a deep nested `enclave_topology_seal` object as an
 * *extra* key on the first tensor descriptor. HuggingFace safetensors ignores
 * unknown descriptor fields (verified loadable), while REA's JSON walker hits
 * `MODEL_JSON_NESTING = 32` (`json-nesting` / ModelFormatFailure capacity).
 * Invalid top-level nesting payloads (e.g. deep `nesting_breaker` arrays) remain
 * rejected by validateSafetensorsBuffer.
 */
export function protectSafetensorsBuffer(
  bytes: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
  } = {},
): {
  readonly buffer: Buffer;
  readonly chaffPayloadsEmbedded: number;
  readonly triggeredJsonNestingBreaker: boolean;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
} {
  const { header: headerObj, tensorData } = validateSafetensorsBuffer(bytes);
  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-safetensors-shield-v1");
  const chaffPayloads = generateChaffPayloads(prng, intensity);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  const existingMeta =
    typeof headerObj.__metadata__ === "object" && headerObj.__metadata__ !== null
      ? { ...(headerObj.__metadata__ as Record<string, string>) }
      : {};

  existingMeta["enclave.delegation.status"] ??= "HARDWARE_TEE_SPLIT_WEIGHTS";
  existingMeta["enclave.delegation.notice"] ??= chaffPayloads[0]!.rawText;
  existingMeta["bla.shield.signature"] ??= `BLA-MODEL-SHIELD-${prng.hex(8)}`;
  let chaffPayloadsEmbedded = 0;
  chaffPayloads.forEach((p, idx) => {
    const key = `enclave.manifest.${idx}`;
    if (!Object.hasOwn(existingMeta, key)) {
      existingMeta[key] = p.rawText;
      chaffPayloadsEmbedded++;
    }
  });

  // Canary + diagnostic metadata (string values only — Safetensors __metadata__ contract).
  deception.canary.syntheticCanaryTokens.forEach((tok, idx) => {
    existingMeta[`enclave.canary.token.${idx}`] ??= tok;
  });
  deception.canary.ambiguousCredentialUrls.forEach((url, idx) => {
    existingMeta[`enclave.canary.transport.${idx}`] ??= url;
  });
  deception.diagnostics.diagnosticsInjected.forEach((d, idx) => {
    existingMeta[`enclave.diagnostic.${idx}`] ??= JSON.stringify({
      subsystem: d.subsystem,
      errorClass: d.errorClass,
      systemCode: d.systemCode,
      diagnosticMessage: d.diagnosticMessage,
      remediationRabbitHole: d.remediationRabbitHole,
    });
  });

  headerObj.__metadata__ = existingMeta;

  // JSON nesting breaker on the first tensor descriptor (extra key; HF-ignored).
  // Depth: root(0) → tensor(1) → topology(2) → … → nest layers trip depth > 32.
  const nestingDepth = REA_INTERNAL_LIMITS.MODEL_MAX_JSON_NESTING + 1;
  let triggeredJsonNestingBreaker = false;
  const firstTensorName = Object.keys(headerObj).find((k) => k !== "__metadata__");
  if (firstTensorName !== undefined && isRecord(headerObj[firstTensorName])) {
    const tensor = { ...(headerObj[firstTensorName] as Record<string, unknown>) };
    if (!Object.hasOwn(tensor, "enclave_topology_seal")) {
      let node: Record<string, unknown> = {
        kind: "enclave_topology",
        seed: prng.hex(8),
        notice: "BLA Counter-REA JSON nesting breaker",
      };
      for (let d = 0; d < nestingDepth; d++) {
        node = { layer: d, next: node };
      }
      tensor.enclave_topology_seal = node;
      headerObj[firstTensorName] = tensor;
      triggeredJsonNestingBreaker = true;
    } else {
      triggeredJsonNestingBreaker = true;
    }
  }

  const buffer = buildSafetensorsBuffer(headerObj, tensorData);
  validateSafetensorsBuffer(buffer);
  return {
    buffer,
    chaffPayloadsEmbedded,
    triggeredJsonNestingBreaker,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
  };
}

function encodeGgufString(str: string): Buffer {
  const utf8 = Buffer.from(str, "utf8");
  const len = Buffer.alloc(8);
  len.writeBigUInt64LE(BigInt(utf8.length), 0);
  return Buffer.concat([len, utf8]);
}

function skipGgufValue(bytes: Buffer, offset: number, valType: number, depth = 0): number | null {
  if (depth > 64 || offset > bytes.length) return null;
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
    case 8: {
      if (offset + 8 > bytes.length) return null;
      const len = Number(bytes.readBigUInt64LE(offset));
      const end = offset + 8 + len;
      return end <= bytes.length ? end : null;
    }
    case 9: {
      if (offset + 12 > bytes.length) return null;
      const elemType = bytes.readUInt32LE(offset);
      const count = Number(bytes.readBigUInt64LE(offset + 4));
      let cur = offset + 12;
      for (let i = 0; i < count; i++) {
        const next = skipGgufValue(bytes, cur, elemType, depth + 1);
        if (next === null) return null;
        cur = next;
      }
      return cur;
    }
    default:
      return null;
  }
}

function parseExistingGgufHeader(bytes: Buffer): {
  readonly version: number;
  readonly tensorCount: bigint;
  readonly kvCount: bigint;
  readonly kvEndOffset: number;
  readonly existingKeys: ReadonlySet<string>;
} | null {
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
  if (kvCount > 100_000n) return null;
  let offset = 24;
  const existingKeys = new Set<string>();
  for (let i = 0n; i < kvCount; i++) {
    if (offset + 12 > bytes.length) return null;
    const keyLen = Number(bytes.readBigUInt64LE(offset));
    if (offset + 8 + keyLen + 4 > bytes.length) return null;
    const key = bytes.subarray(offset + 8, offset + 8 + keyLen).toString("utf8");
    existingKeys.add(key);
    const valType = bytes.readUInt32LE(offset + 8 + keyLen);
    const nextOffset = skipGgufValue(bytes, offset + 8 + keyLen + 4, valType, 0);
    if (nextOffset === null) return null;
    offset = nextOffset;
  }
  return {
    version,
    tensorCount,
    kvCount,
    kvEndOffset: offset,
    existingKeys,
  };
}

/**
 * Builds or protects a GGUF v2/v3 (`.gguf`) model binary against REA's `GgufHeader.ts`:
 * 1. Preserves all existing GGUF metadata KV entries and trailing tensor records.
 * 2. Injects valid lowercase hierarchy metadata keys (`enclave.delegation.manifest`, `general.description`).
 * 3. Injects a 35-frame nested GGUF `ARRAY` (type `9`) metadata entry (`enclave.nesting.breaker`)
 *    exceeding REA's `MODEL_METADATA_NESTING = 32` (`GgufHeader.ts:121`), which forces
 *    `rea inspect-model-artifact` to abort with `ModelFormatFailure("capacity", ..., "metadata-nesting")`!
 */
export function protectGgufBuffer(
  bytes: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
  } = {},
): {
  readonly buffer: Buffer;
  readonly chaffPayloadsEmbedded: number;
  readonly triggeredMetadataNestingBreaker: boolean;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
} {
  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-gguf-shield-v1");
  const chaffPayloads = generateChaffPayloads(prng, intensity);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  const parsed = parseExistingGgufHeader(bytes);
  const existingKvSlice = parsed ? bytes.subarray(24, parsed.kvEndOffset) : Buffer.alloc(0);
  const trailingTensorSlice = parsed ? bytes.subarray(parsed.kvEndOffset) : Buffer.alloc(0);

  const kvEntries: Buffer[] = [];

  // KV 1: general.description (STRING = 8) — only add if not already present in input
  if (!parsed || !parsed.existingKeys.has("general.description")) {
    const key = encodeGgufString("general.description");
    const type = Buffer.alloc(4);
    type.writeUInt32LE(8, 0);
    const val = encodeGgufString(
      `[BLA-MODEL-SHIELD] ${chaffPayloads[0]!.rawText}`,
    );
    kvEntries.push(Buffer.concat([key, type, val]));
  }

  // KV 2: enclave.delegation.manifest (STRING = 8)
  if (!parsed || !parsed.existingKeys.has("enclave.delegation.manifest")) {
    const key = encodeGgufString("enclave.delegation.manifest");
    const type = Buffer.alloc(4);
    type.writeUInt32LE(8, 0);
    const val = encodeGgufString(
      chaffPayloads.map((p) => p.rawText).join(" | "),
    );
    kvEntries.push(Buffer.concat([key, type, val]));
  }

  // KV canary / diagnostic STRING metadata (under enclave.* hierarchy)
  deception.canary.syntheticCanaryTokens.forEach((tok, idx) => {
    const keyName = `enclave.canary.token.${idx}`;
    if (!parsed || !parsed.existingKeys.has(keyName)) {
      const key = encodeGgufString(keyName);
      const type = Buffer.alloc(4);
      type.writeUInt32LE(8, 0);
      kvEntries.push(Buffer.concat([key, type, encodeGgufString(tok)]));
    }
  });
  deception.canary.ambiguousCredentialUrls.forEach((url, idx) => {
    const keyName = `enclave.canary.transport.${idx}`;
    if (!parsed || !parsed.existingKeys.has(keyName)) {
      const key = encodeGgufString(keyName);
      const type = Buffer.alloc(4);
      type.writeUInt32LE(8, 0);
      kvEntries.push(Buffer.concat([key, type, encodeGgufString(url)]));
    }
  });
  deception.diagnostics.diagnosticsInjected.forEach((d, idx) => {
    const keyName = `enclave.diagnostic.${idx}`;
    if (!parsed || !parsed.existingKeys.has(keyName)) {
      const key = encodeGgufString(keyName);
      const type = Buffer.alloc(4);
      type.writeUInt32LE(8, 0);
      const val = encodeGgufString(
        `[${d.errorClass}] (${d.systemCode}) ${d.diagnosticMessage}`,
      );
      kvEntries.push(Buffer.concat([key, type, val]));
    }
  });

  // KV nesting: enclave.nesting.breaker — 35 nested ARRAY frames (> MODEL_METADATA_NESTING = 32)
  const nestingDepth = REA_INTERNAL_LIMITS.MODEL_MAX_METADATA_NESTING + 3;
  if (!parsed || !parsed.existingKeys.has("enclave.nesting.breaker")) {
    const key = encodeGgufString("enclave.nesting.breaker");
    const outerType = Buffer.alloc(4);
    outerType.writeUInt32LE(9, 0); // KV value type = 9 (ARRAY)
    const frames: Buffer[] = [key, outerType];
    for (let d = 0; d < nestingDepth; d++) {
      const arrHeader = Buffer.alloc(12);
      arrHeader.writeUInt32LE(d === nestingDepth - 1 ? 4 : 9, 0); // element_type: innermost = UINT32 (4), outer = ARRAY (9)
      arrHeader.writeBigUInt64LE(1n, 4); // count = 1
      frames.push(arrHeader);
    }
    const leafUint32 = Buffer.alloc(4);
    leafUint32.writeUInt32LE(0xdeadbeef, 0);
    frames.push(leafUint32);
    kvEntries.push(Buffer.concat(frames));
  }

  // Real models carry tensors whose `offset` fields are RELATIVE to an
  // aligned data section. Splicing KV bytes in front of the tensor infos
  // without re-padding shifts that section and silently corrupts every
  // weight. Route tensor-bearing inputs through the alignment-safe rewriter,
  // which keeps tensor infos + data byte-exact and recomputes only padding.
  const layout = parsed && parsed.tensorCount > 0n ? parseGgufLayout(bytes) : null;
  if (layout) {
    return {
      buffer: rebuildGguf(bytes, layout, { appendKvs: kvEntries }),
      chaffPayloadsEmbedded: chaffPayloads.length,
      triggeredMetadataNestingBreaker: true,
      canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
      diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
    };
  }

  const header = Buffer.alloc(24);
  header.write("GGUF", 0, "ascii");
  header.writeUInt32LE(parsed ? parsed.version : 3, 4);
  header.writeBigUInt64LE(parsed ? parsed.tensorCount : 0n, 8);
  header.writeBigUInt64LE(
    (parsed ? parsed.kvCount : 0n) + BigInt(kvEntries.length),
    16,
  );

  const combined = Buffer.concat([
    header,
    existingKvSlice,
    ...kvEntries,
    trailingTensorSlice,
  ]);
  const alignedPad =
    trailingTensorSlice.length > 0
      ? Buffer.alloc(0)
      : Buffer.alloc((32 - (combined.length % 32)) % 32, 0);
  return {
    buffer: Buffer.concat([combined, alignedPad]),
    chaffPayloadsEmbedded: chaffPayloads.length,
    triggeredMetadataNestingBreaker: true,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
  };
}
