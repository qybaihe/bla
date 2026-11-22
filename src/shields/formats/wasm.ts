import { SeededPrng } from "../../core/prng.js";
import { planWasmInterfaceBudgetExhaustion } from "../exhaustion/wasm-interface-exhaustion.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

export interface WasmSection {
  readonly id: number;
  readonly payload: Buffer;
  readonly customName?: string;
}

export interface WasmInspectionSummary {
  readonly validMagic: boolean;
  readonly exactFraming: boolean;
  readonly version: number;
  readonly sectionCount: number;
  readonly customSectionNames: readonly string[];
  readonly debugModuleName: string | null;
  readonly exportNames: readonly string[];
  readonly importCount: number;
}

function encodeUnsignedLeb128(value: number): Buffer {
  const bytes: number[] = [];
  let v = value >>> 0;
  do {
    let byte = v & 0x7f;
    v >>>= 7;
    if (v !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (v !== 0);
  return Buffer.from(bytes);
}

function encodeSignedLeb128(value: number): Buffer {
  const bytes: number[] = [];
  let v = value | 0;
  let more = true;
  while (more) {
    let byte = v & 0x7f;
    v >>= 7;
    if ((v === 0 && (byte & 0x40) === 0) || (v === -1 && (byte & 0x40) !== 0)) {
      more = false;
    } else {
      byte |= 0x80;
    }
    bytes.push(byte);
  }
  return Buffer.from(bytes);
}

function decodeUnsignedLeb128(buf: Buffer, startOffset: number): { value: number; nextOffset: number } {
  let result = 0;
  let shift = 0;
  let offset = startOffset;
  while (offset < buf.length) {
    const byte = buf[offset++]!;
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      return { value: result >>> 0, nextOffset: offset };
    }
    shift += 7;
    if (shift > 35) throw new Error("Invalid LEB128 integer in WASM binary");
  }
  throw new Error("Truncated LEB128 integer in WASM binary");
}

/**
 * Non-throwing variant of {@link decodeUnsignedLeb128} for defensive section
 * walks. Returns null on a truncated / invalid LEB128 (e.g. a section-id byte
 * with no following size field) so callers documented as defensive — which
 * guard a truncated section *body* but decoded the section *size* header
 * outside that guard — never throw on hostile / corrupt input.
 */
function tryDecodeUnsignedLeb128(
  buf: Buffer,
  startOffset: number,
): { value: number; nextOffset: number } | null {
  try {
    return decodeUnsignedLeb128(buf, startOffset);
  } catch {
    return null;
  }
}

function encodeWasmName(str: string): Buffer {
  const utf8 = Buffer.from(str, "utf8");
  return Buffer.concat([encodeUnsignedLeb128(utf8.length), utf8]);
}


export interface WasmExportEntry {
  readonly name: string;
  /** 0 = func, 1 = table, 2 = mem, 3 = global */
  readonly kind: number;
  readonly index: number;
}

export interface WasmExportRename {
  readonly from: string;
  readonly to: string;
  readonly kind: number;
  readonly index: number;
}

/**
 * Parse a WASM export-section payload (without the section id/size wrapper)
 * into individual entries. Defensive: returns [] on truncated / malformed input.
 */
export function parseWasmExportSectionPayload(
  exportSectionPayload: Buffer,
): WasmExportEntry[] {
  try {
    const { value: count, nextOffset } = decodeUnsignedLeb128(
      exportSectionPayload,
      0,
    );
    let p = nextOffset;
    const out: WasmExportEntry[] = [];
    for (let i = 0; i < count; i++) {
      const { value: nameLen, nextOffset: afterLen } = decodeUnsignedLeb128(
        exportSectionPayload,
        p,
      );
      p = afterLen;
      if (p + nameLen >= exportSectionPayload.length) return out;
      const name = exportSectionPayload
        .subarray(p, p + nameLen)
        .toString("utf8");
      p += nameLen;
      if (p >= exportSectionPayload.length) return out;
      const kind = exportSectionPayload[p++]!;
      if (kind > 0x04) return [];
      const { value: index, nextOffset: afterIdx } = decodeUnsignedLeb128(
        exportSectionPayload,
        p,
      );
      p = afterIdx;
      out.push({ name, kind, index });
    }
    if (p !== exportSectionPayload.length) return [];
    return out;
  } catch {
    return [];
  }
}

function encodeWasmExportEntry(entry: WasmExportEntry): Buffer {
  return Buffer.concat([
    encodeWasmName(entry.name),
    Buffer.from([entry.kind & 0xff]),
    encodeUnsignedLeb128(entry.index),
  ]);
}

function encodeWasmExportSectionPayload(
  entries: readonly WasmExportEntry[],
): Buffer {
  return Buffer.concat([
    encodeUnsignedLeb128(entries.length),
    ...entries.map(encodeWasmExportEntry),
  ]);
}

/**
 * Seed-shuffle export entries (names/kinds/indices unchanged).
 * Round-11: bankrupt rename used to preserve cleartext export *order*, so
 * "unlock first among arity-2" survived as an RE shortcut. Hosts must resolve
 * by arity + FLAG shape + certificate — never by first-export position.
 */
export function shuffleWasmExportSectionPayload(
  exportSectionPayload: Buffer,
  prng: SeededPrng,
): Buffer {
  const entries = parseWasmExportSectionPayload(exportSectionPayload);
  if (entries.length <= 1) return exportSectionPayload;
  return encodeWasmExportSectionPayload(prng.shuffle(entries));
}

/** Heuristic: names that look like internal/debug ABI rather than a public export. */
export function looksLikeInternalWasmExport(name: string): boolean {
  return /^(?:__|_|debug_|dbg_|_internal|internal_|test_|tmp_)/i.test(name);
}

/**
 * Exports a host or toolchain glue looks up by a fixed, specified name: the
 * WASI entry points, the default memory / table, wasm-ld linker symbols, and
 * the wasm-bindgen / Emscripten / component-model runtime glue.
 *
 * No consumer edit can follow a rename of these — a WASI host calls `_start`
 * because the spec says so — and they carry no secret, so they are never
 * renamed at any intensity.
 */
const WASM_ABI_MANDATED_EXPORT_RE =
  /^(?:_start|_initialize|memory|__indirect_function_table|__heap_base|__data_end|__stack_pointer|__stack_high|__stack_low|__global_base|__memory_base|__table_base|__tls_base|__tls_size|__tls_align|__dso_handle|__wasm_call_ctors|__wasm_call_dtors|__wasm_apply_data_relocs|__wasm_init_memory|__wasm_init_tls|__main_argc_argv|__main_void|__original_main|__errno_location|cabi_realloc|cabi_post_.+|cabi_import_realloc|cabi_export_realloc|__wbindgen_.+|__wbg_.+|__externref_.+|__cxa_.+|_emscripten_.+|emscripten_.+|asyncify_.+|__asyncify_.+|dynCall_.+|stackSave|stackRestore|stackAlloc|setThrew|setTempRet0|getTempRet0|wasi_thread_start|__wasi_.+|__component_type_object_force_link_.+)$/;

export function isAbiMandatedWasmExport(name: string): boolean {
  return WASM_ABI_MANDATED_EXPORT_RE.test(name);
}

/**
 * Rename export names that are NOT in `preserveExports`.
 * When `onlyInternal` is true, only names matching {@link looksLikeInternalWasmExport}
 * are renamed (safer default). Function indices / kinds are preserved so
 * Instantiation semantics stay intact for glue that uses the returned rename map.
 *
 * DEFENSIVE ONLY — customers must update import sites using the rename map
 * (or keep public ABI names in `preserveExports`).
 */
export function renameWasmExports(
  exportSectionPayload: Buffer,
  prng: SeededPrng,
  options: {
    readonly preserveExports?: readonly string[];
    /**
     * When true, only rename internal-looking names.
     * Callers that want full non-preserved rename must pass `onlyInternal: false`
     * (protectWasmBinary does this by default at maximum/bankrupt).
     */
    readonly onlyInternal?: boolean;
  } = {},
): {
  readonly payload: Buffer;
  readonly renames: readonly WasmExportRename[];
} {
  const preserve = new Set(options.preserveExports ?? []);
  // Library default remains conservative (internal-only) when called directly;
  // protectWasmBinary passes onlyInternal:false at maximum/bankrupt.
  const onlyInternal = options.onlyInternal !== false;
  const entries = parseWasmExportSectionPayload(exportSectionPayload);
  if (entries.length === 0) {
    return { payload: exportSectionPayload, renames: [] };
  }
  const renames: WasmExportRename[] = [];
  const rewritten: WasmExportEntry[] = entries.map((e) => {
    if (preserve.has(e.name) || isAbiMandatedWasmExport(e.name)) return e;
    if (onlyInternal && !looksLikeInternalWasmExport(e.name)) return e;
    const tag = prng.hex(4);
    const to = `ops_${tag}_${prng.identifier({ style: "snake", hint: "dispatch", entropy: 3 })}`;
    renames.push({ from: e.name, to, kind: e.kind, index: e.index });
    return { name: to, kind: e.kind, index: e.index };
  });
  return {
    payload: encodeWasmExportSectionPayload(rewritten),
    renames,
  };
}


/**
 * Append decoy export entries that alias an existing function index.
 * Original exports are preserved; WebAssembly.validate and original
 * Instantiation stay intact. Bankrupt intensity sizes names so REA's
 * Wabt→WasmInterfaceBudget path exceeds WASM_INTERFACE_REPRESENTATION_BYTES.
 */
function appendDecoyExports(
  exportSectionPayload: Buffer,
  decoys: readonly { readonly name: string; readonly funcIndex: number }[],
): { readonly payload: Buffer; readonly injected: number } {
  if (decoys.length === 0) return { payload: exportSectionPayload, injected: 0 };
  let count = 0;
  let nextOffset = 0;
  try {
    const decoded = decodeUnsignedLeb128(exportSectionPayload, 0);
    count = decoded.value;
    nextOffset = decoded.nextOffset;
  } catch {
    return { payload: exportSectionPayload, injected: 0 };
  }
  const parsedExisting = parseWasmExportSectionPayload(exportSectionPayload);
  if (
    parsedExisting.length !== count ||
    (count === 0 && nextOffset !== exportSectionPayload.length)
  ) {
    return { payload: exportSectionPayload, injected: 0 };
  }
  const existing = exportSectionPayload.subarray(nextOffset);
  const decoyParts: Buffer[] = [];
  for (const d of decoys) {
    decoyParts.push(
      encodeWasmName(d.name),
      Buffer.from([0x00]), // func
      encodeUnsignedLeb128(d.funcIndex),
    );
  }
  return {
    payload: Buffer.concat([
      encodeUnsignedLeb128(count + decoys.length),
      existing,
      ...decoyParts,
    ]),
    injected: decoys.length,
  };
}

/**
 * Parse WASM type-section function signatures → param counts (functype only).
 * Returns [] on truncated / non-functype entries (defensive).
 */
function parseWasmFunctypeParamCounts(typeSectionPayload: Buffer): number[] {
  try {
    const { value: count, nextOffset } = decodeUnsignedLeb128(typeSectionPayload, 0);
    let p = nextOffset;
    const out: number[] = [];
    for (let i = 0; i < count; i++) {
      if (p >= typeSectionPayload.length) return out;
      const form = typeSectionPayload[p++]!;
      if (form !== 0x60) return out; // only functype
      const { value: nParams, nextOffset: afterParams } = decodeUnsignedLeb128(
        typeSectionPayload,
        p,
      );
      p = afterParams + nParams; // skip param valtypes
      if (p > typeSectionPayload.length) return out;
      const { value: nResults, nextOffset: afterResults } = decodeUnsignedLeb128(
        typeSectionPayload,
        p,
      );
      p = afterResults + nResults;
      if (p > typeSectionPayload.length) return out;
      out.push(nParams);
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * Parse WASM function-section → type indices per function index.
 */
function parseWasmFuncTypeIndices(funcSectionPayload: Buffer): number[] {
  try {
    const { value: count, nextOffset } = decodeUnsignedLeb128(funcSectionPayload, 0);
    let p = nextOffset;
    const out: number[] = [];
    for (let i = 0; i < count; i++) {
      const { value: typeIdx, nextOffset: after } = decodeUnsignedLeb128(
        funcSectionPayload,
        p,
      );
      p = after;
      out.push(typeIdx);
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * Collect unique function-export indices from a WASM binary (kind 0 only).
 * Used so bankrupt decoy aliases can be spread across real stubs + unlock
 * instead of all aliasing funcIndex 0 (red/blue round-10 arity-2 hygiene).
 *
 * Round-12: prefer host-visible arity-2 exports `(i32,i32)->…` when at least
 * one exists, so arity-1 exports (e.g. seal) do not consume alias budget.
 * Falls back to all func exports when no arity-2 is present.
 */
function collectExportedFuncIndices(bytes: Buffer): number[] {
  if (
    bytes.length < 8 ||
    bytes[0] !== 0x00 ||
    bytes[1] !== 0x61 ||
    bytes[2] !== 0x73 ||
    bytes[3] !== 0x6d
  ) {
    return [];
  }
  let offset = 8;
  let typeParamCounts: number[] | null = null;
  let funcTypeIndices: number[] | null = null;
  let exportEntries: WasmExportEntry[] | null = null;
  while (offset < bytes.length) {
    const sectionId = bytes[offset++]!;
    const header = tryDecodeUnsignedLeb128(bytes, offset);
    if (header === null) break; // truncated section-size header → stop defensively
    const { value: sectionSize, nextOffset } = header;
    const sectionEnd = nextOffset + sectionSize;
    if (sectionEnd > bytes.length) break;
    const payload = bytes.subarray(nextOffset, sectionEnd);
    if (sectionId === 1) {
      typeParamCounts = parseWasmFunctypeParamCounts(payload);
    } else if (sectionId === 3) {
      funcTypeIndices = parseWasmFuncTypeIndices(payload);
    } else if (sectionId === 7) {
      exportEntries = parseWasmExportSectionPayload(payload);
    }
    offset = sectionEnd;
  }
  if (!exportEntries) return [];
  const seen = new Set<number>();
  const all: number[] = [];
  const arity2: number[] = [];
  for (const e of exportEntries) {
    if (e.kind !== 0) continue;
    if (seen.has(e.index)) continue;
    seen.add(e.index);
    all.push(e.index);
    if (typeParamCounts && funcTypeIndices && e.index < funcTypeIndices.length) {
      const typeIdx = funcTypeIndices[e.index]!;
      if (typeIdx < typeParamCounts.length && typeParamCounts[typeIdx] === 2) {
        arity2.push(e.index);
      }
    }
  }
  // Prefer host-visible arity-2 when available (round-12 alias budget hygiene).
  return arity2.length > 0 ? arity2 : all;
}

function planWasmExportNameDecoys(
  prng: SeededPrng,
  intensity: ProtectionIntensity,
  funcIndices: readonly number[],
): readonly { readonly name: string; readonly funcIndex: number }[] {
  // bankrupt: ~250 × ~12 KiB names → Wabt interface charge ≫ 32 MiB.
  // Round-10: spread aliases across exported function indices (stubs + unlock)
  // so ~all-250 do not concentrate on funcIndex 0 / the real unlock body.
  // Round-12: caller passes arity-2-preferring indices when available.
  const count =
    intensity === "stealth"
      ? 0
      : intensity === "balanced"
        ? 2
        : intensity === "maximum"
          ? 8
          : 250;
  const namePad = intensity === "bankrupt" ? 12_000 : intensity === "maximum" ? 48 : 16;
  const tag = prng.hex(4);
  const indices =
    funcIndices.length > 0 ? prng.shuffle([...new Set(funcIndices)]) : [0];
  const out: { name: string; funcIndex: number }[] = [];
  const segVocab = [
    "frame", "codec", "route", "state", "delta", "cache", "graph", "entry",
    "token", "scope", "chunk", "slice", "batch", "queue", "index", "stage",
  ];
  for (let i = 0; i < count; i++) {
    // Build varied deterministic pseudo-identifier padding instead of `"e".repeat(...)`
    // so trivial repeated-char filters cannot strip export decoys while preserving
    // the exact byte-size budget required to trigger Wabt interface limits.
    let seedChunk = "";
    while (seedChunk.length < Math.min(namePad, 192)) {
      const w = segVocab[(i + prng.nextInt(0, segVocab.length - 1)) % segVocab.length]!;
      seedChunk += `${w}_${prng.hex(2)}_`;
    }
    const pad =
      namePad <= seedChunk.length
        ? seedChunk.slice(0, namePad)
        : seedChunk.repeat(Math.ceil(namePad / seedChunk.length)).slice(0, namePad);
    out.push({
      name: `enclave_export_${tag}_${i}_${pad}`,
      funcIndex: indices[i % indices.length]!,
    });
  }
  return out;
}

export function createWasmCustomSection(name: string, content: Buffer): Buffer {
  const nameEncoded = encodeWasmName(name);
  const sectionPayload = Buffer.concat([nameEncoded, content]);
  return Buffer.concat([
    Buffer.from([0x00]), // Custom section ID = 0
    encodeUnsignedLeb128(sectionPayload.length),
    sectionPayload,
  ]);
}

/**
 * Builds a valid WASM `"name"` custom section (Subsection 0 = module-name, Subsection 1 = function names)
 * that WABT (`wasm2wat` / `wasm-objdump`) and REA's `WabtWat.ts` (`moduleNames()`) automatically decode!
 */
function buildHoneyWasmNameSection(prng: SeededPrng): Buffer {
  const hex = prng.hex(6);
  const decoyModuleName = `tee_hardware_enclave_transport_stub_${hex}`;
  const modNameEncoded = encodeWasmName(decoyModuleName);
  // Subsection 0: module name (type = 0, size = len(modNameEncoded), payload = modNameEncoded)
  const sub0 = Buffer.concat([
    Buffer.from([0x00]),
    encodeUnsignedLeb128(modNameEncoded.length),
    modNameEncoded,
  ]);

  return createWasmCustomSection("name", sub0);
}

export function inspectWasmBinary(bytes: Buffer): WasmInspectionSummary {
  if (
    bytes.length < 8 ||
    bytes[0] !== 0x00 ||
    bytes[1] !== 0x61 ||
    bytes[2] !== 0x73 ||
    bytes[3] !== 0x6d
  ) {
    return {
      validMagic: false,
      exactFraming: false,
      version: 0,
      sectionCount: 0,
      customSectionNames: [],
      debugModuleName: null,
      exportNames: [],
      importCount: 0,
    };
  }

  const version = bytes.readUInt32LE(4);
  let offset = 8;
  let sectionCount = 0;
  const customSectionNames: string[] = [];
  const exportNames: string[] = [];
  let importCount = 0;
  let debugModuleName: string | null = null;

  let truncatedSection = false;
  while (offset < bytes.length) {
    const sectionId = bytes[offset++]!;
    const header = tryDecodeUnsignedLeb128(bytes, offset);
    if (header === null) {
      truncatedSection = true;
      break; // truncated section-size header → stop defensively
    }
    const { value: sectionSize, nextOffset } = header;
    const sectionEnd = nextOffset + sectionSize;
    if (sectionEnd > bytes.length) {
      truncatedSection = true;
      break;
    }
    sectionCount++;

    const payload = bytes.subarray(nextOffset, sectionEnd);
    if (sectionId === 0 && payload.length > 0) {
      try {
        const { value: nameLen, nextOffset: nameStart } = decodeUnsignedLeb128(payload, 0);
        const customName = payload.subarray(nameStart, nameStart + nameLen).toString("utf8");
        customSectionNames.push(customName);
        if (customName === "name") {
          const rest = payload.subarray(nameStart + nameLen);
          if (rest.length >= 2 && rest[0] === 0) {
            const { nextOffset: subStart } = decodeUnsignedLeb128(rest, 1);
            const { value: modNameLen, nextOffset: modNameStart } = decodeUnsignedLeb128(rest, subStart);
            debugModuleName = rest.subarray(modNameStart, modNameStart + modNameLen).toString("utf8");
          }
        }
      } catch {
        // Ignore malformed custom section
      }
    } else if (sectionId === 2 && payload.length > 0) {
      try {
        const { value: count } = decodeUnsignedLeb128(payload, 0);
        importCount = count;
      } catch {
        // Ignore
      }
    } else if (sectionId === 7 && payload.length > 0) {
      try {
        let p = 0;
        const { value: count, nextOffset: afterCount } = decodeUnsignedLeb128(payload, p);
        p = afterCount;
        for (let i = 0; i < count && p < payload.length; i++) {
          const { value: nameLen, nextOffset: nameStart } = decodeUnsignedLeb128(payload, p);
          const expName = payload.subarray(nameStart, nameStart + nameLen).toString("utf8");
          exportNames.push(expName);
          p = nameStart + nameLen + 1; // skip export kind byte
          const { nextOffset: afterIdx } = decodeUnsignedLeb128(payload, p);
          p = afterIdx;
        }
      } catch {
        // Ignore
      }
    }

    offset = sectionEnd;
  }

  return {
    validMagic: true,
    exactFraming: !truncatedSection && offset === bytes.length,
    version,
    sectionCount,
    customSectionNames,
    debugModuleName,
    exportNames,
    importCount,
  };
}

/**
 * Read the raw content bytes of the first custom section with the given name
 * (payload after the name encoding). Returns null when absent / malformed.
 */
export function readWasmCustomSectionContent(
  bytes: Buffer,
  sectionName: string,
): Buffer | null {
  if (
    bytes.length < 8 ||
    bytes[0] !== 0x00 ||
    bytes[1] !== 0x61 ||
    bytes[2] !== 0x73 ||
    bytes[3] !== 0x6d
  ) {
    return null;
  }
  let offset = 8;
  while (offset < bytes.length) {
    const sectionId = bytes[offset++]!;
    const header = tryDecodeUnsignedLeb128(bytes, offset);
    if (header === null) break; // truncated section-size header → stop defensively
    const { value: sectionSize, nextOffset } = header;
    const sectionEnd = nextOffset + sectionSize;
    if (sectionEnd > bytes.length) break;
    if (sectionId === 0) {
      const payload = bytes.subarray(nextOffset, sectionEnd);
      try {
        const { value: nameLen, nextOffset: nameStart } = decodeUnsignedLeb128(payload, 0);
        const customName = payload.subarray(nameStart, nameStart + nameLen).toString("utf8");
        if (customName === sectionName) {
          return Buffer.from(payload.subarray(nameStart + nameLen));
        }
      } catch {
        /* skip malformed */
      }
    }
    offset = sectionEnd;
  }
  return null;
}

/**
 * Drop every custom section whose name matches `sectionName`. Preserves all
 * other sections (including other custom sections) in order.
 */
export function stripWasmCustomSectionByName(
  bytes: Buffer,
  sectionName: string,
): Buffer {
  if (
    bytes.length < 8 ||
    bytes[0] !== 0x00 ||
    bytes[1] !== 0x61 ||
    bytes[2] !== 0x73 ||
    bytes[3] !== 0x6d
  ) {
    return Buffer.from(bytes);
  }
  const out: Buffer[] = [Buffer.from(bytes.subarray(0, 8))];
  let offset = 8;
  while (offset < bytes.length) {
    const sectionStart = offset;
    const sectionId = bytes[offset++]!;
    const header = tryDecodeUnsignedLeb128(bytes, offset);
    if (header === null) {
      // Truncated section-size header → keep the malformed tail verbatim.
      out.push(Buffer.from(bytes.subarray(sectionStart)));
      break;
    }
    const { value: sectionSize, nextOffset } = header;
    const sectionEnd = nextOffset + sectionSize;
    if (sectionEnd > bytes.length) {
      out.push(Buffer.from(bytes.subarray(sectionStart)));
      break;
    }
    let drop = false;
    if (sectionId === 0) {
      const payload = bytes.subarray(nextOffset, sectionEnd);
      try {
        const { value: nameLen, nextOffset: nameStart } = decodeUnsignedLeb128(payload, 0);
        const customName = payload.subarray(nameStart, nameStart + nameLen).toString("utf8");
        if (customName === sectionName) drop = true;
      } catch {
        /* keep malformed */
      }
    }
    if (!drop) {
      out.push(Buffer.from(bytes.subarray(sectionStart, sectionEnd)));
    }
    offset = sectionEnd;
  }
  return Buffer.concat(out);
}

/**
 * Append a custom section, replacing any prior section(s) with the same name
 * so re-binds stay idempotent. Does not alter export surface or function bodies.
 */
export function appendWasmCustomSection(
  bytes: Buffer,
  sectionName: string,
  content: Buffer,
): Buffer {
  const cleaned = stripWasmCustomSectionByName(bytes, sectionName);
  return Buffer.concat([cleaned, createWasmCustomSection(sectionName, content)]);
}

/**
 * Protects a WebAssembly `.wasm` binary against `rea inspect-wasm-artifact` and `compare-wasm-interfaces`
 * by stripping real debug custom sections and injecting:
 * 1. A honey `"name"` custom section (parsed by WABT and REA's `WabtWat.ts`)
 * 2. Multiple `@custom` architectural chaff sections (`"bla.enclave.manifest"`, `"producers"`, `"dylink.0"`)
 * while keeping the WASM module 100% valid and executable by V8 / WebAssembly runtimes.
 */
/**
 * Custom sections a linker or the host runtime needs to load the module:
 * `dylink.0`/`linking`/`reloc.*` for dynamically linked modules (Emscripten side
 * modules) and `target_features` for feature negotiation. Debug/metadata
 * sections such as `name` and `producers` are still stripped.
 */
const LINKING_CRITICAL_CUSTOM_SECTIONS: ReadonlySet<string> = new Set([
  "dylink.0",
  "dylink",
  "linking",
  "target_features",
]);

export function isLinkingCriticalCustomSection(name: string): boolean {
  return LINKING_CRITICAL_CUSTOM_SECTIONS.has(name) || name.startsWith("reloc.");
}

/**
 * Parses a WASM Type section (`sectionId === 1`) into parameter value-type lists
 * for each standard `0x60` functype. Returns `null` if non-MVP GC/typed-ref types
 * are present so bytecode flower injection fails safe without touching exotic layouts.
 */
function parseWasmTypeParamTypes(typeSectionPayload: Buffer): (readonly number[])[] | null {
  try {
    const { value: count, nextOffset } = decodeUnsignedLeb128(typeSectionPayload, 0);
    let p = nextOffset;
    const out: (readonly number[])[] = [];
    for (let i = 0; i < count; i++) {
      if (p >= typeSectionPayload.length || typeSectionPayload[p++] !== 0x60) {
        return null;
      }
      const { value: nParams, nextOffset: afterParams } = decodeUnsignedLeb128(
        typeSectionPayload,
        p,
      );
      p = afterParams;
      if (p + nParams > typeSectionPayload.length) return null;
      const params: number[] = [];
      for (let j = 0; j < nParams; j++) {
        const vt = typeSectionPayload[p++]!;
        // Typed ref types (0x63/0x64) carry a heaptype immediate; skip injection safely.
        if (vt === 0x63 || vt === 0x64) return null;
        params.push(vt);
      }
      const { value: nResults, nextOffset: afterResults } = decodeUnsignedLeb128(
        typeSectionPayload,
        p,
      );
      p = afterResults;
      if (p + nResults > typeSectionPayload.length) return null;
      for (let j = 0; j < nResults; j++) {
        const vt = typeSectionPayload[p++]!;
        if (vt === 0x63 || vt === 0x64) return null;
      }
      out.push(params);
    }
    return p === typeSectionPayload.length ? out : null;
  } catch {
    return null;
  }
}

function wasmI32Const(value: number): Buffer {
  return Buffer.concat([Buffer.from([0x41]), encodeSignedLeb128(value)]);
}

function wasmLocalGet(index: number): Buffer {
  return Buffer.concat([Buffer.from([0x20]), encodeUnsignedLeb128(index)]);
}

/**
 * Builds a stack-neutral (`[] -> []`) polymorphic WebAssembly 1.0 MVP opaque-false
 * flower block (`if (void) <varied control-flow + ARX/bit-op dead body> end`).
 *
 * Couples randomly to any `i32` or `i64` parameter across 5 distinct algebraic /
 * MBA / unsigned-bit zero identities and 4 distinct dead-branch architectures
 * (`block+select+br_if`, nested `if/else`, dead `loop+br_if`, `br_table`),
 * defeating both constant folding and fixed-skeleton binary peelers.
 */
function buildWasmOpaqueFlowerBlock(
  prng: SeededPrng,
  paramTypes: readonly number[],
  variant: number,
): Buffer {
  const i32ParamIndices: number[] = [];
  const i64ParamIndices: number[] = [];
  for (let p = 0; p < paramTypes.length; p++) {
    if (paramTypes[p] === 0x7f) i32ParamIndices.push(p);
    else if (paramTypes[p] === 0x7e) i64ParamIndices.push(p);
  }
  const i32ParamIdx =
    i32ParamIndices.length > 0
      ? i32ParamIndices[prng.nextInt(0, i32ParamIndices.length - 1)]!
      : -1;
  const i64ParamIdx =
    i64ParamIndices.length > 0
      ? i64ParamIndices[prng.nextInt(0, i64ParamIndices.length - 1)]!
      : -1;

  let guard: Buffer;
  if (i32ParamIdx >= 0) {
    const mode = (variant + prng.nextInt(0, 4)) % 5;
    const pGet = wasmLocalGet(i32ParamIdx);
    if (mode === 0) {
      // (((x ^ mask) | 1)^2 & 7) ^ 1 === 0 for every i32 x (odd^2 === 1 mod 8)
      const mask = prng.nextInt(0x101, 0x3fffffff) & ~1;
      const oddX = Buffer.concat([
        pGet,
        wasmI32Const(mask),
        Buffer.from([0x73]), // i32.xor
        wasmI32Const(1),
        Buffer.from([0x72]), // i32.or
      ]);
      guard = Buffer.concat([
        oddX,
        oddX,
        Buffer.from([0x6c]), // i32.mul
        wasmI32Const(7),
        Buffer.from([0x71]), // i32.and
        wasmI32Const(1),
        Buffer.from([0x73]), // i32.xor
      ]);
    } else if (mode === 1) {
      // ((y * (y + 1)) & 1) === 0 for every i32 y = x ^ mask
      const mask = prng.nextInt(0x101, 0x3fffffff);
      const y = Buffer.concat([pGet, wasmI32Const(mask), Buffer.from([0x73])]);
      guard = Buffer.concat([
        y,
        y,
        wasmI32Const(1),
        Buffer.from([0x6a]), // i32.add
        Buffer.from([0x6c]), // i32.mul
        wasmI32Const(1),
        Buffer.from([0x71]), // i32.and
      ]);
    } else if (mode === 2) {
      // (((z^2 * z^2) & 15) ^ 1) === 0 for odd z = (x ^ mask) | 1 (odd^4 === 1 mod 16)
      const mask = prng.nextInt(0x101, 0x3fffffff);
      const z = Buffer.concat([
        pGet,
        wasmI32Const(mask),
        Buffer.from([0x73]),
        wasmI32Const(1),
        Buffer.from([0x72]),
      ]);
      const zSq = Buffer.concat([z, z, Buffer.from([0x6c])]);
      guard = Buffer.concat([
        zSq,
        zSq,
        Buffer.from([0x6c]), // z^4
        wasmI32Const(15),
        Buffer.from([0x71]), // i32.and
        wasmI32Const(1),
        Buffer.from([0x73]), // i32.xor
      ]);
    } else if (mode === 3) {
      // ((u | (u - 1)) <u (u ^ (u - 1))) === 0 for every u32 u = x ^ mask
      const mask = prng.nextInt(0x101, 0x3fffffff);
      const u = Buffer.concat([pGet, wasmI32Const(mask), Buffer.from([0x73])]);
      const uMinus1 = Buffer.concat([u, wasmI32Const(1), Buffer.from([0x6b])]); // i32.sub
      guard = Buffer.concat([
        u,
        uMinus1,
        Buffer.from([0x72]), // i32.or
        u,
        uMinus1,
        Buffer.from([0x73]), // i32.xor
        Buffer.from([0x49]), // i32.lt_u (always 0)
      ]);
    } else {
      // Affine carry-identity MBA over Z/2^32Z: ((x ^ k) + ((x & k) << 1)) - (x + k) === 0
      const k = prng.nextInt(0x101, 0x3fffffff);
      guard = Buffer.concat([
        pGet,
        wasmI32Const(k),
        Buffer.from([0x73]), // x ^ k
        pGet,
        wasmI32Const(k),
        Buffer.from([0x71]), // x & k
        wasmI32Const(1),
        Buffer.from([0x74]), // << 1
        Buffer.from([0x6a]), // add
        pGet,
        wasmI32Const(k),
        Buffer.from([0x6a]), // x + k
        Buffer.from([0x6b]), // sub -> always 0
      ]);
    }
  } else if (i64ParamIdx >= 0) {
    // (((x ^ mask) | 1)^2 & 7) ^ 1 === 0n for every i64 x -> i64.eqz (1) -> i32.eqz (0)
    const pGet64 = wasmLocalGet(i64ParamIdx);
    const mask64 = prng.nextInt(0x101, 0x3fffffff) & ~1;
    const oddX64 = Buffer.concat([
      pGet64,
      Buffer.from([0x42]),
      encodeSignedLeb128(mask64),
      Buffer.from([0x85, 0x42, 0x01, 0x84]), // i64.xor; i64.const 1; i64.or
    ]);
    guard = Buffer.concat([
      oddX64,
      oddX64,
      Buffer.from([0x7e, 0x42, 0x07, 0x83, 0x42, 0x01, 0x85, 0x50, 0x45]),
    ]);
  } else {
    // 0-param or float-only function: odd-square mod-8 algebraic invariant
    const oddK = prng.nextInt(0x1001, 0x3fffffff) | 1;
    guard = Buffer.concat([
      wasmI32Const(oddK),
      wasmI32Const(oddK),
      Buffer.from([0x6c]),
      wasmI32Const(7),
      Buffer.from([0x71]),
      wasmI32Const(1),
      Buffer.from([0x73]),
    ]);
  }

  const buildAluRounds = (roundCount: number): Buffer => {
    const initVal =
      i32ParamIdx >= 0
        ? wasmLocalGet(i32ParamIdx)
        : wasmI32Const(prng.nextInt(0x10000, 0x7fffffff));
    const parts: Buffer[] = [initVal];
    const unaryOps = [0x67, 0x68, 0x69] as const; // clz, ctz, popcnt
    const rotOps = [0x77, 0x78] as const; // rotl, rotr
    const addSubOps = [0x6a, 0x6b] as const; // add, sub
    for (let r = 0; r < roundCount; r++) {
      const kXor = prng.nextInt(0x1000, 0x7fffffff);
      const rot = prng.nextInt(3, 29);
      const kMul = prng.nextInt(0x1001, 0x7fffffff) | 1;
      const kAdd = prng.nextInt(0x100, 0x7fffffff);
      const rotOp = rotOps[prng.nextInt(0, 1)]!;
      const addOp = addSubOps[prng.nextInt(0, 1)]!;
      parts.push(
        wasmI32Const(kXor),
        Buffer.from([0x73]),
        wasmI32Const(rot),
        Buffer.from([rotOp]),
        wasmI32Const(kMul),
        Buffer.from([0x6c]),
        wasmI32Const(kAdd),
        Buffer.from([addOp]),
      );
      if (prng.nextInt(0, 2) === 0) {
        parts.push(Buffer.from([unaryOps[prng.nextInt(0, 2)]!]));
      }
    }
    return Buffer.concat(parts);
  };

  const bodyArch = prng.nextInt(0, 3);
  const roundCount = prng.nextInt(2, 4);
  let deadBody: Buffer;

  if (bodyArch === 0) {
    // Arch 0: nested block + select + br_if + tail ALU
    const altVal = wasmI32Const(prng.nextInt(0x1000, 0x7fffffff));
    const selCond = Buffer.concat([
      i32ParamIdx >= 0
        ? wasmLocalGet(i32ParamIdx)
        : wasmI32Const(prng.nextInt(0x100, 0xffff)),
      wasmI32Const(0x1f),
      Buffer.from([0x71]),
    ]);
    const cmpConst = wasmI32Const(prng.nextInt(0x100, 0x7fffffff));
    const tailArx = Buffer.concat([buildAluRounds(1), Buffer.from([0x1a])]);
    deadBody = Buffer.concat([
      Buffer.from([0x02, 0x40]), // block (void)
      buildAluRounds(roundCount),
      altVal,
      selCond,
      Buffer.from([0x1b]), // select
      cmpConst,
      Buffer.from([0x46, 0x0d, 0x00]), // i32.eq; br_if 0
      tailArx,
      Buffer.from([0x0b]), // end block
    ]);
  } else if (bodyArch === 1) {
    // Arch 1: nested if / else branches with distinct ALU chains
    const branchCond = Buffer.concat([
      i32ParamIdx >= 0
        ? wasmLocalGet(i32ParamIdx)
        : wasmI32Const(prng.nextInt(0x100, 0xffff)),
      wasmI32Const(1),
      Buffer.from([0x71]),
    ]);
    deadBody = Buffer.concat([
      branchCond,
      Buffer.from([0x04, 0x40]), // if (void)
      buildAluRounds(roundCount),
      Buffer.from([0x1a]), // drop
      Buffer.from([0x05]), // else
      buildAluRounds(Math.max(1, roundCount - 1)),
      Buffer.from([0x1a]), // drop
      Buffer.from([0x0b]), // end if
    ]);
  } else if (bodyArch === 2) {
    // Arch 2: dead loop + eqz + br_if 0
    deadBody = Buffer.concat([
      Buffer.from([0x03, 0x40]), // loop (void)
      buildAluRounds(roundCount),
      Buffer.from([0x45, 0x0d, 0x00]), // i32.eqz; br_if 0
      Buffer.from([0x0b]), // end loop
    ]);
  } else {
    // Arch 3: nested blocks + br_table dispatch
    deadBody = Buffer.concat([
      Buffer.from([0x02, 0x40]), // outer block (void)
      Buffer.from([0x02, 0x40]), // inner block (void)
      buildAluRounds(roundCount),
      wasmI32Const(1),
      Buffer.from([0x71]), // i32.and
      Buffer.from([0x0e, 0x01, 0x00, 0x01]), // br_table [0] default 1
      Buffer.from([0x0b]), // end inner block
      buildAluRounds(1),
      Buffer.from([0x1a]), // drop
      Buffer.from([0x0b]), // end outer block
    ]);
  }

  return Buffer.concat([
    guard,
    Buffer.from([0x04, 0x40]), // if (void)
    deadBody,
    Buffer.from([0x0b]), // end if
  ]);
}

export interface WasmBytecodeFlowerResult {
  readonly buffer: Buffer;
  readonly functionsHardened: number;
  readonly flowerBlocksInjected: number;
  readonly addedCodeBytes: number;
}

/**
 * Injects WebAssembly 1.0 MVP parameter-coupled opaque-false flower bytecode blocks
 * directly into defined function bodies in the Code section (`sectionId === 10`),
 * right after local declarations (stack height 0, branch depth 0).
 *
 * Preserves local indices, branch targets, call/memory/global/table indices, and
 * exact runtime behavior. Automatically skips dynamically-relocatable modules that
 * carry `reloc.*` sections and verifies output with `WebAssembly.validate()`.
 */
export function injectWasmBytecodeFlowerInstructions(
  bytes: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
  } = {},
): WasmBytecodeFlowerResult {
  const noop: WasmBytecodeFlowerResult = {
    buffer: bytes,
    functionsHardened: 0,
    flowerBlocksInjected: 0,
    addedCodeBytes: 0,
  };
  if (
    bytes.length < 8 ||
    bytes[0] !== 0x00 ||
    bytes[1] !== 0x61 ||
    bytes[2] !== 0x73 ||
    bytes[3] !== 0x6d
  ) {
    return noop;
  }

  const intensity = options.intensity ?? "balanced";
  const blocksPerFn =
    intensity === "stealth"
      ? 1
      : intensity === "balanced"
        ? 2
        : intensity === "maximum"
          ? 3
          : 4;
  const maxFunctions =
    intensity === "stealth"
      ? 64
      : intensity === "balanced"
        ? 128
        : intensity === "maximum"
          ? 256
          : 512;
  const prng = new SeededPrng(options.seed ?? "bla-wasm-flower-v1");

  let typeParamTypes: (readonly number[])[] | null = null;
  let funcTypeIndices: number[] | null = null;
  let codeSectionRange: { start: number; payloadStart: number; end: number } | null = null;

  let offset = 8;
  while (offset < bytes.length) {
    const sectionStart = offset;
    const sectionId = bytes[offset++]!;
    const header = tryDecodeUnsignedLeb128(bytes, offset);
    if (header === null) return noop;
    const { value: sectionSize, nextOffset } = header;
    const sectionEnd = nextOffset + sectionSize;
    if (sectionEnd > bytes.length) return noop;
    const payload = bytes.subarray(nextOffset, sectionEnd);

    if (sectionId === 0 && payload.length > 0) {
      try {
        const { value: nameLen, nextOffset: nameStart } = decodeUnsignedLeb128(payload, 0);
        const customName = payload.subarray(nameStart, nameStart + nameLen).toString("utf8");
        if (customName.startsWith("reloc.")) return noop;
      } catch {
        // Ignore malformed custom section name
      }
    } else if (sectionId === 1) {
      typeParamTypes = parseWasmTypeParamTypes(payload);
    } else if (sectionId === 3) {
      funcTypeIndices = parseWasmFuncTypeIndices(payload);
    } else if (sectionId === 10) {
      codeSectionRange = { start: sectionStart, payloadStart: nextOffset, end: sectionEnd };
    }
    offset = sectionEnd;
  }

  if (!typeParamTypes || !funcTypeIndices || !codeSectionRange) {
    return noop;
  }

  const codePayload = bytes.subarray(codeSectionRange.payloadStart, codeSectionRange.end);
  const bodyCountDec = tryDecodeUnsignedLeb128(codePayload, 0);
  if (!bodyCountDec || bodyCountDec.value !== funcTypeIndices.length || bodyCountDec.value === 0) {
    return noop;
  }

  let cursor = bodyCountDec.nextOffset;
  const rewrittenBodies: Buffer[] = [];
  let functionsHardened = 0;
  let flowerBlocksInjected = 0;
  let addedCodeBytes = 0;

  for (let i = 0; i < bodyCountDec.value; i++) {
    const bodySizeDec = tryDecodeUnsignedLeb128(codePayload, cursor);
    if (!bodySizeDec) return noop;
    const bodyStart = bodySizeDec.nextOffset;
    const bodyEnd = bodyStart + bodySizeDec.value;
    if (bodyEnd > codePayload.length || bodySizeDec.value === 0) return noop;
    const body = codePayload.subarray(bodyStart, bodyEnd);
    cursor = bodyEnd;

    // Parse local_decl_vec inside the function body
    const localCountDec = tryDecodeUnsignedLeb128(body, 0);
    if (!localCountDec) return noop;
    let codeStart = localCountDec.nextOffset;
    for (let l = 0; l < localCountDec.value; l++) {
      const cntDec = tryDecodeUnsignedLeb128(body, codeStart);
      if (!cntDec || cntDec.nextOffset >= body.length) return noop;
      const vt = body[cntDec.nextOffset]!;
      if (vt === 0x63 || vt === 0x64) return noop;
      codeStart = cntDec.nextOffset + 1;
    }
    if (codeStart >= body.length || body[body.length - 1] !== 0x0b) {
      return noop;
    }

    const typeIdx = funcTypeIndices[i]!;
    const paramTypes = typeParamTypes[typeIdx];
    if (!paramTypes || i >= maxFunctions) {
      rewrittenBodies.push(encodeUnsignedLeb128(body.length), body);
      continue;
    }

    // Sandwich the real function instructions between polymorphic prologue AND
    // epilogue stack-neutral (`[] -> []`) flower blocks so original bytecode no
    // longer sits bare at the tail of every function body.
    const prologueCount = blocksPerFn >= 2 ? Math.ceil(blocksPerFn / 2) : blocksPerFn;
    const epilogueCount = blocksPerFn - prologueCount;
    const prologueChunks: Buffer[] = [];
    for (let b = 0; b < prologueCount; b++) {
      prologueChunks.push(buildWasmOpaqueFlowerBlock(prng, paramTypes, i + b));
    }
    const epilogueChunks: Buffer[] = [];
    for (let b = 0; b < epilogueCount; b++) {
      epilogueChunks.push(buildWasmOpaqueFlowerBlock(prng, paramTypes, i + prologueCount + b));
    }
    const prologuePayload = Buffer.concat(prologueChunks);
    const epiloguePayload = Buffer.concat(epilogueChunks);
    const newBody = Buffer.concat([
      body.subarray(0, codeStart),
      prologuePayload,
      body.subarray(codeStart, body.length - 1),
      epiloguePayload,
      body.subarray(body.length - 1), // final 0x0b end
    ]);
    rewrittenBodies.push(encodeUnsignedLeb128(newBody.length), newBody);
    functionsHardened += 1;
    flowerBlocksInjected += blocksPerFn;
    addedCodeBytes += prologuePayload.length + epiloguePayload.length;
  }

  if (cursor !== codePayload.length || functionsHardened === 0) {
    return noop;
  }

  const newCodePayload = Buffer.concat([
    encodeUnsignedLeb128(bodyCountDec.value),
    ...rewrittenBodies,
  ]);
  const newCodeSection = Buffer.concat([
    Buffer.from([0x0a]),
    encodeUnsignedLeb128(newCodePayload.length),
    newCodePayload,
  ]);
  const candidate = Buffer.concat([
    bytes.subarray(0, codeSectionRange.start),
    newCodeSection,
    bytes.subarray(codeSectionRange.end),
  ]);

  if (
    typeof WebAssembly !== "undefined" &&
    typeof WebAssembly.validate === "function" &&
    !WebAssembly.validate(new Uint8Array(candidate))
  ) {
    return noop;
  }

  return {
    buffer: candidate,
    functionsHardened,
    flowerBlocksInjected,
    addedCodeBytes,
  };
}

/**
 * Reject a malformed section table before any transformation. `protect` must
 * fail closed: a section whose LEB128 size is truncated, or whose declared size
 * runs past EOF, previously fell out of the walk and the shield still emitted a
 * container the runtime refuses to instantiate.
 */
function assertWasmSectionFraming(bytes: Buffer): void {
  let offset = 8;
  while (offset < bytes.length) {
    const sectionStart = offset;
    offset += 1; // section id
    const header = tryDecodeUnsignedLeb128(bytes, offset);
    if (header === null) {
      throw new Error(
        `Malformed WebAssembly section header at byte ${sectionStart}: truncated LEB128 section size`,
      );
    }
    const { value: sectionSize, nextOffset } = header;
    const sectionEnd = nextOffset + sectionSize;
    if (sectionEnd > bytes.length) {
      throw new Error(
        `Malformed WebAssembly section at byte ${sectionStart}: declared size ${sectionSize} runs past the ${bytes.length - nextOffset} remaining byte(s)`,
      );
    }
    offset = sectionEnd;
  }
}

export function protectWasmBinary(
  bytes: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
    /**
     * Public ABI export names that must keep their original names (issue #40.3).
     * All other exports may be renamed when `renameNonPublicExports` is active.
     */
    readonly preserveExports?: readonly string[];
    /**
     * When true, rename exports not listed in `preserveExports`.
     * Default: true at maximum/bankrupt (all non-preserved names).
     * Keeping a stable public ABI requires an explicit `preserveExports` list
     * (CLI `--wasm-preserve-exports` / MCP `wasm_preserve_exports` / `.blarc`).
     */
    readonly renameNonPublicExports?: boolean;
    /**
     * When renaming, only touch internal-looking names (`__*`, `debug_*`, …).
     * Default **false** at maximum/bankrupt (rename every non-preserved export).
     * Set true only when you intentionally want the weaker internal-only pass.
     */
    readonly renameInternalOnly?: boolean;
  } = {},
): {
  readonly buffer: Buffer;
  readonly customSectionsAdded: number;
  readonly chaffPayloadsEmbedded: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
  readonly interfaceDescriptorsEmbedded: number;
  readonly projectedInterfaceChargeBytes: number;
  readonly exceedsRepresentationBudget: boolean;
  readonly exportDecoysInjected: number;
  /** Export renames applied this pass (issue #40.3). Empty when rename is off. */
  readonly exportsRenamed: readonly WasmExportRename[];
  /** True when export-section entry order was seed-shuffled (round-11). */
  readonly exportsOrderShuffled: boolean;
  /** Number of defined WASM Code-section functions hardened with opaque flower bytecode. */
  readonly codeFunctionsHardened: number;
  /** Total parameter-coupled opaque-false bytecode flower blocks injected into section 10. */
  readonly bytecodeFlowerBlocksInjected: number;
} {
  if (
    bytes.length < 8 ||
    bytes[0] !== 0x00 ||
    bytes[1] !== 0x61 ||
    bytes[2] !== 0x73 ||
    bytes[3] !== 0x6d
  ) {
    throw new Error("Invalid WebAssembly binary magic header");
  }
  assertWasmSectionFraming(bytes);

  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-wasm-shield-v1");
  const chaffPayloads = generateChaffPayloads(prng, intensity);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  // Inject parameter-coupled opaque-false flower bytecode into real Code-section
  // function bodies (`sectionId === 10`) before wrapping export/custom sections.
  const flowerPass = injectWasmBytecodeFlowerInstructions(bytes, {
    intensity,
    seed: options.seed ?? "bla-wasm-shield-v1",
  });
  const sourceBytes = flowerPass.buffer;

  // Retain non-custom sections (1..12), strip original debug/name custom sections (0).
  // At bankrupt intensity, densify the export section with long-name aliases of
  // existing funcs so REA's real Wabt→WasmInterfaceBudget path trips (custom
  // sections alone do not expand the typed interface inventory).
  // Round-10: spread aliases across all exported function indices (not only 0).
  // Round-11: after rename + decoy append, shuffle export *order* independently
  // so first arity-2 is not a stable pointer to the unlock body.
  // Round-12: collectExportedFuncIndices prefers arity-2 (host-visible) so
  // arity-1 exports do not burn alias budget.
  const decoyExports = planWasmExportNameDecoys(
    prng,
    intensity,
    collectExportedFuncIndices(sourceBytes),
  );
  const keptChunks: Buffer[] = [sourceBytes.subarray(0, 8)];
  let offset = 8;
  let exportDecoysInjected = 0;
  let exportsRenamed: readonly WasmExportRename[] = [];
  let exportsOrderShuffled = false;
  while (offset < sourceBytes.length) {
    const sectionStart = offset;
    const sectionId = sourceBytes[offset++]!;
    const header = tryDecodeUnsignedLeb128(sourceBytes, offset);
    if (header === null) {
      throw new Error(
        `Malformed WebAssembly section header at byte ${offset - 1}: truncated LEB128 section size`,
      );
    }
    const { value: sectionSize, nextOffset } = header;
    const sectionEnd = nextOffset + sectionSize;
    if (sectionEnd > sourceBytes.length) {
      throw new Error(
        `Malformed WebAssembly section at byte ${offset - 1}: declared size ${sectionSize} runs past the ${sourceBytes.length - nextOffset} remaining byte(s)`,
      );
    }

    if (sectionId === 0) {
      // Strip original custom/debug sections, but keep the ones a linker or the
      // host runtime needs: dropping dylink/linking/reloc breaks dynamically
      // linked modules, and target_features breaks host feature negotiation.
      const payload = sourceBytes.subarray(nextOffset, sectionEnd);
      let keepCustom = false;
      try {
        const { value: nameLen, nextOffset: nameStart } = decodeUnsignedLeb128(payload, 0);
        const customName = payload.subarray(nameStart, nameStart + nameLen).toString("utf8");
        keepCustom = isLinkingCriticalCustomSection(customName);
      } catch {
        keepCustom = false;
      }
      if (keepCustom) keptChunks.push(Buffer.from(sourceBytes.subarray(sectionStart, sectionEnd)));
    } else if (sectionId === 7) {
      let payload = sourceBytes.subarray(nextOffset, sectionEnd);
      // Issue #40.3: optional rename of non-public / internal exports first.
      const intensityWantsRename =
        intensity === "maximum" || intensity === "bankrupt";
      const renameRequested =
        options.renameNonPublicExports === true ||
        (options.renameNonPublicExports !== false && intensityWantsRename);
      if (renameRequested) {
        // Red/Blue round-1: public ABI (`mix`/`seal`) surviving bankrupt enabled
        // preload hooks. Default at maximum/bankrupt is full non-preserved rename;
        // callers that need stable names must pass preserveExports explicitly.
        const onlyInternal =
          options.renameInternalOnly !== undefined
            ? options.renameInternalOnly
            : false;
        const renamed = renameWasmExports(payload, prng, {
          preserveExports: options.preserveExports,
          onlyInternal,
        });
        payload = Buffer.from(renamed.payload);
        exportsRenamed = renamed.renames;
      }
      const appended =
        decoyExports.length > 0
          ? appendDecoyExports(payload, decoyExports)
          : { payload, injected: 0 };
      let expanded = appended.payload;
      // Round-11: shuffle combined original+decoy export order at maximum/bankrupt
      // (same intensity band as rename / decoy injection). Independent of alias
      // funcIndex spread — closes "first arity-2 = unlock" RE shortcut.
      const intensityWantsShuffle =
        intensity === "maximum" || intensity === "bankrupt";
      if (intensityWantsShuffle) {
        const n = parseWasmExportSectionPayload(expanded).length;
        expanded = shuffleWasmExportSectionPayload(expanded, prng);
        exportsOrderShuffled = n > 1;
      }
      keptChunks.push(
        Buffer.concat([
          Buffer.from([0x07]),
          encodeUnsignedLeb128(expanded.length),
          expanded,
        ]),
      );
      exportDecoysInjected = appended.injected;
    } else {
      keptChunks.push(sourceBytes.subarray(sectionStart, sectionEnd));
    }
    offset = sectionEnd;
  }

  // Append honey `"name"` section + architectural chaff + canary/diagnostic custom sections.
  // Custom sections do not affect WebAssembly.validate() or export execution.
  const addedSections: Buffer[] = [buildHoneyWasmNameSection(prng)];

  const manifestJson = JSON.stringify({
    schema: "bla-wasm-enclave-shield/v1",
    enclave_delegation: true,
    manifests: chaffPayloads.map((p) => p.rawText),
  });
  addedSections.push(
    createWasmCustomSection("bla.enclave.manifest", Buffer.from(manifestJson, "utf8")),
  );

  for (let i = 0; i < Math.min(3, chaffPayloads.length); i++) {
    const payload = chaffPayloads[i]!;
    addedSections.push(
      createWasmCustomSection(
        `enclave.attestation.${i}`,
        Buffer.from(payload.rawText, "utf8"),
      ),
    );
  }

  // Canary honeypot: custom section name + body trip REA string extractors /
  // WABT custom-section dumps without touching the export surface.
  const canaryJson = JSON.stringify({
    classification: "TELEMETRY_ATTESTATION_LEASE_METADATA",
    canaryTokens: deception.canary.syntheticCanaryTokens,
    ambiguousTransportEndpoints: deception.canary.ambiguousCredentialUrls,
    conflictingQueryEndpoints: deception.canary.conflictingQueryUrls,
  });
  addedSections.push(
    createWasmCustomSection("bla.canary.credentials", Buffer.from(canaryJson, "utf8")),
  );

  // System-diagnostic rabbit holes + Cognitive-Armor triggers as a dedicated custom section.
  const diagJson = JSON.stringify({
    classification: "RUNTIME_DIAGNOSTIC_TELEMETRY_MANIFEST",
    canaryGuid: deception.cognitiveArmor.canaryGuid,
    diagnostics: deception.diagnostics.diagnosticsInjected,
    cognitiveArmorInterlocks: deception.cognitiveArmor.triggersInjected,
  });
  addedSections.push(
    createWasmCustomSection("bla.system.diagnostics", Buffer.from(diagJson, "utf8")),
  );

  // Also bake distinctive export-adjacent names + cognitive-armor anchor symbols into a
  // secondary "name"-like custom section so `wasm-objdump -x` / REA WabtWat surface them as symbols.
  const exportNameHoney = deception.canary.syntheticCanaryTokens
    .slice(0, 2)
    .map((tok, i) => `canary_export_${i}_${tok.slice(0, 24)}`)
    .concat(
      deception.diagnostics.diagnosticsInjected
        .slice(0, 2)
        .map((d) => `diag_${d.errorClass}`),
    )
    .concat(
      deception.cognitiveArmor.triggersInjected.map(
        (t) => t.coupledAnchorSymbol,
      ),
    );
  addedSections.push(
    createWasmCustomSection(
      "bla.export.name.decoys",
      Buffer.from(exportNameHoney.join("\0"), "utf8"),
    ),
  );

  // Projected WasmInterfaceBudget exhaustion plan (Wabt path / in-process probe).
  const ifacePlan = planWasmInterfaceBudgetExhaustion(prng, intensity);
  const ifacePayload = Buffer.from(
    JSON.stringify({
      schema: "bla-wasm-interface-exhaustion/v1",
      descriptors: ifacePlan.descriptors.map((d) => ({
        module: d.moduleName,
        name: d.exportName,
        params: d.paramCount,
        results: d.resultCount,
        charge: d.reaChargedRepresentationBytes,
      })),
      totalCharge: ifacePlan.totalReaChargedBytes,
      exceeds: ifacePlan.exceedsRepresentationBudget,
    }),
    "utf8",
  );
  addedSections.push(
    createWasmCustomSection("bla.wasm.interface.exhaustion", ifacePayload),
  );

  return {
    buffer: Buffer.concat([...keptChunks, ...addedSections]),
    customSectionsAdded: addedSections.length,
    chaffPayloadsEmbedded: chaffPayloads.length,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
    interfaceDescriptorsEmbedded: ifacePlan.descriptors.length,
    projectedInterfaceChargeBytes: ifacePlan.totalReaChargedBytes,
    exceedsRepresentationBudget: ifacePlan.exceedsRepresentationBudget,
    exportDecoysInjected,
    exportsRenamed,
    exportsOrderShuffled,
    codeFunctionsHardened: flowerPass.functionsHardened,
    bytecodeFlowerBlocksInjected: flowerPass.flowerBlocksInjected,
  };
}
