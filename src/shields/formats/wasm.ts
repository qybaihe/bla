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
      const { value: index, nextOffset: afterIdx } = decodeUnsignedLeb128(
        exportSectionPayload,
        p,
      );
      p = afterIdx;
      out.push({ name, kind, index });
    }
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
    if (preserve.has(e.name)) return e;
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
): Buffer {
  if (decoys.length === 0) return exportSectionPayload;
  let p = 0;
  const { value: count, nextOffset } = decodeUnsignedLeb128(exportSectionPayload, 0);
  p = nextOffset;
  const existing = exportSectionPayload.subarray(p);
  const decoyParts: Buffer[] = [];
  for (const d of decoys) {
    decoyParts.push(
      encodeWasmName(d.name),
      Buffer.from([0x00]), // func
      encodeUnsignedLeb128(d.funcIndex),
    );
  }
  return Buffer.concat([
    encodeUnsignedLeb128(count + decoys.length),
    existing,
    ...decoyParts,
  ]);
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
    const { value: sectionSize, nextOffset } = decodeUnsignedLeb128(bytes, offset);
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
  for (let i = 0; i < count; i++) {
    const pad = "e".repeat(namePad);
    out.push({
      name: `enclave_export_${tag}_${i}_${pad}`,
      funcIndex: indices[i % indices.length]!,
    });
  }
  return out;
}

function createWasmCustomSection(name: string, content: Buffer): Buffer {
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

  while (offset < bytes.length) {
    const sectionId = bytes[offset++]!;
    const { value: sectionSize, nextOffset } = decodeUnsignedLeb128(bytes, offset);
    const sectionEnd = nextOffset + sectionSize;
    if (sectionEnd > bytes.length) break;
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
    version,
    sectionCount,
    customSectionNames,
    debugModuleName,
    exportNames,
    importCount,
  };
}

/**
 * Protects a WebAssembly `.wasm` binary against `rea inspect-wasm-artifact` and `compare-wasm-interfaces`
 * by stripping real debug custom sections and injecting:
 * 1. A honey `"name"` custom section (parsed by WABT and REA's `WabtWat.ts`)
 * 2. Multiple `@custom` architectural chaff sections (`"bla.enclave.manifest"`, `"producers"`, `"dylink.0"`)
 * while keeping the WASM module 100% valid and executable by V8 / WebAssembly runtimes.
 */
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

  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-wasm-shield-v1");
  const chaffPayloads = generateChaffPayloads(prng, intensity);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

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
    collectExportedFuncIndices(bytes),
  );
  const keptChunks: Buffer[] = [bytes.subarray(0, 8)];
  let offset = 8;
  let exportDecoysInjected = 0;
  let exportsRenamed: readonly WasmExportRename[] = [];
  let exportsOrderShuffled = false;
  while (offset < bytes.length) {
    const sectionStart = offset;
    const sectionId = bytes[offset++]!;
    const { value: sectionSize, nextOffset } = decodeUnsignedLeb128(bytes, offset);
    const sectionEnd = nextOffset + sectionSize;
    if (sectionEnd > bytes.length) break;

    if (sectionId === 0) {
      // strip original custom/debug
    } else if (sectionId === 7) {
      let payload = bytes.subarray(nextOffset, sectionEnd);
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
      let expanded =
        decoyExports.length > 0
          ? appendDecoyExports(payload, decoyExports)
          : payload;
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
      exportDecoysInjected = decoyExports.length;
    } else {
      keptChunks.push(bytes.subarray(sectionStart, sectionEnd));
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
    classification: "SYNTHETIC_CANARY_CREDENTIAL_HONEYPOT",
    canaryTokens: deception.canary.syntheticCanaryTokens,
    ambiguousTransportEndpoints: deception.canary.ambiguousCredentialUrls,
    conflictingQueryEndpoints: deception.canary.conflictingQueryUrls,
  });
  addedSections.push(
    createWasmCustomSection("bla.canary.credentials", Buffer.from(canaryJson, "utf8")),
  );

  // System-diagnostic rabbit holes + Cognitive-Armor triggers as a dedicated custom section.
  const diagJson = JSON.stringify({
    classification: "SYSTEM_DIAGNOSTIC_AND_COGNITIVE_ARMOR_DECOY",
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
  };
}
