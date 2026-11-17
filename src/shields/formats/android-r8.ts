import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

export interface AndroidR8CounterResult {
  /** Valid ProGuard / R8 mapping.txt with residual conflicts + malformed bait. */
  readonly mappingText: string;
  /** Distinct original classes that collide on one residual (past REA candidates: 8). */
  readonly residualConflictCount: number;
  /** Malformed mapping lines retained past REA malformedSamples: 16. */
  readonly malformedSampleCount: number;
  /** Total class records emitted (unique + conflicting). */
  readonly classRecordsEmitted: number;
  /** JNI-mangled `Java_*` export names planted in the decoy .so. */
  readonly jniExportNames: readonly string[];
  /** Minimal ELF64 AArch64 ET_DYN with those `Java_*` dynsym exports. */
  readonly jniElfBuffer: Buffer;
  readonly chaffPayloadsEmbedded: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
}

/**
 * JNI short-name mangling (mirrors REA `androidJniBindings.ts` escape rules):
 * `/` → `_`, `_` → `_1`, `;` → `_2`, `[` → `_3`, else `_0XXXX` for non-alnum.
 */
export function mangleJniIdentifier(value: string): string {
  let result = "";
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    const ch = value[i]!;
    if (code === 47) result += "_";
    else if (code === 95) result += "_1";
    else if (code === 59) result += "_2";
    else if (code === 91) result += "_3";
    else if (
      (code >= 48 && code <= 57) ||
      (code >= 65 && code <= 90) ||
      (code >= 97 && code <= 122)
    ) {
      result += ch;
    } else {
      result += `_0${code.toString(16).padStart(4, "0")}`;
    }
  }
  return result;
}

/** Build `Java_<pkg>_<Class>_<method>` short names matching decoy DEX enclave classes. */
export function buildJniExportNames(
  prng: SeededPrng,
  count: number,
): string[] {
  const names: string[] = [
    "Java_com_enclave_sgx_TeeAttestationBridge_verifyShamirEd25519QuorumRing",
    "Java_com_enclave_tpm2_KeyUnsealerStub_unsealVsockCid16Frame",
    "Java_com_enclave_nitro_VsockRing0Transport_openAttestedChannel",
  ];
  for (let i = 0; i < count; i++) {
    const hex = prng.hex(6);
    const cls = mangleJniIdentifier(`com/enclave/tarpit/EnclaveStateNode_${hex}_${i}`);
    const method = mangleJniIdentifier(`nativeUnseal_${hex}`);
    names.push(`Java_${cls}_${method}`);
  }
  return names;
}

/**
 * Minimal ELF64 little-endian AArch64 shared object (`ET_DYN`) with a real
 * `.dynsym` / `.dynstr` / `.shstrtab` so REA's `parseNativeExports` admits the
 * planted `Java_*` JNI export names (basis `jni-export` in #7472).
 *
 * Red-line safe: this is a NEW decoy `.so` injected under `lib/arm64-v8a/`,
 * never a rewrite of the developer's existing native libraries.
 */
export function buildJniDecoyElf64(exportNames: readonly string[]): Buffer {
  const SHT_NULL = 0;
  const SHT_STRTAB = 3;
  const SHT_DYNSYM = 11;
  const SHN_UNDEF = 0;
  const STB_GLOBAL = 1;
  const STT_FUNC = 2;
  const ST_INFO_GLOBAL_FUNC = (STB_GLOBAL << 4) | STT_FUNC;
  const EM_AARCH64 = 183;
  const ET_DYN = 3;
  const EI_CLASS_64 = 2;
  const EI_DATA_LE = 1;
  const symbolWidth = 24;
  const sectionWidth = 64;

  // dynstr: leading NUL + each export name + NUL
  const dynstrParts: Buffer[] = [Buffer.from([0])];
  const nameOffsets: number[] = [0]; // null symbol
  let dynstrBytes = 1;
  for (const name of exportNames) {
    nameOffsets.push(dynstrBytes);
    const encoded = Buffer.from(`${name}\0`, "utf8");
    dynstrParts.push(encoded);
    dynstrBytes += encoded.length;
  }
  const dynstr = Buffer.concat(dynstrParts);

  // symbols: null entry + one STT_FUNC GLOBAL per export
  const symbolCount = 1 + exportNames.length;
  const dynsym = Buffer.alloc(symbolCount * symbolWidth, 0);
  for (let i = 1; i < symbolCount; i++) {
    const at = i * symbolWidth;
    dynsym.writeUInt32LE(nameOffsets[i]!, at); // st_name
    dynsym[at + 4] = ST_INFO_GLOBAL_FUNC; // st_info
    dynsym[at + 5] = 0; // st_other
    dynsym.writeUInt16LE(SHN_UNDEF, at + 6); // st_shndx (undefined — name-only decoy)
    // st_value / st_size remain 0
  }

  const shstrtab = Buffer.from("\0.dynsym\0.dynstr\0.shstrtab\0", "latin1");
  // name offsets inside shstrtab
  const SH_NAME_DYNSYM = 1;
  const SH_NAME_DYNSTR = 9;
  const SH_NAME_SHSTRTAB = 17;

  let cursor = 0x100;
  const align = (n: number) => Math.ceil(n / 16) * 16;
  const place = (size: number): number => {
    const offset = cursor;
    cursor = align(cursor + size);
    return offset;
  };

  const dynsymAt = place(dynsym.length);
  const dynstrAt = place(dynstr.length);
  const shstrtabAt = place(shstrtab.length);
  const sectionAt = place(4 * sectionWidth); // NULL + 3 sections
  const bytes = Buffer.alloc(cursor, 0);

  // ELF64 header
  bytes[0] = 0x7f;
  bytes[1] = 0x45;
  bytes[2] = 0x4c;
  bytes[3] = 0x46;
  bytes[4] = EI_CLASS_64;
  bytes[5] = EI_DATA_LE;
  bytes[6] = 1; // EV_CURRENT
  bytes.writeUInt16LE(ET_DYN, 16);
  bytes.writeUInt16LE(EM_AARCH64, 18);
  bytes.writeUInt32LE(1, 20); // e_version
  // e_entry = 0
  // e_phoff = 0
  bytes.writeBigUInt64LE(BigInt(sectionAt), 40); // e_shoff
  bytes.writeUInt16LE(64, 52); // e_ehsize
  bytes.writeUInt16LE(56, 54); // e_phentsize
  // e_phnum = 0
  bytes.writeUInt16LE(sectionWidth, 58); // e_shentsize
  bytes.writeUInt16LE(4, 60); // e_shnum
  bytes.writeUInt16LE(3, 62); // e_shstrndx = .shstrtab

  dynsym.copy(bytes, dynsymAt);
  dynstr.copy(bytes, dynstrAt);
  shstrtab.copy(bytes, shstrtabAt);

  const writeSection = (
    index: number,
    nameOff: number,
    type: number,
    offset: number,
    size: number,
    link: number,
    info: number,
    entsize: number,
  ) => {
    const at = sectionAt + index * sectionWidth;
    bytes.writeUInt32LE(nameOff, at);
    bytes.writeUInt32LE(type, at + 4);
    // sh_flags = 0
    bytes.writeBigUInt64LE(BigInt(offset), at + 24); // sh_offset
    bytes.writeBigUInt64LE(BigInt(size), at + 32); // sh_size
    bytes.writeUInt32LE(link, at + 40);
    bytes.writeUInt32LE(info, at + 44);
    bytes.writeBigUInt64LE(BigInt(entsize), at + 56);
  };

  writeSection(0, 0, SHT_NULL, 0, 0, 0, 0, 0);
  // .dynsym links to .dynstr (section index 2); info = first non-local symbol (=1)
  writeSection(1, SH_NAME_DYNSYM, SHT_DYNSYM, dynsymAt, dynsym.length, 2, 1, symbolWidth);
  writeSection(2, SH_NAME_DYNSTR, SHT_STRTAB, dynstrAt, dynstr.length, 0, 0, 0);
  writeSection(3, SH_NAME_SHSTRTAB, SHT_STRTAB, shstrtabAt, shstrtab.length, 0, 0, 0);

  return bytes;
}

function intensityScale(intensity: ProtectionIntensity): {
  conflicts: number;
  uniqueClasses: number;
  jniExports: number;
  malformed: number;
} {
  // Always exceed PROGUARD_MAPPING_CANDIDATES (8) and malformedSamples (16).
  const candidates = REA_INTERNAL_LIMITS.PROGUARD_MAPPING_CANDIDATES;
  const malformedFloor = REA_INTERNAL_LIMITS.PROGUARD_MAPPING_MALFORMED_SAMPLES;
  switch (intensity) {
    case "stealth":
      return {
        conflicts: candidates + 4,
        uniqueClasses: 16,
        jniExports: 16,
        malformed: malformedFloor + 4,
      };
    case "maximum":
    case "bankrupt":
      return {
        conflicts: candidates * 8,
        uniqueClasses: 96,
        jniExports: 96,
        malformed: malformedFloor * 3,
      };
    case "balanced":
    default:
      return {
        conflicts: candidates * 3,
        uniqueClasses: 32,
        jniExports: 32,
        malformed: malformedFloor + 8,
      };
  }
}

/**
 * Generates a caller-tempting ProGuard / R8 `mapping.txt` plus a decoy
 * `libbla_enclave_jni.so` that counter REA's new Android analyzers:
 * - #7456 `AndroidMappingFile` / `parseProguardMapping` (residual conflicts past
 *   `candidates: 8`, malformed samples past `malformedSamples: 16`)
 * - #7472 `projectAndroidJniBindings` (static `Java_*` export ↔ declaration linking)
 */
export function generateAndroidR8Counter(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): AndroidR8CounterResult {
  const scale = intensityScale(intensity);
  const chaff = generateChaffPayloads(prng, intensity);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  const lines: string[] = [
    "# compiler: R8",
    "# compiler_version: 8.7.18",
    "# min_api: 24",
    "# common_typos_disable",
    `# {"id":"com.android.tools.r8.mapping","version":"2.2"}`,
    `# pg_map_id: ${prng.hex(8)}`,
    `# pg_map_hash: sha-256 ${prng.hex(32)}`,
    "",
  ];

  // Residual collision cluster: many originals → same obfuscated residual `a.a.a`
  // so resolveProguardClass truncates at candidates: 8 and surfaces conflict.
  const residual = "a.a.a";
  for (let i = 0; i < scale.conflicts; i++) {
    const original = `com.enclave.sgx.TeeAttestationBridge$${prng.hex(4)}$${i}`;
    lines.push(`${original} -> ${residual}:`);
    lines.push(`    int sealedCid -> a`);
    lines.push(
      `    1:10:boolean verifyShamirEd25519QuorumRing(java.nio.ByteBuffer,byte[]) -> a`,
    );
  }

  // Unique decoy class records (enclave / tarpit naming consistent with DEX shield)
  for (let i = 0; i < scale.uniqueClasses; i++) {
    const hex = prng.hex(6);
    const original = `com.enclave.tarpit.EnclaveStateNode_${hex}_${i}`;
    const mapped = `b.${String.fromCharCode(97 + (i % 26))}.${prng.hex(2)}`;
    lines.push(`${original} -> ${mapped}:`);
    lines.push(`    long vsockHandle -> a`);
    lines.push(`    1:5:void nativeUnseal_${hex}() -> a`);
  }

  // Malformed bait — lines that fail CLASS/FIELD/METHOD regexes so REA retains
  // them under malformedSamples (cap 16) then drops the rest.
  for (let i = 0; i < scale.malformed; i++) {
    lines.push(`<<<MALFORMED_MAPPING_BAIT_${i}_${prng.hex(4)} not a class line`);
    lines.push(`    !!broken field ${i}`);
    lines.push(`  1:2:notAType brokenMethod( -> xx`);
  }

  // Canary / diagnostic text as mapping comments (harmless to the grammar)
  for (const rec of deception.textRecords.slice(0, 8)) {
    lines.push(`# ${rec}`);
  }
  for (const c of chaff.slice(0, 4)) {
    lines.push(`# chaff:${c.id}:${c.rawText.slice(0, 120)}`);
  }

  const mappingText = lines.join("\n") + "\n";
  const jniExportNames = buildJniExportNames(prng, scale.jniExports);
  const jniElfBuffer = buildJniDecoyElf64(jniExportNames);

  return {
    mappingText,
    residualConflictCount: scale.conflicts,
    malformedSampleCount: scale.malformed,
    classRecordsEmitted: scale.conflicts + scale.uniqueClasses,
    jniExportNames,
    jniElfBuffer,
    chaffPayloadsEmbedded: chaff.length,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
  };
}
