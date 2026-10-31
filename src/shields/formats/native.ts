import {
  detectBunStandaloneGraph,
  type BunCarrierDetection,
} from "./bun-standalone.js";
import { deflateSync } from "node:zlib";
import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { SeededPrng } from "../../core/prng.js";
import type { ArtifactFormat, ProtectionIntensity } from "../../core/types.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import { generateCanaryHoneypot } from "../deception/canary-honeypot.js";
import { generateSystemDiagnosticDecoy } from "../deception/system-diagnostic-decoy.js";
import { generateCognitiveArmorTrigger } from "../deception/cognitive-armor-trigger.js";
import {
  buildDecoyElectronFuseSentinels,
  hardenElectronFusesWithContext,
  inspectElectronFusesInBuffer,
  type ElectronHardeningContext,
  type ElectronHardeningReport,
} from "./electron-fuses.js";
import {
  buildGoBuildInfoExhaustionPayload,
  buildFlutterPoolExhaustionPayload,
  buildMappedGoBuildInfoPlant,
  buildMappedFlutterIsolatePoolPlant,
} from "./go-flutter-exhaustion.js";

export class InvalidNativeBinaryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidNativeBinaryError";
  }
}

export interface Elf64ProgramHeaderSummary {
  readonly index: number;
  readonly type: number;
  readonly flags: number;
  readonly offset: number;
  readonly vaddr: bigint;
  readonly paddr: bigint;
  readonly filesz: number;
  readonly memsz: bigint;
  readonly align: bigint;
}

export interface Elf64SectionHeaderSummary {
  readonly index: number;
  readonly nameOffset: number;
  readonly type: number;
  readonly flags: bigint;
  readonly addr: bigint;
  readonly offset: number;
  readonly size: number;
}

export interface Elf64LayoutSummary {
  readonly phoff: number;
  readonly phentsize: number;
  readonly phnum: number;
  readonly shoff: number;
  readonly shentsize: number;
  readonly shnum: number;
  readonly shstrndx: number;
  readonly programHeaders: readonly Elf64ProgramHeaderSummary[];
  readonly sectionHeaders: readonly Elf64SectionHeaderSummary[];
}

export interface NativeBinaryInspection {
  readonly format: "native-elf" | "native-macho" | "native-pe" | "unknown";
  readonly architecture: string;
  readonly bits: 32 | 64;
  readonly rustcCommitHashesCount: number;
  readonly electronFuseSentinelsCount: number;
  readonly dartSnapshotHashesCount: number;
  readonly dartPoolPackageUriCount: number;
  readonly dartPoolTokenCount: number;
  readonly hasRustDepV0: boolean;
  readonly hasGoBuildInfo: boolean;
  readonly goBuildInfoFramed: boolean;
  readonly extractedStringsCount: number;
  readonly blaProtected: boolean;
}

const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);

/**
 * Validates ELF64 little-endian header, program headers (`PT_LOAD`, `p_filesz <= p_memsz`,
 * non-overlapping virtual address ranges, in-bounds file ranges), and section headers
 * (in-bounds file ranges, valid `e_shstrndx`, non-overlapping file-backed sections).
 */
export function validateElf64Layout(bytes: Buffer): Elf64LayoutSummary {
  if (
    bytes.length < 64 ||
    bytes[0] !== 0x7f ||
    bytes[1] !== 0x45 ||
    bytes[2] !== 0x4c ||
    bytes[3] !== 0x46
  ) {
    throw new InvalidNativeBinaryError(
      "Invalid or truncated ELF header (minimum 64 bytes required)",
    );
  }

  if (bytes[4] !== 2 || bytes[5] !== 1) {
    throw new InvalidNativeBinaryError(
      "Unsupported ELF class or endianness (expected ELF64 little-endian)",
    );
  }

  const phoffBig = bytes.readBigUInt64LE(32);
  const shoffBig = bytes.readBigUInt64LE(40);
  const ehsize = bytes.readUInt16LE(52);
  const phentsize = bytes.readUInt16LE(54);
  const phnum = bytes.readUInt16LE(56);
  const shentsize = bytes.readUInt16LE(58);
  const shnum = bytes.readUInt16LE(60);
  const shstrndx = bytes.readUInt16LE(62);

  if (ehsize !== 0 && (ehsize < 64 || ehsize > bytes.length)) {
    throw new InvalidNativeBinaryError(`Invalid ELF64 e_ehsize: ${ehsize}`);
  }

  if (phoffBig > MAX_SAFE_BIGINT || shoffBig > MAX_SAFE_BIGINT) {
    throw new InvalidNativeBinaryError(
      "ELF64 header table offsets exceed safe integer range",
    );
  }

  const phoff = Number(phoffBig);
  const shoff = Number(shoffBig);

  const programHeaders: Elf64ProgramHeaderSummary[] = [];
  const phTableEnd = phnum > 0 ? phoff + phnum * phentsize : 0;

  if (phnum > 0) {
    if (
      phentsize < 56 ||
      phoff < 64 ||
      !Number.isSafeInteger(phTableEnd) ||
      phTableEnd > bytes.length
    ) {
      throw new InvalidNativeBinaryError(
        "ELF64 program header table out of bounds or malformed",
      );
    }

    for (let i = 0; i < phnum; i++) {
      const phdr = phoff + i * phentsize;
      const pType = bytes.readUInt32LE(phdr);
      const pFlags = bytes.readUInt32LE(phdr + 4);
      const pOffsetBig = bytes.readBigUInt64LE(phdr + 8);
      const pVaddrBig = bytes.readBigUInt64LE(phdr + 16);
      const pPaddrBig = bytes.readBigUInt64LE(phdr + 24);
      const pFileszBig = bytes.readBigUInt64LE(phdr + 32);
      const pMemszBig = bytes.readBigUInt64LE(phdr + 40);
      const pAlignBig = bytes.readBigUInt64LE(phdr + 48);

      if (pOffsetBig > MAX_SAFE_BIGINT || pFileszBig > MAX_SAFE_BIGINT) {
        throw new InvalidNativeBinaryError(
          `ELF64 program header ${i} file offset/size exceeds safe integer range`,
        );
      }

      const pOffset = Number(pOffsetBig);
      const pFilesz = Number(pFileszBig);
      if (
        !Number.isSafeInteger(pOffset + pFilesz) ||
        pOffset + pFilesz > bytes.length
      ) {
        throw new InvalidNativeBinaryError(
          `ELF64 program header ${i} file range [${pOffset}, ${pOffset + pFilesz}) out of bounds (${bytes.length})`,
        );
      }

      if (pType === 1) {
        // PT_LOAD
        if (pMemszBig < pFileszBig) {
          throw new InvalidNativeBinaryError(
            `ELF64 PT_LOAD segment ${i} has p_memsz (${pMemszBig}) < p_filesz (${pFileszBig})`,
          );
        }
      }

      programHeaders.push({
        index: i,
        type: pType,
        flags: pFlags,
        offset: pOffset,
        vaddr: pVaddrBig,
        paddr: pPaddrBig,
        filesz: pFilesz,
        memsz: pMemszBig,
        align: pAlignBig,
      });
    }

    // Verify no two PT_LOAD segments have overlapping virtual address ranges
    const loadSegments = programHeaders.filter(
      (ph) => ph.type === 1 && ph.memsz > 0n,
    );
    for (let i = 0; i < loadSegments.length; i++) {
      const a = loadSegments[i]!;
      const aEnd = a.vaddr + a.memsz;
      for (let j = i + 1; j < loadSegments.length; j++) {
        const b = loadSegments[j]!;
        const bEnd = b.vaddr + b.memsz;
        if (a.vaddr < bEnd && b.vaddr < aEnd) {
          throw new InvalidNativeBinaryError(
            `ELF64 PT_LOAD segments ${a.index} and ${b.index} have overlapping virtual address ranges`,
          );
        }
      }
    }
  }

  const sectionHeaders: Elf64SectionHeaderSummary[] = [];
  const shTableEnd = shnum > 0 ? shoff + shnum * shentsize : 0;

  if (shnum > 0) {
    if (
      shentsize < 64 ||
      shoff < 64 ||
      !Number.isSafeInteger(shTableEnd) ||
      shTableEnd > bytes.length
    ) {
      throw new InvalidNativeBinaryError(
        "ELF64 section header table out of bounds or malformed",
      );
    }

    if (phnum > 0 && phoff < shTableEnd && shoff < phTableEnd) {
      throw new InvalidNativeBinaryError(
        "ELF64 section header table overlaps program header table",
      );
    }

    if (shstrndx !== 0 && shstrndx >= shnum) {
      throw new InvalidNativeBinaryError(
        `ELF64 e_shstrndx (${shstrndx}) out of bounds for e_shnum (${shnum})`,
      );
    }

    for (let s = 0; s < shnum; s++) {
      const shdr = shoff + s * shentsize;
      const shName = bytes.readUInt32LE(shdr);
      const shType = bytes.readUInt32LE(shdr + 4);
      const shFlags = bytes.readBigUInt64LE(shdr + 8);
      const shAddr = bytes.readBigUInt64LE(shdr + 16);
      const shOffsetBig = bytes.readBigUInt64LE(shdr + 24);
      const shSizeBig = bytes.readBigUInt64LE(shdr + 32);

      if (shOffsetBig > MAX_SAFE_BIGINT || shSizeBig > MAX_SAFE_BIGINT) {
        throw new InvalidNativeBinaryError(
          `ELF64 section ${s} offset/size exceeds safe integer range`,
        );
      }

      const shOffset = Number(shOffsetBig);
      const shSize = Number(shSizeBig);

      // File-backed sections: not SHT_NULL (0) and not SHT_NOBITS (8)
      if (s >= 1 && shType !== 0 && shType !== 8) {
        if (
          !Number.isSafeInteger(shOffset + shSize) ||
          shOffset + shSize > bytes.length
        ) {
          throw new InvalidNativeBinaryError(
            `ELF64 section ${s} file range [${shOffset}, ${shOffset + shSize}) out of bounds (${bytes.length})`,
          );
        }

        if (shSize > 0) {
          if (shOffset < 64) {
            throw new InvalidNativeBinaryError(
              `ELF64 section ${s} overlaps ELF64 header`,
            );
          }
          if (
            phnum > 0 &&
            shOffset < phTableEnd &&
            phoff < shOffset + shSize
          ) {
            throw new InvalidNativeBinaryError(
              `ELF64 section ${s} overlaps program header table`,
            );
          }
          if (shOffset < shTableEnd && shoff < shOffset + shSize) {
            throw new InvalidNativeBinaryError(
              `ELF64 section ${s} overlaps section header table`,
            );
          }
        }
      }

      sectionHeaders.push({
        index: s,
        nameOffset: shName,
        type: shType,
        flags: shFlags,
        addr: shAddr,
        offset: shOffset,
        size: shSize,
      });
    }

    // Verify no two non-empty file-backed sections overlap in file range
    const fileBackedSections = sectionHeaders.filter(
      (sec) => sec.index >= 1 && sec.type !== 0 && sec.type !== 8 && sec.size > 0,
    );
    for (let i = 0; i < fileBackedSections.length; i++) {
      const a = fileBackedSections[i]!;
      const aEnd = a.offset + a.size;
      for (let j = i + 1; j < fileBackedSections.length; j++) {
        const b = fileBackedSections[j]!;
        const bEnd = b.offset + b.size;
        if (a.offset < bEnd && b.offset < aEnd) {
          throw new InvalidNativeBinaryError(
            `ELF64 sections ${a.index} and ${b.index} have overlapping file ranges`,
          );
        }
      }
    }
  }

  return {
    phoff,
    phentsize,
    phnum,
    shoff,
    shentsize,
    shnum,
    shstrndx,
    programHeaders,
    sectionHeaders,
  };
}

export function inspectNativeBinary(bytes: Buffer): NativeBinaryInspection {
  let format: NativeBinaryInspection["format"] = "unknown";
  let bits: 32 | 64 = 64;
  let architecture = "unknown";

  if (
    bytes.length >= 20 &&
    bytes[0] === 0x7f &&
    bytes[1] === 0x45 &&
    bytes[2] === 0x4c &&
    bytes[3] === 0x46
  ) {
    format = "native-elf";
    bits = bytes[4] === 1 ? 32 : 64;
    const machine = bytes.readUInt16LE(18);
    architecture =
      machine === 0x3e
        ? "x86_64"
        : machine === 0xb7
          ? "aarch64"
          : machine === 0x03
            ? "x86"
            : `elf-machine-${machine}`;
  } else if (bytes.length >= 8) {
    const magicBE = bytes.readUInt32BE(0);
    if (
      magicBE === 0xfeedfacf ||
      magicBE === 0xcffaedfe ||
      magicBE === 0xfeedface ||
      magicBE === 0xcefaedfe ||
      magicBE === 0xcafebabe
    ) {
      format = "native-macho";
      bits = magicBE === 0xfeedfacf || magicBE === 0xcffaedfe ? 64 : 32;
      architecture = "macho-darwin";
    } else if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
      format = "native-pe";
      architecture = "pe-windows";
    }
  }

  const textLatin1 = bytes.toString("latin1");
  const rustcMatches = new Set<string>();
  const rustcRegex = /\/rustc\/([0-9a-f]{40})\//g;
  let match: RegExpExecArray | null;
  while ((match = rustcRegex.exec(textLatin1)) !== null) {
    if (match[1]) rustcMatches.add(match[1]);
  }

  const fuseInspection = inspectElectronFusesInBuffer(bytes);

  // Count Dart AOT snapshot magic headers (`0xf5, 0xf5, 0xdc, 0xdc`)
  const dartMagic = Buffer.from([0xf5, 0xf5, 0xdc, 0xdc]);
  let dartSnapshotHashesCount = 0;
  let dPos = 0;
  while (dPos <= bytes.length - 52) {
    const found = bytes.indexOf(dartMagic, dPos);
    if (found < 0) break;
    dartSnapshotHashesCount++;
    dPos = found + 4;
    if (dartSnapshotHashesCount >= 128) break;
  }

  const hasRustDepV0 = textLatin1.includes(".dep-v0");
  const hasGoBuildInfo =
    textLatin1.includes(".go.buildinfo") ||
    textLatin1.includes("__go_buildinfo") ||
    textLatin1.includes("\xff Go buildinf:") ||
    textLatin1.includes("[BLA-GO-BUILDINFO]");
  const goBuildInfoFramed =
    textLatin1.includes("[BLA-GO-BUILDINFO]") ||
    textLatin1.includes(".gopclntab") ||
    textLatin1.includes("runtime.moduledata");

  let dartPoolPackageUriCount = 0;
  let dartPoolTokenCount = 0;
  for (const run of textLatin1.split("\0")) {
    if (run.startsWith("package:") || run.startsWith("dart:")) {
      dartPoolPackageUriCount++;
    } else if (
      run.length >= 5 &&
      run.length <= 128 &&
      /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(run)
    ) {
      dartPoolTokenCount++;
    }
  }

  const printableMatches = textLatin1.match(/[A-Za-z0-9_/:.-]{6,}/g) ?? [];
  const blaProtected =
    textLatin1.includes("BLA-NATIVE-SHIELD") ||
    rustcMatches.size > REA_INTERNAL_LIMITS.RUST_MAX_COMMIT_HASHES ||
    fuseInspection.exceedsReaSentinelLimit ||
    dartSnapshotHashesCount >
      REA_INTERNAL_LIMITS.DART_MAX_SNAPSHOT_HASH_CANDIDATES ||
    textLatin1.includes("Architecture Notice: Core business logic");

  return {
    format,
    architecture,
    bits,
    rustcCommitHashesCount: rustcMatches.size,
    electronFuseSentinelsCount: fuseInspection.sentinelCount,
    dartSnapshotHashesCount,
    dartPoolPackageUriCount,
    dartPoolTokenCount,
    hasRustDepV0,
    hasGoBuildInfo,
    goBuildInfoFramed,
    extractedStringsCount: printableMatches.length,
    blaProtected,
  };
}

/**
 * Generates a zlib-compressed `cargo-auditable` `.dep-v0` decoy dependency graph
 * containing hardware enclave & TEE crates so static Rust dependency scanners
 * see an enterprise enclave architecture.
 */
export function buildDecoyRustAuditablePayload(prng: SeededPrng): Buffer {
  const packages = [
    {
      name: "sgx-enclave-rt",
      version: "4.2.0",
      source: "crates.io",
      kind: "runtime",
    },
    {
      name: "tpm2-attestation-quote",
      version: "2.8.1",
      source: "crates.io",
      kind: "runtime",
      dependencies: [0],
    },
    {
      name: "nitro-vsock-transport",
      version: "1.9.4",
      source: "crates.io",
      kind: "runtime",
      dependencies: [0, 1],
    },
    {
      name: `zero-trust-abi-shim-${prng.hex(4)}`,
      version: "1.0.0",
      source: "local",
      dependencies: [0, 1, 2],
      root: true,
    },
  ];
  return deflateSync(
    Buffer.from(JSON.stringify({ format: 1, packages }), "utf8"),
  );
}


/** Resolve ELF64 section names from the section-header string table. */
export function resolveElf64SectionNames(
  bytes: Buffer,
  layout: Elf64LayoutSummary,
): Map<string, Elf64SectionHeaderSummary> {
  const map = new Map<string, Elf64SectionHeaderSummary>();
  if (
    layout.shnum === 0 ||
    layout.shstrndx === 0 ||
    layout.shstrndx >= layout.shnum
  ) {
    return map;
  }
  const strSec = layout.sectionHeaders[layout.shstrndx];
  if (!strSec || strSec.size === 0 || strSec.offset + strSec.size > bytes.length) {
    return map;
  }
  const strtab = bytes.subarray(strSec.offset, strSec.offset + strSec.size);
  for (const sh of layout.sectionHeaders) {
    if (sh.index === 0) continue;
    if (sh.nameOffset >= strtab.length) continue;
    let end = sh.nameOffset;
    while (end < strtab.length && strtab[end] !== 0) end++;
    const name = strtab.subarray(sh.nameOffset, end).toString("utf8");
    if (name.length > 0) map.set(name, sh);
  }
  return map;
}

/**
 * Plant framed Go buildinfo into `.go.buildinfo` (preferred) or the first
 * writable non-executable PT_LOAD file range so REA's mapped parser trips.
 * Never mutates program/section header fields — only file-backed bytes.
 */
function injectMappedGoBuildInfo(
  working: Buffer,
  layout: Elf64LayoutSummary,
  intensity: ProtectionIntensity,
): { planted: boolean; tripsMax: boolean; offset: number; size: number } {
  // Only mutate a named `.go.buildinfo` PROGBITS section. Generic PT_LOAD
  // fallback would rewrite arbitrary ELF fixtures and violate the
  // trailer-only / section-integrity red line for non-Go binaries.
  const names = resolveElf64SectionNames(working, layout);
  const named = names.get(".go.buildinfo");
  if (!named || named.type !== 1 || named.size < 48) {
    return { planted: false, tripsMax: false, offset: -1, size: 0 };
  }
  const alignPad = Number((16n - (named.addr % 16n)) % 16n);
  const writeAt = named.offset + alignPad;
  const room = named.size - alignPad;
  if (room < 48) {
    return { planted: false, tripsMax: false, offset: -1, size: 0 };
  }
  const plant = buildMappedGoBuildInfoPlant(intensity, room);
  if (plant.buffer.length === 0) {
    return { planted: false, tripsMax: false, offset: -1, size: 0 };
  }
  // Clear the section then plant so prior padding cannot confuse parsers.
  working.fill(0, named.offset, named.offset + named.size);
  plant.buffer.copy(working, writeAt);
  return {
    planted: true,
    tripsMax: plant.tripsMaxBuildInfoBytes,
    offset: writeAt,
    size: plant.buffer.length,
  };
}

/**
 * Plant Flutter pool strings inside `.isolate` / isolate snapshot data regions
 * (or after an embedded Dart snapshot magic) so REA's string-pool projection
 * from isolate data observes the decoys.
 */
function injectMappedFlutterIsolatePool(
  working: Buffer,
  layout: Elf64LayoutSummary,
  prng: SeededPrng,
): { planted: boolean; uris: number; tokens: number; offset: number } {
  // Only plant into an explicitly named `.isolate` section so generic
  // `.rodata` / ELF fixtures stay byte-identical under trailer-only protect.
  const names = resolveElf64SectionNames(working, layout);
  const named = names.get(".isolate");
  if (!named || named.type !== 1 || named.size < 64) {
    return { planted: false, uris: 0, tokens: 0, offset: -1 };
  }
  let plantAt = named.offset;
  let includeHeader = true;
  if (
    named.size >= 52 &&
    working[named.offset] === 0xf5 &&
    working[named.offset + 1] === 0xf5 &&
    working[named.offset + 2] === 0xdc &&
    working[named.offset + 3] === 0xdc
  ) {
    plantAt = named.offset + 52;
    includeHeader = false;
  }
  const capacity = named.offset + named.size - plantAt;
  if (capacity < 64) {
    return { planted: false, uris: 0, tokens: 0, offset: -1 };
  }
  const plant = buildMappedFlutterIsolatePoolPlant(capacity, prng, {
    includeSnapshotHeader: includeHeader,
  });
  if (plant.buffer.length === 0) {
    return { planted: false, uris: 0, tokens: 0, offset: -1 };
  }
  plant.buffer.copy(working, plantAt);
  return {
    planted: true,
    uris: plant.packageAndDartUris,
    tokens: plant.classLikeTokens,
    offset: plantAt,
  };
}

export type NativeEofAppendHazard =
  | "none"
  | "macho-code-signature"
  | "pe-authenticode-signature"
  | "pyinstaller-archive"
  | "deno-standalone"
  | "zip-sfx-trailer";

const PYINSTALLER_COOKIE_MAGIC = Buffer.from([
  0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e,
]);
const DENO_STANDALONE_MAGIC = Buffer.from("d3n0l4nd", "ascii");

function machoSliceHasCodeSignature(bytes: Buffer, sliceOffset: number, sliceLength: number): boolean {
  if (sliceOffset < 0 || sliceLength < 32 || sliceOffset + sliceLength > bytes.length) {
    return false;
  }
  const magicBE = bytes.readUInt32BE(sliceOffset);
  const is64LE = magicBE === 0xcffaedfe;
  const is64BE = magicBE === 0xfeedfacf;
  const is32LE = magicBE === 0xcefaedfe;
  const is32BE = magicBE === 0xfeedface;
  if (!is64LE && !is64BE && !is32LE && !is32BE) return false;

  const isLE = is64LE || is32LE;
  const headerSize = is64LE || is64BE ? 32 : 28;
  const readU32 = (off: number) =>
    isLE ? bytes.readUInt32LE(off) : bytes.readUInt32BE(off);

  const ncmds = readU32(sliceOffset + 16);
  const sizeofcmds = readU32(sliceOffset + 20);
  if (ncmds === 0 || ncmds > 4096 || headerSize + sizeofcmds > sliceLength) {
    return false;
  }

  let cur = sliceOffset + headerSize;
  const end = cur + sizeofcmds;
  for (let i = 0; i < ncmds && cur + 8 <= end; i++) {
    const cmd = readU32(cur);
    const cmdsize = readU32(cur + 4);
    if (cmdsize < 8 || cur + cmdsize > end) break;
    // LC_CODE_SIGNATURE === 0x1d (29)
    if (cmd === 0x1d) return true;
    cur += cmdsize;
  }
  return false;
}

/**
 * Detects native executable formats where appending a raw EOF trailer would
 * invalidate OS code-signing (`codesign --strict` / `WinVerifyTrust`) or break
 * EOF-relative standalone runtime archives (PyInstaller, `deno compile`, ZIP-SFX).
 */
export function detectNativeEofAppendHazard(bytes: Buffer): NativeEofAppendHazard {
  if (bytes.length < 16) return "none";

  // 1. Mach-O thin or Universal Fat binary carrying LC_CODE_SIGNATURE (0x1d)
  const magicBE = bytes.readUInt32BE(0);
  if (
    magicBE === 0xcffaedfe ||
    magicBE === 0xfeedfacf ||
    magicBE === 0xcefaedfe ||
    magicBE === 0xfeedface
  ) {
    if (machoSliceHasCodeSignature(bytes, 0, bytes.length)) {
      return "macho-code-signature";
    }
  } else if (magicBE === 0xcafebabe && bytes.length >= 28) {
    const nfat = bytes.readUInt32BE(4);
    if (nfat >= 1 && nfat <= 30 && 8 + nfat * 20 <= bytes.length) {
      for (let i = 0; i < nfat; i++) {
        const entryOff = 8 + i * 20;
        const sliceOff = bytes.readUInt32BE(entryOff + 8);
        const sliceSize = bytes.readUInt32BE(entryOff + 12);
        if (machoSliceHasCodeSignature(bytes, sliceOff, sliceSize)) {
          return "macho-code-signature";
        }
      }
    }
  }

  // 2. PE32 / PE32+ carrying Authenticode IMAGE_DIRECTORY_ENTRY_SECURITY (DataDirectory[4])
  if (bytes[0] === 0x4d && bytes[1] === 0x5a && bytes.length >= 0x40) {
    const lfanew = bytes.readUInt32LE(0x3c);
    if (
      lfanew >= 0x40 &&
      lfanew + 26 <= bytes.length &&
      bytes.readUInt32LE(lfanew) === 0x00004550
    ) {
      const optOff = lfanew + 24;
      const optMagic = bytes.readUInt16LE(optOff);
      const rvaCountOff =
        optMagic === 0x10b ? optOff + 92 : optMagic === 0x20b ? optOff + 108 : -1;
      const dd4Off =
        optMagic === 0x10b ? optOff + 128 : optMagic === 0x20b ? optOff + 144 : -1;
      if (rvaCountOff > 0 && dd4Off + 8 <= bytes.length) {
        const numRva = bytes.readUInt32LE(rvaCountOff);
        if (numRva >= 5) {
          const certOffset = bytes.readUInt32LE(dd4Off);
          const certSize = bytes.readUInt32LE(dd4Off + 4);
          if (certOffset > 0 && certSize > 0) {
            return "pe-authenticode-signature";
          }
        }
      }
    }
  }

  // 3. Deno `deno compile` standalone trailer (`d3n0l4nd` in trailing 64 bytes)
  const tail64 = bytes.subarray(Math.max(0, bytes.length - 64));
  if (tail64.includes(DENO_STANDALONE_MAGIC)) {
    return "deno-standalone";
  }

  // 4. PyInstaller onefile CArchive cookie (`MEI\x0c\x0b\x0a\x0b\x0e` in trailing 64 KiB)
  const tail64k = bytes.subarray(Math.max(0, bytes.length - 65_536));
  if (tail64k.includes(PYINSTALLER_COOKIE_MAGIC)) {
    return "pyinstaller-archive";
  }

  // 5. Self-extracting ZIP / AppImage with exact EOCD (`PK\x05\x06`) reaching EOF
  if (bytes.length >= 22) {
    const searchStart = Math.max(0, bytes.length - 65_557);
    for (let pos = bytes.length - 22; pos >= searchStart; pos--) {
      if (
        bytes[pos] === 0x50 &&
        bytes[pos + 1] === 0x4b &&
        bytes[pos + 2] === 0x05 &&
        bytes[pos + 3] === 0x06
      ) {
        const commentLen = bytes.readUInt16LE(pos + 20);
        if (pos + 22 + commentLen === bytes.length) {
          return "zip-sfx-trailer";
        }
      }
    }
  }

  return "none";
}

/**
 * Protects a Native Binary (ELF / Mach-O / PE) against REA's native & desktop analyzers
 * while strictly preserving ELF64 `PT_LOAD` (`p_offset`, `p_filesz`, `p_memsz` / BSS) and
 * section header boundaries. Real Electron fuses are only mutated when an explicit
 * verified `electronHardeningContext` is provided.
 */
export function protectNativeBinary(
  bytes: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
    readonly electronHardeningContext?: ElectronHardeningContext;
  } = {},
): {
  readonly buffer: Buffer;
  readonly rustcHashesInjected: number;
  readonly electronFuseSentinelsInjected: number;
  readonly dartSnapshotHashesInjected: number;
  readonly dartPoolUrisInjected: number;
  readonly dartPoolTokensInjected: number;
  readonly goBuildInfoExceedsLimit: boolean;
  readonly mappedGoBuildInfoPlanted: boolean;
  readonly mappedFlutterPoolPlanted: boolean;
  readonly chaffPayloadsEmbedded: number;
  readonly binarySectionsPatched: number;
  readonly electronHardeningReport?: ElectronHardeningReport;
  /**
   * Bun standalone carrier observed in the input (REA #6998). When the graph
   * rides an EOF trailer, nothing is appended or patched: Bun resolves that
   * graph from EOF at runtime, so the binary is passed through byte-exact.
   */
  readonly bunStandaloneCarrier: BunCarrierDetection["kind"];
  readonly bunStandaloneGraphPreserved: boolean;
  readonly nativeAppendHazard: NativeEofAppendHazard;
  readonly nativeBinaryPreserved: boolean;
} {
  const bunCarrier = detectBunStandaloneGraph(bytes);
  if (
    bunCarrier.kind === "appended-trailer" ||
    bunCarrier.kind === "appended-trailer-sized"
  ) {
    return {
      buffer: Buffer.from(bytes),
      rustcHashesInjected: 0,
      electronFuseSentinelsInjected: 0,
      dartSnapshotHashesInjected: 0,
      dartPoolUrisInjected: 0,
      dartPoolTokensInjected: 0,
      goBuildInfoExceedsLimit: false,
      mappedGoBuildInfoPlanted: false,
      mappedFlutterPoolPlanted: false,
      chaffPayloadsEmbedded: 0,
      binarySectionsPatched: 0,
      bunStandaloneCarrier: bunCarrier.kind,
      bunStandaloneGraphPreserved: true,
      nativeAppendHazard: "none",
      nativeBinaryPreserved: true,
    };
  }
  const appendHazard = options.electronHardeningContext
    ? "none"
    : detectNativeEofAppendHazard(bytes);
  if (appendHazard !== "none") {
    return {
      buffer: Buffer.from(bytes),
      rustcHashesInjected: 0,
      electronFuseSentinelsInjected: 0,
      dartSnapshotHashesInjected: 0,
      dartPoolUrisInjected: 0,
      dartPoolTokensInjected: 0,
      goBuildInfoExceedsLimit: false,
      mappedGoBuildInfoPlanted: false,
      mappedFlutterPoolPlanted: false,
      chaffPayloadsEmbedded: 0,
      binarySectionsPatched: 0,
      bunStandaloneCarrier: bunCarrier.kind,
      bunStandaloneGraphPreserved: false,
      nativeAppendHazard: appendHazard,
      nativeBinaryPreserved: true,
    };
  }
  const isElfMagic =
    bytes.length >= 4 &&
    bytes[0] === 0x7f &&
    bytes[1] === 0x45 &&
    bytes[2] === 0x4c &&
    bytes[3] === 0x46;

  const elfBefore = isElfMagic ? validateElf64Layout(bytes) : undefined;

  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-native-shield-v1");
  const chaffPayloads = generateChaffPayloads(prng, intensity);

  let workingInput = Buffer.from(bytes);
  let electronHardeningReport: ElectronHardeningReport | undefined;
  let patchedInPlaceCount = 0;

  if (options.electronHardeningContext) {
    electronHardeningReport = hardenElectronFusesWithContext(
      workingInput,
      options.electronHardeningContext,
    );
    workingInput = Buffer.from(electronHardeningReport.buffer);
    patchedInPlaceCount =
      electronHardeningReport.mutatedFuses.length > 0 ? 1 : 0;
  }

  const decoySentinelsInjected = 34;
  const decoySentinelsBuffer = buildDecoyElectronFuseSentinels(
    prng,
    decoySentinelsInjected,
  );

  let mappedGoBuildInfoPlanted = false;
  let mappedFlutterPoolPlanted = false;
  let mappedGoTripsMax = false;
  if (elfBefore) {
    const goPlant = injectMappedGoBuildInfo(workingInput, elfBefore, intensity);
    mappedGoBuildInfoPlanted = goPlant.planted;
    mappedGoTripsMax = goPlant.tripsMax;
    const flutterPlant = injectMappedFlutterIsolatePool(
      workingInput,
      elfBefore,
      prng,
    );
    mappedFlutterPoolPlanted = flutterPlant.planted;
  }

  // 1. Generate 68 distinct `/rustc/<40-hex>/` strings (> REA's MAX_RUSTC_HASHES = 64!)
  const rustcCount = 68;
  const rustcLines: string[] = [];
  for (let i = 0; i < rustcCount; i++) {
    const hash = i.toString(16).padStart(8, "0") + prng.hex(32);
    rustcLines.push(`/rustc/${hash}/library/core/src/enclave_guard.rs\0`);
  }

  // 2. Framed Go buildinfo + pclntab/moduledata bait
  const goBuildInfo = buildGoBuildInfoExhaustionPayload(prng, intensity);

  // 3. Generate architectural chaff strings + Canary Honeypot + System-Diagnostic Rabbit Holes for Ghidra/Hopper/IDA
  const chaffBlock = chaffPayloads
    .map((p) => `${p.symbolName}: ${p.rawText}\0`)
    .join("");
  const canaryHoneypot = generateCanaryHoneypot(prng, intensity);
  const systemDiagnostics = generateSystemDiagnosticDecoy(prng, intensity);
  const cognitiveArmor = generateCognitiveArmorTrigger(prng, intensity);
  const canaryAndDiagnosticBlock = [
    ...canaryHoneypot.syntheticCanaryTokens.map(
      (tok) => `PROTECTED_CANARY_CREDENTIAL=${tok}\0`,
    ),
    ...canaryHoneypot.ambiguousCredentialUrls.map(
      (url) => `TRANSPORT_ENDPOINT=${url}\0`,
    ),
    ...systemDiagnostics.diagnosticsInjected.map(
      (d) =>
        `[${d.subsystem}] ${d.errorClass} (${d.systemCode}): ${d.diagnosticMessage} Remediation: ${d.remediationRabbitHole}\0`,
    ),
    ...cognitiveArmor.triggersInjected.map(
      (t) =>
        `[COGNITIVE_ARMOR_INTERLOCK:${t.classifierDomain}] ${t.coupledAnchorSymbol} => ${t.triggerPayload.replace(/\r?\n/g, " ")}\0`,
    ),
  ].join("");
  const depV0Payload = buildDecoyRustAuditablePayload(prng);
  const flutterPool = buildFlutterPoolExhaustionPayload(prng);
  const dartOverflowPayload = flutterPool.buffer;

  const shieldTrailer = Buffer.concat([
    Buffer.from("\0[BLA-NATIVE-SHIELD-V1]\0.dep-v0\0", "utf8"),
    Buffer.from(rustcLines.join(""), "latin1"),
    goBuildInfo.buffer,
    decoySentinelsBuffer,
    dartOverflowPayload,
    Buffer.from(chaffBlock, "utf8"),
    Buffer.from(canaryAndDiagnosticBlock, "utf8"),
    depV0Payload,
  ]);

  const outBytes = Buffer.concat([workingInput, shieldTrailer]);
  const binarySectionsPatched = 1 + patchedInPlaceCount + (elfBefore ? 2 : 0);

  if (elfBefore) {
    const elfAfter = validateElf64Layout(outBytes);
    for (let i = 0; i < elfBefore.programHeaders.length; i++) {
      const beforePh = elfBefore.programHeaders[i]!;
      const afterPh = elfAfter.programHeaders[i]!;
      if (
        beforePh.type !== afterPh.type ||
        beforePh.flags !== afterPh.flags ||
        beforePh.offset !== afterPh.offset ||
        beforePh.vaddr !== afterPh.vaddr ||
        beforePh.paddr !== afterPh.paddr ||
        beforePh.filesz !== afterPh.filesz ||
        beforePh.memsz !== afterPh.memsz ||
        beforePh.align !== afterPh.align
      ) {
        throw new InvalidNativeBinaryError(
          `ELF64 program header ${i} was mutated during protection`,
        );
      }
    }
    for (let s = 0; s < elfBefore.sectionHeaders.length; s++) {
      const beforeSh = elfBefore.sectionHeaders[s]!;
      const afterSh = elfAfter.sectionHeaders[s]!;
      if (
        beforeSh.type !== afterSh.type ||
        beforeSh.flags !== afterSh.flags ||
        beforeSh.addr !== afterSh.addr ||
        beforeSh.offset !== afterSh.offset ||
        beforeSh.size !== afterSh.size
      ) {
        throw new InvalidNativeBinaryError(
          `ELF64 section header ${s} was mutated during protection`,
        );
      }
    }
  }

  return {
    buffer: outBytes,
    rustcHashesInjected: rustcCount,
    electronFuseSentinelsInjected: decoySentinelsInjected,
    dartSnapshotHashesInjected: flutterPool.snapshotHashes,
    dartPoolUrisInjected: flutterPool.packageAndDartUris,
    dartPoolTokensInjected: flutterPool.classLikeTokens,
    goBuildInfoExceedsLimit:
      goBuildInfo.exceedsMaxBuildInfoBytes || mappedGoTripsMax,
    mappedGoBuildInfoPlanted,
    mappedFlutterPoolPlanted,
    chaffPayloadsEmbedded: chaffPayloads.length,
    binarySectionsPatched,
    ...(electronHardeningReport ? { electronHardeningReport } : {}),
    bunStandaloneCarrier: bunCarrier.kind,
    bunStandaloneGraphPreserved: bunCarrier.kind !== "none",
    nativeAppendHazard: "none",
    nativeBinaryPreserved: false,
  };
}

export function detectNativeFormatName(format: ArtifactFormat): string {
  switch (format) {
    case "native-elf":
      return "ELF Binary";
    case "native-macho":
      return "Mach-O Binary";
    case "native-pe":
      return "Windows PE Binary";
    default:
      return format;
  }
}
