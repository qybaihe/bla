import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";
import { buildJniExportNames } from "./android-r8.js";
import {
  DEX_ENDIAN_LE,
  DEX_HEADER_SIZE,
  DEX_LEGACY_VERSIONS,
  computeAdler32,
  recomputeDexChecksums,
} from "./dex-layout.js";

function dexHeaderError(bytes: Buffer): string | undefined {
  if (bytes.length < DEX_HEADER_SIZE || bytes.toString("latin1", 0, 4) !== "dex\n" || bytes[7] !== 0) {
    return "expected a complete DEX header";
  }
  const version = bytes.toString("latin1", 4, 7);
  if (version === "041") return "DEX v041 container layout is unsupported";
  if (!DEX_LEGACY_VERSIONS.has(version)) return `unsupported DEX version ${version}`;
  if (bytes.readUInt32LE(36) !== DEX_HEADER_SIZE) return "invalid header_size";
  if (bytes.readUInt32LE(40) !== DEX_ENDIAN_LE) return "unsupported endian_tag";
  if (bytes.readUInt32LE(32) !== bytes.length) return "file_size does not match input length";
  // All sizes are unsigned; use multiplication in number space to avoid wraparound.
  for (const [at, width] of [[44, 1], [56, 4], [64, 4], [72, 12], [80, 8], [88, 8], [96, 32], [104, 1]] as const) {
    const size = bytes.readUInt32LE(at) * width;
    const offset = bytes.readUInt32LE(at + 4);
    if (size > 0 && (offset < DEX_HEADER_SIZE || offset + size > bytes.length)) {
      return `section at header offset ${at} exceeds file bounds`;
    }
  }
  const mapOff = bytes.readUInt32LE(52);
  if (mapOff !== 0 && (mapOff < DEX_HEADER_SIZE || mapOff + 4 > bytes.length ||
      mapOff + 4 + bytes.readUInt32LE(mapOff) * 12 > bytes.length)) {
    return "map_list exceeds file bounds";
  }
}

/**
 * Inspects an Android Dalvik Executable (`.dex`) buffer.
 */
export function inspectAndroidDex(bytes: Buffer): {
  readonly validDex: boolean;
  readonly version: string;
  readonly fileSize: number;
  readonly decoyClassesCount: number;
  readonly blaProtected: boolean;
} {
  if (dexHeaderError(bytes)) {
    return {
      validDex: false,
      version: "000",
      fileSize: 0,
      decoyClassesCount: 0,
      blaProtected: false,
    };
  }
  const version = bytes.subarray(4, 7).toString("ascii");
  const fileSize = bytes.readUInt32LE(32);
  const storedAdler = bytes.readUInt32LE(8);
  const computedAdler = computeAdler32(bytes.subarray(12));
  const textLatin1 = bytes.toString("latin1");
  const decoyMatches = textLatin1.match(/Lcom\/enclave\/[A-Za-z0-9_/$]+;/g);
  const decoyClassesCount = decoyMatches ? decoyMatches.length : 0;
  const headerConsistent =
    fileSize === bytes.length && storedAdler === computedAdler;
  return {
    validDex: true,
    version,
    fileSize,
    decoyClassesCount,
    blaProtected:
      headerConsistent &&
      decoyClassesCount >= 8 &&
      textLatin1.includes("Lcom/enclave/sgx/TeeAttestationBridge;"),
  };
}

/**
 * Protects or constructs an Android `.dex` bytecode container (`dex\n035\0`)
 * against REA's `search-android-classes`, `inspect-android-class`, and `trace-android-references`
 * (JADX / JEB providers) by injecting decoy TEE/SGX Dalvik class descriptors and
 * recomputing the DEX header `file_size` (`0x20`), `signature` SHA-1 (`0x0C..0x1F`),
 * and `checksum` Adler32 (`0x08..0x0B`).
 */
export function protectAndroidDexBuffer(
  bytes: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
  } = {},
): {
  readonly buffer: Buffer;
  readonly decoyClassesInjected: number;
  readonly chaffPayloadsEmbedded: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
} {
  const error = dexHeaderError(bytes);
  if (error) throw new Error(`Invalid Android DEX container: ${error}; refusing to synthesize a replacement container.`);
  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-dex-shield-v1");
  const chaffPayloads = generateChaffPayloads(prng, intensity);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  const decoyClassCount = intensity === "stealth" ? 12 : intensity === "balanced" ? 28 : 64;
  const decoyClasses: string[] = [
    "Lcom/enclave/sgx/TeeAttestationBridge;",
    "Lcom/enclave/tpm2/KeyUnsealerStub;",
    "Lcom/enclave/nitro/VsockRing0Transport;",
  ];
  for (let i = 0; i < decoyClassCount; i++) {
    decoyClasses.push(`Lcom/enclave/tarpit/EnclaveStateNode_${prng.hex(6)}_${i};`);
  }

  // Trailer doubles as a string-pool pollution region for JADX/JEB string scanners
  // and plants JNI-mangled Java_* names that match the decoy .so exports (REA #7472).
  const jniNames = buildJniExportNames(prng, intensity === "stealth" ? 8 : intensity === "balanced" ? 16 : 48);
  const trailerText = [
    "\0[BLA-DEX-SHIELD-V1]",
    ...decoyClasses,
    ...jniNames,
    ...chaffPayloads.map((p) => p.rawText),
    ...deception.textRecords,
  ].join("\0") + "\0";

  const outDex = Buffer.concat([bytes, Buffer.from(trailerText, "utf8")]);
  // Update file_size at offset 32
  outDex.writeUInt32LE(outDex.length, 32);
  return {
    buffer: recomputeDexChecksums(outDex),
    decoyClassesInjected: decoyClasses.length,
    chaffPayloadsEmbedded: chaffPayloads.length,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
  };
}

/**
 * Inspects and shields Unity IL2CPP `global-metadata.dat` (`0xFAB11BAF`)
 * against REA's `inspect-il2cpp-metadata` (`src/il2cpp/Il2cppMetadataAdmission.ts`).
 */
export function protectIl2cppMetadataBuffer(
  bytes: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
  } = {},
): {
  readonly buffer: Buffer;
  readonly decoyLiteralsInjected: number;
  readonly chaffPayloadsEmbedded: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
} {
  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-il2cpp-shield-v1");
  const chaffPayloads = generateChaffPayloads(prng, intensity);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  if (bytes.length < 256 || bytes.readUInt32LE(0) !== 0xfab11baf) {
    throw new Error(
      "Invalid Unity IL2CPP metadata: expected the 0xFAB11BAF magic with at least 256 bytes; refusing to synthesize a replacement container.",
    );
  }
  const header = Buffer.from(bytes);

  const decoyLiteralsCount = intensity === "stealth" ? 32 : intensity === "balanced" ? 128 : 512;
  const literals: string[] = [];
  for (let i = 0; i < decoyLiteralsCount; i++) {
    const chaff = chaffPayloads[i % chaffPayloads.length]!;
    literals.push(`Enclave.Ring0.Tarpit_${i}_${prng.hex(8)}:${chaff.rawText}`);
  }
  for (const rec of deception.textRecords) {
    literals.push(rec);
  }

  const trailer = Buffer.from(
    `\0[BLA-IL2CPP-SHIELD]\0${literals.join("\0")}\0`,
    "utf8",
  );

  return {
    buffer: Buffer.concat([header, trailer]),
    decoyLiteralsInjected: decoyLiteralsCount,
    chaffPayloadsEmbedded: chaffPayloads.length,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
  };
}
