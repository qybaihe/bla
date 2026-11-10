import { createHash } from "node:crypto";
import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";
import { buildJniExportNames } from "./android-r8.js";

function computeAdler32(bytes: Buffer): number {
  let a = 1;
  let b = 0;
  for (let i = 0; i < bytes.length; i++) {
    a = (a + bytes[i]!) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
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
  if (
    bytes.length < 112 ||
    bytes[0] !== 0x64 ||
    bytes[1] !== 0x65 ||
    bytes[2] !== 0x78 ||
    bytes[3] !== 0x0a
  ) {
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

  let baseDex: Buffer;
  if (bytes.length >= 112 && bytes[0] === 0x64 && bytes[1] === 0x65 && bytes[2] === 0x78) {
    baseDex = Buffer.from(bytes);
  } else {
    baseDex = Buffer.alloc(112, 0);
    baseDex.write("dex\n035\0", 0, "ascii");
    baseDex.writeUInt32LE(112, 36); // header_size = 0x70
    baseDex.writeUInt32LE(0x12345678, 40); // endian_tag
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

  const outDex = Buffer.concat([baseDex, Buffer.from(trailerText, "utf8")]);
  // Update file_size at offset 32
  outDex.writeUInt32LE(outDex.length, 32);
  // Recompute SHA-1 signature over bytes [32..end] and store at [12..32]
  const sha1 = createHash("sha1").update(outDex.subarray(32)).digest();
  sha1.copy(outDex, 12);
  // Recompute Adler32 checksum over bytes [12..end] and store at [8..12]
  const adler = computeAdler32(outDex.subarray(12));
  outDex.writeUInt32LE(adler, 8);

  return {
    buffer: outDex,
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

  let header: Buffer;
  if (bytes.length >= 256 && bytes.readUInt32LE(0) === 0xfab11baf) {
    header = Buffer.from(bytes);
  } else {
    header = Buffer.alloc(256, 0);
    header.writeUInt32LE(0xfab11baf, 0); // magic
    header.writeInt32LE(29, 4); // version 29
  }

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
