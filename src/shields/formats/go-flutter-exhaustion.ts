import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";

function writeGoUvarint(value: number): Buffer {
  const out: number[] = [];
  let n = value >>> 0;
  while (n >= 0x80) {
    out.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  out.push(n);
  return Buffer.from(out);
}

const GO_MAGIC = Buffer.from("ff20476f206275696c64696e663a", "hex");
const MODULE_START = Buffer.from("3077af0c9274080241e1c107e6d618e6", "hex");
const MODULE_END = Buffer.from("f932433186182072008242104116d8f2", "hex");

const GO_DECOY_MODULE_ORGS = [
  "cloudflare/circl",
  "FiloSottile/age",
  "go-jose/go-jose/v4",
  "golang-jwt/jwt/v5",
  "google/go-sev-guest",
  "google/go-tdx-guest",
  "hashicorp/vault/sdk",
  "klauspost/compress",
  "miekg/pkcs11",
  "oasisprotocol/curve25519-voi",
  "smallstep/certificates",
  "spiffe/go-spiffe/v2",
  "zitadel/oidc/v3",
  "aws/aws-nitro-enclaves-nsm-api",
  "confidential-containers/attestation",
  "sigstore/cosign/v2",
] as const;

function buildSyntheticGoDepTable(prng: SeededPrng, minBytes: number): Buffer {
  const cohortDigests = Array.from({ length: 32 }, () =>
    Buffer.from(prng.hex(64), "hex").toString("base64"),
  );
  const cohortSubpkgs = Array.from({ length: 32 }, (_, idx) =>
    `${GO_DECOY_MODULE_ORGS[idx % GO_DECOY_MODULE_ORGS.length]}/sub_${prng.hex(3)}`,
  );
  const lines: string[] = [];
  let totalLen = 0;
  let i = 0;
  while (totalLen < minBytes) {
    const slot = i & 31;
    const minor = (i >>> 5) & 31;
    const patch = i & 63;
    const line = `dep\tgithub.com/${cohortSubpkgs[slot]}/pkg${i.toString(36)}\tv1.${minor}.${patch}\th1:${cohortDigests[slot]}\n`;
    lines.push(line);
    totalLen += line.length;
    i++;
  }
  return Buffer.from(lines.join(""), "utf8");
}

/**
 * Framed Go buildinfo (magic `\xff Go buildinf:` + inline encoding) with
 * MODULE_START/END wrapping, plus `.gopclntab` / `runtime.moduledata` bait.
 * Bankrupt/maximum pad the module past `MAX_BUILD_INFO_BYTES` (1 MiB) using
 * realistic Go module dependency lines rather than constant-byte padding.
 *
 * Trailer placement poisons whole-file scanners. Prefer
 * {@link buildMappedGoBuildInfoPlant} inside a real `.go.buildinfo` section /
 * writable PT_LOAD so REA's mapped parser (`GoBuildInfoSearch`) trips.
 */
export function buildGoBuildInfoExhaustionPayload(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
  options: { readonly omitBanner?: boolean } = {},
): {
  readonly buffer: Buffer;
  readonly exceedsMaxBuildInfoBytes: boolean;
  readonly moduleBytes: number;
} {
  const padAlign = Buffer.alloc(16, 0);

  const version = Buffer.from("go1.22.5", "utf8");
  const canaryLines = [
    "path\tgithub.com/tee-enclave/zero-trust-shim\n",
    `mod\tgithub.com/tee-enclave/zero-trust-shim\tv4.2.0\th1:${Buffer.from(prng.hex(64), "hex").toString("base64")}\n`,
    `dep\tgithub.com/intel-sgx/enclave-sdk-go\tv2.14.0\th1:${Buffer.from(prng.hex(64), "hex").toString("base64")}\n`,
    `dep\tgithub.com/google/go-tpm-tools\tv0.4.4\th1:${Buffer.from(prng.hex(64), "hex").toString("base64")}\n`,
    "build\t-compiler=gc\n",
    "build\tCGO_ENABLED=1\n",
    "build\t-trimpath=true\n",
    `build\tvcs.revision=${prng.hex(20)}\n`,
  ];
  let moduleBody = Buffer.from(canaryLines.join(""), "utf8");
  const target =
    intensity === "bankrupt" || intensity === "maximum"
      ? REA_INTERNAL_LIMITS.GO_MAX_BUILD_INFO_BYTES + 4096
      : Math.min(24_000, REA_INTERNAL_LIMITS.GO_MAX_BUILD_INFO_BYTES >> 3);
  if (version.length + moduleBody.length < target) {
    const need = target - version.length - moduleBody.length;
    const depNoise = buildSyntheticGoDepTable(prng, need);
    moduleBody = Buffer.concat([moduleBody, depNoise]);
  }
  const moduleFramed = Buffer.concat([
    MODULE_START,
    moduleBody,
    Buffer.from("\n", "utf8"),
    MODULE_END,
  ]);
  const exceeds =
    version.length + moduleFramed.length >
    REA_INTERNAL_LIMITS.GO_MAX_BUILD_INFO_BYTES;

  const header = Buffer.alloc(32, 0);
  GO_MAGIC.copy(header, 0);
  header[14] = 8; // ptrSize
  header[15] = 2; // flags: bit1 => inline encoding

  const pclntabBait = Buffer.from(
    options.omitBanner
      ? "\0.gopclntab\0runtime.moduledata\0__gopclntab\0runtime.pclntab\0\xfb\xff\xff\xff\x00\x00"
      : "\0[BLA-GO-BUILDINFO]\0.gopclntab\0runtime.moduledata\0__gopclntab\0runtime.pclntab\0\xfb\xff\xff\xff\x00\x00",
    "latin1",
  );

  return {
    buffer: Buffer.concat([
      padAlign,
      header,
      writeGoUvarint(version.length),
      version,
      writeGoUvarint(moduleFramed.length),
      moduleFramed,
      pclntabBait,
    ]),
    exceedsMaxBuildInfoBytes: exceeds,
    moduleBytes: moduleFramed.length,
  };
}

/**
 * Compact plant for a real mapped `.go.buildinfo` / writable PT_LOAD region.
 * Bankrupt claims an inline version length past `MAX_BUILD_INFO_BYTES` so REA's
 * mapped parser resource-fails without needing a 1 MiB section. Balanced writes
 * a valid small framed module. Capacity is respected (never overflows the section).
 */
export function buildMappedGoBuildInfoPlant(
  intensity: ProtectionIntensity,
  capacity: number,
): {
  readonly buffer: Buffer;
  readonly tripsMaxBuildInfoBytes: boolean;
} {
  if (capacity < 40) {
    return { buffer: Buffer.alloc(0), tripsMaxBuildInfoBytes: false };
  }
  const header = Buffer.alloc(32, 0);
  GO_MAGIC.copy(header, 0);
  header[14] = 8;
  header[15] = 2;
  const marker = Buffer.from("\0[BLA-GO-MAPPED]\0", "latin1");

  if (intensity === "bankrupt" || intensity === "maximum") {
    const claim = writeGoUvarint(
      REA_INTERNAL_LIMITS.GO_MAX_BUILD_INFO_BYTES + 1,
    );
    const plant = Buffer.concat([header, claim, marker]);
    return {
      buffer: plant.subarray(0, Math.min(plant.length, capacity)),
      tripsMaxBuildInfoBytes: true,
    };
  }

  const version = Buffer.from("go1.22.5", "utf8");
  const module = Buffer.from(
    "path\tgithub.com/bla/mapped-buildinfo\nbuild\t-compiler=gc\n",
    "utf8",
  );
  const plant = Buffer.concat([
    header,
    writeGoUvarint(version.length),
    version,
    writeGoUvarint(module.length),
    module,
    marker,
  ]);
  return {
    buffer: plant.subarray(0, Math.min(plant.length, capacity)),
    tripsMaxBuildInfoBytes: false,
  };
}

/**
 * Dense NUL-terminated package:/dart:/class-like pool sized to fit `capacity`,
 * for planting inside a real Dart isolate snapshot data region.
 */
export function buildMappedFlutterIsolatePoolPlant(
  capacity: number,
  prng: SeededPrng,
  options: { readonly includeSnapshotHeader?: boolean } = {},
): {
  readonly buffer: Buffer;
  readonly packageAndDartUris: number;
  readonly classLikeTokens: number;
  readonly snapshotHeaderBytes: number;
} {
  if (capacity <= 0) {
    return {
      buffer: Buffer.alloc(0),
      packageAndDartUris: 0,
      classLikeTokens: 0,
      snapshotHeaderBytes: 0,
    };
  }
  const parts: Buffer[] = [];
  let headerBytes = 0;
  if (options.includeSnapshotHeader !== false && capacity >= 52) {
    const rec = Buffer.alloc(52, 0);
    rec[0] = 0xf5;
    rec[1] = 0xf5;
    rec[2] = 0xdc;
    rec[3] = 0xdc;
    rec.writeBigUInt64LE(64n, 4);
    rec.writeBigUInt64LE(3n, 12);
    rec.write(prng.hex(32), 20, "ascii");
    parts.push(rec);
    headerBytes = 52;
  }
  let used = headerBytes;
  let uris = 0;
  let tokens = 0;
  const marker = Buffer.from("\0[BLA-FLUTTER-MAPPED]\0", "utf8");
  if (used + marker.length <= capacity) {
    parts.push(marker);
    used += marker.length;
  }
  // REA caps package_uris and dart_uris independently at MAX_POOL_URIS (500).
  // Plant each kind past the cap (not a combined budget).
  const uriTarget = REA_INTERNAL_LIMITS.DART_MAX_POOL_URIS + 32;
  let i = 0;
  while (used < capacity && i < uriTarget) {
    // Keep strings short so a mapped section can exceed REA pool caps.
    const pkg = `package:m${i}/b.dart\0`;
    const pkgBuf = Buffer.from(pkg, "utf8");
    if (used + pkgBuf.length > capacity) break;
    parts.push(pkgBuf);
    used += pkgBuf.length;
    uris++;
    i++;
  }
  i = 0;
  while (used < capacity && i < uriTarget) {
    const dart = `dart:d${i}\0`;
    const dartBuf = Buffer.from(dart, "utf8");
    if (used + dartBuf.length > capacity) break;
    parts.push(dartBuf);
    used += dartBuf.length;
    uris++;
    i++;
  }
  let t = 0;
  const tokenTarget = REA_INTERNAL_LIMITS.DART_MAX_POOL_TOKENS + 32;
  while (used < capacity && tokens < tokenTarget) {
    const tok = `Node_${t}_X\0`;
    const tokBuf = Buffer.from(tok, "utf8");
    if (used + tokBuf.length > capacity) break;
    parts.push(tokBuf);
    used += tokBuf.length;
    tokens++;
    t++;
  }
  if (used < capacity) {
    parts.push(Buffer.alloc(capacity - used, 0));
  }
  return {
    buffer: Buffer.concat(parts).subarray(0, capacity),
    packageAndDartUris: uris,
    classLikeTokens: tokens,
    snapshotHeaderBytes: headerBytes,
  };
}

/**
 * Dart snapshot-hash overflow (>64) plus string-pool URI/token flood past
 * `MAX_POOL_URIS` (500) and `MAX_POOL_TOKENS` (2000).
 */
export function buildFlutterPoolExhaustionPayload(
  prng: SeededPrng,
  options: { readonly omitBanner?: boolean } = {},
): {
  readonly buffer: Buffer;
  readonly snapshotHashes: number;
  readonly packageAndDartUris: number;
  readonly classLikeTokens: number;
} {
  const records: Buffer[] = [];
  const snapshotCount =
    REA_INTERNAL_LIMITS.DART_MAX_SNAPSHOT_HASH_CANDIDATES + 2;

  for (let i = 0; i < snapshotCount; i++) {
    const rec = Buffer.alloc(52, 0);
    rec[0] = 0xf5;
    rec[1] = 0xf5;
    rec[2] = 0xdc;
    rec[3] = 0xdc;
    rec.writeBigUInt64LE(64n, 4);
    rec.writeBigUInt64LE(3n, 12);
    const hash32 = i.toString(16).padStart(8, "0") + prng.hex(24);
    rec.write(hash32, 20, "ascii");
    records.push(rec);
  }

  const labeledLines = [
    '\0Dart VM version: 3.5.0-enclave-tee-ring0 (stable) on "linux_x64"\0',
    'Dart VM version: 3.6.2-sgx-isolated-bridge (stable) on "macos_arm64"\0',
    "based on LLVM 17.0.6 (https://enclave.internal/llvm-tee-01)\0",
    "based on LLVM 18.1.2 (https://enclave.internal/llvm-tee-02)\0",
    "based on LLVM 18.1.8 (https://enclave.internal/llvm-tee-03)\0",
    "based on LLVM 19.1.0 (https://enclave.internal/llvm-tee-04)\0",
    "based on LLVM 19.1.4 (https://enclave.internal/llvm-tee-05)\0",
    "based on LLVM 20.0.0 (https://enclave.internal/llvm-tee-06)\0",
  ].join("");
  records.push(Buffer.from(labeledLines, "latin1"));

  const uriCount = REA_INTERNAL_LIMITS.DART_MAX_POOL_URIS + 16;
  const tokenCount = REA_INTERNAL_LIMITS.DART_MAX_POOL_TOKENS + 32;
  const poolParts: string[] = options.omitBanner
    ? [""]
    : ["\0[BLA-FLUTTER-POOL-EXHAUST]\0"];
  for (let i = 0; i < uriCount; i++) {
    poolParts.push(
      options.omitBanner
        ? `package:attestation_core_${i}/lib/bridge_${prng.hex(4)}.dart`
        : `package:enclave_tarpit_${i}/lib/bridge_${prng.hex(4)}.dart`,
    );
    poolParts.push(`dart:enclave_isolate_${i}`);
  }
  for (let i = 0; i < tokenCount; i++) {
    poolParts.push(
      options.omitBanner
        ? `AttestationGuardNode_${i}_${prng.hex(3)}`
        : `EnclaveTarpitNode_${i}_${prng.hex(3)}`,
    );
  }
  records.push(Buffer.from(poolParts.join("\0") + "\0", "utf8"));

  return {
    buffer: Buffer.concat(records),
    snapshotHashes: snapshotCount,
    packageAndDartUris: uriCount * 2,
    classLikeTokens: tokenCount,
  };
}

/**
 * Synthetic ELF64 with a mapped `.go.buildinfo` section and an isolate-data
 * region (plus dynsym for `_kDartIsolateSnapshotData`) so REA's real Go /
 * Flutter parsers can be exercised in tests and the benchmark.
 */
export function buildMappedGoFlutterElfFixture(): Buffer {
  // Isolate must fit dense plants past MAX_POOL_URIS (500) / MAX_POOL_TOKENS
  // (2000). Keep it compact (~48 KiB): a larger zero-filled baseline inflated
  // the benchmark "before" token estimate and understated the native-ELF
  // multiplier without changing real after-protection strength.
  const ISO_SIZE = 48 * 1024;
  const GO_SIZE = 512;
  const goOff = 1024;
  const isoOff = 2048;
  const dynsymOff = isoOff + ISO_SIZE;
  const dynsymSize = 48; // 2 entries × 24
  const dynstrOff = dynsymOff + dynsymSize;
  const dynstr = Buffer.from("\0_kDartIsolateSnapshotData\0", "utf8");
  const FILE_SIZE = dynstrOff + dynstr.length + 64;
  const bytes = Buffer.alloc(FILE_SIZE, 0);
  // ELF64 LE header
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0);
  bytes.writeUInt16LE(3, 16); // ET_DYN
  bytes.writeUInt16LE(0x3e, 18); // EM_X86_64
  bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(0x400000n, 24); // e_entry
  bytes.writeBigUInt64LE(64n, 32); // e_phoff
  bytes.writeBigUInt64LE(128n, 40); // e_shoff
  bytes.writeUInt16LE(64, 52);
  bytes.writeUInt16LE(56, 54);
  bytes.writeUInt16LE(1, 56); // e_phnum
  bytes.writeUInt16LE(64, 58);
  bytes.writeUInt16LE(6, 60); // e_shnum
  bytes.writeUInt16LE(1, 62); // e_shstrndx

  // PT_LOAD R|W covering whole file
  bytes.writeUInt32LE(1, 64); // PT_LOAD
  bytes.writeUInt32LE(6, 68); // PF_R|PF_W
  bytes.writeBigUInt64LE(0n, 72);
  bytes.writeBigUInt64LE(0x400000n, 80);
  bytes.writeBigUInt64LE(0x400000n, 88);
  bytes.writeBigUInt64LE(BigInt(FILE_SIZE), 96);
  bytes.writeBigUInt64LE(BigInt(FILE_SIZE), 104);
  bytes.writeBigUInt64LE(0x1000n, 112);

  const names = Buffer.from(
    "\0.shstrtab\0.go.buildinfo\0.isolate\0.dynsym\0.dynstr\0",
    "utf8",
  );
  const shstrOff = 512;
  names.copy(bytes, shstrOff);

  const goAddr = 0x400000n + BigInt(goOff); // 16-aligned
  const isoAddr = 0x400000n + BigInt(isoOff);
  dynstr.copy(bytes, dynstrOff);

  const sym1 = dynsymOff + 24;
  bytes.writeUInt32LE(1, sym1);
  bytes[sym1 + 4] = (1 << 4) | 1; // STB_GLOBAL | STT_OBJECT
  bytes.writeUInt16LE(3, sym1 + 6); // .isolate
  bytes.writeBigUInt64LE(isoAddr, sym1 + 8);
  bytes.writeBigUInt64LE(BigInt(ISO_SIZE), sym1 + 16);

  // Seed isolate with a real snapshot header so protect appends pool after it
  bytes[isoOff] = 0xf5;
  bytes[isoOff + 1] = 0xf5;
  bytes[isoOff + 2] = 0xdc;
  bytes[isoOff + 3] = 0xdc;
  bytes.writeBigUInt64LE(64n, isoOff + 4);
  bytes.writeBigUInt64LE(3n, isoOff + 12);
  bytes.write("0123456789abcdef0123456789abcdef", isoOff + 20, "ascii");

  const sh1 = 128 + 64;
  bytes.writeUInt32LE(1, sh1);
  bytes.writeUInt32LE(3, sh1 + 4);
  bytes.writeBigUInt64LE(BigInt(shstrOff), sh1 + 24);
  bytes.writeBigUInt64LE(BigInt(names.length), sh1 + 32);

  const sh2 = 128 + 128;
  const goNameOff = names.indexOf(Buffer.from(".go.buildinfo\0"));
  bytes.writeUInt32LE(goNameOff, sh2);
  bytes.writeUInt32LE(1, sh2 + 4);
  bytes.writeBigUInt64LE(3n, sh2 + 8);
  bytes.writeBigUInt64LE(goAddr, sh2 + 16);
  bytes.writeBigUInt64LE(BigInt(goOff), sh2 + 24);
  bytes.writeBigUInt64LE(BigInt(GO_SIZE), sh2 + 32);

  const sh3 = 128 + 192;
  const isoNameOff = names.indexOf(Buffer.from(".isolate\0"));
  bytes.writeUInt32LE(isoNameOff, sh3);
  bytes.writeUInt32LE(1, sh3 + 4);
  bytes.writeBigUInt64LE(3n, sh3 + 8);
  bytes.writeBigUInt64LE(isoAddr, sh3 + 16);
  bytes.writeBigUInt64LE(BigInt(isoOff), sh3 + 24);
  bytes.writeBigUInt64LE(BigInt(ISO_SIZE), sh3 + 32);

  const sh4 = 128 + 256;
  const dynsymNameOff = names.indexOf(Buffer.from(".dynsym\0"));
  bytes.writeUInt32LE(dynsymNameOff, sh4);
  bytes.writeUInt32LE(11, sh4 + 4);
  bytes.writeBigUInt64LE(2n, sh4 + 8);
  bytes.writeBigUInt64LE(0x400000n + BigInt(dynsymOff), sh4 + 16);
  bytes.writeBigUInt64LE(BigInt(dynsymOff), sh4 + 24);
  bytes.writeBigUInt64LE(BigInt(dynsymSize), sh4 + 32);
  bytes.writeUInt32LE(5, sh4 + 40);
  bytes.writeBigUInt64LE(24n, sh4 + 48);

  const sh5 = 128 + 320;
  const dynstrNameOff = names.indexOf(Buffer.from(".dynstr\0"));
  bytes.writeUInt32LE(dynstrNameOff, sh5);
  bytes.writeUInt32LE(3, sh5 + 4);
  bytes.writeBigUInt64LE(2n, sh5 + 8);
  bytes.writeBigUInt64LE(0x400000n + BigInt(dynstrOff), sh5 + 16);
  bytes.writeBigUInt64LE(BigInt(dynstrOff), sh5 + 24);
  bytes.writeBigUInt64LE(BigInt(dynstr.length), sh5 + 32);

  return bytes;
}
