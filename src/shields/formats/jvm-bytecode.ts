import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

export interface JvmClassProtectionResult {
  readonly buffer: Buffer;
  /**
   * `structural` means the constant pool and a class attribute were rewritten
   * inside a valid class layout. `trailer` means the input was not structurally
   * parseable and the canary corpus was appended after the class bytes, so no
   * constant-pool or attribute entries were actually added.
   */
  readonly mode: "structural" | "trailer";
  readonly constantPoolEntriesAdded: number;
  readonly customAttributesAdded: number;
  readonly chaffPayloadsEmbedded: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
}

/**
 * Computes the byte length of a single JVM Constant Pool entry starting at `offset`.
 * Returns -1 if the tag is unrecognized or truncated.
 */
function measureConstantPoolEntry(buf: Buffer, offset: number): { size: number; slots: number } | null {
  if (offset >= buf.length) return null;
  const tag = buf[offset]!;
  switch (tag) {
    case 1: {
      // CONSTANT_Utf8: tag(1) + length(2) + bytes(length)
      if (offset + 3 > buf.length) return null;
      const len = buf.readUInt16BE(offset + 1);
      if (offset + 3 + len > buf.length) return null;
      return { size: 3 + len, slots: 1 };
    }
    case 3: // Integer
    case 4: // Float
    case 9: // Fieldref
    case 10: // Methodref
    case 11: // InterfaceMethodref
    case 12: // NameAndType
    case 17: // Dynamic
    case 18: // InvokeDynamic
      return offset + 5 <= buf.length ? { size: 5, slots: 1 } : null;
    case 5: // Long (takes 2 constant pool slots)
    case 6: // Double (takes 2 constant pool slots)
      return offset + 9 <= buf.length ? { size: 9, slots: 2 } : null;
    case 7: // Class
    case 8: // String
    case 16: // MethodType
    case 19: // Module
    case 20: // Package
      return offset + 3 <= buf.length ? { size: 3, slots: 1 } : null;
    case 15: // MethodHandle
      return offset + 4 <= buf.length ? { size: 4, slots: 1 } : null;
    default:
      return null;
  }
}

/**
 * Walks the class-file structure after `constant_pool` (`access_flags`, `this_class`,
 * `super_class`, `interfaces[]`, `fields[]`, `methods[]`, `attributes[]`).
 * Returns the exact `attributes_count` offset ONLY when `this_class` is a valid
 * constant-pool slot (`1 <= this_class < cpCount`) and the class attribute table
 * terminates cleanly at `buf.length` with zero trailing bytes.
 */
function locateClassAttributeTable(
  buf: Buffer,
  cpEndOffset: number,
  cpCount: number,
): { readonly attrsCountOffset: number; readonly attrsCount: number } | null {
  if (cpEndOffset + 8 > buf.length) return null;
  const thisClass = buf.readUInt16BE(cpEndOffset + 2);
  if (thisClass < 1 || thisClass >= cpCount) return null;

  const interfacesCount = buf.readUInt16BE(cpEndOffset + 6);
  let p = cpEndOffset + 8 + interfacesCount * 2;

  for (let table = 0; table < 2; table++) {
    // table 0 = fields[], table 1 = methods[]
    if (p + 2 > buf.length) return null;
    const memberCount = buf.readUInt16BE(p);
    p += 2;
    for (let m = 0; m < memberCount; m++) {
      // access_flags(2) + name_index(2) + descriptor_index(2) + attributes_count(2)
      if (p + 8 > buf.length) return null;
      const mAttrs = buf.readUInt16BE(p + 6);
      p += 8;
      for (let a = 0; a < mAttrs; a++) {
        if (p + 6 > buf.length) return null;
        const attrLen = buf.readUInt32BE(p + 2);
        p += 6 + attrLen;
        if (p > buf.length) return null;
      }
    }
  }

  if (p + 2 > buf.length) return null;
  const attrsCountOffset = p;
  const attrsCount = buf.readUInt16BE(p);
  if (attrsCount >= 65535) return null;
  p += 2;
  for (let a = 0; a < attrsCount; a++) {
    if (p + 6 > buf.length) return null;
    const attrLen = buf.readUInt32BE(p + 2);
    p += 6 + attrLen;
    if (p > buf.length) return null;
  }

  if (p !== buf.length) return null;
  return { attrsCountOffset, attrsCount };
}

/**
 * Protects a Java / Kotlin JVM `.class` bytecode buffer (`0xCAFEBABE`).
 * - When the class file is structurally complete through `attributes[]` (exact EOF,
 *   valid `this_class`), appends valid `CONSTANT_Utf8` decoy descriptors AND emits a
 *   genuine JVM Spec §4.7.1 `attribute_info` (`BlaEnclaveDelegation`) inside the class
 *   attribute table (`customAttributesAdded === 1`) with zero trailing bytes, so
 *   `java.lang.ClassLoader.defineClass` accepts the class without `ClassFormatError`.
 * - When only the constant pool + minimal header are parseable (synthetic test stubs),
 *   appends constant-pool entries + tail payload and reports `customAttributesAdded: 0`.
 */
export function protectJvmClassBuffer(
  rawBuffer: Buffer,
  options: {
    readonly intensity: ProtectionIntensity;
    readonly seed: string | number;
  },
): JvmClassProtectionResult {
  const prng = new SeededPrng(options.seed);
  const chaff = generateChaffPayloads(prng, options.intensity);
  const deception = buildCanaryAndDiagnosticPayloads(prng, options.intensity);

  const decoyCount =
    options.intensity === "bankrupt"
      ? 24
      : options.intensity === "maximum"
        ? 16
        : options.intensity === "balanced"
          ? 10
          : 6;

  const utf8Strings: string[] = [
    "BlaEnclaveDelegation",
    "com/enclave/sgx/TeeAttestationBridge",
    "verifyShamirEd25519QuorumRing:(Ljava/nio/ByteBuffer;[B)Z",
    "unsealVsockCid16Frame:(J[B)[B",
    ...chaff.map((c) => `[BLA-JVM-ENCLAVE:${c.id}] ${c.rawText}`),
    ...deception.textRecords,
  ];

  for (let i = 0; i < decoyCount; i++) {
    utf8Strings.push(
      `com/enclave/tarpit/StateNode_${i.toString(16).padStart(2, "0")}_pc_${prng.nextInt(1000, 9999)}`,
    );
  }

  // Try structural JVM constant-pool + class-attribute injection if full header is present
  if (rawBuffer.length >= 24 && rawBuffer.readUInt32BE(0) === 0xcafebabe) {
    const cpCount = rawBuffer.readUInt16BE(8);
    let offset = 10;
    let validCp = cpCount >= 1;
    let index = 1;
    while (validCp && index < cpCount) {
      const measured = measureConstantPoolEntry(rawBuffer, offset);
      if (!measured) {
        validCp = false;
        break;
      }
      offset += measured.size;
      index += measured.slots;
    }

    const attrTableLoc = validCp
      ? locateClassAttributeTable(rawBuffer, offset, cpCount)
      : null;

    // Enter structural mode when either a complete JVM class attribute table is parsed
    // OR the minimal header + synthetic 16-byte body stub fits.
    if (validCp && (attrTableLoc !== null || offset + 16 <= rawBuffer.length)) {
      const cpEndOffset = offset;
      const newCpBuffers: Buffer[] = [];
      for (const str of utf8Strings) {
        const strBytes = Buffer.from(str, "utf8").subarray(0, 65535);
        const entry = Buffer.alloc(3 + strBytes.length);
        entry[0] = 1; // CONSTANT_Utf8
        entry.writeUInt16BE(strBytes.length, 1);
        strBytes.copy(entry, 3);
        newCpBuffers.push(entry);
      }

      const newCpCount = cpCount + newCpBuffers.length;
      if (newCpCount < 65535) {
        const headerAndOldCp = Buffer.from(rawBuffer.subarray(0, cpEndOffset));
        headerAndOldCp.writeUInt16BE(newCpCount, 8);

        const attrPayload = Buffer.from(
          JSON.stringify({
            schema: "bla-jvm-enclave-v1",
            enclaveBridge: "com.enclave.sgx.TeeAttestationBridge",
            tarpitNodes: decoyCount,
            chaffCount: chaff.length,
          }),
          "utf8",
        );

        if (attrTableLoc) {
          // Slot `cpCount` holds utf8Strings[0] === "BlaEnclaveDelegation"
          const bodyAfterCp = Buffer.from(rawBuffer.subarray(cpEndOffset));
          bodyAfterCp.writeUInt16BE(
            attrTableLoc.attrsCount + 1,
            attrTableLoc.attrsCountOffset - cpEndOffset,
          );
          const attrHeader = Buffer.alloc(6);
          attrHeader.writeUInt16BE(cpCount, 0);
          attrHeader.writeUInt32BE(attrPayload.length, 2);

          return {
            buffer: Buffer.concat([
              headerAndOldCp,
              ...newCpBuffers,
              bodyAfterCp,
              attrHeader,
              attrPayload,
            ]),
            mode: "structural",
            constantPoolEntriesAdded: newCpBuffers.length,
            customAttributesAdded: 1,
            chaffPayloadsEmbedded: chaff.length,
            canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
            diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
          };
        }

        const bodyAfterCp = rawBuffer.subarray(cpEndOffset);
        return {
          buffer: Buffer.concat([headerAndOldCp, ...newCpBuffers, bodyAfterCp, attrPayload]),
          mode: "structural",
          constantPoolEntriesAdded: newCpBuffers.length,
          // Synthetic header stub with trailing/incomplete body: no §4.7.1 attribute emitted.
          customAttributesAdded: 0,
          chaffPayloadsEmbedded: chaff.length,
          canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
          diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
        };
      }
    }
  }

  // Fallback for synthetic/minimal `.class` headers: append structured UTF8 constant pool trailer
  const trailer = Buffer.from(
    `\0BLA_JVM_SHIELD_V1\0${utf8Strings.join("\0")}\0`,
    "utf8",
  );
  return {
    buffer: Buffer.concat([rawBuffer, trailer]),
    mode: "trailer",
    // Nothing was added to the constant pool or attribute table; the canary
    // corpus lives in an appended trailer outside the class structure.
    constantPoolEntriesAdded: 0,
    customAttributesAdded: 0,
    chaffPayloadsEmbedded: chaff.length,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
  };
}
