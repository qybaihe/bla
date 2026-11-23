import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

import { encodeMutf8 } from "./dex-layout.js";

export interface JvmClassProtectionResult {
  readonly buffer: Buffer;
  readonly mode: "structural";
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

export interface JvmClassInspectionSummary {
  readonly validClass: boolean;
  readonly stateNodeCount: number;
  readonly blaProtected: boolean;
}

/**
 * Structurally inspects a JVM `.class` buffer (`0xCAFEBABE`), verifying constant-pool
 * `CONSTANT_Utf8` entries and class-attribute framing so raw bytes appended past EOF
 * cannot spoof protection status.
 */
export function inspectJvmClass(rawBuffer: Buffer): JvmClassInspectionSummary {
  if (rawBuffer.length < 24 || rawBuffer.readUInt32BE(0) !== 0xcafebabe) {
    return { validClass: false, stateNodeCount: 0, blaProtected: false };
  }
  const cpCount = rawBuffer.readUInt16BE(8);
  let offset = 10;
  let validCp = cpCount >= 1;
  let index = 1;
  let hasDelegationUtf8 = false;
  let stateNodeCount = 0;

  while (validCp && index < cpCount) {
    const measured = measureConstantPoolEntry(rawBuffer, offset);
    if (!measured) {
      validCp = false;
      break;
    }
    if (rawBuffer[offset] === 1) {
      const len = rawBuffer.readUInt16BE(offset + 1);
      const str = rawBuffer.subarray(offset + 3, offset + 3 + len).toString("utf8");
      if (str === "BlaEnclaveDelegation") {
        hasDelegationUtf8 = true;
      } else if (/^com\/enclave\/tarpit\/StateNode_[0-9a-f]+_pc_\d+$/.test(str)) {
        stateNodeCount += 1;
      }
    }
    offset += measured.size;
    index += measured.slots;
  }

  if (!validCp || index !== cpCount) {
    return { validClass: false, stateNodeCount: 0, blaProtected: false };
  }

  const attrTableLoc = locateClassAttributeTable(rawBuffer, offset, cpCount);
  const validFraming = attrTableLoc !== null;

  return {
    validClass: validFraming,
    stateNodeCount: validFraming ? stateNodeCount : 0,
    blaProtected: validFraming && hasDelegationUtf8 && stateNodeCount >= 6,
  };
}

/** Injects a framed JVM class attribute and modified UTF-8 constants. */
export function protectJvmClassBuffer(
  rawBuffer: Buffer,
  options: {
    readonly intensity: ProtectionIntensity;
    readonly seed: string | number;
  },
): JvmClassProtectionResult {
  if (rawBuffer.length < 24 || rawBuffer.readUInt32BE(0) !== 0xcafebabe) {
    throw new Error("Invalid JVM class file header");
  }
  const cpCount = rawBuffer.readUInt16BE(8);
  let cpEnd = 10;
  let index = 1;
  let attributeNameIndex = 0;
  const attributeName = Buffer.from("BlaEnclaveDelegation", "ascii");
  while (index < cpCount) {
    const entry = measureConstantPoolEntry(rawBuffer, cpEnd);
    if (!entry || index + entry.slots > cpCount) {
      throw new Error("Invalid or truncated JVM constant pool");
    }
    if (rawBuffer[cpEnd] === 1 && rawBuffer.subarray(cpEnd + 3, cpEnd + entry.size).equals(attributeName)) {
      attributeNameIndex = index;
    }
    cpEnd += entry.size;
    index += entry.slots;
  }

  const attrs = cpCount >= 1 ? locateClassAttributeTable(rawBuffer, cpEnd, cpCount) : null;
  if (!attrs) throw new Error("Invalid or truncated JVM class attribute table");
  if (attrs.attrsCount === 0xffff) throw new Error("JVM class attribute table is full");

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
    ...(attributeNameIndex ? [] : ["BlaEnclaveDelegation"]),
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

  const newCpCount = cpCount + utf8Strings.length;
  if (newCpCount > 0xffff) throw new Error("JVM constant pool has insufficient slots for protection");

  const newCpBuffers = utf8Strings.map((text) => {
    const body = encodeMutf8(text);
    if (body.length > 0xffff) throw new Error("JVM constant exceeds the modified UTF-8 size limit");
    const entry = Buffer.alloc(3 + body.length);
    entry[0] = 1; // CONSTANT_Utf8
    entry.writeUInt16BE(body.length, 1);
    body.copy(entry, 3);
    return entry;
  });
  const headerAndOldCp = Buffer.from(rawBuffer.subarray(0, cpEnd));
  headerAndOldCp.writeUInt16BE(newCpCount, 8);

  const body = Buffer.from(rawBuffer.subarray(cpEnd));
  body.writeUInt16BE(attrs.attrsCount + 1, attrs.attrsCountOffset - cpEnd);
  const attrPayload = Buffer.from(JSON.stringify({
    schema: "bla-jvm-enclave-v1",
    enclaveBridge: "com.enclave.sgx.TeeAttestationBridge",
    tarpitNodes: decoyCount,
    chaffCount: chaff.length,
  }), "utf8");
  const attrHeader = Buffer.alloc(6);
  attrHeader.writeUInt16BE(attributeNameIndex || cpCount, 0);
  attrHeader.writeUInt32BE(attrPayload.length, 2);

  return {
    buffer: Buffer.concat([headerAndOldCp, ...newCpBuffers, body, attrHeader, attrPayload]),
    mode: "structural",
    constantPoolEntriesAdded: newCpBuffers.length,
    customAttributesAdded: 1,
    chaffPayloadsEmbedded: chaff.length,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
  };
}
