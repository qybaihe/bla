import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

/**
 * UF2 firmware container shield — counters REA #8230
 * (`Uf2ArtifactReader` / `src/domain/firmware/uf2.ts`), which inventories and
 * extracts address-contiguous main-flash regions from Microsoft UF2 drag-and-
 * drop firmware images and reports not-main-flash / file-container / numbering
 * faults as coverage limitations.
 *
 * Red-line contract (Microsoft UF2 spec + REA decoder):
 *  - Existing blocks are preserved **byte-exact**.
 *  - Appended decoys ALWAYS set `UF2_FLAG_NOT_MAIN_FLASH` (0x1) and/or
 *    `UF2_FLAG_FILE_CONTAINER` (0x1000). Bootloaders MUST ignore those blocks
 *    when writing flash, so the developer's real payload still flashes and
 *    runs. We never emit a plain main-flash decoy.
 *  - Partial / invalid blocks are never introduced into the original range;
 *    only well-formed 512-byte trailing blocks are appended.
 *
 * At bankrupt intensity the decoy family / numbering surface is densified so
 * REA's inventory reports many not-main-flash + file-container blocks and
 * incomplete numbering groups (coverage → unknown) without touching flash.
 */

export const UF2_BLOCK_BYTES = REA_INTERNAL_LIMITS.UF2_BLOCK_BYTES;
const UF2_DATA_OFFSET = 32;
const UF2_DATA_BYTES = REA_INTERNAL_LIMITS.UF2_DATA_BYTES;
const UF2_MAGIC_START0 = 0x0a32_4655;
const UF2_MAGIC_START1 = 0x9e5d_5157;
const UF2_MAGIC_END = 0x0ab1_6f30;
const UF2_FLAG_NOT_MAIN_FLASH = 0x0000_0001;
const UF2_FLAG_FILE_CONTAINER = 0x0000_1000;
const UF2_FLAG_FAMILY_ID = 0x0000_2000;

/** Marker string embedded in decoy payloads (auditor / inspect). */
export const UF2_SHIELD_MARKER = "[BLA-UF2-SHIELD]";

/**
 * Subset of Microsoft uf2families.json IDs that REA names (see
 * `src/domain/firmware/uf2Families.ts`). Used as decoy family bait so REA
 * inventories named families that never write flash.
 */
const NAMED_DECOY_FAMILIES: readonly number[] = [
  0xe48b_ff56, // RP2040
  0xe48b_ff59, // RP2350_ARM_S
  0x1c5f_21b0, // ESP32
  0xc47e_5767, // ESP32S3
  0xd42b_a06c, // ESP32C3
  0xada5_2840, // NRF52840
  0x5775_5a57, // STM32F4
  0x5511_4460, // SAMD51
];

export interface Uf2Inspection {
  readonly validMagic: boolean;
  readonly blockCount: number;
  readonly blaProtected: boolean;
  readonly notMainFlashDecoyHint: boolean;
}

function readBlockMagicsOk(bytes: Buffer, offset: number): boolean {
  if (offset + UF2_BLOCK_BYTES > bytes.length) return false;
  return (
    bytes.readUInt32LE(offset) === UF2_MAGIC_START0 &&
    bytes.readUInt32LE(offset + 4) === UF2_MAGIC_START1 &&
    bytes.readUInt32LE(offset + UF2_BLOCK_BYTES - 4) === UF2_MAGIC_END
  );
}

/** True when the buffer begins with a complete, well-formed UF2 block. */
export function isUf2Container(bytes: Buffer): boolean {
  return readBlockMagicsOk(bytes, 0);
}

export function inspectUf2Firmware(bytes: Buffer): Uf2Inspection {
  const validMagic = isUf2Container(bytes);
  const blockCount = validMagic
    ? Math.floor(bytes.length / UF2_BLOCK_BYTES)
    : 0;
  const marker = Buffer.from(UF2_SHIELD_MARKER, "utf8");
  return {
    validMagic,
    blockCount,
    blaProtected: bytes.includes(marker),
    notMainFlashDecoyHint: bytes.includes(marker),
  };
}

function writeUf2Block(fields: {
  readonly flags: number;
  readonly address: number;
  readonly payload: Buffer;
  readonly blockNo: number;
  readonly numBlocks: number;
  readonly familyOrSize: number;
}): Buffer {
  const block = Buffer.alloc(UF2_BLOCK_BYTES, 0);
  const size = Math.min(fields.payload.length, UF2_DATA_BYTES);
  block.writeUInt32LE(UF2_MAGIC_START0, 0);
  block.writeUInt32LE(UF2_MAGIC_START1, 4);
  block.writeUInt32LE(fields.flags >>> 0, 8);
  block.writeUInt32LE(fields.address >>> 0, 12);
  block.writeUInt32LE(size, 16);
  block.writeUInt32LE(fields.blockNo >>> 0, 20);
  block.writeUInt32LE(fields.numBlocks >>> 0, 24);
  block.writeUInt32LE(fields.familyOrSize >>> 0, 28);
  fields.payload.subarray(0, size).copy(block, UF2_DATA_OFFSET);
  block.writeUInt32LE(UF2_MAGIC_END, UF2_BLOCK_BYTES - 4);
  return block;
}

function decoyPayload(prng: SeededPrng, text: string, tag: string): Buffer {
  const body = Buffer.from(
    `${UF2_SHIELD_MARKER}\n${tag}\n${text}\nnonce=${prng.hex(16)}\n`,
    "utf8",
  );
  if (body.length <= UF2_DATA_BYTES) return body;
  return body.subarray(0, UF2_DATA_BYTES);
}

function intensityPlan(intensity: ProtectionIntensity): {
  readonly namedFamilies: number;
  readonly unknownFamilies: number;
  readonly notMainPerFamily: number;
  readonly fileContainers: number;
  readonly numberingGaps: boolean;
} {
  switch (intensity) {
    case "stealth":
      return {
        namedFamilies: 1,
        unknownFamilies: 1,
        notMainPerFamily: 2,
        fileContainers: 1,
        numberingGaps: false,
      };
    case "balanced":
      return {
        namedFamilies: 3,
        unknownFamilies: 2,
        notMainPerFamily: 4,
        fileContainers: 4,
        numberingGaps: true,
      };
    case "maximum":
      return {
        namedFamilies: 6,
        unknownFamilies: 6,
        notMainPerFamily: 8,
        fileContainers: 12,
        numberingGaps: true,
      };
    case "bankrupt":
      return {
        namedFamilies: NAMED_DECOY_FAMILIES.length,
        unknownFamilies: 16,
        notMainPerFamily: 12,
        fileContainers: 32,
        numberingGaps: true,
      };
  }
}

/**
 * Protect a UF2 firmware image by appending well-formed not-main-flash and
 * file-container decoy blocks. Original blocks (including any real main-flash
 * payload) are never rewritten.
 */
export function protectUf2FirmwareBuffer(
  input: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string;
  } = {},
): {
  readonly buffer: Buffer;
  readonly blocksInjected: number;
  readonly notMainFlashBlocks: number;
  readonly fileContainerBlocks: number;
  readonly decoyFamilies: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
  readonly originalBlocksPreserved: number;
} {
  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-uf2-shield");
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);
  const plan = intensityPlan(intensity);

  const base = isUf2Container(input) ? input : Buffer.alloc(0);
  // Preserve only complete trailing blocks of a valid container; drop a
  // trailing partial (REA already excludes partial finals) so we append on a
  // block boundary without rewriting earlier bytes.
  const preservedLength =
    base.length === 0
      ? 0
      : Math.floor(base.length / UF2_BLOCK_BYTES) * UF2_BLOCK_BYTES;
  const preserved = preservedLength === base.length ? base : base.subarray(0, preservedLength);
  const originalBlocksPreserved = preservedLength / UF2_BLOCK_BYTES;

  const injected: Buffer[] = [];
  let notMainFlashBlocks = 0;
  let fileContainerBlocks = 0;
  const familyIds = new Set<number>();

  const named = NAMED_DECOY_FAMILIES.slice(0, plan.namedFamilies);
  const unknown: number[] = [];
  for (let i = 0; i < plan.unknownFamilies; i++) {
    // High-bit decoy IDs outside the small Microsoft registry REA embeds.
    unknown.push((0xa11ce000 + (prng.nextInt(0, 0xffff) << 4) + i) >>> 0);
  }
  const families = [...named, ...unknown];

  for (const familyId of families) {
    familyIds.add(familyId);
    const declared = plan.notMainPerFamily;
    // Emit fewer than declared (and optionally skip block 0) so REA records
    // absent / out-of-range numbering for this decoy family — coverage unknown.
    const emitCount = plan.numberingGaps
      ? Math.max(1, declared - 1 - (declared > 3 ? 1 : 0))
      : declared;
    const startNo = plan.numberingGaps && declared > 2 ? 1 : 0;
    for (let i = 0; i < emitCount; i++) {
      const record =
        deception.textRecords[
          (injected.length + i) % Math.max(1, deception.textRecords.length)
        ] ?? `family=0x${familyId.toString(16)}`;
      const payload = decoyPayload(
        prng,
        record,
        `not-main-flash family=0x${familyId.toString(16)}`,
      );
      injected.push(
        writeUf2Block({
          flags: UF2_FLAG_NOT_MAIN_FLASH | UF2_FLAG_FAMILY_ID,
          address: 0x1000_0000 + (familyId & 0xffff) * 0x1000 + i * 256,
          payload,
          blockNo: startNo + i,
          numBlocks: declared,
          familyOrSize: familyId,
        }),
      );
      notMainFlashBlocks += 1;
    }
  }

  for (let i = 0; i < plan.fileContainers; i++) {
    const familyId =
      families[i % Math.max(1, families.length)] ?? 0xb1a00d00;
    familyIds.add(familyId >>> 0);
    const record =
      deception.textRecords[i % Math.max(1, deception.textRecords.length)] ??
      "file-container";
    const payload = decoyPayload(
      prng,
      record,
      `file-container idx=${i}`,
    );
    // File-container flag alone is enough; REA treats it as overriding
    // not-main-flash. We still OR not-main-flash for belt-and-suspenders
    // bootloader safety on idiosyncratic flashers.
    injected.push(
      writeUf2Block({
        flags:
          UF2_FLAG_FILE_CONTAINER |
          UF2_FLAG_NOT_MAIN_FLASH |
          UF2_FLAG_FAMILY_ID,
        address: 0x2000_0000 + i * 512,
        payload,
        blockNo: i,
        numBlocks: plan.fileContainers,
        familyOrSize: familyId >>> 0,
      }),
    );
    fileContainerBlocks += 1;
  }

  // Hard ceiling: never approach UF2_MAX_REGIONS with flash regions — we emit
  // zero main-flash decoys. Keep total injected blocks well under staging.
  const maxInjected = Math.min(
    injected.length,
    Math.floor(REA_INTERNAL_LIMITS.FIRMWARE_MAX_STAGING_BYTES / UF2_BLOCK_BYTES / 4),
  );
  const clipped = injected.slice(0, maxInjected);
  // not-main blocks are emitted first; file-container blocks follow.
  const clippedNotMain = Math.min(notMainFlashBlocks, clipped.length);
  const clippedFile = Math.min(
    fileContainerBlocks,
    Math.max(0, clipped.length - clippedNotMain),
  );

  return {
    buffer: Buffer.concat([preserved, ...clipped]),
    blocksInjected: clipped.length,
    notMainFlashBlocks: clippedNotMain,
    fileContainerBlocks: clippedFile,
    decoyFamilies: familyIds.size,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
    originalBlocksPreserved,
  };
}
