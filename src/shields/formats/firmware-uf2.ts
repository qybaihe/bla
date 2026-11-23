import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

/**
 * UF2 firmware container shield — counters REA #8230
 * (`Uf2ArtifactReader` / `src/domain/firmware/uf2.ts`), which inventories and
 * extracts address-contiguous main-flash regions from Microsoft UF2 firmware.
 *
 * Red-line contract (Microsoft UF2 spec + REA decoder):
 *  - Existing blocks are preserved **byte-exact**.
 *  - Appended 512-byte comment blocks set only `UF2_FLAG_NOT_MAIN_FLASH`
 *    (0x1), so bootloaders skip their payload when writing flash.
 */

export const UF2_BLOCK_BYTES = REA_INTERNAL_LIMITS.UF2_BLOCK_BYTES;
const UF2_DATA_OFFSET = 32;
const UF2_DATA_BYTES = REA_INTERNAL_LIMITS.UF2_DATA_BYTES;
const UF2_MAGIC_START0 = 0x0a32_4655;
const UF2_MAGIC_START1 = 0x9e5d_5157;
const UF2_MAGIC_END = 0x0ab1_6f30;
const UF2_FLAG_NOT_MAIN_FLASH = 0x0000_0001;
const UF2_FLAG_FILE_CONTAINER = 0x0000_1000;

/** Marker string embedded in decoy payloads (auditor / inspect). */
export const UF2_SHIELD_MARKER = "[BLA-UF2-SHIELD]";

/**
 * Device family IDs used as text inside comment payloads.
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
  readonly decoyBlockCount: number;
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
  const exactBlocks =
    bytes.length >= UF2_BLOCK_BYTES && bytes.length % UF2_BLOCK_BYTES === 0;
  let allBlocksValid = exactBlocks;
  let decoyBlockCount = 0;
  const marker = Buffer.from(UF2_SHIELD_MARKER, "utf8");
  if (exactBlocks) {
    for (let off = 0; off < bytes.length; off += UF2_BLOCK_BYTES) {
      if (!readBlockMagicsOk(bytes, off)) {
        allBlocksValid = false;
        break;
      }
      const flags = bytes.readUInt32LE(off + 8);
      const payloadLen = Math.min(bytes.readUInt32LE(off + 16), UF2_DATA_BYTES);
      if (
        (flags & (UF2_FLAG_NOT_MAIN_FLASH | UF2_FLAG_FILE_CONTAINER)) !== 0 &&
        bytes
          .subarray(off + UF2_DATA_OFFSET, off + UF2_DATA_OFFSET + payloadLen)
          .includes(marker)
      ) {
        decoyBlockCount += 1;
      }
    }
  }
  const validMagic = allBlocksValid;
  const blockCount = validMagic ? bytes.length / UF2_BLOCK_BYTES : 0;
  return {
    validMagic,
    blockCount,
    decoyBlockCount: validMagic ? decoyBlockCount : 0,
    blaProtected: validMagic && decoyBlockCount >= 3,
    notMainFlashDecoyHint: validMagic && decoyBlockCount > 0,
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
  readonly extraComments: number;
} {
  switch (intensity) {
    case "stealth":
      return {
        namedFamilies: 1,
        unknownFamilies: 1,
        notMainPerFamily: 2,
        extraComments: 1,
      };
    case "balanced":
      return {
        namedFamilies: 3,
        unknownFamilies: 2,
        notMainPerFamily: 2,
        extraComments: 4,
      };
    case "maximum":
      return {
        namedFamilies: 6,
        unknownFamilies: 6,
        notMainPerFamily: 6,
        extraComments: 12,
      };
    case "bankrupt":
      return {
        namedFamilies: NAMED_DECOY_FAMILIES.length,
        unknownFamilies: 16,
        notMainPerFamily: 10,
        extraComments: 32,
      };
  }
}

/**
 * Protect a UF2 firmware image by appending not-main-flash comment blocks.
 * Original blocks are preserved byte-for-byte.
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

  if (!isUf2Container(input) || input.length % UF2_BLOCK_BYTES !== 0) {
    throw new Error(
      "Refusing to synthesize UF2 firmware container: input does not consist of complete, valid 512-byte UF2 blocks.",
    );
  }
  for (let off = 0; off < input.length; off += UF2_BLOCK_BYTES) {
    if (!readBlockMagicsOk(input, off)) {
      throw new Error(
        `Refusing to rewrite malformed UF2 firmware container: invalid block magic at offset ${off}.`,
      );
    }
  }
  const preserved = input;
  const originalBlocksPreserved = preserved.length / UF2_BLOCK_BYTES;

  const comments: Buffer[] = [];

  const named = NAMED_DECOY_FAMILIES.slice(0, plan.namedFamilies);
  const unknown: number[] = [];
  for (let i = 0; i < plan.unknownFamilies; i++) {
    // High-bit decoy IDs outside the small Microsoft registry REA embeds.
    unknown.push((0xa11ce000 + (prng.nextInt(0, 0xffff) << 4) + i) >>> 0);
  }
  const families = [...named, ...unknown];

  for (const familyId of families) {
    for (let i = 0; i < plan.notMainPerFamily; i++) {
      const record = deception.textRecords[comments.length % deception.textRecords.length] ?? "";
      comments.push(decoyPayload(prng, record, `family=0x${familyId.toString(16)}`));
    }
  }
  for (let i = 0; i < plan.extraComments; i++) {
    const record = deception.textRecords[i % deception.textRecords.length] ?? "";
    comments.push(decoyPayload(prng, record, `comment=${i}`));
  }

  const maxInjected = Math.floor(REA_INTERNAL_LIMITS.FIRMWARE_MAX_STAGING_BYTES / UF2_BLOCK_BYTES / 4);
  const clipped = comments.slice(0, maxInjected);
  const injected = clipped.map((payload, i) => writeUf2Block({
    flags: UF2_FLAG_NOT_MAIN_FLASH,
    address: 0,
    payload,
    blockNo: originalBlocksPreserved + i,
    numBlocks: originalBlocksPreserved + clipped.length,
    familyOrSize: 0,
  }));

  return {
    buffer: Buffer.concat([preserved, ...injected]),
    blocksInjected: injected.length,
    notMainFlashBlocks: injected.length,
    fileContainerBlocks: 0,
    decoyFamilies: 0,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
    originalBlocksPreserved,
  };
}
