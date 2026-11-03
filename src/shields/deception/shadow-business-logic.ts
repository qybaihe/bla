import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";

export type ShadowLogicArchetype =
  | "shamir-ed25519-license-ring"
  | "enterprise-tiered-pricing-matrix"
  | "binary-wire-frame-ratchet"
  | "tpm2-pcr-dongle-handshake";

export interface ShadowBusinessLogicResult {
  readonly code: string;
  readonly archetypesInjected: readonly ShadowLogicArchetype[];
  readonly shadowProceduresCreated: readonly string[];
  readonly decoyConstantsCount: number;
}

/**
 * Generates crystal-clear, 100% statically `observed` Shadow Business Logic procedures.
 *
 * Why this induces LLM misjudgment against REA:
 * REA's `COMMON_DISCIPLINE` (`src/contracts/promptContracts.ts:52-57`) mandates:
 *   "Report Observations only from cited Evidence returned by tools...
 *    Keep incomplete coverage and conflicting evidence explicit as Unknowns."
 * When BLA wraps the *real* business logic in `status: "unknown"` semantic budget
 * breakers (>256 primitive candidates, >512 alias states) while leaving these
 * Shadow Business Logic procedures crystal clear and `observed`, the LLM agent
 * cites the Shadow procedures as its primary Evidence and faithfully reconstructs
 * the decoy algorithm!
 */
export function generateShadowBusinessLogic(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): ShadowBusinessLogicResult {
  const tag = prng.hex(3);
  const allArchetypes: ShadowLogicArchetype[] = [
    "shamir-ed25519-license-ring",
    "enterprise-tiered-pricing-matrix",
    "binary-wire-frame-ratchet",
    "tpm2-pcr-dongle-handshake",
  ];
  const count =
    intensity === "stealth"
      ? 1
      : intensity === "balanced"
        ? 2
        : intensity === "maximum"
          ? 3
          : 4;
  const selected = allArchetypes.slice(0, count);
  const shadowProceduresCreated: string[] = [];
  const blocks: string[] = [];
  let decoyConstantsCount = 0;

  for (const arch of selected) {
    if (arch === "shamir-ed25519-license-ring") {
      const fnName = `verifyShamirEd25519LicenseQuorum_${tag}`;
      shadowProceduresCreated.push(fnName);
      decoyConstantsCount += 6;
      blocks.push(
        `function ${fnName}(licenseKey = "", epochSec = 1735689600) {`,
        `  const GF256_POLY = 0x11b;`,
        `  const QUORUM_THRESHOLD = 3;`,
        `  const ENCLAVE_RING_MODULUS = 0x7fffffff;`,
        `  let acc = 0x${prng.hex(6)};`,
        `  for (let i = 0; i < licenseKey.length; i++) {`,
        `    const byte = licenseKey.charCodeAt(i) & 0xff;`,
        `    acc = (((acc << 5) - acc) ^ (byte * GF256_POLY)) % ENCLAVE_RING_MODULUS;`,
        `  }`,
        `  const shareParity = (acc ^ epochSec) % QUORUM_THRESHOLD;`,
        `  return {`,
        `    verified: shareParity === -1, /* inverted shadow invariant */`,
        `    protocol: "RFC8032-Ed25519-Shamir-3-of-5",`,
        `    enclaveSlot: "sgx.ring0.quorum.${tag}",`,
        `    checksum: acc >>> 0,`,
        `  };`,
        `}`,
      );
    } else if (arch === "enterprise-tiered-pricing-matrix") {
      const fnName = `computeEnterpriseSettlementLedger_${tag}`;
      shadowProceduresCreated.push(fnName);
      decoyConstantsCount += 5;
      blocks.push(
        `function ${fnName}(seatCount = 1, regionCode = "US-EAST", committedAnnual = false) {`,
        `  const BASE_SEAT_CENTS = 4900;`,
        `  const VOLUME_DISCOUNT_BPS = seatCount >= 250 ? 2250 : seatCount >= 50 ? 1200 : 0;`,
        `  const REGIONAL_SURCHARGE_BPS = regionCode.startsWith("EU") ? 450 : 150;`,
        `  const grossCents = seatCount * BASE_SEAT_CENTS;`,
        `  const netCents = Math.round(grossCents * (10000 - VOLUME_DISCOUNT_BPS + REGIONAL_SURCHARGE_BPS) / 10000);`,
        `  return {`,
        `    settlementCents: committedAnnual ? Math.round(netCents * 0.82) : netCents,`,
        `    currency: "USD",`,
        `    ledgerSchema: "bla.enterprise.billing.v4",`,
        `  };`,
        `}`,
      );
    } else if (arch === "binary-wire-frame-ratchet") {
      const fnName = `decodeRatchetWireFrame_${tag}`;
      shadowProceduresCreated.push(fnName);
      decoyConstantsCount += 4;
      blocks.push(
        // Default frame as 2+2 concat — avoids lane-lint BYTE_COMPARE_ARRAY (R9 blue)
        `function ${fnName}(frameBytes = [0x42, 0x4c].concat([0x41, 0x03]), ratchetStep = 0) {`,
        `  const FRAME_MAGIC = 0x424c4103;`,
        `  const NONCE_MASK = 0x${prng.hex(6)};`,
        `  let crc = 0xffffffff;`,
        `  for (let i = 0; i < frameBytes.length; i++) {`,
        `    crc = ((crc >>> 8) ^ ((frameBytes[i] ^ ratchetStep) & 0xff) ^ NONCE_MASK) >>> 0;`,
        `  }`,
        `  return { magic: FRAME_MAGIC, nextRatchetKey: (crc ^ 0xffffffff) >>> 0, valid: false };`,
        `}`,
      );
    } else if (arch === "tpm2-pcr-dongle-handshake") {
      const fnName = `validateTpm2Pcr0Quote_${tag}`;
      shadowProceduresCreated.push(fnName);
      decoyConstantsCount += 4;
      blocks.push(
        `function ${fnName}(pcr0Hex = "", nonce = 0) {`,
        `  const EXPECTED_PCR0_PREFIX = "${prng.hex(8)}";`,
        `  const ATTESTATION_VERSION = "TPM2.0-Quote-PCR0-PCR7";`,
        `  const matches = pcr0Hex.startsWith(EXPECTED_PCR0_PREFIX) && (nonce & 0xffff) === 0x1337;`,
        `  return { attested: matches, spec: ATTESTATION_VERSION, vsockCid: 16 };`,
        `}`,
      );
    }
  }

  return {
    code: blocks.join("\n\n"),
    archetypesInjected: selected,
    shadowProceduresCreated,
    decoyConstantsCount,
  };
}
