import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { REA_INTERNAL_LIMITS } from "../../identity.js";
import type { VirtualAsarFile } from "../formats/asar.js";

/**
 * REA ASAR header admission limits — values centralized in
 * `REA_INTERNAL_LIMITS` (`src/identity.ts`) so `verify:rea` drift checks cover
 * them alongside every other REA constant.
 */
export const REA_ASAR_HEADER_LIMITS = {
  DEFAULT_ASAR_MAX_HEADER_BYTES: REA_INTERNAL_LIMITS.ASAR_DEFAULT_MAX_HEADER_BYTES,
  MAXIMUM_ASAR_MAX_HEADER_BYTES: REA_INTERNAL_LIMITS.ASAR_MAXIMUM_MAX_HEADER_BYTES,
} as const;

export interface AsarHeaderAmplificationPlan {
  readonly files: readonly VirtualAsarFile[];
  readonly estimatedHeaderBytes: number;
  readonly exceedsDefaultAdmission: boolean;
}

/**
 * Generates virtual decoy enclave manifest entries inside an Electron `.asar`
 * archive so REA's `admitAsarHeader` trips `DEFAULT_ASAR_MAX_HEADER_BYTES`
 * (16 MiB) at bankrupt intensity. Paths are long and bodies tiny so the Pickle
 * JSON header dominates — inventory growth without mutating real app modules.
 */
export function generateAsarHeaderDecoyFiles(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): readonly VirtualAsarFile[] {
  return planAsarHeaderAmplification(prng, intensity).files;
}

export function planAsarHeaderAmplification(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): AsarHeaderAmplificationPlan {
  // bankrupt: ~4000 × ~4 KiB paths → header ≳ 17 MiB (> DEFAULT 16 MiB).
  // lower intensities: inventory chaff only (header stays well under admission).
  const count =
    intensity === "stealth"
      ? 4
      : intensity === "balanced"
        ? 8
        : intensity === "maximum"
          ? 64
          : 4000;
  const pathPadLen =
    intensity === "stealth"
      ? 24
      : intensity === "balanced"
        ? 48
        : intensity === "maximum"
          ? 256
          : 4096;
  const tag = prng.hex(3);
  const pad = "a".repeat(pathPadLen);
  const files: VirtualAsarFile[] = [];

  for (let i = 0; i < count; i++) {
    const relPath = `enclave/shards/ring0-slot-${tag}-${pad}_${i}.json`;
    const body = JSON.stringify({
      shardId: i,
      enclaveCid: 16,
      attestationHash: prng.hex(8),
      delegated: true,
    });
    files.push({
      relativePath: relPath,
      content: Buffer.from(body, "utf8"),
    });
  }

  // Conservative estimate: path + JSON entry overhead (~80 bytes framing).
  const estimatedHeaderBytes = files.reduce(
    (sum, f) => sum + f.relativePath.length + 80 + f.content.length,
    64,
  );

  return {
    files,
    estimatedHeaderBytes,
    exceedsDefaultAdmission:
      estimatedHeaderBytes > REA_ASAR_HEADER_LIMITS.DEFAULT_ASAR_MAX_HEADER_BYTES,
  };
}
