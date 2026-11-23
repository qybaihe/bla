import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { ASAR_DECOY_DIRECTORY, type VirtualAsarFile } from "../formats/asar.js";

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
 * (16 MiB) at bankrupt intensity. The Pickle JSON header grows through more
 * members with portable basenames and small bodies.
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
  // At bankrupt intensity, basenames and integrity metadata alone
  // contribute more than 16 MiB to the header.
  // lower intensities: inventory chaff only (header stays well under admission).
  const count =
    intensity === "stealth"
      ? 4
      : intensity === "balanced"
        ? 8
        : intensity === "maximum"
          ? 64
          : 48_000;
  const pathPadLen =
    intensity === "stealth"
      ? 24
      : intensity === "balanced"
        ? 48
        : intensity === "maximum"
          ? 140
          : 150;
  const tag = prng.hex(3);
  const pad = "a".repeat(pathPadLen);
  const files: VirtualAsarFile[] = [];
  const directory = "enclave/shards";

  for (let i = 0; i < count; i++) {
    const batch = Math.floor(i / 256);
    const relPath = `${directory}/batch-${batch}/ring0-slot-${tag}-${pad}_${i}.json`;
    const body = JSON.stringify({
      shardId: i,
      enclaveCid: 16,
      attestationHash: prng.hex(8),
      delegated: true,
    });
    files.push({
      relativePath: relPath,
      content: Buffer.from(body, "utf8"),
      [ASAR_DECOY_DIRECTORY]: directory,
    });
  }

  // Lower bound using each basename and the packed-file integrity record.
  const estimatedHeaderBytes = files.reduce(
    (sum, f) => sum + f.relativePath.slice(f.relativePath.lastIndexOf("/") + 1).length + 185,
    64,
  );

  return {
    files,
    estimatedHeaderBytes,
    exceedsDefaultAdmission:
      estimatedHeaderBytes > REA_ASAR_HEADER_LIMITS.DEFAULT_ASAR_MAX_HEADER_BYTES,
  };
}
