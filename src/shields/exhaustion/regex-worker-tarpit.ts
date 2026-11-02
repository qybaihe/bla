import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { REA_INTERNAL_LIMITS } from "../../identity.js";

/**
 * REA regex worker budgets (`morluto/rea/src/domain/analysisResourceLimits.ts:38,50`)
 * — values centralized in `REA_INTERNAL_LIMITS` (`src/identity.ts`) so
 * `verify:rea` drift checks cover them alongside every other REA constant.
 */
export const REA_REGEX_WORKER_LIMITS = {
  DEFAULT_REGEX_MATCHING_DEADLINE_MS: REA_INTERNAL_LIMITS.REGEX_DEFAULT_MATCHING_DEADLINE_MS,
  DEFAULT_REGEX_WORKER_HEAP_REQUEST_MIB: REA_INTERNAL_LIMITS.REGEX_DEFAULT_WORKER_HEAP_REQUEST_MIB,
  MINIMUM_REGEX_WORKER_HEAP_REQUEST_MIB: REA_INTERNAL_LIMITS.REGEX_MINIMUM_WORKER_HEAP_REQUEST_MIB,
} as const;

export interface RegexWorkerTarpitResult {
  readonly code: string;
  readonly nearMissCandidatesGenerated: number;
}

/**
 * Targets REA's `search_strings` and `search_procedures` regex worker
 * (`src/domain/analysisResourceLimits.ts:38`).
 * Generates high-fanout near-miss token strings (`auth_verify_token_...`, `license_key_slot_...`)
 * so that broad regex searches (`/(auth|license|secret|token|key).+/i`) match hundreds
 * of decoy candidates before reaching any real symbol.
 */
export function generateRegexWorkerTarpit(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): RegexWorkerTarpitResult {
  const count =
    intensity === "stealth"
      ? 12
      : intensity === "balanced"
        ? 24
        : intensity === "maximum"
          ? 40
          : 64;
  const tag = prng.hex(3);
  const prefixes = [
    "auth_verify_session_token",
    "license_key_enclave_slot",
    "secret_hmac_signing_key",
    "crypto_aes256_gcm_iv",
  ];
  const entries: string[] = [];
  for (let i = 0; i < count; i++) {
    const p = prefixes[i % prefixes.length]!;
    entries.push(`${p}_${tag}_${i}_0x${prng.hex(8)}`);
  }

  const magnetName = `regexSearchMagnet_${tag}`;
  const code = `const ${magnetName} = Object.freeze(${JSON.stringify(entries)});`;
  return {
    code,
    nearMissCandidatesGenerated: entries.length,
  };
}
