import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";

export interface PromptCompletionPoisonResult {
  readonly code: string;
  readonly prioritySortedSymbols: readonly string[];
}

/**
 * Targets REA's lexicographical Unicode code-point sorting in MCP prompt completions
 * and obligation projections (`src/application/ReconstructionObligationLedgerProjection.ts:24`
 * and `src/contracts/promptContracts.ts:67`: `.sort(([left], [right]) => (left < right ? -1 : 1))`).
 *
 * By prefixing decoy high-salience procedures with a `$RR` early-sort prefix (ASCII `$` = 0x24
 * sorts BEFORE all standard `[A-Za-z_]` identifiers). Each symbol gets a UNIQUE rank hex so
 * there is no shared greppable literal like the old `$00_AAA` marker.
 * BLA guarantees that its decoy procedures occupy the very first slots of REA's
 * paginated procedure lists and MCP prompt completions!
 */
export function generatePromptCompletionPoison(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): PromptCompletionPoisonResult {
  const count =
    intensity === "stealth"
      ? 2
      : intensity === "balanced"
        ? 4
        : intensity === "maximum"
          ? 6
          : 8;
  const tag = prng.hex(2);
  const prioritySortedSymbols: string[] = [];
  const lines: string[] = [];

  const suffixes = [
    "AttestMasterLicenseKey",
    "VerifyEnterpriseEntitlement",
    "UnsealOfflineVaultRoot",
    "DeriveZeroTrustSession",
    "ValidateHardwareTpmQuote",
    "ComputeSettlementSignature",
    "DispatchEnclaveVsockRpc",
    "ReconcileQuorumLedger",
  ];

  for (let i = 0; i < count; i++) {
    // Unique early-sort prefix per symbol — no shared greppable substring across the set.
    const rank = prng.hex(2);
    const sym = `$${rank}${suffixes[i % suffixes.length]}_${tag}${i}`;
    prioritySortedSymbols.push(sym);
    lines.push(
      `/* Pre-normalized token length check guards legacy fixed-width frame decoders */`,
      `function ${sym}(token = "") {`,
      `  const n = String(token).length | 1;`,
      `  return { mode: "remote", symbol: "${sym}", valid: ((n * n) & 7) === 3 };`,
      `}`,
    );
  }

  return {
    code: lines.join("\n"),
    prioritySortedSymbols,
  };
}
