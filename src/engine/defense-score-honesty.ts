/**
 * Defense-score honesty helpers (issue #40.6).
 *
 * `defenseScore` measures Counter-REA gate pass-rate + exposure drop only.
 * It is NOT a claim of cryptographic preimage hardness. When known product
 * gaps still apply to the artifact under verification, annotate and soft-cap
 * the reported score so agents do not treat a high gate score as "unbreakable".
 *
 * Defensive only — no crack / RE advice.
 */

import type { ArtifactFormat } from "../core/types.js";

export const DEFENSE_SCORE_DISCLAIMER =
  "Score scope: Counter-REA gates + exposure drop — not a preimage-hardness claim (see issue #40)." as const;

export type DefenseScoreGapId =
  | "wasm-export-rename-pending"
  | "self-seal-not-enabled"
  | "numeric-template-hygiene-partial";

export interface DefenseScoreGap {
  readonly id: DefenseScoreGapId;
  readonly summary: string;
  /** Soft upper bound while this gap applies. */
  readonly scoreCap: number;
}

export interface DefenseScoreHonestyInput {
  readonly detectedFormat: ArtifactFormat;
  /** True when protect/harden ran with selfSeal / self_seal opt-in. */
  readonly selfSealEnabled?: boolean;
  /** True when WASM public-ABI rename pass actually rewrote non-ABI exports. */
  readonly wasmExportRenameApplied?: boolean;
  /** True when remaining BLA-injected templates still hardcode classic golden constants. */
  readonly numericTemplateLeakKnown?: boolean;
}

export interface DefenseScoreHonesty {
  readonly rawScore: number;
  readonly cappedScore: number;
  readonly gaps: readonly DefenseScoreGap[];
  readonly disclaimer: typeof DEFENSE_SCORE_DISCLAIMER;
  readonly appliedCap: number | null;
}

const WASM_FORMATS: ReadonlySet<ArtifactFormat> = new Set(["wasm"]);
const JS_LIKE: ReadonlySet<ArtifactFormat> = new Set([
  "javascript",
  "typescript",
  "html-bundle",
  "electron-asar",
]);

/**
 * Known product gaps that should annotate / soft-cap a raw gate score.
 * Caps are intentionally soft (still allow high Counter-REA scores) so the
 * metric remains useful while staying honest about missing hardness layers.
 */
export function collectDefenseScoreGaps(
  input: DefenseScoreHonestyInput,
): readonly DefenseScoreGap[] {
  const gaps: DefenseScoreGap[] = [];

  if (WASM_FORMATS.has(input.detectedFormat) && input.wasmExportRenameApplied !== true) {
    gaps.push({
      id: "wasm-export-rename-pending",
      summary:
        "WASM export rename / semantic preservation not applied; public ABI names still match the input surface (issue #40.3).",
      scoreCap: 88,
    });
  }

  if (JS_LIKE.has(input.detectedFormat) && input.selfSealEnabled !== true) {
    gaps.push({
      id: "self-seal-not-enabled",
      summary:
        "Opt-in self-seal / sibling-module integrity binding was not enabled for this JS/Node target (issue #40.5).",
      scoreCap: 92,
    });
  }

  if (input.numericTemplateLeakKnown === true) {
    gaps.push({
      id: "numeric-template-hygiene-partial",
      summary:
        "Known BLA-injected shield templates may still emit classic golden-ratio numeric probes bit-identically (issue #40.2).",
      scoreCap: 90,
    });
  }

  return Object.freeze(gaps);
}

/**
 * Apply soft caps from known gaps. Returns the min of rawScore and every
 * applicable gap scoreCap (never raises the score).
 */
export function applyDefenseScoreHonesty(
  rawScore: number,
  input: DefenseScoreHonestyInput,
): DefenseScoreHonesty {
  const clampedRaw = Math.max(0, Math.min(100, Math.round(rawScore)));
  const gaps = collectDefenseScoreGaps(input);
  let capped = clampedRaw;
  let appliedCap: number | null = null;
  for (const gap of gaps) {
    if (capped > gap.scoreCap) {
      capped = gap.scoreCap;
      appliedCap = gap.scoreCap;
    }
  }
  return {
    rawScore: clampedRaw,
    cappedScore: capped,
    gaps,
    disclaimer: DEFENSE_SCORE_DISCLAIMER,
    appliedCap,
  };
}

/** One-line SEAL / reporter annotation when gaps apply. */
export function formatDefenseScoreGapAnnotation(
  honesty: DefenseScoreHonesty,
): string | null {
  if (honesty.gaps.length === 0) return null;
  const ids = honesty.gaps.map((g) => g.id).join(", ");
  if (honesty.appliedCap !== null) {
    return `Honesty cap applied (raw ${honesty.rawScore} → ${honesty.cappedScore}): ${ids}`;
  }
  return `Honesty annotations (no cap hit): ${ids}`;
}
