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
  | "sidecar-entangle-not-enabled"
  | "pyc-sidecar-host-verify-only"
  | "gguf-sidecar-host-verify-only"
  | "safetensors-sidecar-host-verify-only"
  | "wasm-sidecar-host-verify-only"
  | "numeric-template-hygiene-partial"
  | "native-postlink-cfg-untouched"
  | "native-trailer-unmapped";

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
  /** True when protect/harden ran with sidecarEntangle / sidecar_entangle opt-in. */
  readonly sidecarEntangleEnabled?: boolean;
  /** True when WASM public-ABI rename pass actually rewrote non-ABI exports. */
  readonly wasmExportRenameApplied?: boolean;
  /** True when remaining BLA-injected templates still hardcode classic golden constants. */
  readonly numericTemplateLeakKnown?: boolean;
  /** For post-link native binaries: true when decoys were planted into a mapped PT_LOAD / COFF section, false when trailer-only. */
  readonly nativeMappedSectionInjected?: boolean;
}

export interface DefenseScoreHonesty {
  readonly rawScore: number;
  readonly cappedScore: number;
  readonly gaps: readonly DefenseScoreGap[];
  readonly disclaimer: typeof DEFENSE_SCORE_DISCLAIMER;
  readonly appliedCap: number | null;
}

const WASM_FORMATS: ReadonlySet<ArtifactFormat> = new Set(["wasm"]);
const NATIVE_FORMATS: ReadonlySet<ArtifactFormat> = new Set([
  "native-elf",
  "native-macho",
  "native-pe",
]);
const JS_LIKE: ReadonlySet<ArtifactFormat> = new Set([
  "javascript",
  "typescript",
  "html-bundle",
  "electron-asar",
]);

/** Formats that already ship an opt-in sidecarEntangle strip⇒fail hook. */
const SIDECAR_ENTANGLE_FORMATS: ReadonlySet<ArtifactFormat> = new Set([
  "javascript",
  "typescript",
  "html-bundle",
  "electron-asar",
  "wasm",
  "python-source",
  "python-pyc",
  "model-gguf",
  "model-safetensors",
  "native-elf",
  "native-macho",
  "native-pe",
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

  if (
    SIDECAR_ENTANGLE_FORMATS.has(input.detectedFormat) &&
    input.sidecarEntangleEnabled !== true
  ) {
    gaps.push({
      id: "sidecar-entangle-not-enabled",
      summary:
        "Opt-in sidecarEntangle strip⇒fail binding was not enabled (JS/Python preamble, WASM bla.sidecar.v1, Bun companion, .pyc import-time hook, or GGUF load-time hook); a host-only .pyc marshal trailer or GGUF STRING KV does not count. Default remains OFF (issue #40 / DESIGN).",
      scoreCap: 93,
    });
  }

  // .pyc marshal trailer is host-verify only (importlib ignores it). Enabling
  // sidecarEntangle must not clear the process-start strip⇒fail gap.
  if (input.detectedFormat === "python-pyc" && input.sidecarEntangleEnabled === true) {
    gaps.push({
      id: "pyc-sidecar-host-verify-only",
      summary:
        "sidecarEntangle planted a .pyc TYPE_ASCII marshal trailer verified only by host verifyPycSidecarMarshalNote; importlib still runs after strip or sibling delete. Import-time hook TBD — do not treat this as process-start strip⇒fail (issue #40 / DESIGN).",
      scoreCap: 93,
    });
  }

  // GGUF STRING KV is host-verify only (loaders ignore unknown metadata keys).
  if (input.detectedFormat === "model-gguf" && input.sidecarEntangleEnabled === true) {
    gaps.push({
      id: "gguf-sidecar-host-verify-only",
      summary:
        "sidecarEntangle planted a GGUF bla.sidecar.v1 STRING metadata note verified only by host verifyGgufSidecarMetadataNote; GGUF loaders still load after strip or sibling delete. Load-time hook TBD — do not treat this as process-start strip⇒fail (issue #40 / DESIGN).",
      scoreCap: 93,
    });
  }

  // Safetensors __metadata__ KV is host-verify only (loaders ignore unknown __metadata__ keys).
  if (input.detectedFormat === "model-safetensors" && input.sidecarEntangleEnabled === true) {
    gaps.push({
      id: "safetensors-sidecar-host-verify-only",
      summary:
        "sidecarEntangle planted a Safetensors __metadata__ bla.sidecar.v1 note verified only by host verifySafetensorsSidecarMetadataNote; Safetensors loaders still load tensors after strip or sibling delete (issue #40 / DESIGN).",
      scoreCap: 93,
    });
  }

  // Standalone WASM custom-section is host-verify only until the host JS loader calls verifyWasmSidecarCustomSection.
  if (input.detectedFormat === "wasm" && input.sidecarEntangleEnabled === true) {
    gaps.push({
      id: "wasm-sidecar-host-verify-only",
      summary:
        "sidecarEntangle planted a WASM bla.sidecar.v1 custom section verified by host verifyWasmSidecarCustomSection; WebAssembly.instantiate ignores custom sections unless your JS/host loader enforces verification before instantiation (issue #40 / DESIGN).",
      scoreCap: 93,
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

  if (NATIVE_FORMATS.has(input.detectedFormat)) {
    gaps.push({
      id: "native-postlink-cfg-untouched",
      summary:
        "Post-link native binary shield plants Counter-REA section/metadata decoys without rewriting compiled .text control flow, .dynsym exports, or .init_array; include compile-time headers via bla emit-headers (bla_shield.h / .rs / .go) for in-CFG native tarpits (issue #176).",
      scoreCap: 78,
    });
    if (input.nativeMappedSectionInjected === false) {
      gaps.push({
        id: "native-trailer-unmapped",
        summary:
          "Native shield decoys reside only in an unmapped post-section EOF trailer outside PT_LOAD / COFF sections (strippable via file truncation; issue #176).",
        scoreCap: 68,
      });
    }
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
