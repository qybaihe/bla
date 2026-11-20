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
  | "dex-sidecar-host-verify-only"
  | "sqlite-sidecar-host-verify-only"
  | "sqlite-business-data-readable"
  | "sqlite-decoy-columns-evaluable"
  | "wasm-sidecar-host-verify-only"
  | "esm-import-hoist-before-hooks"
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
  /**
   * True when a JS/TS ES module entry has static import / export-from bindings
   * that the loader instantiates before a prepended sidecar / self-seal IIFE.
   */
  readonly esmImportHoistBeforeHooks?: boolean;
  /**
   * True when a same-directory Node CJS or ESM loader was auto-wired with
   * `entangleWasmLoaderWithSidecars` (or the hook is already present next to
   * the .wasm). Clears `wasm-sidecar-host-verify-only`.
   */
  readonly wasmSidecarLoaderHookApplied?: boolean;
  /**
   * True when a same-directory Python loader was auto-wired with
   * `entanglePycLoaderWithSidecars` (or the hook is already present next to
   * the .pyc). Clears `pyc-sidecar-host-verify-only`.
   */
  readonly pycSidecarLoaderHookApplied?: boolean;
  /**
   * True when a same-directory Python loader was auto-wired with
   * `entangleGgufLoaderWithSidecars` (or the hook is already present next to
   * the .gguf). Clears `gguf-sidecar-host-verify-only`.
   */
  readonly ggufSidecarLoaderHookApplied?: boolean;
  /**
   * True when a same-directory Python loader was auto-wired with
   * `entangleSafetensorsLoaderWithSidecars` (or the hook is already present
   * next to the .safetensors). Clears `safetensors-sidecar-host-verify-only`.
   */
  readonly safetensorsSidecarLoaderHookApplied?: boolean;
  /**
   * How a SQLite database's generated decoy columns are defined: `"eval"`
   * when they call the function no stock connection has (opt-in), otherwise
   * plain SQL. Unknown counts as plain SQL.
   */
  readonly sqliteTrapMode?: "none" | "stock" | "eval";
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
  "android-dex",
  "sqlite",
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
        "Opt-in sidecarEntangle strip⇒fail binding was not enabled (JS/Python preamble, WASM bla.sidecar.v1, Bun companion, .pyc import-time hook, or GGUF / Safetensors load-time hook); a host-only .pyc marshal trailer, GGUF STRING KV, or Safetensors __metadata__ note does not count. Default remains OFF (issue #40 / DESIGN).",
      scoreCap: 93,
    });
  }

  // .pyc marshal trailer is host-verify only (importlib ignores it) until a
  // same-directory Python import-time hook is actually auto-wired (or already
  // present) beside the module.
  if (
    input.detectedFormat === "python-pyc" &&
    input.sidecarEntangleEnabled === true &&
    input.pycSidecarLoaderHookApplied !== true
  ) {
    gaps.push({
      id: "pyc-sidecar-host-verify-only",
      summary:
        "sidecarEntangle planted a .pyc TYPE_ASCII marshal trailer verified by host verifyPycSidecarMarshalNote; importlib ignores the trailer unless a same-directory Python loader (loader.py / __init__.py / __main__.py) was auto-wired with the import-time hook (issue #40 / DESIGN).",
      scoreCap: 93,
    });
  }

  // GGUF STRING KV is host-verify only (loaders ignore unknown metadata keys)
  // until a same-directory Python load-time hook is actually auto-wired (or
  // already present) beside the model.
  if (
    input.detectedFormat === "model-gguf" &&
    input.sidecarEntangleEnabled === true &&
    input.ggufSidecarLoaderHookApplied !== true
  ) {
    gaps.push({
      id: "gguf-sidecar-host-verify-only",
      summary:
        "sidecarEntangle planted a GGUF bla.sidecar.v1 STRING metadata note verified by host verifyGgufSidecarMetadataNote; GGUF loaders still load after strip or sibling delete unless a same-directory Python loader (loader.py / __init__.py / __main__.py) was auto-wired with the load-time hook (issue #40 / DESIGN).",
      scoreCap: 93,
    });
  }

  // Safetensors __metadata__ KV is host-verify only (loaders ignore unknown
  // __metadata__ keys) until a same-directory Python load-time hook is
  // actually auto-wired (or already present) beside the model.
  if (
    input.detectedFormat === "model-safetensors" &&
    input.sidecarEntangleEnabled === true &&
    input.safetensorsSidecarLoaderHookApplied !== true
  ) {
    gaps.push({
      id: "safetensors-sidecar-host-verify-only",
      summary:
        "sidecarEntangle planted a Safetensors __metadata__ bla.sidecar.v1 note verified by host verifySafetensorsSidecarMetadataNote; Safetensors loaders still load tensors after strip or sibling delete unless a same-directory Python loader (loader.py / __init__.py / __main__.py) was auto-wired with the load-time hook (issue #40 / DESIGN).",
      scoreCap: 93,
    });
  }

  // DEX string-pool note is host-verify only (ART/Dalvik ignore unreferenced strings).
  if (input.detectedFormat === "android-dex" && input.sidecarEntangleEnabled === true) {
    gaps.push({
      id: "dex-sidecar-host-verify-only",
      summary:
        "sidecarEntangle planted a DEX bla.sidecar.v1 string-pool note verified only by host verifyDexSidecarStringPoolNote; ART/Dalvik still load after strip or sibling delete. Load-time hook TBD — do not treat this as process-start strip⇒fail (issue #40 / DESIGN).",
      scoreCap: 93,
    });
  }

  // SQLite schema-comment view is host-verify only (SQLite ignores the unused WHERE 0 view).
  if (input.detectedFormat === "sqlite" && input.sidecarEntangleEnabled === true) {
    gaps.push({
      id: "sqlite-sidecar-host-verify-only",
      summary:
        "sidecarEntangle planted a SQLite bla.sidecar.v1 schema-comment view verified only by host verifySqliteSidecarSchemaComment; SQLite still opens after strip or sibling delete. Load-time hook TBD — do not treat this as process-start strip⇒fail (issue #40 / DESIGN).",
      scoreCap: 93,
    });
  }

  // The SQLite shield decorates a database; it hides nothing in it.
  if (input.detectedFormat === "sqlite") {
    gaps.push({
      id: "sqlite-business-data-readable",
      summary:
        "The SQLite shield adds honey tables and decoy rows beside the application's own tables, which are stored exactly as before: any SQLite client reads them. This is decoration, not confidentiality — keep secrets out of a shipped database, or encrypt it (SQLCipher, application-layer encryption).",
      scoreCap: 78,
    });
    if (input.sqliteTrapMode !== "eval") {
      gaps.push({
        id: "sqlite-decoy-columns-evaluable",
        summary:
          "The honey tables' generated columns are plain SQL (the default), so an inspector reads those tables like any other. The form that makes that read fail is opt-in (sqlite_eval_trap / --sqlite-eval-trap) because it also breaks PRAGMA integrity_check, VACUUM and dump/restore for the application.",
        scoreCap: 68,
      });
    }
  }

  // Standalone WASM custom-section is host-verify only until a Node CJS/ESM
  // loader hook is actually auto-wired (or already present) beside the module.
  if (
    input.detectedFormat === "wasm" &&
    input.sidecarEntangleEnabled === true &&
    input.wasmSidecarLoaderHookApplied !== true
  ) {
    gaps.push({
      id: "wasm-sidecar-host-verify-only",
      summary:
        "sidecarEntangle planted a WASM bla.sidecar.v1 custom section verified by host verifyWasmSidecarCustomSection; WebAssembly.instantiate ignores custom sections unless a same-directory Node CJS or ESM (builtin-only imports) loader was auto-wired with the load-time hook (issue #40 / DESIGN).",
      scoreCap: 93,
    });
  }

  // ESM static import / export-from bindings evaluate before any statement in
  // the entry, including a prepended sidecarEntangle / self-seal IIFE. The
  // entry body still fail-closes, but imported module side effects already ran.
  if (
    JS_LIKE.has(input.detectedFormat) &&
    (input.sidecarEntangleEnabled === true || input.selfSealEnabled === true) &&
    input.esmImportHoistBeforeHooks === true
  ) {
    gaps.push({
      id: "esm-import-hoist-before-hooks",
      summary:
        "ES module static import / export-from bindings evaluate before the prepended sidecarEntangle or self-seal IIFE, so imported module side effects still run after a sidecar strip or hook failure. Entry-body fail-closed is not process-start for the hoisted graph (issue #40 / DESIGN).",
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
