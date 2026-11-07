export type ArtifactFormat =
  | "javascript"
  | "typescript"
  | "electron-asar"
  | "sourcemap"
  | "html-bundle"
  | "wasm"
  | "python-source"
  | "python-pyc"
  | "native-elf"
  | "native-macho"
  | "native-pe"
  | "dotnet-managed"
  | "apple-plist"
  | "jvm-class"
  | "sqlite"
  | "model-safetensors"
  | "model-gguf"
  | "android-dex"
  | "il2cpp-metadata"
  | "archive-zip"
  | "android-apk"
  | "erlang-beam"
  | "evm-bytecode"
  | "pcap-capture"
  | "gpu-ptx"
  | "firmware-uf2"
  | "directory"
  | "unknown";

export type ProtectionIntensity = "stealth" | "balanced" | "maximum" | "bankrupt";

export type ReaAttackVectorId =
  | "js-static-semantics"
  | "electron-ipc-bridge"
  | "electron-fuses-inspection"
  | "runtime-cdp-frida-reconciliation"
  | "js-route-rpc-inventory"
  | "sourcemap-recovery"
  | "call-graph-tracing"
  | "obligation-ledger-cloning"
  | "wasm-wat-interface"
  | "python-pyc-marshal"
  | "native-go-buildinfo"
  | "native-rust-auditable"
  | "native-decompiler-pseudocode"
  | "flutter-dart-aot-snapshot"
  | "dotnet-managed-budget"
  | "apple-plist-budget"
  | "jvm-bytecode-decompilation"
  | "sqlite-database-inspection"
  | "model-artifact-inspection"
  | "android-dex-il2cpp-inspection"
  | "archive-inventory"
  | "asar-header-admission"
  | "erlang-beam-inspection"
  | "evm-bytecode-inspection"
  | "pcap-capture-inspection"
  | "gpu-ptx-inspection"
  | "uf2-firmware-inspection"
  | "bun-standalone-module-graph";

export interface ExposedSymbolOrModule {
  readonly id: string;
  readonly name: string;
  readonly kind:
    | "function"
    | "class"
    | "export"
    | "ipc-channel"
    | "route"
    | "rpc-endpoint"
    | "wasm-export"
    | "pyc-code-object"
    | "native-symbol"
    | "metadata-section"
    | "sourcemap-source"
    | "sqlite-table"
    | "model-tensor"
    | "electron-fuse"
    | "dex-class";
  readonly location: string;
  readonly riskLevel: "critical" | "high" | "medium" | "low";
  readonly reaToolUsed: string;
  readonly estimatedTokensToReconstruct: number;
  readonly estimatedCostUsd: number;
  readonly reason: string;
}

export interface ReaSemanticSimulationResult {
  readonly parseStatus: "complete" | "recovered" | "failed";
  readonly examinationStatus: "complete" | "limited";
  readonly triggeredResourceLimits: readonly string[];
  readonly semanticUncertainties: readonly string[];
  readonly visitedAstNodes: number;
  readonly totalFunctions: number;
  readonly decoyFunctionsDetectedAsReal: number;
  readonly staticStringsResolved: number;
  readonly staticStringsOpaque: number;
  readonly ipcChannelsTotal: number;
  readonly ipcChannelsPairedUniquely: number;
  readonly ipcChannelsAmbiguousOrDynamic: number;
  readonly routesDiscovered: number;
  readonly decoyRoutesHarvested: number;
  readonly obligationLedgerNodes: number;
  readonly architecturalChaffPayloads: number;
}

export interface AgentCostEstimate {
  readonly modelName: string;
  readonly estimatedInputTokens: number;
  readonly estimatedOutputTokens: number;
  readonly estimatedMcpToolCalls: number;
  readonly estimatedWallClockSeconds: number;
  readonly estimatedCostUsd: number;
  readonly contextWindowOverflowProbability: number;
  readonly outcomeVerdict:
    | "TRIVIAL_CLONE"
    | "MODERATE_EFFORT"
    | "HIGH_FRICTION"
    | "AGENT_HALLUCINATION_AND_BANKRUPTCY";
}

export interface AuditReport {
  readonly targetPath: string;
  readonly detectedFormat: ArtifactFormat;
  readonly sha256: string;
  readonly byteSize: number;
  readonly timestamp: string;
  readonly exposureScore: number; // 0 (fully shielded) to 100 (completely exposed to REA)
  readonly protectionStatus: "UNPROTECTED" | "PARTIALLY_SHIELDED" | "BLA_PROTECTED";
  readonly reaSimulation: ReaSemanticSimulationResult;
  readonly exposedItems: readonly ExposedSymbolOrModule[];
  readonly vulnerableReaVectors: readonly ReaAttackVectorId[];
  readonly agentEstimates: readonly AgentCostEstimate[];
  readonly headlineWarning: string;
  readonly recommendedCommand: string;
  /** Entries skipped while walking a directory tree (depth/entry/file-size bounds). */
  readonly walkSkipped?: { directories: number; files: number; bytes: number };
}

export interface ProtectionOptions {
  readonly inputPath: string;
  readonly outputPath?: string;
  readonly inPlace?: boolean;
  readonly intensity?: ProtectionIntensity;
  readonly seed?: string | number;
  readonly tarpitDecoyCount?: number;
  readonly tarpitDepth?: number;
  readonly chaffPayloads?: boolean;
  readonly breakSemanticBudgets?: boolean;
  readonly protectElectronIpc?: boolean;
  readonly injectRouteMirage?: boolean;
  readonly honeySourceMaps?: boolean;
  readonly runtimeDeception?: boolean;
  /**
   * When true, embed opt-in risky LLM directive layers (fake COPPA/medical notices,
   * dual-use imitation vocabulary, in-band AI chat markers). Default false.
   */
  readonly llmDirectives?: boolean;
  /**
   * When true, activate weave-decoy entanglement: JS AST weave (always) plus
   * structural Python customer-def weave (shared-slot + opaque-false decoy xref).
   * When false, Python stays warm-init-only. Default false.
   */
  readonly weaveDecoys?: boolean;
  /**
   * Opt-in self-seal / sibling-module integrity binding for JS/Node targets (issue #40.5).
   * When true, harden/protect inject a self-integrity preamble and entangle the opaque seed.
   */
  readonly selfSeal?: boolean;
  /**
   * WASM public ABI export names to keep when rename runs (issue #40.3).
   * At maximum/bankrupt every non-listed export is renamed by default —
   * preserving a stable ABI requires an explicit list.
   */
  readonly wasmPreserveExports?: readonly string[];
  /**
   * When true, allow protecting JS/TS that looks lane-independent (issue #40.1).
   * Default false: protect/defend/harden refuse such gates (red-blue round-1).
   */
  readonly allowLaneIndependentGates?: boolean;
  /**
   * When true, allow bankrupt harden/protect despite plaintext/reversible seal
   * sidecars (red-blue round-2). Default false — refuse.
   */
  readonly allowPlaintextSeal?: boolean;
  /**
   * When true, allow bankrupt harden/protect despite clear WASM param/cipher
   * ASCII carriers (R3PARM/R3CIPH/R2SEAL-class; red-blue round-3). Default false — refuse.
   */
  readonly allowWasmClearParamCarriers?: boolean;
  /**
   * When true, keep stable `__vaultPanelDerive_*` ABI (skip rewrite/refuse).
   * Default false — maximum/bankrupt rewrite to seed-stable `_blaPd_*` (red-blue round-3).
   */
  readonly allowStablePanelDeriveAbi?: boolean;
  /**
   * When true, allow bankrupt harden/protect despite JS AES wrap-key +
   * create*iv + fixed sealed-hdr unwrap footguns (red-blue round-4). Default false — refuse.
   * This is a gate only — not white-box AES.
   */
  readonly allowJsAesUnwrap?: boolean;
  /**
   * When true, allow bankrupt harden/protect despite panel deriveLocal +
   * plaintext panelTokenSha256 offline-oracle packaging (red-blue round-4). Default false — refuse.
   */
  readonly allowPanelOfflineOracle?: boolean;
  /**
   * When true, allow bankrupt harden/protect despite JS←WASM hydrate memory
   * dumps of salt/rounds/cipher (red-blue round-5). Default false — refuse.
   */
  readonly allowJsWasmHydrateDump?: boolean;
  /** Red/blue round-6: allow WASM XOR-mask-beside-blob entitlement packs under bankrupt/maximum. */
  readonly allowWasmXorMaskSidecar?: boolean;
  readonly allowWasmSealXorKnownPlaintext?: boolean;
  /**
   * Optional sibling paths for self-seal when `selfSeal` is true (multi-artifact harden).
   * Relative paths are resolved from the protected module's directory at runtime.
   */
  readonly selfSealSiblingPaths?: readonly string[];
  /**
   * Opt-in sidecar/entry entanglement (issue #40 / Direction-3). When true and
   * `sidecarEntanglePaths` is non-empty, JS/Python protect inserts a strip⇒fail
   * preamble that re-measures sibling sidecar bytes. OFF by default.
   */
  readonly sidecarEntangle?: boolean;
  /**
   * Sibling sidecar paths (relative to the protected module dir, or absolute)
   * measured by the strip⇒fail preamble when `sidecarEntangle` is true.
   */
  readonly sidecarEntanglePaths?: readonly string[];
  /** Soft-fold mismatch into opaque seed instead of hard throw. Default false. */
  readonly sidecarEntangleSoftFold?: boolean;
}

export interface ProtectionMetrics {
  readonly originalBytes: number;
  readonly protectedBytes: number;
  readonly decoyFunctionsInjected: number;
  readonly fakeCrossReferencesCreated: number;
  readonly primitiveCandidateBranchesCreated: number;
  readonly aliasSelectionStatesCreated: number;
  readonly ipcAmbiguitySitesInjected: number;
  readonly decoyRoutesInjected: number;
  readonly chaffPayloadsEmbedded: number;
  readonly honeySourceMapsGenerated: number;
  /** Inline `<script>` bodies the AST shield threw on and shipped unchanged — surfaced so partial HTML protection is never silent. */
  readonly inlineScriptsFailed: number;
  readonly binarySectionsPatched: number;
}

export interface ProtectionResult {
  readonly inputPath: string;
  readonly outputPath: string;
  readonly detectedFormat: ArtifactFormat;
  readonly intensity: ProtectionIntensity;
  /** Present when protect was called with weaveDecoys:true (Python customer-def weave active). */
  readonly weaveDecoys?: boolean;
  /** Present when protect was called with selfSeal:true (JS self-integrity binding active). */
  readonly selfSeal?: boolean;
  /** Present when protect applied sidecar entry entanglement (strip⇒fail preamble). */
  readonly sidecarEntangle?: boolean;
  /** Present when WASM export rename actually rewrote at least one non-preserved export (#40.3). */
  readonly wasmExportRenameApplied?: boolean;
  /** Present when WASM export-section order was seed-shuffled (red-blue round-11). */
  readonly wasmExportOrderShuffled?: boolean;
  /** Count of long-name decoy export aliases injected (red-blue round-10/12 hygiene). */
  readonly wasmExportDecoysInjected?: number;
  readonly seed: string;
  readonly originalSha256: string;
  readonly protectedSha256: string;
  readonly metrics: ProtectionMetrics;
  readonly counteredReaVectors: readonly ReaAttackVectorId[];
  readonly beforeAudit: AuditReport;
  readonly afterAudit: AuditReport;
  readonly elapsedMs: number;
}

export interface VerificationCheck {
  readonly id: string;
  readonly name: string;
  readonly targetReaComponent: string;
  readonly passed: boolean;
  readonly details: string;
}

/** Soft-cap annotation when known product gaps still apply (issue #40.6). */
export interface DefenseScoreGapAnnotation {
  readonly id: string;
  readonly summary: string;
  readonly scoreCap: number;
}

export interface VerificationAgentAction {
  readonly id: string;
  readonly priority: "high" | "medium";
  readonly reason: string;
  readonly instruction: string;
  readonly recommendedMcpTool: string;
  readonly recommendedArgs?: Readonly<Record<string, unknown>>;
}

export interface VerificationReport {
  readonly targetPath: string;
  readonly originalPath?: string;
  readonly detectedFormat: ArtifactFormat;
  readonly overallPassed: boolean;
  /** Soft-capped Counter-REA gate score (0–100). Not a preimage-hardness claim. */
  readonly defenseScore: number;
  /** Raw gate score before honesty soft-caps (issue #40.6). */
  readonly defenseScoreRaw?: number;
  /** Known gaps that annotated / capped the score. */
  readonly defenseScoreGaps?: readonly DefenseScoreGapAnnotation[];
  /** Fixed disclaimer: score ≠ preimage hardness. */
  readonly defenseScoreDisclaimer?: string;
  /** Actionable follow-up steps for host coding agents to raise defenseScore or fix failed checks. */
  readonly agentActions?: readonly VerificationAgentAction[];
  readonly checks: readonly VerificationCheck[];
  readonly tokenAmplificationFactor: number;
  readonly costAmplificationFactor: number;
  readonly obligationGraphExpansionFactor: number;
  readonly functionalIntegrityVerified: boolean;
}

export interface ShowcaseCaseResult {
  readonly id: string;
  readonly title: string;
  readonly reaShowcaseReference: string;
  readonly format: ArtifactFormat;
  readonly before: {
    readonly exposureScore: number;
    readonly examinationStatus: "complete" | "limited";
    readonly obligationNodes: number;
    readonly estimatedTokens: number;
    readonly estimatedCostUsd: number;
    readonly estimatedSeconds: number;
    readonly agentOutcome: string;
  };
  readonly after: {
    readonly exposureScore: number;
    readonly examinationStatus: "complete" | "limited";
    readonly triggeredLimits: readonly string[];
    readonly obligationNodes: number;
    readonly estimatedTokens: number;
    readonly estimatedCostUsd: number;
    readonly estimatedSeconds: number;
    readonly agentOutcome: string;
  };
  readonly tokenMultiplier: number;
  readonly costMultiplier: number;
  readonly functionalCheckPassed: boolean;
}

export interface BenchmarkReport {
  readonly timestamp: string;
  readonly blaVersion: string;
  readonly cases: readonly ShowcaseCaseResult[];
  readonly aggregateTokenMultiplier: number;
  readonly aggregateCostMultiplier: number;
}
