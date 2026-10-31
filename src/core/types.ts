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
  readonly binarySectionsPatched: number;
}

export interface ProtectionResult {
  readonly inputPath: string;
  readonly outputPath: string;
  readonly detectedFormat: ArtifactFormat;
  readonly intensity: ProtectionIntensity;
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

export interface VerificationReport {
  readonly targetPath: string;
  readonly originalPath?: string;
  readonly detectedFormat: ArtifactFormat;
  readonly overallPassed: boolean;
  readonly defenseScore: number; // 0 to 100
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
