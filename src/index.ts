export { BLA_IDENTITY, REA_INTERNAL_LIMITS } from "./identity.js";
export * from "./core/types.js";
export { SeededPrng, deriveSeedLabel } from "./core/prng.js";
export { detectArtifactFormat } from "./core/detector.js";
export { estimateAgentReverseEngineeringCosts } from "./core/token-estimator.js";
export { generateChaffPayloads, type ChaffPayload } from "./shields/chaff/chaff-generator.js";
export {
  generateJsTarpitAndBudgetBreaker,
  generatePythonTarpit,
  type TarpitGenerationResult,
} from "./shields/tarpit/tarpit-generator.js";
export {
  generateRuntimeDeceptionSnippet,
} from "./shields/runtime/runtime-shield.js";
export {
  generateShadowHeapChurnShield,
  encodeSplitShareString,
  generateSplitShareRuntimeHelper,
  type ShadowHeapChurnShieldResult,
  type SplitShareEncodedString,
} from "./shields/runtime/memory-diff-shield.js";
export {
  transformJavaScriptWithBlaShield,
  InvalidJavaScriptCarrierError,
  inferJsLoaderFromPath,
  inferJsCarrierFromPath,
  collectEsmExportedSymbols,
  type JsCarrierType,
  type JsLoaderType,
  type JsTransformOptions,
  type JsShieldTransformResult,
} from "./shields/javascript/ast-shield.js";
export { generateHoneySourceMap, type HoneySourceMap } from "./shields/formats/sourcemap.js";
export {
  UnsupportedAsarError,
  validateAsarBuffer,
  validateAsarProtectionInput,
  unpackAsarBuffer,
  packAsarBuffer,
  type VirtualAsarFile,
  type AsarHeaderNode,
  type AsarValidationOptions,
} from "./shields/formats/asar.js";
export {
  UnsupportedElectronFuseContextError,
  inspectElectronFusesBuffer,
  inspectElectronFusesInBuffer,
  hardenElectronFusesWithContext,
  hardenAndOverflowElectronFuses,
  type ElectronFuseStatus,
  type ElectronFuseInspectionResult,
  type ElectronFuseInspectionSummary,
  type ElectronHardeningContext,
  type ElectronHardeningReport,
} from "./shields/formats/electron-fuses.js";
export { inspectWasmBinary, protectWasmBinary } from "./shields/formats/wasm.js";
export {
  comparePolymorphArtifacts,
  POLYMORPH_REPORT_SCHEMA,
} from "./engine/polymorph-report.js";
export type {
  PolymorphReport,
  PolymorphReportOptions,
  PolymorphExpectMode,
  FilePairMetric,
} from "./engine/polymorph-report.js";
export {
  encryptStrings,
  ENCRYPT_STRINGS_SCHEMA,
  buildKeystream,
  xorEncodeToBytes,
  xorDecodeBytes,
} from "./engine/encrypt-strings.js";
export type {
  EncryptStringsOptions,
  EncryptStringsReport,
  EncryptStringsFileResult,
} from "./engine/encrypt-strings.js";
export {
  applyBindScope,
  buildBindScopeContract,
  buildBindScopeRuntimeSnippet,
  validateBindScopeContract,
  lintBindScopeFile,
  discoverAndLintBindScope,
  bindScopeRefuseMessage,
  hostMatchesBindDomain,
  evaluateBindHost,
  evaluateBindTime,
  BIND_SCOPE_SCHEMA,
  BIND_SCOPE_FILE_NAME,
  BIND_SCOPE_RUNTIME_MARKER,
} from "./engine/bind-scope.js";
export type {
  BindScopeContract,
  BindScopeLintReport,
  BindScopeApplyOptions,
  BindScopeApplyReport,
  BindScopeRefuseReason,
} from "./engine/bind-scope.js";
export {
  lintPlaintextSecretsSource,
  lintPlaintextSecretsFile,
  discoverAndLintPlaintextSecrets,
  plaintextSecretRefuseMessage,
  intensityEnforcesPlaintextSecretRefusal,
  shannonEntropy,
  classifySensitiveLiteral,
  extractStringLiterals,
  PLAINTEXT_SECRET_SCHEMA,
} from "./engine/plaintext-secret-lint.js";
export type {
  PlaintextSecretFinding,
  PlaintextSecretReport,
  PlaintextSecretFindingId,
  PlaintextSecretSeverity,
} from "./engine/plaintext-secret-lint.js";
export {
  InvalidPythonSourceError,
  findPythonPrologueInsertionOffset,
  protectPythonSource,
  inspectPythonPyc,
  protectPythonPycBuffer,
  type PythonPrologueAnalysis,
} from "./shields/formats/python.js";
export {
  InvalidNativeBinaryError,
  validateElf64Layout,
  inspectNativeBinary,
  protectNativeBinary,
  detectNativeEofAppendHazard,
  buildDecoyRustAuditablePayload,
  type Elf64LayoutSummary,
  type NativeEofAppendHazard,
} from "./shields/formats/native.js";
export {
  BUN_TRAILER,
  detectBunStandaloneGraph,
  generateBunStandaloneDecoyGraph,
  serializeBunModuleGraph,
  type BunCarrierDetection,
  type BunDecoyGraphResult,
  type BunDecoyModule,
} from "./shields/formats/bun-standalone.js";
export {
  emitCompileTimeNativeHeader,
  type NativeHeaderLanguage,
  type EmittedNativeHeader,
} from "./shields/formats/headers.js";
export {
  SqliteWalConsistencyError,
  DEFAULT_SQLITE_SENSITIVITY_POLICY,
  validateSqliteFileInput,
  validateSqliteStandaloneBuffer,
  evaluateSqliteSensitivityPolicy,
  minimizeSqliteDatabaseBuffer,
  inspectSqliteBuffer,
  protectSqliteBuffer,
  buildSampleSqliteDatabase,
  type SqliteInspectionSummary,
  type SqliteSensitivityRule,
  type SqliteSensitivityPolicy,
  type SqliteSensitiveColumnFinding,
  type SqlitePolicyEvaluationReport,
} from "./shields/formats/sqlite.js";
export {
  buildSafetensorsBuffer,
  validateSafetensorsBuffer,
  InvalidSafetensorsError,
  inspectModelBuffer,
  protectSafetensorsBuffer,
  protectGgufBuffer,
  type ModelInspectionSummary,
} from "./shields/formats/model.js";
export {
  inspectAndroidDex,
  protectAndroidDexBuffer,
  protectIl2cppMetadataBuffer,
} from "./shields/formats/mobile-game.js";
export {
  generateAndroidR8Counter,
  buildJniDecoyElf64,
  buildJniExportNames,
  mangleJniIdentifier,
  type AndroidR8CounterResult,
} from "./shields/formats/android-r8.js";
export {
  generateAndroidManifestCounter,
  type AndroidManifestCounterResult,
} from "./shields/formats/android-manifest.js";
export {
  UnsupportedArchiveError,
  UnsupportedApkProtectionError,
  readZipEntries,
  writeZipArchive,
  protectZipOrApkBuffer,
} from "./shields/formats/archive.js";
export {
  blaRollupPlugin,
  blaVitePlugin,
  BlaWebpackPlugin,
  blaEsbuildPlugin,
  type BlaBundlerPluginOptions,
} from "./bundler/index.js";
export { auditTarget } from "./engine/auditor.js";
export { protectTarget } from "./engine/protector.js";
export { verifyTarget } from "./engine/verifier.js";
export type { VerifyTargetOptions } from "./engine/verifier.js";
export {
  applyDefenseScoreHonesty,
  collectDefenseScoreGaps,
  DEFENSE_SCORE_DISCLAIMER,
  formatDefenseScoreGapAnnotation,
} from "./engine/defense-score-honesty.js";
export type {
  DefenseScoreGap,
  DefenseScoreGapId,
  DefenseScoreHonesty,
  DefenseScoreHonestyInput,
} from "./engine/defense-score-honesty.js";
export {
  defendTarget,
  type OneClickDefenseOptions,
  type OneClickDefenseReport,
  type OneClickDefenseStageSummary,
} from "./engine/defender.js";
export { runShowcaseBenchmark } from "./engine/benchmark.js";
export {
  discoverHardenableArtifacts,
  discoverHardenTargets,
  hardenProject,
  formatHardenProjectReport,
  BLA_BUILD_OUTPUT_DIR_NAMES,
  type HardenProjectReport,
  type HardenProgressEvent,
  type HardenProgressPhase,
  type HardenArtifactSummary,
  type DiscoveredArtifact,
  type HardenDiscoveryResult,
} from "./engine/harden.js";
export {
  computeHardenRunId,
  computeArtifactRunId,
  readHardenRunSummary,
  HARDEN_SUMMARY_FILE_NAME,
  HARDEN_SUMMARY_SCHEMA,
  type HardenRunIdentity,
  type HardenRunSummary,
  type ReadHardenRunSummaryResult,
} from "./engine/run-evidence.js";
export {
  runReaDriftCheck,
  getRedteamReport,
  resolveReaRoot,
  reaCheckoutPresent,
  reaDistReady,
  type ReaDriftReport,
  type RedteamReportResult,
} from "./engine/rea-observability.js";
export * from "./shields/exhaustion/index.js";
export * from "./shields/deception/index.js";
export {
  generateSelfSealSnippet,
  measureSelfSealDigestOffline,
  SELF_SEAL_SCHEMA,
  type SelfSealOptions,
  type SelfSealSnippet,
} from "./shields/runtime/self-seal.js";
export {
  INTEGRITY_COVERAGE_SCHEMA,
  buildInterleavedCoverageMatrix,
  evaluateCoverageMatrix,
  finalizeCoverageMatrixHashes,
  discoverAndLintIntegrityCoverage,
  type CoverageMatrix,
  type CoverageEvaluation,
  type CoverageRefuseReason,
} from "./engine/integrity-coverage.js";
export * from "./shields/formats/apple-plist.js";
export * from "./shields/formats/dotnet-managed.js";
export * from "./shields/formats/jvm-bytecode.js";
export * from "./core/config.js";
export {
  withLlmDirectives,
  areLlmDirectivesEnabled,
} from "./core/llm-directives.js";
export * from "./core/sarif.js";
export * from "./core/release-plan.js";
export * from "./core/debug-posture.js";
export * from "./core/coverage-contract.js";
export {
  generateManifestSigningKeyPair,
  signManifestPayload,
  verifyManifestSignature,
  readManifestSigningKeyOrThrow,
  type ManifestSignature,
  type ManifestSigningKeyPair,
} from "./core/manifest-signing.js";
export {
  verifyManifestFile,
  type ManifestVerifyResult,
} from "./core/manifest-verify.js";
export {
  resolveSupportedAgentClients,
  detectInstalledClients,
  CLIENT_COMPATIBILITY_MATRIX,
  type SupportedAgentClientId,
} from "./setup/clients.js";
export { runSetup, runUninstall } from "./setup/setup.js";
export { runDoctor } from "./setup/doctor.js";
export { handleMcpRequest, startMcpStdioServer, BLA_MCP_TOOLS, BLA_MCP_RESOURCES, BLA_MCP_PROMPTS } from "./mcp/server.js";
export {
  inspectReleaseExposure,
  type ReleaseExposureReport,
  type ReleaseExposureFinding,
} from "./core/release-exposure.js";

export {
  inspectErlangBeam,
  protectErlangBeamBuffer,
} from "./shields/formats/erlang-beam.js";
export {
  inspectEvmBytecode,
  protectEvmBytecodeBuffer,
  buildSolidityMetadataTrailer,
} from "./shields/formats/evm-bytecode.js";
export {
  inspectPcapCapture,
  protectPcapCaptureBuffer,
} from "./shields/formats/pcap-capture.js";
export {
  inspectGpuPtx,
  protectGpuPtxText,
  FIRMWARE_HARDENING_SKIP_REASON,
  GPU_OBJECT_HARDENING_SKIP_REASON,
} from "./shields/formats/gpu-ptx.js";
export {
  inspectUf2Firmware,
  protectUf2FirmwareBuffer,
  isUf2Container,
  UF2_SHIELD_MARKER,
  UF2_BLOCK_BYTES,
} from "./shields/formats/firmware-uf2.js";
export {
  buildGoBuildInfoExhaustionPayload,
  buildFlutterPoolExhaustionPayload,
  buildMappedGoBuildInfoPlant,
  buildMappedFlutterIsolatePoolPlant,
  buildMappedGoFlutterElfFixture,
} from "./shields/formats/go-flutter-exhaustion.js";

export {
  buildWeavePlan,
  getWeaveDirectivesMarkdown,
  inspectWeaveHints,
  verifyWeaveTarget,
  WEAVE_ACCEPTANCE_TESTS,
  WEAVE_AGENT_PLAYBOOK,
  WEAVE_DECOY_DOC_PATH,
  WEAVE_DECOY_SCHEMA,
  WEAVE_DIRECTIVES_URI,
  WEAVE_EXECUTOR_CHECKLIST,
  WEAVE_FORBIDDEN,
  WEAVE_PRINCIPLES,
  WEAVE_VERIFY_SCHEMA,
  type WeaveAgentAction,
  type WeaveAgentPlaybookPhase,
  type WeaveBranchCandidate,
  type WeaveCheckResult,
  type WeaveFileVerification,
  type WeaveFunctionCandidate,
  type WeaveMaturity,
  type WeavePlan,
  type WeavePlanStatus,
  type WeaveStateSlotCandidate,
  type WeaveSurgicalWorkorder,
  type WeaveTargetEntry,
  type WeaveVerificationReport,
} from "./shields/weave/weave-decoy.js";


export {
  lintLaneIndependence,
  lintLaneIndependenceFile,
  discoverAndLintLaneIndependence,
  LANE_INDEPENDENCE_SCHEMA,
  formatSupportsLaneIndependenceLint,
  laneIndependenceRefuseMessage,
  type LaneIndependenceFinding,
  type LaneIndependenceReport,
  type LaneIndependenceFindingId,
  type LaneIndependenceSeverity,
} from "./engine/lane-independence-lint.js";
export {
  scanPackagingGates,
  evaluateHardenProjectPackagingBlocks,
  formatPackagingGatesReport,
  PACKAGING_GATES_SCHEMA,
  type PackagingGateId,
  type PackagingGateFinding,
  type PackagingGateRemediation,
  type PackagingGatesReport,
  type PackagingGatesScanOptions,
  type PackagingGatesAllowOptions,
} from "./engine/packaging-gates.js";
export {
  lintSealCommitmentSource,
  lintSealCommitmentFile,
  discoverAndLintSealSidecars,
  findSiblingSealSidecars,
  sealCommitmentRefuseMessage,
  intensityEnforcesSealRefusal,
  SEAL_COMMITMENT_SCHEMA,
  type SealCommitmentFinding,
  type SealCommitmentReport,
  type SealCommitmentFindingId,
  type SealCommitmentSeverity,
} from "./engine/seal-commitment-lint.js";
export {
  lintWasmParamCarrierBuffer,
  lintWasmParamCarrierFile,
  discoverAndLintWasmParamCarriers,
  wasmParamCarrierRefuseMessage,
  intensityEnforcesWasmParamRefusal,
  buildTestWasmWithParamCarrier,
  WASM_PARAM_CARRIER_SCHEMA,
  type WasmParamCarrierFinding,
  type WasmParamCarrierReport,
  type WasmParamCarrierFindingId,
  type WasmParamCarrierSeverity,
} from "./engine/wasm-param-carrier-lint.js";
export {
  lintWasmXorMaskSidecarBuffer,
  lintWasmXorMaskSidecarFile,
  discoverAndLintWasmXorMaskSidecars,
  buildTestWasmWithXorMaskSidecar,
  wasmXorMaskSidecarRefuseMessage,
  intensityEnforcesWasmXorMaskSidecarRefusal,
  WASM_XOR_MASK_SIDECAR_SCHEMA,
  type WasmXorMaskSidecarFinding,
  type WasmXorMaskSidecarReport,
  type WasmXorMaskSidecarFindingId,
  type WasmXorMaskSidecarSeverity,
} from "./engine/wasm-xor-mask-sidecar-lint.js";
export {
  lintWasmSealXorKnownPlaintextBuffer,
  lintWasmSealXorKnownPlaintextFile,
  discoverAndLintWasmSealXorKnownPlaintext,
  buildTestWasmWithSealXorKnownPlaintext,
  wasmSealXorKnownPlaintextRefuseMessage,
  intensityEnforcesWasmSealXorKnownPlaintextRefusal,
  WASM_SEAL_XOR_KNOWN_PLAINTEXT_SCHEMA,
  type WasmSealXorKnownPlaintextFinding,
  type WasmSealXorKnownPlaintextReport,
  type WasmSealXorKnownPlaintextFindingId,
  type WasmSealXorKnownPlaintextSeverity,
} from "./engine/wasm-seal-xor-known-plaintext-lint.js";
export {
  lintPanelDeriveAbiSource,
  lintPanelDeriveAbiFile,
  discoverAndLintPanelDerive,
  rewriteStablePanelDeriveSymbols,
  panelDeriveSeedRoot,
  panelDeriveReplacementName,
  intensityRewritesPanelDerive,
  PANEL_DERIVE_ABI_SCHEMA,
  type PanelDeriveFinding,
  type PanelDeriveAbiReport,
  type PanelDeriveFindingId,
  type PanelDeriveSeverity,
  type PanelDeriveRewriteResult,
} from "./engine/panel-derive-abi-lint.js";
export {
  parseWasmExportSectionPayload,
  renameWasmExports,
  shuffleWasmExportSectionPayload,
  looksLikeInternalWasmExport,
  type WasmExportEntry,
  type WasmExportRename,
} from "./shields/formats/wasm.js";

export {
  planSidecarEntanglement,
  computeSidecarBindingDigest,
  generateSidecarJsPreamble,
  generateSidecarPythonPreamble,
  bindSidecarEntanglement,
  bindPythonSidecarEntanglement,
  entangleJsEntryWithSidecars,
  entanglePythonEntryWithSidecars,
  SIDECAR_ENTANGLE_SCHEMA,
  type SidecarEntanglePlan,
  type SidecarEntanglePlanOptions,
  type SidecarBindingPart,
  type SidecarBindingDigest,
  type SidecarBindingMode,
  type SidecarJsInjectOptions,
  type SidecarJsInjectResult,
  type SidecarJsBindResult,
  type SidecarPythonInjectOptions,
  type SidecarPythonInjectResult,
  type SidecarPythonBindResult,
} from "./shields/runtime/sidecar-entangle.js";

export {
  recommendOpaqueSeedBinding,
} from "./shields/tarpit/opaque-predicates.js";

