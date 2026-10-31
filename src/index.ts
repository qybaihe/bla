export { BLA_IDENTITY, REA_INTERNAL_LIMITS } from "./identity.js";
export * from "./core/types.js";
export { SeededPrng } from "./core/prng.js";
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
export {
  defendTarget,
  type OneClickDefenseOptions,
  type OneClickDefenseReport,
  type OneClickDefenseStageSummary,
} from "./engine/defender.js";
export { runShowcaseBenchmark } from "./engine/benchmark.js";
export {
  discoverHardenableArtifacts,
  hardenProject,
  formatHardenProjectReport,
  BLA_BUILD_OUTPUT_DIR_NAMES,
  type HardenProjectReport,
  type HardenArtifactSummary,
  type DiscoveredArtifact,
} from "./engine/harden.js";
export * from "./shields/exhaustion/index.js";
export * from "./shields/deception/index.js";
export * from "./shields/formats/apple-plist.js";
export * from "./shields/formats/dotnet-managed.js";
export * from "./shields/formats/jvm-bytecode.js";
export * from "./core/config.js";
export * from "./core/sarif.js";
export * from "./core/release-plan.js";
export * from "./core/debug-posture.js";
export * from "./core/coverage-contract.js";
export {
  resolveSupportedAgentClients,
  detectInstalledClients,
  CLIENT_COMPATIBILITY_MATRIX,
  type SupportedAgentClientId,
} from "./setup/clients.js";
export { runSetup, runUninstall } from "./setup/setup.js";
export { runDoctor } from "./setup/doctor.js";
export { handleMcpRequest, startMcpStdioServer, BLA_MCP_TOOLS } from "./mcp/server.js";
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
  buildGoBuildInfoExhaustionPayload,
  buildFlutterPoolExhaustionPayload,
  buildMappedGoBuildInfoPlant,
  buildMappedFlutterIsolatePoolPlant,
  buildMappedGoFlutterElfFixture,
} from "./shields/formats/go-flutter-exhaustion.js";
