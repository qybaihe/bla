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
  transformJavaScriptWithBlaShield,
  type JsShieldTransformResult,
} from "./shields/javascript/ast-shield.js";
export { generateHoneySourceMap, type HoneySourceMap } from "./shields/formats/sourcemap.js";
export {
  unpackAsarBuffer,
  packAsarBuffer,
  type VirtualAsarFile,
} from "./shields/formats/asar.js";
export {
  inspectElectronFusesInBuffer,
  hardenAndOverflowElectronFuses,
  type ElectronFuseInspectionSummary,
} from "./shields/formats/electron-fuses.js";
export { inspectWasmBinary, protectWasmBinary } from "./shields/formats/wasm.js";
export {
  protectPythonSource,
  inspectPythonPyc,
  protectPythonPycBuffer,
} from "./shields/formats/python.js";
export {
  inspectNativeBinary,
  protectNativeBinary,
  buildDecoyRustAuditablePayload,
} from "./shields/formats/native.js";
export {
  emitCompileTimeNativeHeader,
  type NativeHeaderLanguage,
  type EmittedNativeHeader,
} from "./shields/formats/headers.js";
export {
  inspectSqliteBuffer,
  protectSqliteBuffer,
  buildSampleSqliteDatabase,
  type SqliteInspectionSummary,
} from "./shields/formats/sqlite.js";
export {
  buildSafetensorsBuffer,
  inspectModelBuffer,
  protectSafetensorsBuffer,
  protectGgufBuffer,
  UnsupportedGgufProtectionError,
  type ModelInspectionSummary,
} from "./shields/formats/model.js";
export {
  inspectAndroidDex,
  protectAndroidDexBuffer,
  protectIl2cppMetadataBuffer,
} from "./shields/formats/mobile-game.js";
export {
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
export { runShowcaseBenchmark } from "./engine/benchmark.js";
export {
  resolveSupportedAgentClients,
  type SupportedAgentClientId,
} from "./setup/clients.js";
export { runSetup, runUninstall } from "./setup/setup.js";
export { runDoctor } from "./setup/doctor.js";
export { handleMcpRequest, startMcpStdioServer, BLA_MCP_TOOLS } from "./mcp/server.js";
