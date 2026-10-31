export const BLA_IDENTITY = Object.freeze({
  name: "BLA",
  fullName: "Blind LLM Agents",
  packageName: "bla-agents",
  packageAlias: "bla-shield",
  cliBinary: "bla",
  cliAlias: "bla-agents",
  version: "1.5.2",
  slogan: "Poison -> Exhaust -> Hallucinate. Make Reverse Engineering Bankrupt Again.",
  counterpart: {
    name: "REA",
    fullName: "Reverse Engineer Anything",
    packageName: "rea-agents",
    slogan: "Decompile -> Understand -> Recreate",
  },
  repositoryUrl: "https://github.com/qybaihe/bla",
  mcpServerName: "bla",
  skillName: "blind-llm-agents",
});

/**
 * Exact internal resource limits & sentinels extracted from REA (`morluto/rea`):
 * - `src/domain/javascript/javascriptSemanticResourceLimits.ts`
 * - `src/domain/javascript/javascriptStaticAnalysis.ts`
 * - `src/domain/electron/electronFuses.ts` & `src/electron/ElectronFuseReader.ts`
 * - `src/rust/RustBinaryImage.ts` & `src/rust/RustAuditableReader.ts`
 * - `src/flutter/FlutterPayloadScan.ts`
 * - `src/sqlite/SqliteDatabaseLimits.ts` & `src/sqlite/SqliteDatabaseInspection.ts`
 * - `src/model/ModelFormat.ts` (`SafetensorsHeader.ts` & `GgufHeader.ts`)
 * - `src/domain/wasm/wasmInterface.ts`
 * - `src/dotnet/ManagedDecodeBudget.ts`
 * - `src/domain/android/proguardMapping.ts` & `androidMapping.ts` (REA #7456)
 * - `src/domain/android/androidJniBindings.ts` & `src/android/AndroidJniLibraries.ts` (REA #7472)
 * - `src/domain/native/nativeExports.ts` (`MAX_NATIVE_EXPORT_ROWS`)
 * - `bridge/android/ReaJadxBridge.java` (`MAX_EXTERNAL_XREF_BYTES`, REA #8154)
 */
export const REA_INTERNAL_LIMITS = Object.freeze({
  /** Maximum distinct alternatives retained in one normalized primitive value (`SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT`). */
  SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT: 256,
  /** Maximum active expression nesting during inert semantic evaluation (`SEMANTIC_EXPRESSION_DEPTH_LIMIT`). */
  SEMANTIC_EXPRESSION_DEPTH_LIMIT: 256,
  /** Getter jobs and local result work retained in one precise query (`SEMANTIC_GETTER_EXPANSION_LIMIT`). */
  SEMANTIC_GETTER_EXPANSION_LIMIT: 512,
  /** Additional selector states retained by one precise alias query (`SEMANTIC_ALIAS_SELECTION_LIMIT`). */
  SEMANTIC_ALIAS_SELECTION_LIMIT: 512,
  /** Bound normalized strings and transient keys (`SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT`). */
  SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT: 1_048_576,
  /** Electron wrapper call-path expansion depth limit (`electronWrappedCallPaths.ts`). */
  ELECTRON_CALL_PATH_DEPTH_LIMIT: 128,
  /** Electron wrapper call-path visit limit (`electronWrappedCallPaths.ts`). */
  ELECTRON_CALL_PATH_VISIT_LIMIT: 1_000_000,
  /** Electron Fuse ASCII sentinel (`ELECTRON_FUSE_SENTINEL` in `electronFuses.ts`). */
  ELECTRON_FUSE_SENTINEL: "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX",
  /** Maximum Electron fuse sentinels per slice (`maximumSentinelsPerSlice` in `ElectronFuseReader.ts`). */
  ELECTRON_MAX_SENTINELS_PER_SLICE: 32,
  /** Maximum inferred rustc commit hashes in `RustBinaryImage.ts` (`MAX_RUSTC_HASHES`). */
  RUST_MAX_COMMIT_HASHES: 64,
  /** Compressed `.dep-v0` section limit in `RustAuditableReader.ts` (`RUST_SECTION_BYTES`). */
  RUST_DEP_V0_SECTION_BYTES: 1_048_576,
  /** Maximum distinct Dart AOT snapshot hashes in `FlutterPayloadScan.ts` (`MAX_SNAPSHOT_HASH_CANDIDATES`). */
  DART_MAX_SNAPSHOT_HASH_CANDIDATES: 64,
  /** Maximum toolchain lines in `FlutterPayloadScan.ts` (`MAX_TOOLCHAIN_LINES`). */
  DART_MAX_TOOLCHAIN_LINES: 4,
  /** Maximum Safetensors JSON nesting depth (`MODEL_JSON_NESTING` in `ModelFormat.ts`). */
  MODEL_MAX_JSON_NESTING: 32,
  /** Maximum GGUF array metadata nesting frames (`MODEL_METADATA_NESTING` in `ModelFormat.ts`). */
  MODEL_MAX_METADATA_NESTING: 32,
  /** SQLite inspection JSON reply budget (`SQLITE_DATABASE_LIMITS.outputBytes` = 16 MiB). */
  SQLITE_OUTPUT_BYTES_LIMIT: 16_777_216,
  /** WASM typed interface representation budget (`WASM_INTERFACE_REPRESENTATION_BYTES` = 32 MiB). */
  WASM_INTERFACE_REPRESENTATION_BYTES: 33_554_432,
  /** .NET Managed metadata representation budget (`MAX_METADATA_REPRESENTATION_BYTES` = 64 MiB). */
  MANAGED_METADATA_REPRESENTATION_BYTES: 67_108_864,
  /** CDP/Web runtime aggregate script-source budget (`WEB_RUNTIME_LIMITS.sourceBytes` = 32 MiB in `src/domain/webRuntime.ts`). */
  WEB_RUNTIME_SOURCE_BYTES: 33_554_432,
  /** LLDB native call tracer aggregate JSON byte cap (`MAX_TRACE_BYTES` = 8 MiB in `bridge/native/rea_lldb_tracer.py`). */
  LLDB_MAX_TRACE_BYTES: 8_388_608,
  /** LLDB native call tracer aggregate frame cap (`MAX_TRACE_FRAMES` = 65,536 in `bridge/native/rea_lldb_tracer.py`). */
  LLDB_MAX_TRACE_FRAMES: 65_536,
  /** LLDB native call tracer non-breakpoint stop cap (`MAX_OTHER_STOPS` = 256 in `bridge/native/rea_lldb_tracer.py`). */
  LLDB_MAX_OTHER_STOPS: 256,
  /** LLDB Objective-C selector C-string read cap (`MAX_SELECTOR_BYTES` = 1024 in `bridge/native/rea_lldb_tracer.py`). */
  LLDB_MAX_SELECTOR_BYTES: 1_024,
  /** GDB session command output byte cap (`MAX_COMMAND_OUTPUT_BYTES` = 16 MiB in `src/gdb/GdbSessionManager.ts`). */
  GDB_MAX_COMMAND_OUTPUT_BYTES: 16_777_216,
  /** GDB session MI output record cap (`MAX_COMMAND_OUTPUT_RECORDS` = 16,384 in `src/gdb/GdbSessionManager.ts`). */
  GDB_MAX_COMMAND_OUTPUT_RECORDS: 16_384,
  /** Rizin debugger session frame byte cap (`MAX_FRAME_BYTES` = 16 MiB in `src/rizin/RizinDebugSessionManager.ts`). */
  RIZIN_MAX_FRAME_BYTES: 16_777_216,
  /** Rizin debugger command frame count cap (`MAX_COMMAND_FRAMES` = 4,096 in `src/rizin/RizinDebugSessionManager.ts`). */
  RIZIN_MAX_COMMAND_FRAMES: 4_096,
  /** Environment differential comparison per-step diff cap (`STEP_DIFFERENCE_LIMIT` = 20 in `src/application/environment/environmentCompareDiff.ts`). */
  ENVIRONMENT_COMPARE_STEP_DIFF_LIMIT: 20,
  /** Go build-info aggregate string budget (`MAX_BUILD_INFO_BYTES` = 1 MiB in `src/go/GoBinaryImage.ts`). */
  GO_MAX_BUILD_INFO_BYTES: 1_048_576,
  /** Go build-info cumulative header-search budget (`MAX_HEADER_SEARCH_BYTES` = 256 MiB in `src/go/GoBinaryImage.ts`). */
  GO_MAX_HEADER_SEARCH_BYTES: 268_435_456,
  /** Flutter/Dart AOT string-pool URI projection cap (`MAX_POOL_URIS` = 500 in `src/flutter/FlutterBuildProvider.ts`). */
  DART_MAX_POOL_URIS: 500,
  /** Flutter/Dart AOT class-like token projection cap (`MAX_POOL_TOKENS` = 2_000 in `src/flutter/FlutterBuildProvider.ts`). */
  DART_MAX_POOL_TOKENS: 2_000,
  /** Erlang BEAM hard ceiling on IFF chunks (`MAX_INSPECT_ERLANG_BEAM_CHUNKS` = 256). */
  BEAM_MAX_CHUNKS: 256,
  /** Erlang BEAM hard ceiling on atom-table entries (`MAX_INSPECT_ERLANG_BEAM_ATOMS` = 65_536). */
  BEAM_MAX_ATOMS: 65_536,
  /** Erlang BEAM default max_chunks admission (schema default 64). */
  BEAM_DEFAULT_MAX_CHUNKS: 64,
  /** Erlang BEAM default max_atoms admission (schema default 4096). */
  BEAM_DEFAULT_MAX_ATOMS: 4_096,
  /** EVM interface worker input-byte ceiling (`EVM_INTERFACE_LIMITS.inputBytes` = 4 MiB). */
  EVM_INPUT_BYTES: 4_194_304,
  /** EVM interface worker reply-byte ceiling (`EVM_INTERFACE_LIMITS.outputBytes` = 16 MiB). */
  EVM_OUTPUT_BYTES: 16_777_216,
  /** EVM interface diagnostic capture ceiling (`EVM_INTERFACE_LIMITS.diagnosticBytes` = 1 MiB). */
  EVM_DIAGNOSTIC_BYTES: 1_048_576,
  /** tshark JSON decode ceiling (`TSHARK_JSON_MAX_BYTES` = 8 MiB in `src/pcap/PcapOutput.ts`). */
  PCAP_TSHARK_JSON_MAX_BYTES: 8_388_608,
  /** GPU retained report budget (`GPU_REPORT_BYTES` = 16 MiB in `src/gpu/GpuSource.ts`). */
  GPU_REPORT_BYTES: 16_777_216,
  /** GPU object decode budget (`GPU_OBJECT_BYTES` = 128 MiB in `src/gpu/GpuSource.ts`). */
  GPU_OBJECT_BYTES: 134_217_728,
  /** Firmware staging byte ceiling (`MAX_FIRMWARE_STAGING_BYTES` = 512 MiB). */
  FIRMWARE_MAX_STAGING_BYTES: 536_870_912,
  /** Firmware extraction depth ceiling (`MAX_FIRMWARE_EXTRACTION_DEPTH` = 10). */
  FIRMWARE_MAX_EXTRACTION_DEPTH: 10,
  /**
   * Caller-selected ProGuard / R8 mapping admission (`ANDROID_MAPPING_LIMITS` /
   * `PROGUARD_MAPPING_LIMITS` in `src/domain/android/androidMapping.ts` +
   * `proguardMapping.ts`, added by REA #7456).
   */
  ANDROID_MAPPING_FILE_BYTES: 67_108_864,
  PROGUARD_MAPPING_INDEX_BYTES: 134_217_728,
  PROGUARD_MAPPING_PROJECTION_BYTES: 8_388_608,
  PROGUARD_MAPPING_MALFORMED_SAMPLES: 16,
  PROGUARD_MAPPING_CANDIDATES: 8,
  /** JNI native-declaration ↔ .so export report budget (`ANDROID_JNI_REPORT_BYTES` in `androidJniBindings.ts`, REA #7472). */
  ANDROID_JNI_REPORT_BYTES: 16_777_216,
  /** Per-library / aggregate JNI .so inventory caps (`ANDROID_JNI_LIBRARY_LIMITS` in `AndroidJniLibraries.ts`). */
  ANDROID_JNI_LIBRARY_BYTES: 67_108_864,
  ANDROID_JNI_TOTAL_BYTES: 268_435_456,
  ANDROID_JNI_FACTS_BYTES: 16_777_216,
  ANDROID_JNI_LIBRARY_ENTRIES: 100_000,
  ANDROID_JNI_LIBRARIES: 2_048,
  /** Native export inventory row ceiling (`MAX_NATIVE_EXPORT_ROWS` in `nativeExports.ts`). */
  MAX_NATIVE_EXPORT_ROWS: 262_144,
  /**
   * AndroidManifest component inventory bounds (`ANDROID_MANIFEST_LIMITS` in
   * `src/android/AndroidManifestComponents.ts`, REA #7379 / refined by #7818).
   * Exceeding any of these flips the inventory to `status: "partial"` so REA
   * itself admits the component map is unestablished.
   */
  ANDROID_MANIFEST_COMPONENTS: 512,
  ANDROID_MANIFEST_INTENT_FILTERS: 32,
  ANDROID_MANIFEST_INTENT_VALUES: 64,
  ANDROID_MANIFEST_AUTHORITIES: 64,
  ANDROID_MANIFEST_RESOLVED_NAME_BYTES: 1_048_576,
  ANDROID_MANIFEST_AUTHORITY_BYTES: 1_048_576,
  ANDROID_MANIFEST_PERMISSION_BYTES: 1_048_576,
  ANDROID_MANIFEST_PROCESS_BYTES: 1_048_576,
  ANDROID_MANIFEST_DETAIL_BYTES: 1_048_576,
  /**
   * External DEX invoke prototype + caller inventory budget
   * (`MAX_EXTERNAL_XREF_BYTES` in `bridge/android/ReaJadxBridge.java`, REA #8154).
   * Derived as `(MAX_XREF_TEXT_BYTES = 8 MiB - 1 KiB) / 8`.
   */
  ANDROID_EXTERNAL_XREF_BYTES: 1_048_448,
  ANDROID_XREF_TEXT_BYTES: 8_387_584,
  /**
   * Bun standalone module-graph reader (`BunModuleGraphLayout.ts` /
   * `BunStandaloneArtifactReader.ts`, REA #6998).
   */
  BUN_RECORD_BYTES_1_3_3: 36,
  BUN_RECORD_BYTES_1_3_9: 52,
  BUN_MAX_MODULE_COUNT: 100_000,
  BUN_MAX_RETAINED_BYTES: 268_435_456,
  BUN_MAX_LOGICAL_PATH_PARTS: 256,
  BUN_MAX_LOGICAL_PATH_NODES: 250_000,
  BUN_METADATA_CACHE_BYTES: 262_144,
  BUN_METADATA_CACHE_ENTRIES: 1_024,
});
