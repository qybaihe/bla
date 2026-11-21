export const BLA_IDENTITY = Object.freeze({
  name: "BLA",
  fullName: "Blind LLM Agents",
  packageName: "bla-agents",
  packageAlias: "bla-shield",
  cliBinary: "bla",
  cliAlias: "bla-agents",
  version: "3.5.6",
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
 * - `src/domain/firmware/uf2.ts` (`UF2_BLOCK_BYTES`, `UF2_MAX_REGIONS`, REA #8230)
 * - `src/domain/native/nativeAotPe.ts` (`NATIVE_AOT_MAX_*`, REA #10067/#10094)
 * - `src/il2cpp/Il2cppMetadataV108.ts` + `Il2cppMetadataProvider.ts` (REA #9925)
 * - `src/domain/android/dexTypes.ts` (`dexTypeSchema` 255-dimension cap, REA #10227)
 * - `src/domain/native/dwarfUnits.ts` + `elfDebugLink.ts` + `elfDependencies.ts`
 *   (REA tip 05be423ac: DWARF units, ELF debug-link, ELF DT_NEEDED)
 * - `src/domain/java/mavenGradleMetadata.ts` + `src/domain/nuget/nupkg.ts`
 * - `src/domain/firmware/androidOtaPayload.ts` + `src/artifacts/AndroidBootImageFormat.ts`
 * - `src/domain/uefi/uefiLimits.ts` + `src/domain/inesContainer.ts`
 * - `src/domain/compression/zstandardFrameAllowance.ts`
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
  /**
   * UF2 firmware container decoder (`src/domain/firmware/uf2.ts`, REA #8230).
   * `UF2_BLOCK_BYTES` / payload area are Microsoft UF2 constants; `UF2_MAX_REGIONS`
   * is REA's retained address-discontiguous region ceiling.
   */
  UF2_BLOCK_BYTES: 512,
  UF2_DATA_BYTES: 476,
  UF2_MAX_REGIONS: 65_536,
  /**
   * Electron ASAR header admission (`electronAsar.ts`: `DEFAULT_ASAR_MAX_HEADER_BYTES`
   * / `MAXIMUM_ASAR_MAX_HEADER_BYTES`).
   */
  ASAR_DEFAULT_MAX_HEADER_BYTES: 16 * 1024 * 1024,
  ASAR_MAXIMUM_MAX_HEADER_BYTES: 256 * 1024 * 1024,
  /**
   * Frida capture limits (`src/frida/fridaCaptureLimits.ts:2-11`).
   */
  FRIDA_MAX_SESSION_CAPTURE_BYTES: 16 * 1024 * 1024,
  FRIDA_MAX_MESSAGE_METADATA_BYTES: 128 * 1024,
  FRIDA_MAX_MESSAGE_TYPE_BYTES: 4 * 1024,
  FRIDA_MAX_MESSAGE_TEXT_BYTES: 32 * 1024,
  FRIDA_MAX_CAPTURE_JSON_NODES: 250_000,
  FRIDA_MAX_JSON_DEPTH: 64,
  /**
   * Regex worker budgets (`src/domain/analysisResourceLimits.ts:38,50`).
   */
  REGEX_DEFAULT_MATCHING_DEADLINE_MS: 5_000,
  REGEX_DEFAULT_WORKER_HEAP_REQUEST_MIB: 128,
  REGEX_MINIMUM_WORKER_HEAP_REQUEST_MIB: 7,
  /**
   * NativeAOT PE parser budgets (`src/domain/native/nativeAotPe.ts`).
   * REA #10067/#10094 owned the per-operation ceilings. REA #4445
   * (c8d5413d0, tip 1ba93b460) renamed `NATIVE_AOT_MAX_WORK_UNITS` to
   * `NATIVE_AOT_BASE_WORK_UNITS` and scales work as
   * `BASE + 8 * min(sourceBytes, MAX_SOURCE_BYTES)`, bounded by the
   * source-byte ceiling. Honesty catalog update — a budget *relaxation*,
   * not a new 1:1 densify trip target.
   */
  NATIVE_AOT_MAX_SOURCE_BYTES: 134_217_728,
  NATIVE_AOT_MAX_REPORT_BYTES: 4_194_304,
  /** @deprecated REA renamed this to NATIVE_AOT_BASE_WORK_UNITS; kept as an alias. */
  NATIVE_AOT_MAX_WORK_UNITS: 67_108_864,
  NATIVE_AOT_BASE_WORK_UNITS: 67_108_864,
  NATIVE_AOT_WORK_UNITS_PER_SOURCE_BYTE: 8,
  NATIVE_AOT_MAX_WORKING_MEMORY_BYTES: 67_108_864,
  /**
   * IL2CPP metadata provider + v108 header/string observation
   * (`Il2cppMetadataProvider.ts` INPUT/OUTPUT; `Il2cppMetadataV108.ts` —
   * REA #9925 feat(il2cpp): retain v108 header and string evidence).
   * Bounded sample only — not a densify trip target; catalogued for honesty.
   */
  IL2CPP_METADATA_INPUT_BYTES: 268_435_456,
  IL2CPP_METADATA_OUTPUT_BYTES: 67_108_864,
  IL2CPP_BINARY_BYTES: 1_073_741_824,
  IL2CPP_V108_SAMPLE_STRINGS: 16,
  IL2CPP_V108_SAMPLE_BYTES: 128,
  IL2CPP_V108_SCAN_BATCH_BYTES: 65_536,
  /**
   * DEX type/prototype descriptor admission (`dexTypes.ts`, REA #10227).
   * Official Dalvik/ART array-dimension ceiling is 255; REA now rejects
   * 256-dimension JNI descriptors at schema admission. Honesty catalog only —
   * not a densify trip target: planting 256-dimension types would emit
   * invalid DEX and break the protected runtime.
   */
  DEX_ARRAY_DIMENSIONS: 255,
  /**
   * Android JNI native-inventory split facts (`ReaJadxBridge.java`,
   * REA #9756 / 9943c1c8b). Report allowance only — more than 64 split
   * types or 256-character names are classified unknown. Honesty catalog
   * only; not a densify trip target: planting fake
   * `android:requiredSplitTypes` would perturb Play Feature Delivery /
   * split-install behavior of the protected APK.
   */
  ANDROID_NATIVE_SPLIT_TYPES: 64,
  ANDROID_NATIVE_SPLIT_TYPE_CHARS: 256,
  /**
   * JavaScript member-mutation work allowance (`javascriptSemanticWorkAllowance.ts`,
   * REA #11144 / #11181). Recoverable analysis budget (runtime setting
   * `javascript.member_mutation_alias_states`, env
   * `REA_JAVASCRIPT_MEMBER_MUTATION_ALIAS_STATES`). Honesty catalog only —
   * not a densify trip target: planting enough alias-state mutations to
   * exceed the default 524,288 allowance would bloat and risk perturbing
   * real member-mutation behavior of the protected program, and the caller
   * can raise the cap to 8,388,608.
   */
  JAVASCRIPT_MEMBER_MUTATION_ALIAS_STATES: 524_288,
  JAVASCRIPT_MEMBER_MUTATION_ALIAS_STATES_MAX: 8_388_608,
  /**
   * SQLite owned-worker JS heap ceiling (`SqliteDatabaseLimits.ts`,
   * advertised as `SQLITE_WORKER_HEAP_BYTES` / `workerHeapMiB` on tip
   * 26d88826c). Honesty catalog only — not a densify trip target: this is
   * a worker `--max-old-space-size` cap, not plantable in a protected
   * program. REA 26d88826c also mostly *projects existing* fixed
   * allowances as typed refusals (Ghidra seed, ZIP Zstd window, Flutter,
   * native command output, etc.) rather than adding new trip-able budgets.
   */
  SQLITE_WORKER_HEAP_BYTES: 268_435_456,
  /**
   * New REA analyzers on tip 05be423ac (Android OTA / boot image, Maven POM
   * + Gradle module metadata, NuGet .nupkg, DWARF compile units, ELF
   * `.gnu_debuglink` / `.gnu_debugaltlink`, ELF DT_NEEDED / versions /
   * imports). Honesty catalog only — not densify trip targets:
   *
   * - File-byte and report/pagination ceilings (`MAX_INSPECT_*_FILE_BYTES`,
   *   `MAX_INSPECT_DWARF_UNITS_LIMIT` / default page 32, NuGet nuspec 16 MiB)
   *   are caller-selected admission or walk caps, not plantable budgets.
   * - DWARF abbrev/form-decode and unit walk caps (8,192 abbrevs; 1,048,576
   *   form-decode steps; 100,000 units) sit in optional `.debug_*` sections,
   *   but planting tens of thousands of units or a 256 MiB decompressed
   *   section would massively bloat the image; a stop is an incomplete
   *   census / per-unit issue, not a 1:1 refuse that BLA can trip without
   *   that bloat. 256-row pages are caller-recoverable.
   * - ELF DT_NEEDED / version / import ceilings cannot be planted without
   *   breaking the dynamic linker of the protected image.
   * - Maven/Gradle dependency-row, variant, and XML-node allowances cannot
   *   be planted in a published POM / module file without perturbing
   *   resolution of the protected build.
   * - Extra `.nupkg` ZIP members at the 65,536-entry inventory cap would
   *   balloon the package; NuGet restore may also consume unexpected
   *   `lib`/`build` members.
   * - Android OTA partition/operation and boot-image ramdisk/header bounds
   *   cannot be planted without breaking the update or boot image.
   * - PE certificate-table alignment padding reject (#11823) is analyzer
   *   validation (same class as #9666), not a densify target. CycloneDX
   *   Go/Rust projection, HAR body-identity (#11829), and LimitRef typed
   *   refusals re-own existing allowances.
   */
  MAX_INSPECT_DWARF_UNITS_FILE_BYTES: 536_870_912,
  MAX_DWARF_DECOMPRESSED_SECTION_BYTES: 268_435_456,
  MAX_INSPECT_DWARF_UNITS_LIMIT: 256,
  DEFAULT_INSPECT_DWARF_UNITS_LIMIT: 32,
  MAX_DWARF_UNITS: 100_000,
  MAX_DWARF_ABBREV_ENTRIES: 8_192,
  MAX_DWARF_FORM_DECODE_STEPS: 1_048_576,
  MAX_INSPECT_ELF_DEBUG_LINK_FILE_BYTES: 536_870_912,
  MAX_INSPECT_ELF_DEBUG_LINK_ENTRIES: 256,
  MAX_INSPECT_ELF_DEPENDENCY_FILE_BYTES: 536_870_912,
  MAX_INSPECT_ELF_DEPENDENCY_NEEDED: 65_536,
  MAX_INSPECT_ELF_DEPENDENCY_VERSIONS: 65_536,
  MAX_INSPECT_ELF_DEPENDENCY_IMPORTS: 262_144,
  MAX_INSPECT_MAVEN_GRADLE_METADATA_FILE_BYTES: 16_777_216,
  MAVEN_GRADLE_METADATA_DEPENDENCY_ROWS: 65_536,
  MAVEN_GRADLE_METADATA_VARIANTS: 4_096,
  MAX_INSPECT_NUGET_NUPKG_FILE_BYTES: 536_870_912,
  MAX_INSPECT_NUGET_NUPKG_ENTRIES: 65_536,
  MAX_INSPECT_NUGET_NUPKG_NUSPEC_BYTES: 16_777_216,
  ANDROID_OTA_MAX_MANIFEST_BYTES: 16_777_216,
  ANDROID_OTA_MAX_PARTITIONS: 4_096,
  ANDROID_OTA_MAX_OPERATIONS: 65_536,
  ANDROID_BOOT_MAX_VENDOR_RAMDISKS: 4_096,
  ANDROID_BOOT_MAX_HEADER_SIZE: 1_048_576,
  /**
   * New REA ceilings on tip 31aaec6b4 (198 commits after 05be423ac; almost
   * entirely test / fix / refactor — no new feat analyzers). Honesty catalog
   * only — not densify trip targets:
   *
   * - `ANDROID_PACKED_TABLE_BYTES` (16 MiB) caps decode of Android APS2 / RELR
   *   packed relocation tables (`elfPointerRelocations.ts`, #12047). Planting
   *   a 16 MiB reloc table would bloat or break the protected ELF.
   * - `MAX_PE_OPTIONAL_HEADER_BYTES` (4096) is PE header validation before
   *   classification (`binaryTarget.ts` / inventory, #11691). A larger
   *   optional header is an invalid PE, not a plantable 1:1 refuse.
   * - `DEFAULT_INSPECT_ELF_NOTE_ENTRIES` was raised to 128 so distribution
   *   glibc notes fit (#11847); the hard ceiling
   *   `MAX_INSPECT_ELF_NOTE_ENTRIES` (256) and file-byte cap were already
   *   present on the previous tip (admission / incomplete-census, not new).
   */
  ANDROID_PACKED_TABLE_BYTES: 16_777_216,
  MAX_PE_OPTIONAL_HEADER_BYTES: 4_096,
  /**
   * New REA ceilings on tip c84fde05e (345 commits after 31aaec6b4; 230 fix /
   * 41 refactor / 22 test / 19 perf / 14 docs / 9 ci / 10 feat). The feat
   * commits add inspection capability (FDO packaging/dlopen notes #7237,
   * Ghidra prototype conflicts #8161, MIPS32 PIC shared images, RISC-V
   * initializers / PIC, cargo-auditable dependencies from WASM #5069,
   * DOS COM import, Ghidra 12.2, EM_PPC64 classification) — not plantable
   * densify trip targets. Honesty catalog only:
   *
   * - `FDO_ALLOWANCE` (64 KiB) is a shared per-report JSON decode cap for
   *   ELF FDO packaging / dlopen notes (`ElfFdoNote.ts`, #7237). Planting
   *   dense 64 KiB notes would bloat the ELF; overflow is left undecoded.
   * - `BUNDLE_INFO_PLIST_INPUT_BYTES` (64 MiB) and `INFO_PLIST_DECODE_MIB`
   *   (16) cap Info.plist admission / decode (`AppBundleExecutable.ts`).
   *   A 64 MiB property list would bloat or break the app bundle.
   * - `MAX_WASM_SECTIONS` (65,536) caps cargo-auditable WASM walks
   *   (`RustWasmImage.ts`, #5069). Planting 65,536 sections would bloat
   *   or break the module.
   * - Also noted, not catalogued as new trip targets: `MIPS_GNU_ATTRIBUTES_MAX_BYTES`
   *   (4096, format validation), PE resource `METADATA_BYTES` (8 MiB),
   *   `ASN1_DEPTH_BUDGET` (64, Authenticode nesting — planting would
   *   invalidate the certificate), `GUARDIAN_READINESS_BYTES` (4096, JADX
   *   workspace, not plantable). `MAX_VENDOR_HEADER_SIZE` (1 MiB) was
   *   already catalogued as `ANDROID_BOOT_MAX_HEADER_SIZE`.
   */
  FDO_ALLOWANCE: 65_536,
  BUNDLE_INFO_PLIST_INPUT_BYTES: 64 * 1024 * 1024,
  INFO_PLIST_DECODE_MIB: 16,
  MAX_WASM_SECTIONS: 65_536,
  /**
   * New REA ceilings on tip a2acbe393 (358 commits after c84fde05e; 139 test /
   * 137 fix / 56 refactor / 15 docs / 4 feat / 3 perf / 2 ci / 2 chore).
   * The feat commits add inspection capability (pure-TypeScript UEFI firmware
   * tools #12342, NES 2.0 container headers #10674, ELFv2 PPC64 Power ISA 3.0
   * lane #12517, unresolved managed definition coordinates #12462) — not
   * plantable densify trip targets. Honesty catalog only:
   *
   * - `UEFI_FIRMWARE_INPUT_BYTES` (128 MiB), `UEFI_FIRMWARE_MAX_VOLUMES`
   *   (1024), `UEFI_FIRMWARE_MAX_FILES` (100,000), `UEFI_FIRMWARE_MAX_DEPTH`
   *   (5), `UEFI_FIRMWARE_LZMA_OUTPUT_BYTES` (64 MiB),
   *   `UEFI_FIRMWARE_SCAN_RECORDS` (100,000), and
   *   `UEFI_FIRMWARE_DECODED_BYTES` (128 MiB) are admission / coverage /
   *   decompression caps for the new UEFI parser (`uefiLimits.ts`, #12342).
   *   Planting a 128 MiB image or 100,000 FFS files would bloat or break a
   *   real firmware volume; overflow turns coverage partial, it is not a
   *   trip-able densify target.
   * - NES 2.0 inspection (`inesContainer.ts`, #10674) admits declared PRG/CHR
   *   region sizes; those are format-valid header fields, not plantable
   *   densify counters.
   * - `ZSTD_MAX_FRAMES` (4096) caps exact-frame Zstandard walks
   *   (`zstandardFrameAllowance.ts`, #12416). Planting 4096 frames would
   *   bloat or break the compressed payload.
   * - Also noted, not catalogued as new trip targets: runtime-settable
   *   inventory additions (`REA_BRIDGE_MAX_REQUEST_BYTES`,
   *   `REA_BRIDGE_MAX_REPLY_BYTES`, `REA_CAPTURE_PACKET_JSON_EXPANSION_BYTES`,
   *   `REA_DEBUGGER_MAX_COMMAND_OUTPUT_BYTES`, MCP startup / input / response
   *   budgets, `REA_JADX_HEAP_MIB`, `REA_KUNA_CACHE_MAX_BYTES`,
   *   `ghidra.value_flow_*` operation/edge caps) — process or tool budgets,
   *   not artifact-plantable. Several were already noted on earlier tips.
   */
  UEFI_FIRMWARE_INPUT_BYTES: 128 * 1024 * 1024,
  UEFI_FIRMWARE_MAX_VOLUMES: 1_024,
  UEFI_FIRMWARE_MAX_FILES: 100_000,
  UEFI_FIRMWARE_MAX_DEPTH: 5,
  UEFI_FIRMWARE_LZMA_OUTPUT_BYTES: 64 * 1024 * 1024,
  UEFI_FIRMWARE_SCAN_RECORDS: 100_000,
  UEFI_FIRMWARE_DECODED_BYTES: 128 * 1024 * 1024,
  ZSTD_MAX_FRAMES: 4_096,
});
