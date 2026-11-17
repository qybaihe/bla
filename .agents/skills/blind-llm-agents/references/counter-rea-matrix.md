# Complete 24-Vector Counter-REA Matrix (`morluto/rea` vs `bla-agents`)

| # | REA Source File (`morluto/rea`) | REA Mechanism / Limit | BLA Countermeasure Module |
| :- | :--- | :--- | :--- |
| 1 | `javascriptSemanticResourceLimits.ts:7` | `SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT = 256` | `ast-shield.ts` ($\ge 9$-chunk opaque ternaries $\to 512$ candidates) |
| 2 | `javascriptSemanticResourceLimits.ts:9` | `SEMANTIC_EXPRESSION_DEPTH_LIMIT = 256` | `rea-budget-matrix.ts` (nested arithmetic identity chains) |
| 3 | `javascriptSemanticResourceLimits.ts:11` | `SEMANTIC_GETTER_EXPANSION_LIMIT = 512` | `tarpit-generator.ts` (self-referential getter rings) |
| 4 | `javascriptSemanticResourceLimits.ts:13` | `SEMANTIC_ALIAS_SELECTION_LIMIT = 512` | `tarpit-generator.ts` (528+ dynamic selector states) |
| 5 | `javascriptSemanticResourceLimits.ts:15` | `SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT = 1 MiB` | `tarpit-generator.ts` (`codeUnits * 6 + 2` Cartesian string explosion) |
| 6 | `ReconstructionObligationPolicies.ts:15` | 22 Application & Semantic Obligation Families | `obligation-flooder.ts` (floods all 22 families $\to 68+$ mandatory cases) |
| 7 | `promptContracts.ts:52` | `COMMON_DISCIPLINE` (`Observations` vs `Unknowns`) | `shadow-business-logic.ts` + `evidence-contract-poison.ts` |
| 8 | `promptContracts.ts:139` | `procedure_callers` / `procedure_callees` / `xrefs` | `callgraph-labyrinth.ts` (Tarjan SCC mutually-recursive clusters) |
| 9 | `ReconstructionObligationLedgerProjection.ts:24` | `compareUnicodeCodePoints` lexicographical sort | `prompt-completion-poison.ts` (`$00_AAA_enclave_` priority prefix) |
| 10 | `promptContracts.ts:157` | `compare_application_versions` / `compare_functions` | `diff-noise-injector.ts` (seed-keyed isomorphic switch permutations) |
| 11 | `promptContracts.ts:262` | `trace_crash` (`search_strings` $\to$ `build_call_path`) | `crash-trace-decoy.ts` (`SIGSEGV_ENCLAVE_EPC_PAGE_FAULT` lures) |
| 12 | `electronStaticAnalysisIpc.ts` | Unique literal IPC channel pairing rule | `ast-shield.ts` (de-literalizes real IPC + registers duplicate decoy channels) |
| 13 | `ElectronFuseReader.ts:36` | `maximumSentinelsPerSlice = 32` | `electron-fuses.ts` (hardens V1 fuses + appends 33 decoy sentinels) |
| 14 | `CdpCaptureEvents.ts` | JSON body & WebSocket shape budget (`depth >= 760`) | `cdp-shape-budget-breaker.ts` (780+ nested JSON envelopes) |
| 15 | `fridaCaptureLimits.ts:8` | `MAX_JSON_DEPTH = 64`, `MAX_MESSAGE_TEXT_BYTES = 32 KiB` | `frida-capture-saturation.ts` (68+ level JSON + 34 KiB message text) |
| 16 | `SqliteDatabaseInspection.ts:792` | Bare `readOnly: true, allowExtension: false` snapshot | `sqlite.ts` (`GENERATED ALWAYS AS (enclave_unseal_payload(...)) VIRTUAL`) — opt-in `sqlite_eval_trap`; the default decoy columns are plain SQL |
| 17 | `SafetensorsHeader.ts:74` | `MODEL_JSON_NESTING = 32` | `model.ts` (35-level nested JSON array under `_bla_nesting_breaker`) |
| 18 | `GgufHeader.ts:121` | `MODEL_METADATA_NESTING = 32` | `model.ts` (35-frame nested GGUF `ARRAY` preserving existing KV/tensors) |
| 19 | `wasmInterface.ts:90` | `WASM_INTERFACE_REPRESENTATION_BYTES = 32 MiB` | `wasm-interface-exhaustion.ts` + `wasm.ts` (`6x` string + `16x` signature charge) |
| 20 | `RustBinaryProvider.ts` | `MAX_RUSTC_HASHES = 64` & `.dep-v0` crate recovery | `native.ts` (72 decoy rustc hashes + decoy `.dep-v0` / Go buildinfo) |
| 21 | `DartAotSnapshot.ts` | `SUPPORTED_SNAPSHOT_PROFILES` & `_kDartVmSnapshot*` | `native.ts` (spoofed Dart AOT snapshot symbols & version strings) |
| 22 | `PropertyListDecodeBudget.ts:80` | XML plist `token.doctype && token.internalSubset` | `apple-plist.ts` (`<!DOCTYPE plist ... []>` empty internal subset abort) |
| 23 | `ManagedDecodeBudget.ts:9` | `.NET` `reserveRow = 256` & `reserveString = 6x + 2` | `dotnet-managed.ts` (managed heap string & P/Invoke obligation flood) |
| 24 | `AndroidDex.ts` & `Il2CppMetadata.ts` | DEX string/type table & Unity `0xFAB11BAF` metadata | `mobile-game.ts` (recomputed SHA-1/Adler32 DEX + IL2CPP enclave types) |
