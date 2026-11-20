# BLA nightly development log

## 2026-11-20 ~America/Los_Angeles / ~2026-11-21 02:00 Asia/Shanghai

### REA delta
- Pulled `morluto/rea`: `c84fde05e` → `a2acbe393` (**+358** commits). Dirty
  `third_party/*` submodule checkouts were left untouched.
- No new 1:1 trip-able densify constants. The delta is mostly test / fix /
  refactor (139 test / 137 fix / 56 refactor / 15 docs / 4 feat / 3 perf /
  2 ci / 2 chore). Feat commits add inspection capability, not plantable
  densify targets: pure-TypeScript UEFI firmware tools (#12342), NES 2.0
  container headers (#10674), ELFv2 PPC64 Power ISA 3.0 lane (#12517),
  unresolved managed definition coordinates (#12462). New or newly
  advertised ceilings are admission / coverage / decompression caps, not
  plantable without breaking the artifact:
  - `UEFI_FIRMWARE_INPUT_BYTES` = 128 MiB, `UEFI_FIRMWARE_MAX_VOLUMES` = 1024,
    `UEFI_FIRMWARE_MAX_FILES` = 100,000, `UEFI_FIRMWARE_MAX_DEPTH` = 5,
    `UEFI_FIRMWARE_LZMA_OUTPUT_BYTES` = 64 MiB, `UEFI_FIRMWARE_SCAN_RECORDS` =
    100,000, `UEFI_FIRMWARE_DECODED_BYTES` = 128 MiB (`uefiLimits.ts`, #12342)
    — admission / coverage / decompression caps for the new UEFI parser;
    planting a 128 MiB image or 100,000 FFS files would bloat or break a
    real firmware volume, and overflow turns coverage partial.
  - `ZSTD_MAX_FRAMES` = 4096 (`zstandardFrameAllowance.ts`, #12416) — exact-
    frame Zstandard walk cap; planting 4096 frames would bloat or break the
    compressed payload.
  - NES 2.0 inspection (`inesContainer.ts`, #10674) admits declared PRG/CHR
    region sizes; those are format-valid header fields, not plantable
    densify counters.
  - Also noted, not catalogued as new trip targets: runtime-settable
    inventory additions (`REA_BRIDGE_MAX_REQUEST_BYTES`,
    `REA_BRIDGE_MAX_REPLY_BYTES`, `REA_CAPTURE_PACKET_JSON_EXPANSION_BYTES`,
    `REA_DEBUGGER_MAX_COMMAND_OUTPUT_BYTES`, MCP startup / input / response
    budgets, `REA_JADX_HEAP_MIB`, `REA_KUNA_CACHE_MAX_BYTES`,
    `ghidra.value_flow_*` operation/edge caps) — process or tool budgets,
    not artifact-plantable. Several were already noted on earlier tips.
- Catalogued the new headline maxima in `REA_INTERNAL_LIMITS` (honesty only).

### Done tonight
- Landed the Safetensors load-time hook (`generateSidecarSafetensorsLoaderSnippet` /
  `prependSafetensorsSidecarLoaderHook` / `entangleSafetensorsLoaderWithSidecars` /
  `computeSafetensorsSidecarCodeIdentity`; marker `_installSafetensorsSidecarLoaderHook`;
  `protectTarget` + `hardenProject` post-pass). Auto-wired only into a
  same-directory Python loader named `loader.py`, `__init__.py`, or
  `__main__.py` that already mentions the `.safetensors` basename
  (`selectPythonSafetensorsLoader` / `discoverPythonSafetensorsLoader` /
  `isSafePythonSafetensorsLoader` / `isSafetensorsSidecarLoaderHookWired` /
  `sourceMentionsSafetensorsFile`). The hook does not rewrite the
  `.safetensors` artifact (header JSON tensor descriptors, `data_offsets`,
  dtype, and tensor bytes stay bit-exact; the existing `__metadata__`
  `bla.sidecar.v1` host-verify note remains the only Safetensors mutation).
  Test / already-entangled / self-seal / unknown helper files are never
  hooked. Vector `safetensors-sidecar-entangle` is recorded and
  `safetensors-sidecar-host-verify-only` is cleared only when that hook was
  actually written. Default OFF via existing `sidecarEntangle`.
- Live BLA tree was pulled `6507e0d` / `3.5.2` → `24b6161` / `3.5.3`
  (daytime patch release already on main: binary Apple plist EOF trailer
  preservation, multi-site soft-mode self-seal tamper parity, esbuild
  `node_modules` path-segment filtering, CLI error control-character
  sanitization, website verifier sibling-prefix containment; #255–#259).
- Gates: build OK, tests **1315 passed / 5 skipped**, benchmark **14/14**
  runtime-equivalent.

### Next step (following night)
1. DEX / SQLite load-time hooks (same honesty bar: only record the vector /
   clear `*-host-verify-only` when a real load-time hook was written).
2. Browser WASM loader auto-wire (the hook still needs Node `fs` /
   `crypto`; a browser snippet would have to verify without those).
3. ESM hook that runs before hoisted *user* imports; MCP one-click
   polish; empirical JADX / Android red-team; ESP #8228; Dependabot majors.


## 2026-11-19 ~America/Los_Angeles / ~2026-11-20 02:00 Asia/Shanghai

### REA delta
- Pulled `morluto/rea`: `31aaec6b4` → `c84fde05e` (**+345** commits). Dirty
  `third_party/*` submodule checkouts were left untouched.
- No new 1:1 trip-able densify constants. The delta is mostly fix / refactor /
  test / perf (230 fix / 41 refactor / 22 test / 19 perf / 14 docs / 9 ci /
  10 feat). Feat commits add inspection capability, not plantable densify
  targets: FDO packaging/dlopen notes (#7237), Ghidra prototype conflicts
  (#8161), MIPS32 PIC shared images, RISC-V initializers / PIC, cargo-auditable
  dependencies from WASM (#5069), DOS COM import, Ghidra 12.2, EM_PPC64
  classification. New or newly advertised ceilings are admission / decode /
  format-validation caps, not plantable without breaking the artifact:
  - `FDO_ALLOWANCE` = 64 KiB (`ElfFdoNote.ts`, #7237) — shared per-report JSON
    decode cap for ELF FDO packaging / dlopen notes; overflow is left
    undecoded, and planting dense 64 KiB notes would bloat the ELF.
  - `BUNDLE_INFO_PLIST_INPUT_BYTES` = 64 MiB and `INFO_PLIST_DECODE_MIB` = 16
    (`AppBundleExecutable.ts`) — Info.plist admission / decode caps; a 64 MiB
    property list would bloat or break the app bundle.
  - `MAX_WASM_SECTIONS` = 65,536 (`RustWasmImage.ts`, #5069) — cargo-auditable
    WASM walk cap; planting 65,536 sections would bloat or break the module.
  - Also noted, not catalogued as new trip targets: `MIPS_GNU_ATTRIBUTES_MAX_BYTES`
    (4096, format validation), PE resource `METADATA_BYTES` (8 MiB),
    `ASN1_DEPTH_BUDGET` (64, Authenticode nesting), `GUARDIAN_READINESS_BYTES`
    (4096, JADX workspace). `MAX_VENDOR_HEADER_SIZE` (1 MiB) was already
    catalogued as `ANDROID_BOOT_MAX_HEADER_SIZE`.
- Catalogued the new headline maxima in `REA_INTERNAL_LIMITS` (honesty only).

### Done tonight
- Landed the GGUF load-time hook (`generateSidecarGgufLoaderSnippet` /
  `prependGgufSidecarLoaderHook` / `entangleGgufLoaderWithSidecars` /
  `computeGgufSidecarCodeIdentity`; marker `_installGgufSidecarLoaderHook`;
  `protectTarget` + `hardenProject` post-pass). Auto-wired only into a
  same-directory Python loader named `loader.py`, `__init__.py`, or
  `__main__.py` that already mentions the `.gguf` basename
  (`selectPythonGgufLoader` / `discoverPythonGgufLoader` /
  `isSafePythonGgufLoader` / `isGgufSidecarLoaderHookWired` /
  `sourceMentionsGgufFile`). The hook does not rewrite the `.gguf` (tensor
  infos, relative tensor offsets, and tensor bytes stay bit-exact; the
  existing alignment-safe `bla.sidecar.v1` STRING metadata note remains the
  only GGUF mutation). Test / already-entangled / self-seal / unknown helper
  files are never hooked. Vector `gguf-sidecar-entangle` is recorded and
  `gguf-sidecar-host-verify-only` is cleared only when that hook was actually
  written. Default OFF via existing `sidecarEntangle`.
- Live BLA tree was pulled `4bb09a6` / `3.5.1` → `1d4d490` (still `3.5.1`,
  unreleased daytime work already on main: WASM Code-section opaque flower
  bytecode, decoy-tell scrub, rare-CJK BPE amplification).
- Gates: build OK, tests **1296 passed / 5 skipped**, benchmark **14/14**
  runtime-equivalent.
- Cut `bla-agents@3.5.2` (tag `bla-agents-3.5.2`).

### Next step (following night)
1. Safetensors / DEX / SQLite load-time hooks (same honesty bar: only record
   the vector / clear `*-host-verify-only` when a real load-time hook was
   written). Safetensors Python loaders are the closest remaining analogue.
2. Browser WASM loader auto-wire (the hook still needs Node `fs` /
   `crypto`; a browser snippet would have to verify without those).
3. ESM hook that runs before hoisted *user* imports; MCP one-click
   polish; empirical JADX / Android red-team; ESP #8228; Dependabot majors.


## 2026-11-18 ~America/Los_Angeles / ~2026-11-19 02:00 Asia/Shanghai

### REA delta
- Pulled `morluto/rea`: `05be423ac` → `31aaec6b4` (**+198** commits). Dirty
  `third_party/*` deletions were left untouched.
- No new 1:1 trip-able densify constants. The delta is almost entirely test /
  fix / refactor / chore / perf (no new `feat` analyzers). New or newly
  advertised ceilings are admission / format-validation / incomplete-census
  caps, not plantable without breaking the artifact:
  - `ANDROID_PACKED_TABLE_BYTES` = 16 MiB (`elfPointerRelocations.ts`, #12047)
    — decode cap for Android APS2 / RELR packed relocation tables; planting a
    16 MiB reloc table would bloat or break the protected ELF.
  - `MAX_PE_OPTIONAL_HEADER_BYTES` = 4096 (`binaryTarget.ts` / inventory,
    #11691) — PE header validation before classification; a larger optional
    header is an invalid PE (same class as #11823).
  - `DEFAULT_INSPECT_ELF_NOTE_ENTRIES` was raised to 128 so distribution
    glibc notes fit (#11847); the hard ceiling
    `MAX_INSPECT_ELF_NOTE_ENTRIES` (256) and file-byte cap were already
    present on the previous tip.
- Catalogued the new headline maxima in `REA_INTERNAL_LIMITS` (honesty only).

### Done tonight
- Landed the `.pyc` import-time hook (`generateSidecarPycLoaderSnippet` /
  `prependPycSidecarLoaderHook` / `entanglePycLoaderWithSidecars` /
  `computePycSidecarCodeIdentity`; marker `_installPycSidecarLoaderHook`;
  `protectTarget` + `hardenProject` post-pass). Auto-wired only into a
  same-directory (or parent-of-`__pycache__`) Python loader named
  `loader.py`, `__init__.py`, or `__main__.py` that already mentions the
  module or `.pyc` basename (`selectPythonPycLoader` /
  `discoverPythonPycLoader` / `isSafePythonPycLoader` /
  `isPycSidecarLoaderHookWired` / `sourceMentionsPycModule`). The hook
  does not rewrite the `.pyc` (marshal layout, `co_filename` / `co_name`,
  PEP 552 hash header, and `co_consts` weaves stay untouched) and never
  targets the `.py` source of the `.pyc`, test files, or already-entangled
  / self-seal entries. Vector `pyc-sidecar-entangle` is recorded and
  `pyc-sidecar-host-verify-only` is cleared only when that hook was
  actually written. Default OFF via existing `sidecarEntangle`.
- Live BLA tree was pulled `64dfa50` / `3.4.4` → `c20d5dc` / `3.5.0`
  before this increment (daytime PRs already on main: ship-ready harden
  apply/restore, shield equivalence, PCAP tshark allowance, site version
  sync).
- Gates: build OK, tests **1282 passed / 5 skipped**, benchmark **14/14** runtime-equivalent.
- Cut `bla-agents@3.5.1` (tag `bla-agents-3.5.1`).

### Next step (following night)
1. GGUF / DEX / Safetensors / SQLite load-time hooks (same honesty bar:
   only record the vector / clear `*-host-verify-only` when a real
   load-time hook was written).
2. Browser WASM loader auto-wire (the hook still needs Node `fs` /
   `crypto`; a browser snippet would have to verify without those).
3. ESM hook that runs before hoisted *user* imports; MCP one-click
   polish; empirical JADX / Android red-team; ESP #8228; Dependabot majors.


## 2026-11-17 ~America/Los_Angeles / ~2026-11-18 02:00 Asia/Shanghai

### REA delta
- Pulled `morluto/rea`: `26d88826c` → `05be423ac` (**+41** commits). Dirty
  `third_party/*` deletions were left untouched.
- No new 1:1 trip-able densify constants. New analyzers add inspection /
  walk / pagination ceilings that are not plantable without breaking the
  protected artifact or massively bloating it:
  - Android OTA payload inventory (#11378) and boot-image inspection —
    planting extra partitions, operations, or vendor ramdisks would break
    the update / boot image.
  - Maven POM + Gradle module metadata, NuGet `.nupkg` — planting
    dependency rows or 65,536 ZIP members would perturb resolution or
    balloon the package.
  - DWARF compile units, ELF `.gnu_debuglink` / debugaltlink, ELF
    DT_NEEDED / versions / imports — DT_NEEDED cannot be planted without
    breaking the dynamic linker; DWARF/file-byte/page ceilings are
    admission or incomplete-census caps, not 1:1 refuses.
  - PE certificate-table alignment padding reject (#11823) is analyzer
    validation (same class as #9666). CycloneDX Go/Rust projection, HAR
    body-identity (#11829), and LimitRef typed refusals re-own existing
    allowances.
- Catalogued the headline maxima in `REA_INTERNAL_LIMITS` (honesty only).

### Done tonight
- Extended the WASM JS-loader hook auto-wire to a same-directory Node.js
  ESM loader whose static `import` / `export-from` specifiers are Node
  builtins only (`detectWasmJsLoaderCarrier` /
  `esmStaticImportsAreNodeBuiltinsOnly` / `listStaticEsmModuleSpecifiers`;
  `protectTarget` + `hardenProject` post-pass; `carrier: "module"`).
  Known names stay `<stem>.*`, `loader.*`, `index.*`; `.cjs` still wins a
  same-rank tie, then `.js`, then `.mjs`. Browser `fetch`-only loaders,
  ESM files that statically import user modules or `.wasm`, minified /
  test files, and already-entangled entries remain untouched. Vector
  `wasm-sidecar-entangle` is recorded and `wasm-sidecar-host-verify-only`
  is cleared only when that hook was actually written. Default OFF via
  existing `sidecarEntangle`.
- Honesty: `jsModuleHasHoistedDependencyGraph` no longer treats Node
  builtin-only static imports as a user hoisted graph (so a dedicated
  ESM WASM loader does not get a spurious `esm-import-hoist-before-hooks`
  soft-cap). User-module imports such as `./lib.js` are still flagged.
- Live BLA tree was pulled `645993f` / `3.4.2` → `f6f37c4` / `3.4.3`
  before this increment (daytime PRs already on main: PE32/ARM64/ELF32
  `.enclave` islands, anti-marker-spoofing, fail-closed GGUF, MCP/CLI
  hygiene).
- Gates: build OK, tests **988 passed / 4 skipped**, benchmark **14/14**
  runtime-equivalent.

### Next step (following night)
1. `.pyc` import-time hook (only then record `pyc-sidecar-entangle` /
   clear `pyc-sidecar-host-verify-only`).
2. GGUF / DEX / Safetensors / SQLite load-time hooks (same honesty bar).
3. Browser WASM loader auto-wire (the hook still needs Node `fs` /
   `crypto`; a browser snippet would have to verify without those).
4. ESM hook that runs before hoisted *user* imports; MCP one-click
   polish; empirical JADX / Android red-team; ESP #8228; Dependabot majors.


## 2026-11-16 ~America/Los_Angeles / ~2026-11-17 02:00 Asia/Shanghai

### REA delta
- Pulled `morluto/rea`: `f916b3ecf` → `26d88826c` (**+208** commits). Dirty
  `third_party/*` deletions were left untouched (a stash-pop auto-merge of
  `package-lock.json` was restored to HEAD so only those deletions remain
  dirty).
- No new 1:1 trip-able densify constants that beat the queued WASM JS-loader
  auto-wire.
- Catalog-only / honesty notes (not implemented as new densify counters):
  - `SQLITE_WORKER_HEAP_BYTES` = 256 MiB (`SqliteDatabaseLimits.workerHeapMiB`,
    newly advertised on this tip). Owned-worker `--max-old-space-size` cap —
    not plantable in a protected program; catalogued in `REA_INTERNAL_LIMITS`.
  - The bulk of the delta *projects existing* fixed allowances as typed
    refusals (`feat(errors|native|flutter|pcap|artifacts): carry the value
    of each fixed … allowance`, Ghidra seed / ZIP Zstd window / native
    command output / Flutter ceilings relocated or re-exported, not raised).
  - Evidence format revision 2 (`feat(evidence)!: name the Evidence subject
    by its target identity`, #11416) — contract revision, not a densify
    target.
  - `fix(browser): report semantic limits reached by captured scripts`
    (#11755) reports already-catalogued web-bundle / JS semantic controls;
    no new plantable budget.

### Done tonight
- Auto-wired the 2026-11-15 WASM JS-loader hook into a known, safe customer
  loader path (`selectNodeWasmJsLoader` / `discoverNodeWasmJsLoader` /
  `isSafeNodeWasmJsLoader` / `isWasmSidecarLoaderHookWired` /
  `listSameDirNodeWasmJsLoaderCandidates`; `protectTarget` + `hardenProject`
  post-pass). The hook is injected only into a same-directory Node.js
  CommonJS file that already uses `fs` and `WebAssembly.instantiate` /
  `compile` / `instantiateStreaming` and mentions the `.wasm` basename.
  Known names only: `<stem>.cjs`/`.js`, `loader.*`, `index.*` (`.cjs` wins
  a same-rank tie). Browser `fetch`-only loaders, ESM static `import` /
  `import.meta`, minified / test files, already-entangled self-seal or
  sidecar-preamble entries, files over 64 KiB (predicate run on the
  pre-protect input), and unranked unique app files such as `license.cjs`
  are left untouched — this keeps CrackMe v9 `license.cjs` + `core.wasm`
  (baked self-seal digests) behavior-preserving. The hook is written
  before the `bla.sidecar.v1` custom section is planted and before a JS
  sidecar preamble, and a new section is planted only when the only
  JS/Python entry being bound is the dedicated loader itself (never when
  a foreign entry may already bake a wasm digest). Export surface and
  function bodies stay unchanged. Vector `wasm-sidecar-entangle` is
  recorded and defenseScore gap `wasm-sidecar-host-verify-only` is cleared
  only when that hook was actually written (`wasmSidecarLoaderHookApplied`;
  `verifyTarget` also detects a sibling hook via
  `isWasmSidecarLoaderHookWired`). Default OFF via existing
  `sidecarEntangle`.
- Live BLA tree was pulled `98e01cc` → `de982cb` before this increment
  (daytime PRs already on 3.4.1: MCP in-place confirmation / arg bounds,
  lint SARIF, coverage floors, reporter sanitization, bundler skip
  summary, Node 22 pin, ESM import-hoist honesty, SEO).
- Gates: build OK, tests **938 passed / 4 skipped**, benchmark **14/14**
  runtime-equivalent.
- Pushed `origin/main`; release **bla-agents@3.4.2**.

### Next step (following night)
1. `.pyc` import-time hook (only then record `pyc-sidecar-entangle` /
   clear `pyc-sidecar-host-verify-only`).
2. GGUF / DEX / Safetensors / SQLite load-time hooks (same honesty bar).
3. MCP one-click polish; ESM loader hook that runs before hoisted
   imports; empirical JADX / Android red-team; ESP #8228; Dependabot majors.



## 2026-11-15 ~America/Los_Angeles / ~2026-11-16 02:00 Asia/Shanghai

### REA delta
- Pulled `morluto/rea`: `1ba93b460` → `f916b3ecf` (**+320** commits). Dirty
  `third_party/*` deletions were left untouched.
- No new 1:1 trip-able densify constants that beat the queued WASM JS-loader hook.
- Catalog-only / honesty notes (not implemented as new densify counters):
  - REA #11144 / #11181: `DEFAULT_JAVASCRIPT_MEMBER_MUTATION_ALIAS_STATES = 524_288`
    / `MAXIMUM_JAVASCRIPT_MEMBER_MUTATION_ALIAS_STATES = 8_388_608` (recoverable
    runtime setting `javascript.member_mutation_alias_states`). Planting enough
    alias-state mutations to trip the default would bloat and risk perturbing
    real member-mutation behavior; catalogued in `REA_INTERNAL_LIMITS`.
  - New tool/reply budgets `REA_BRIDGE_MAX_REPLY_BYTES` (default 256 MiB) and
    `REA_CAPTURE_PACKET_JSON_EXPANSION_BYTES` (default 128 GiB) — not plantable
    in a protected program.
  - `APK_SIGNING_BLOCK_MAX_PAIRS = 4096` (admission cap on signing-block pairs)
    — not a densify trip target (stuffing the signing block would break
    signature / installer validity).

### Done tonight
- Optional JS-loader hook for WASM `bla.sidecar.v1` custom-section verification
  (`computeWasmSidecarCodeIdentity` / `generateSidecarWasmLoaderSnippet` /
  `prependWasmSidecarLoaderHook` / `entangleWasmLoaderWithSidecars`; marker
  `_installWasmSidecarLoaderHook`; wraps `WebAssembly.instantiate` /
  `compile` / `instantiateStreaming`; identity is SHA-256 of the module with
  the note stripped so a strip still matches and fails closed; unrelated WASM
  passes through). Host-opt-in snippet — the hook runs only when the customer
  prepends it into the loader that instantiates the module. Vector
  `wasm-sidecar-entangle` reserved, not recorded; defenseScore gap
  `wasm-sidecar-host-verify-only` soft-cap 93 kept; default OFF via existing
  `sidecarEntangle`. Export surface and function bodies stay unchanged.
- Gates: build OK, tests **907 passed / 4 skipped**, benchmark **14/14** runtime-equivalent.

### Next step (following night)
1. Auto-wire the WASM JS-loader hook into a known customer loader path (only
   then record `wasm-sidecar-entangle` / clear `wasm-sidecar-host-verify-only`).
2. `.pyc` import-time hook; GGUF / DEX / Safetensors / SQLite load-time hooks.
3. MCP one-click polish; empirical JADX / Android red-team; ESP #8228; Dependabot majors.


## 2026-11-14 ~America/Los_Angeles / Asia/Shanghai

### REA delta
- Pulled `morluto/rea`: `3cb75d46b` → `1ba93b460` (**+199** commits). Dirty
  `third_party/*` deletions were left untouched.
- No new 1:1 trip-able densify constants that beat the queued SQLite
  schema-comment sidecar increment.
- Catalog-only / honesty notes (not implemented as new densify counters):
  - REA #4445 (`c8d5413d0`): NativeAOT work budget renamed
    `NATIVE_AOT_MAX_WORK_UNITS` → `NATIVE_AOT_BASE_WORK_UNITS` and scaled as
    `BASE + 8 * min(sourceBytes, MAX_SOURCE_BYTES)`. Budget *relaxation*;
    catalogued in `REA_INTERNAL_LIMITS`.
  - REA #9756 (`9943c1c8b`): `NATIVE_SPLIT_TYPES = 64` /
    `NATIVE_SPLIT_TYPE_CHARS = 256` report allowance. Planting fake
    `android:requiredSplitTypes` would perturb split-install behavior —
    not a densify trip target.
  - GGUF empty innermost ARRAY now counts against existing
    `MODEL_METADATA_NESTING = 32` (`d7c73923d`). BLA's 35-frame densify
    already trips this bound.
  - `feat(python): decode CPython 3.14 and 3.15 pyc code objects`
    (`1d08253ff`, `PYTHON_PYC_SLICE_MAGIC = 3608`) — capability expansion,
    not a budget/limit trip target.

### Done tonight
- SQLite schema-comment / reserved-VIEW sidecarEntangle strip⇒fail
  (`generateSidecarSqliteSchemaComment` / `bindSqliteSidecarEntanglement` /
  `entangleSqliteEntryWithSidecars` / `verifySqliteSidecarSchemaComment` /
  `extractSqliteSidecarSchemaComment` / `stripSqliteSidecarSchemaComment`;
  unused `bla_sidecar_v1` VIEW with `SELECT … AS "bla.sidecar.v1" WHERE 0`;
  protect + harden SQLite post-pass; vector `sqlite-sidecar-entangle`
  reserved, not recorded; defenseScore gap `sqlite-sidecar-host-verify-only`
  soft-cap 93; default OFF via existing `sidecarEntangle`). User tables,
  rows, query results, WAL/FK, and application_id / user_version stay
  unchanged.
- Gates: build OK, tests **891 passed / 4 skipped**, benchmark **14/14**
  runtime-equivalent.

### Next step (following night)
1. Optional JS-loader `verifyWasmSidecarCustomSection` (host JS snippet for WASM loaders).
2. `.pyc` import-time hook; GGUF / DEX / Safetensors / SQLite load-time hooks.
3. MCP one-click polish; empirical JADX / Android red-team; ESP #8228; Dependabot majors.


## 2026-11-10 ~America/Los_Angeles (box) / Asia/Shanghai

### REA delta
- Pulled `morluto/rea`: `e9b6c87c1` → `b2f3dc81f` (**+12** commits).
- Headline: recoverable analysis budgets across CLI/MCP (#9706) — existing
  ceilings become caller-selectable/recoverable (desktop SQLite view policy,
  ASAR/Ghidra admission, JS semantic precision, WASM representation, source-map,
  historical capture, Frida/LLDB retention, Go/Rust inspection, etc.). **No new
  1:1 trip-able densify constants** that beat the queued ASAR main JS preamble.
- Also: PE cert-table misalignment reject (#9666), desktop multi-task capture
  (#9216), JS application path admission (#9789), docs/CI polish.

### Done tonight
- ASAR main JS preamble strip⇒fail (`generateSidecarAsarMainJsPreamble` /
  `selectAsarMainJsMember` / `asarMemberPathFromMain` /
  `entangleAsarMainJsWithSidecars` / `prependAsarMainJsPreamble`; marker
  `__blaAsarSidecarDigest`; protect + harden ASAR post-pass; vector
  `asar-sidecar-entangle`; default OFF via existing `sidecarEntangle`).
- Gates: build OK, tests **693 passed / 4 skipped**, benchmark **14/14**
  runtime-equivalent.
- Pushed `origin/main`; release **bla-agents@3.2.4**.

### Next step (following night)
1. Optional JS-loader `verifyWasmSidecarCustomSection` (host JS snippet for WASM loaders).
2. Deception shields → more formats (DEX string pool / SQLite comments / Safetensors·GGUF header metadata densify) or MCP one-click polish.
3. Re-scan REA recoverable-budget calibration for any new numeric densify targets.


## 2026-11-09 ~Asia/Shanghai

### REA delta
- Pulled `morluto/rea`: `559083be2` → `e9b6c87c1` (**+142** commits).
- Headline surface area: desktop/AppImage host tooling, Android `.note.android.ident`,
  Deno compile inventory (#8527), ELF unwind/init arrays, V8 cachedData boundaries —
  no new 1:1 trip-able budget constants that beat the queued ASAR companion slice.
- Electron ASAR tests/polish only (`#9549` authorized ASAR path) — reinforces
  archive-note strip⇒fail as the right defensive increment.

### Done tonight
- ASAR archive-note sidecar entanglement (`generateSidecarAsarArchiveNote` /
  `bindAsar` / `entangleAsar` / `verifyAsarSidecarArchiveNote`; in-archive
  `.bla/sidecar.v1.json` binding `enclave/hardware-tee-bridge.js`; protect +
  harden ASAR-only post-pass; default OFF via existing `sidecarEntangle`).
- Fixed accidental `selfSeal` spread onto the ASAR decoy `VirtualAsarFile`.
- Gates: build OK, tests **683 passed / 4 skipped**, benchmark **14/14** runtime-equivalent.
- Pushed `origin/main`; release **bla-agents@3.2.2**.

### Next step (following night)
1. Optional ASAR main JS preamble (Electron fs-patched member re-measure).
2. Optional JS-loader `verifyWasmSidecarCustomSection`.
3. Scan REA Deno compile (#8527) / ELF unwind for a net-positive 1:1 counter.

## 2026-11-01 ~02:10 (Asia/Singapore)

### REA delta
- Pulled `morluto/rea`: tip now `60149282f` (was ~`69bf61f7c` / `a989c0e45` era).
- Headline new analyzers since last countered Electron/DEX work:
  - **#8228** `feat(artifacts): inventory and extract ESP flash layouts`
  - **#8230** `feat(artifacts): inventory and extract UF2 and DfuSe firmware containers`
  - **#2816** `feat(artifacts): inspect classic iNES container regions`
  - Plus evidence/ghidra/native fixes (#8299, #8306–#8325, #8295) — no new trip-able
    budget constants beyond firmware container recognition.

### Done tonight
- Countered REA **#8230** with UF2 append-only not-main-flash / file-container
  decoys (`src/shields/formats/firmware-uf2.ts` + detector/protector/auditor/
  identity/`verify:rea`/tests). Red-line: never emit main-flash decoys; never
  rewrite original blocks.
- Fixed `verify:rea` obligation-family catalog (26 incl. `url-scheme`).
- Gates: build OK, tests **247/247** (+1 skipped), benchmark 14/14 runtime-
  equivalent, verify:rea **74/74**.
- Release **bla-agents@1.6.2**.
- Queued (not done): ESP flash image (#8228) trailing/partition deception;
  DfuSe (CRC-sensitive); iNES (#2816, niche).

### Next step (following night)
1. ESP flash / esp-image (#8228) counter — unsigned only; trailing undescribed
   bytes + partition-table decoys without breaking checksums/Secure Boot.
2. Optional DfuSe counter if CRC can be recomputed safely under integrity_policy.
3. Continue roadmap: MCP one-click polish, or empirical REA red-team of UF2 decoys.


## 2026-11-01 (Asia/Shanghai)

### REA delta
- Inspected `morluto/rea`: `69bf61f7c` → `a989c0e45` (**17 commits**).
- Headline new analyzer: **`47fa6ab37`** (`feat(electron): report custom URL protocol registrations` — `electronStaticAnalysisProtocol.ts`, `electronStaticAnalysisValues.ts`, `electronStaticAnalysisBrowser.ts`, and 26th `"url-scheme"` family in `ReconstructionObligationPolicies.ts`).

### Done tonight
- Countered REA `47fa6ab37` in `ast-shield.ts`, `rea-budget-matrix.ts`, and `obligation-flooder.ts` (custom URL scheme de-literalization incl. 1–2 char schemes, `registerSchemesAsPrivileged` boolean blackout, `contextBridge.exposeInMainWorld` member blackout, `BrowserWindow` `webPreferences` + `preload` blackout, proven `"electron"` dead-branch decoy protocols, and 26th `"url-scheme"` obligation flood).
- Added `detectNativeEofAppendHazard` (`LC_CODE_SIGNATURE`, PE Authenticode `DataDirectory[4]`, PyInstaller, Deno standalone, ZIP-SFX) + executable mode preservation + `.bunfs-snapshot` sidecar audit verification loop.
- Fixed `html-bundle` multi-`<script>` global collision, `importmap`/`application/json` preservation, Vite external-script bootstrap, and `auditor.ts` `<script>` extraction + full chaff manifest header matching.
- Added cross-platform POSIX/SARIF Windows fixes (`C:\...` drive colons, 8.3 short paths, `cmd.exe /c npm`, `System32\tar.exe`, `.gitattributes`) and `windows-latest` to `.github/workflows/ci.yml`.
- Upgraded public challenge target to **CrackMe v5.2** (anchor `0x3aa14b2c`, Windows CRLF normalization + V8 `Function.prototype.toString` anti-`fs.readFileSync`-virtualization check).
- Prepared feature PR for next release (`bla-agents@1.6.0`).

## 2026-10-31 (Asia/Shanghai)

### Recovery
- Investigated reported "last night failed" claim: working tree was **clean** at
  `b2d6436` (v1.5.1), in sync with `origin/main`, CI green. No dirty state /
  merge conflict / uncommitted junk to recover. Proceeded with new work.

### REA delta
- Pulled `morluto/rea`: `c0c390220` → `69bf61f7c` (**46 commits**).
- Headline new analyzer: **#8154** external DEX method caller tracing
  (`MAX_XREF_TEXT_BYTES` = 8 MiB − 1 KiB, `MAX_EXTERNAL_XREF_BYTES` = that / 8).
- Also noted: #8015 .NET field constant defaults (no new trip-able budget);
  #8117 Apple `.appex`/`.framework`/`.xpc`/`.plugin` bundle open (admission
  expansion, not a densify target tonight).

### Done tonight
- `src/shields/formats/android-dex-xref.ts` + unsigned-APK wiring in `archive.ts`.
- `src/identity.ts` + `verify:rea` (.java walk) + tests.
- Release **bla-agents@1.5.2**.

### Next step (2026-11-01)
1. Empirical red-team: point sibling REA JADX external-references tool at a
   BLA-hardened unsigned APK fixture; capture before/after in `docs/redteam/`.
2. Optionally densify decoy callers further / add overload prototype bait for
   the method_inventory stage of #8154.
3. Continue roadmap: ESP32 / Godot PCK / process-echo evidence deception, or
   MCP one-click polish.

## 2026-10-28 (Asia/Shanghai)

### REA delta
- Pulled `morluto/rea`: `dd7a2da5b` → `0cd7ef456` (**325 commits**).
- New analyzers / budgets worth countering:
  - **#7456** caller-selected R8/ProGuard mapping (`PROGUARD_MAPPING_LIMITS`:
    candidates=8, malformedSamples=16, projectionBytes=8MiB, indexBytes=128MiB;
    `ANDROID_MAPPING_LIMITS.fileBytes`=64MiB).
  - **#7472** JNI native-declaration ↔ `.so` export linking
    (`ANDROID_JNI_REPORT_BYTES`=16MiB, `ANDROID_JNI_LIBRARY_LIMITS`).
  - **#7379** selected AndroidManifest component declarations (queued for next night).
- Remainder of delta: evidence/contract refactors, browser/cli fixes — no new
  BLA-relevant budget constants beyond the Android set above.

### Done tonight
- `src/identity.ts`: registered Android mapping + JNI + `MAX_NATIVE_EXPORT_ROWS` limits.
- `src/shields/formats/android-r8.ts`: mapping generator (residual conflicts +
  malformed bait) + ELF64 AArch64 ET_DYN decoy with real `Java_*` dynsym exports.
- Wired into unsigned APK path + DEX trailer JNI names.
- `verify:rea` catalog extended (Object.freeze-aware).
- Release **bla-agents@1.4.6**.

### Next step (2026-10-29)
1. Empirical red-team: point sibling REA Android mapping + JNI tools at a
   BLA-hardened unsigned APK fixture; capture before/after in `docs/redteam/`.
2. Counter REA #7379 with binary/XML AndroidManifest component decoys (unsigned only).
3. Optionally densify decoy JNI `.so` past `ANDROID_JNI_REPORT_BYTES` projection
   when intensity ≥ maximum (keep red-line: never rewrite developer libs).
