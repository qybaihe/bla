# BLA nightly development log

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
