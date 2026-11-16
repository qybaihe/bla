# DESIGN: Sidecar / entry entanglement (issue #40 / STATE)

Status: **JS + Python + WASM + Bun companion + ASAR archive-note + ASAR main JS preamble strip⇒fail; .pyc marshal-note + GGUF STRING metadata note are host-verify only** — binding digest + JS/Python preambles + WASM `bla.sidecar.v1` custom-section note + Bun sibling `.bla-sidecar.v1.json` companion note (byte-exact binary) + ASAR in-archive `.bla/sidecar.v1.json` note + optional Electron main JS preamble (`generateSidecarAsarMainJsPreamble`) + CPython `.pyc` TYPE_ASCII marshal trailer (`generateSidecarPycMarshalNote` / `verifyPycSidecarMarshalNote`, importlib-ignored, no process-start fail) + GGUF `bla.sidecar.v1` STRING metadata KV (`generateSidecarGgufMetadataNote` / `verifyGgufSidecarMetadataNote`, alignment-safe rewrite keeps tensor bytes bit-exact; loaders ignore unknown STRING keys) + protect/harden opt-in landed; defenseScore gap when `sidecarEntangle` is off landed; `.pyc` / GGUF / Safetensors / DEX / SQLite host-only notes annotate `pyc-sidecar-host-verify-only` / `gguf-sidecar-host-verify-only` / `safetensors-sidecar-host-verify-only` / `dex-sidecar-host-verify-only` / `sqlite-sidecar-host-verify-only` and must not record the process-start vectors; optional JS-loader hook `generateSidecarWasmLoaderSnippet` / `prependWasmSidecarLoaderHook` / `entangleWasmLoaderWithSidecars` landed 2026-11-15 (host must prepend it into the loader that instantiates the module — `wasm-sidecar-host-verify-only` stays until that hook is actually wired; do not record `wasm-sidecar-entangle` yet); **2026-11-16 honesty:** ESM static `import` / `export-from` bindings evaluate before the prepended JS IIFE — annotate `esm-import-hoist-before-hooks` (soft-cap 93); do not treat entry-body fail-closed as process-start for the hoisted graph. Remaining: `.pyc` import-time hook; GGUF/DEX/Safetensors/SQLite load-time hooks; ESM loader hook that runs before hoisted imports.

## Goal

Decoy / chaff sidecars must not be dismissible as an "independent protection layer".
If an attacker strips a sidecar or decoy file, the **entry** (main module / primary
artifact) must fail closed (integrity mismatch), not keep running happily.

This is the same honesty principle as weave-decoy: shared state + entry-reachable
checks beat orphan honeypot files.

## Non-goals

- No crack / RE playbooks.
- No claim that entanglement equals cryptographic unbreakability.
- No mandatory sidecar for every format in 1.6.x.

## Design (v1)

1. **Binding digest** — at protect time, compute `H = SHA-256(entryBytes || sidecarBytes || seedTag)`.
2. **Entry hook** — inject a tiny preamble (JS/Python) or custom-section note (WASM) that
   re-measures sibling sidecar path(s) and compares to `H` (or folds `H` into the opaque seed /
   self-seal digest — see `#40.5`).
3. **Strip ⇒ fail** — missing or altered sidecar changes the digest → opaque happy-path /
   activation gate fails.
4. **Opt-in** — `sidecarEntangle: true` in `.blarc` / CLI / MCP (not enabled by default until
   format coverage is broader).

## First slice (this batch)

- This DESIGN note (normative intent).
- Stub helper `planSidecarEntanglement()` returning a `bla-sidecar-entangle/v1` plan
  object (paths, digest algorithm, entry hook kind) **without** rewriting binaries yet.
- Unit tests for the planner.

## Follow-ups

- ~~Entry self-coverage~~ — landed 2026-11-05: self-seal embeds a canonical entry self-digest finalized at write time; harden reports `integrityCoverageSelfVerified` and drops paper self edges when it does not verify.
- ~~Wire planner into `protectTarget` for JS + Python when `sidecarEntangle` is set.~~ — JS 2026-11-05; Python 2026-11-06 nightly.
- ~~WASM custom-section note + host-side verify.~~ — 2026-11-07 nightly: `generateSidecarWasmCustomSection` / `bindWasmSidecarEntanglement` / `entangleWasmEntryWithSidecars` / `verifyWasmSidecarCustomSection`; protect + harden WASM-only post-pass.
- ~~Optional JS-loader hook for `verifyWasmSidecarCustomSection`.~~ — 2026-11-15 nightly: `computeWasmSidecarCodeIdentity` / `generateSidecarWasmLoaderSnippet` / `prependWasmSidecarLoaderHook` / `entangleWasmLoaderWithSidecars` wrap `WebAssembly.instantiate` / `compile` / `instantiateStreaming` so a protected module whose `bla.sidecar.v1` section is stripped or whose siblings were altered fails closed at load time. Unrelated WASM passes through (identity is SHA-256 of the module with the note stripped). Host-opt-in snippet — it runs only when prepended/eval'd in the customer's loader. **Honesty:** do not record `wasm-sidecar-entangle` / do not clear `wasm-sidecar-host-verify-only` until a protect/harden path actually injects this hook into the loader that instantiates the module. Default OFF via existing `sidecarEntangle`.
- ~~Bun / EOF-preserved native companion note.~~ — 2026-11-08 nightly: `generateSidecarBunCompanionNote` / `bindBunSidecarEntanglement` / `entangleBunEntryWithSidecars` / `verifyBunSidecarCompanionNote`; protect auto-binds `.bunfs-snapshot`; harden Bun-only post-pass; binary stays byte-exact.
- ~~Honesty: when entanglement is off, defenseScore gap annotation (like self-seal).~~ — 2026-11-08 nightly: `sidecar-entangle-not-enabled` soft-cap (93) via `sidecarEntangleEnabled` / MCP `sidecar_entangle_enabled`.
- ~~Extend to ASAR archive-note companion~~ — 2026-11-09 nightly: `generateSidecarAsarArchiveNote` / `bindAsarSidecarEntanglement` / `entangleAsarEntryWithSidecars` / `verifyAsarSidecarArchiveNote`; protect + harden ASAR post-pass plant `.bla/sidecar.v1.json` binding `enclave/hardware-tee-bridge.js`.
- ~~ASAR main JS preamble (Electron fs-patched re-measure)~~ — 2026-11-10 nightly: `generateSidecarAsarMainJsPreamble` / `selectAsarMainJsMember` / `entangleAsarMainJsWithSidecars`; protect + harden prepend strip⇒fail preamble to package.json#main (or heuristic entry).
- ~~CPython `.pyc` marshal trailer note (host verify)~~ — 2026-11-11 nightly: `generateSidecarPycMarshalNote` / `bindPycSidecarEntanglement` / `entanglePycEntryWithSidecars` / `verifyPycSidecarMarshalNote`; TYPE_ASCII trailer after root (importlib-safe). **Honesty:** do not record `pyc-sidecar-entangle` until an import-time hook lands; defenseScore gap `pyc-sidecar-host-verify-only`. Default OFF.
- ~~GGUF STRING metadata note (host verify)~~ — 2026-11-12 nightly: `generateSidecarGgufMetadataNote` / `bindGgufSidecarEntanglement` / `entangleGgufEntryWithSidecars` / `verifyGgufSidecarMetadataNote`; `bla.sidecar.v1` STRING KV via alignment-safe `rebuildGguf` (tensor bytes bit-exact). **Honesty:** do not record `gguf-sidecar-entangle` until a load-time hook lands; defenseScore gap `gguf-sidecar-host-verify-only`. Also fixed `protectGgufBuffer` to use the same rewriter so tensor-bearing GGUFs no longer silently shift the data section. Default OFF. Remaining: `.pyc` import-time hook; GGUF/DEX/Safetensors/SQLite load-time hooks.
- ~~JS runtime carrier honesty~~ — 2026-11-13: `.mjs`, `import`/`export`, top-level `await`, `import.meta`, and `.js` under nearest `package.json` `"type": "module"` are detected via Babel `program.sourceType` + `refineJsCarrierForRuntimePaths` and now receive an ESM-native strip⇒fail preamble (`import { createRequire } from "node:module"` + `import.meta.url`), with matching ESM `self-seal` support.
- **ESM import-hoist honesty** — 2026-11-16: the ESM-native preamble fail-closes the entry body, but static `import` / `export-from` bindings are instantiated first, so imported module side effects still run after sidecar strip or hook failure (`jsModuleHasHoistedDependencyGraph`; the BLA `createRequire` preamble import is ignored). Annotate defenseScore gap `esm-import-hoist-before-hooks` (soft-cap 93) when sidecar or self-seal is on. CJS `require()` after the preamble remains process-start. A true pre-import hook (custom ESM loader / `module.register` before the graph loads) is still TBD.
- ~~Safetensors `__metadata__` note (host verify)~~ — 2026-11-13: `generateSidecarSafetensorsMetadataNote` / `bindSafetensorsSidecarEntanglement` / `entangleSafetensorsEntryWithSidecars` / `verifySafetensorsSidecarMetadataNote`; `bla.sidecar.v1` `__metadata__` key keeps tensor bytes bit-exact; `defenseScore` annotates `safetensors-sidecar-host-verify-only` and `wasm-sidecar-host-verify-only` (soft-cap 93).
- ~~DEX string-pool note (host verify)~~ — 2026-11-13 nightly: `generateSidecarDexStringPoolNote` / `bindDexSidecarEntanglement` / `entangleDexEntryWithSidecars` / `verifyDexSidecarStringPoolNote`; unreferenced sort-last `bla.sidecar.v1=` pool string via `parseDexLayout` / `rebuildDex` (existing string indices + instruction bytes unchanged; trailers preserved). **Honesty:** do not record `dex-sidecar-entangle` until a load-time hook lands; defenseScore gap `dex-sidecar-host-verify-only`. Default OFF.
- ~~SQLite schema-comment / reserved-VIEW note (host verify)~~ — 2026-11-14 nightly: `generateSidecarSqliteSchemaComment` / `bindSqliteSidecarEntanglement` / `entangleSqliteEntryWithSidecars` / `verifySqliteSidecarSchemaComment`; unused `bla_sidecar_v1` VIEW (`SELECT '<json>' AS "bla.sidecar.v1" WHERE 0`) keeps user tables, rows, query results, WAL/FK, and application_id/user_version unchanged. **Honesty:** do not record `sqlite-sidecar-entangle` until a load-time hook lands; defenseScore gap `sqlite-sidecar-host-verify-only`. Default OFF. Remaining: `.pyc` import-time hook; GGUF/DEX/Safetensors/SQLite load-time hooks.
