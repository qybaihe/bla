# DESIGN: Sidecar / entry entanglement (issue #40 / STATE)

Status: **JS + Python + WASM + Bun companion + ASAR archive-note + ASAR main JS preamble strip⇒fail; .pyc marshal-note + GGUF STRING metadata note are host-verify only** — binding digest + JS/Python preambles + WASM `bla.sidecar.v1` custom-section note + Bun sibling `.bla-sidecar.v1.json` companion note (byte-exact binary) + ASAR in-archive `.bla/sidecar.v1.json` note + optional Electron main JS preamble (`generateSidecarAsarMainJsPreamble`) + CPython `.pyc` TYPE_ASCII marshal trailer (`generateSidecarPycMarshalNote` / `verifyPycSidecarMarshalNote`, importlib-ignored, no process-start fail) + GGUF `bla.sidecar.v1` STRING metadata KV (`generateSidecarGgufMetadataNote` / `verifyGgufSidecarMetadataNote`, alignment-safe rewrite keeps tensor bytes bit-exact; loaders ignore unknown STRING keys) + protect/harden opt-in landed; defenseScore gap when `sidecarEntangle` is off landed; `.pyc` / GGUF host-only notes annotate `pyc-sidecar-host-verify-only` / `gguf-sidecar-host-verify-only` and must not record the process-start vectors; optional JS-loader `verifyWasmSidecarCustomSection`, `.pyc` import-time hook, and GGUF load-time hook still TBD.

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
- ~~Bun / EOF-preserved native companion note.~~ — 2026-11-08 nightly: `generateSidecarBunCompanionNote` / `bindBunSidecarEntanglement` / `entangleBunEntryWithSidecars` / `verifyBunSidecarCompanionNote`; protect auto-binds `.bunfs-snapshot`; harden Bun-only post-pass; binary stays byte-exact.
- ~~Honesty: when entanglement is off, defenseScore gap annotation (like self-seal).~~ — 2026-11-08 nightly: `sidecar-entangle-not-enabled` soft-cap (93) via `sidecarEntangleEnabled` / MCP `sidecar_entangle_enabled`.
- ~~Extend to ASAR archive-note companion~~ — 2026-11-09 nightly: `generateSidecarAsarArchiveNote` / `bindAsarSidecarEntanglement` / `entangleAsarEntryWithSidecars` / `verifyAsarSidecarArchiveNote`; protect + harden ASAR post-pass plant `.bla/sidecar.v1.json` binding `enclave/hardware-tee-bridge.js`.
- ~~ASAR main JS preamble (Electron fs-patched re-measure)~~ — 2026-11-10 nightly: `generateSidecarAsarMainJsPreamble` / `selectAsarMainJsMember` / `entangleAsarMainJsWithSidecars`; protect + harden prepend strip⇒fail preamble to package.json#main (or heuristic entry).
- ~~CPython `.pyc` marshal trailer note (host verify)~~ — 2026-11-11 nightly: `generateSidecarPycMarshalNote` / `bindPycSidecarEntanglement` / `entanglePycEntryWithSidecars` / `verifyPycSidecarMarshalNote`; TYPE_ASCII trailer after root (importlib-safe). **Honesty:** do not record `pyc-sidecar-entangle` until an import-time hook lands; defenseScore gap `pyc-sidecar-host-verify-only`. Default OFF.
- ~~GGUF STRING metadata note (host verify)~~ — 2026-11-12 nightly: `generateSidecarGgufMetadataNote` / `bindGgufSidecarEntanglement` / `entangleGgufEntryWithSidecars` / `verifyGgufSidecarMetadataNote`; `bla.sidecar.v1` STRING KV via alignment-safe `rebuildGguf` (tensor bytes bit-exact). **Honesty:** do not record `gguf-sidecar-entangle` until a load-time hook lands; defenseScore gap `gguf-sidecar-host-verify-only`. Also fixed `protectGgufBuffer` to use the same rewriter so tensor-bearing GGUFs no longer silently shift the data section. Default OFF. Remaining: `.pyc` import-time hook; GGUF load-time hook; optional JS-loader `verifyWasmSidecarCustomSection`; next candidates: DEX string pool / SQLite comments / Safetensors header metadata.
- ~~JS runtime carrier honesty~~ — 2026-11-13 red: `.js` entries evaluated as ES modules without import/export (top-level `await`, `import.meta`, or nearest `package.json` `"type": "module"`) got the CommonJS preamble and the intact artifact threw `integrity binding mismatch`. Carrier detection now uses Babel `program.sourceType` plus `refineJsCarrierForRuntimePaths` (output + input location), so the #162 refusal fires. An ESM-native preamble (`import.meta.url` + `node:fs`) remains TBD.
