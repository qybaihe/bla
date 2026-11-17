# Format appendix: WebAssembly

Load this when hardening `.wasm` modules.

## Intensity & rename

At `maximum` / `bankrupt`, BLA renames exports (red-blue round-1: a silent `mix`/`seal` ABI enabled preload hooks). Three kinds of name stay:

1. **Names a host looks up by specification** — `_start`, `_initialize`, `memory`, `__indirect_function_table`, wasm-ld linker symbols, and the wasm-bindgen / Emscripten / component-model glue (`__wbindgen_*`, `cabi_realloc`, `stackSave`, …). No caller can follow a rename of these and they carry no secret, so they are never renamed.
2. **Names another file in the project refers to.** `bla_harden` keeps them and reports each as `artifacts[].wasmExportsAutoPreserved` `{ name, referencedBy }`. They remain a stable hook surface: if one guards entitlement logic, rename it in your own source and its callers.
3. **Names you list.** Do **not** ship a stable public WASM ABI unless glue outside the project truly requires it — and then list the names **explicitly**:

| Surface | How |
| :--- | :--- |
| MCP | `wasm_preserve_exports: ["main","add"]` on harden/defend/protect |
| CLI | `--wasm-preserve-exports main,add` |
| Config | `.blarc` `"wasmPreserveExports": ["main","add"]` |

Everything else is renamed, and the old → new map comes back as `artifacts[].wasmExportRenames` (`bla_harden`), `protection.wasmExportRenames` (`bla_defend`) or `wasmExportRenames` (`bla_protect`). A caller outside the project has to be updated from that map. `balanced` and `stealth` rename nothing.

## Size

At `bankrupt` a module grows by megabytes — the decoy exports are the exhaustion mechanism, and a 41-byte module comes out near 7 MB. At `maximum` the same module is a few tens of kilobytes and still gets export renaming and decoys. The harden report states it (`outputSize`, per-artifact `inputBytes` / `outputBytes`) and `nextSteps` flags growth of a megabyte or more. For a module that is downloaded by browsers, choose `maximum`, or keep `bankrupt` for the rest of the build and harden the module separately at a lower intensity.

## Verify honesty

Standalone `bla_verify` soft-caps WASM with `wasm-export-rename-pending` unless you pass `wasm_export_rename_applied: true` (set when `ProtectionResult.wasmExportRenameApplied` was true). Defend/harden already forward that flag into their embedded verify step.

## Data-section seal carriers (red-blue round-3)

Export rename closes the public `mix`/`seal` hook surface. It does **not** hide plaintext entitlement material in active data:

- Avoid shipping ASCII magics such as `R2SEAL` / `R3PARM` / `R3CIPH` followed by clear salt, round counts, invertible revisions, or certificate ciphertext.
- If the gate must load schedule params from WASM, encrypt them or bind the blob under **`self_seal`** with the entry module — especially when a sibling `seal.json` already publishes one-way digests.

## Round-3 residual gate

- Run `bla_lint_wasm_params` / `bla lint-wasm-params` before shipping. Bankrupt harden refuses clear param/cipher magics unless `allow_wasm_clear_params`.
- This is a **detection gate**, not data-section encryption.

## Sealed blobs still need JS honesty (red-blue round-4)

Encrypting WASM data (no clear `R3PARM`) closes the ASCII-carrier lint. If the **JS loader** still does `Buffer.from(WRAP_KEY_HEX, "hex")` + `createDecipheriv` against a fixed hdr, Node instrumentation recovers params. Run `bla_lint_js_aes_unwrap` on the loader; bankrupt refuses that footgun. BLA does **not** claim white-box AES.


## Unlock-in-WASM + mask hygiene (red-blue R5–R12)

Export rename closes public `mix`/`seal` hooks. It does **not** replace careful entitlement packaging:

| Round | Do | Lint / engine |
| :--- | :--- | :--- |
| R5–R6 | Keep ARX+compare+decrypt **inside** `unlock`; JS must not hydrate→dump salt/rounds/cipher | `bla_lint_js_wasm_hydrate_dump` |
| R6 | Never store plaintext XOR mask beside masked pack | `bla_lint_wasm_xor_mask_sidecar` |
| R7 | Never put `seal.revision` under repeating XOR mask; use one-way mask KDF | `bla_lint_wasm_seal_xor_known_plaintext` |
| R8+ | `SHA-256(key)` mask; commitment **outside** XOR; entropy pad ≠ revision | Skill recipe (R7 lint covers KP) |
| R9 | Seed-derived rounds + nonzero pad3 | Skill recipe |
| R10–R12 | Engine: arity-2 alias spread + export-order shuffle + prefer arity-2 decoys | protect defaults |
| Host | Resolve by arity + FLAG shape + `certificateSha256`, never first export | Skill recipe |

Project scan: `bla_lint` / `bla lint .`. Honesty: full WASM RE + online/SMT vs commitment remains possible — gates ≠ white-box.
