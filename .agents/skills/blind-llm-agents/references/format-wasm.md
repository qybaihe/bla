# Format appendix: WebAssembly

Load this when hardening `.wasm` modules.

## Intensity & rename

At `maximum` / `bankrupt`, BLA renames **all** exports not listed in the preserve list (red-blue round-1: silent `mix`/`seal` ABI enabled preload hooks). Do **not** ship a stable public WASM ABI unless glue truly requires it — and then list names **explicitly**:

| Surface | How |
| :--- | :--- |
| MCP | `wasm_preserve_exports: ["main","add"]` on harden/defend/protect |
| CLI | `--wasm-preserve-exports main,add` |
| Config | `.blarc` `"wasmPreserveExports": ["main","add"]` |

Glue that imports renamed symbols should consume the rename map from the protect report.

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
