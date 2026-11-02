# Format appendix: WebAssembly

Load this when hardening `.wasm` modules.

## Intensity & rename

At `maximum` / `bankrupt`, BLA may rename **internal-looking** exports (`__*`, `debug_*`, …). Public ABI names the customer must keep go in the preserve list:

| Surface | How |
| :--- | :--- |
| MCP | `wasm_preserve_exports: ["main","add"]` on harden/defend/protect |
| CLI | `--wasm-preserve-exports main,add` |
| Config | `.blarc` `"wasmPreserveExports": ["main","add"]` |

Glue that imports renamed symbols should consume the rename map from the protect report.

## Verify honesty

Standalone `bla_verify` soft-caps WASM with `wasm-export-rename-pending` unless you pass `wasm_export_rename_applied: true` (set when `ProtectionResult.wasmExportRenameApplied` was true). Defend/harden already forward that flag into their embedded verify step.
