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
