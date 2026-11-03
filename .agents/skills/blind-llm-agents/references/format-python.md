# Format appendix: Python (`.py` / `.pyc`)

Load this when hardening Python sources or bytecode.

## `weave_decoys` is the structural switch

| Flag | `.py` behavior | `.pyc` behavior |
| :--- | :--- | :--- |
| `weave_decoys: false` (default) | Warm-init / tarpit only — not structural customer-def weave | Trailer-oriented |
| `weave_decoys: true` | Customer `FunctionDef` bodies get shared-slot touch + opaque-false decoy calls | Customer `co_consts` CODE weave |

JS AST weave in the same tree stays always-on regardless of this flag.

## Recommended path

1. Read MCP resource `bla://directives/weave-decoy` (directives travel with the MCP server; no repo checkout required).
2. Plan: `bla_weave_plan` `{ "path": "<project-or-file>" }`.
3. Apply: `bla_harden` / `bla_defend` / `bla_protect` with `weave_decoys: true`.

## PyInstaller honesty

CArchive peel on onefile bundles is expected. Densify by shielding `.py`/`.pyc` **before** bundling rather than only the final binary.
