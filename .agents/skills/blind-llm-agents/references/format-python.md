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

## What the `.py` shield changes — and what it leaves readable

- **Your code keeps its text.** Functions, classes, constants and string literals are not renamed or encoded; the shield adds decoy state and functions around them (`weave_decoys` also threads decoy calls through your function bodies). A licence gate is still readable and patchable — *noticing* a patch is what `sidecar_entangle` adds (below). Keep secrets out of Python source.
- **The hardened file is UTF-8.** A module that declares another encoding (`# -*- coding: latin-1 -*-`, a BOM) is decoded the way CPython decodes it and its declaration is rewritten. Single-byte code pages and `cp932` / `shift_jis` / `euc_jp` / `euc_kr` / `gb2312` / `gbk` are supported; `big5`, `gb18030`, `cp949`, `cp950` and the JIS X 0213 codecs only when the file is pure ASCII — otherwise the file is refused (`re-save the file as UTF-8`) instead of being corrupted.
- **It does not take names from the module.** Generated code binds no `_` (so `gettext.install()` keeps working), reaches builtins only through one private `import builtins as _…` alias (a module that defines its own `hash` or `len`, and `importlib.reload`, behave as before), and is inserted on a statement boundary after the docstring and `from __future__` imports.
- **It does add public names.** The decoy functions and state are module-level names without a leading underscore: 9 at `stealth`, 14 at `balanced`, 22 at `maximum` / `bankrupt`. A module without `__all__` exports them through `from module import *`, and anything that enumerates a module's attributes (`fire.Fire()`, plugin scanners) sees them. Define `__all__`, or put that module in `exclude`.
- **Size.** Each module grows by a fixed amount, whatever its own size: about 14 KB at `stealth`, 27 KB at `balanced`, 46–50 KB at `maximum` / `bankrupt` (a 75-byte `__init__.py` becomes 50 KB). The report's `outputSize` has the totals.
- Python 3.12 f-strings (PEP 701: nested quotes, multi-line fields) are handled.

## Shipping a hardened Python project

Python is hardened as source, so there is no build output to promote: `apply` refuses to overwrite source files. Copy the project to a staging directory, lay `.bla-hardened/` over it, run the tests there, and package from that copy. Never replace your sources with hardened output.

## `sidecar_entangle`: which module checks, and when

One module gets a load-time check that hashes the hardened files in its own directory tree and stops with `integrity binding mismatch` when one was changed, replaced or removed. It runs when that module is imported, and only then. The report names it (`pythonSidecarEntry`). It is chosen in this order:

1. `policy.py`, if the project has one.
2. If the project declares console scripts (`[project.scripts]` / `[project.gui-scripts]` / `[tool.poetry.scripts]` in `pyproject.toml`, `console_scripts` in `setup.cfg` / `setup.py`): the outermost package `__init__.py` of the module the first script imports — Python runs it on every way into the package, including the installed script, which never touches a `run.py` beside the package. Without a package, the script's module itself.
3. A program entry: `__main__.py`, then `main.py` / `app.py` / `cli.py` / `manage.py` / `run.py` / `server.py` / `wsgi.py` / `asgi.py` (shallowest first).
4. The shallowest `__init__.py`, then the first file by name.

Read the report before relying on it:

- `integrityBindingSkipped` lists hardened files the check does not reach (anything above or beside the checking module's directory, and SQLite databases, which the application may write).
- `pythonSidecarUncoveredEntries` lists declared console scripts that never import the checking module: started that way, nothing is verified. Import it from those modules and harden again.
- A bytecode-only tree (`.pyc` without `.py`) and PyInstaller / Nuitka / cx_Freeze bundles ship no sibling sources. The check lets the program start there without verifying anything — it adds nothing to those targets.
- The check is one readable block in one module. It stops a patched file from going unnoticed; it does not stop someone who also removes the check.

## PyInstaller honesty

CArchive peel on onefile bundles is expected. Densify by shielding `.py`/`.pyc` **before** bundling rather than only the final binary.
