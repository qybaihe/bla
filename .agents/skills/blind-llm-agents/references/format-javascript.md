# Format appendix: JavaScript / TypeScript / Electron

Load this when hardening JS/TS bundles, Node modules, HTML bundles, or Electron `.asar`.

## Defaults

- JS AST weave is **always on** during protect/defend/harden (not gated by `weave_decoys`).
- Prefer `bla_harden` for a project/build dir; `bla_defend` / `bla_protect` for a named file.
- Honey source maps default **on**. MCP: `honey_source_maps` (protect). CLI: `--no-honey-maps` to disable.
- **Build first.** With a `dist/` / `build/` / `out/` directory present, `bla_harden` hardens what is in it and treats the JS/TS/HTML beside it as build inputs (`skippedSourceFiles`). Tool configs, tests, `.d.ts` declarations and the scripts `package.json` runs for build / test / release are never hardened (`skippedDevTooling`). A file `package.json` declares as `main` / `bin` / `exports` is product code wherever it lives.

## What callers of a hardened module can still rely on

- Exported and top-level function and class names: `fn.name`, `error.name`, `instance.constructor.name`, `instanceof`, inheritance and `super()`, and the module's export list are unchanged at every intensity. Logging, DI containers, ORMs and test frameworks that read names keep working.
- Hardened TypeScript keeps its types and starts with `// @ts-nocheck`, so the injected code is not held to the project's `strict` settings. Prefer hardening the compiled JavaScript.
- Hardened functions run extra code on every call (the shadow-heap churn that defeats memory diffing — about 60 ns per call, the same at every intensity). I/O-bound code does not notice; a tokenizer-style loop that calls a tiny function a million times measured about 26× slower. Measure the hot paths after `apply`, and leave a hot module out with `exclude` (`bla_harden` `{ "exclude": ["dist/vendor/codec.js"] }`, CLI `--exclude`, `.blarc` `"exclude"`) rather than lowering protection for the whole build.
- Every hardened JS / HTML file carries a fixed decoy payload: roughly 50 KB at `stealth`, 80 KB at `balanced`, 110–180 KB at `maximum` and 150–210 KB at `bankrupt`, whatever the size of the original. A build with many small chunks grows accordingly; the report's `outputSize` has the totals.
- A hardened file is a different file. Anything pinned to its bytes — Subresource Integrity hashes, a service-worker precache manifest, a CSP hash — has to be regenerated after `apply`.

## Stronger options (opt-in)

| Goal | MCP | CLI / config |
| :--- | :--- | :--- |
| Sibling-module integrity binding | `self_seal: true` | `--self-seal` / `.blarc` `"selfSeal": true` |
| Structural decoys (also helps Python in the same tree) | `weave_decoys: true` | `--weave-decoys` |
| Overwrite the input file | `in_place: true` **and** `confirm_overwrite: true` | `--in-place` |

Pair with weave when the tree also has Python customer defs.

### What the integrity binding covers

`self_seal` and `sidecar_entangle` are Node programs: they read sibling files with `node:fs` and hash them with `node:crypto` when a module loads. The harden report says exactly what that reaches:

- `integrityBindingEntry` — the one module that pins its hardened siblings and refuses to load when one was changed, replaced or removed. For a package that is both a library and a CLI the check is hosted where both ways in pass through (`bin` loads `main` ⇒ `main`).
- `integrityBindingUncoveredEntries` — entry points `package.json` declares that never load that module. Started there, a replaced sibling goes unnoticed (each self-sealed file still checks its own bytes). Load the entry module from them and harden again.
- `integrityBindingSkipped` — artifacts hardened **without** the binding: browser bundles (a page loads them, or they use `document` / `window` and no Node API — the preamble would stop the page from loading), and mutable data such as a SQLite database the application writes to. For a web build use server-side checks and Subresource Integrity instead.

## Sensitive literals that survive

`maximum` / `bankrupt` encode string literals and the static text of template literals that are 3 to 256 characters long; `stealth` / `balanced` do not encode strings at all. Whatever `bla_lint` would call a `plaintext-secret` and can still be read verbatim in the output is listed per artifact in `plaintextSurvivors` (source line + clipped preview). At `maximum` / `bankrupt` that is what the shield cannot reach — object keys, regular expressions, HTML attributes, and any string longer than 256 characters (an embedded PEM key, a long token, a JSON blob): move the value into a plain string literal of ordinary length, or better, off the client.

`plaintextSurvivors` only lists what looks like a secret (a digest, a key, a generated token, a PEM header). An ordinary string that stays readable for one of the reasons above — a licence-format regular expression, a long message — is not listed: if its wording matters, check the hardened file for it yourself.

Some strings are left readable on purpose, at every intensity, because the program or its tooling reads them as text:

- what names a file — `import "…"`, `require("…")`, `import("…")`, `require.resolve("…")`, `import.meta.resolve("…")`, `new URL("…", import.meta.url)` — so a bundler, packager or deploy-time file tracer run after hardening still finds it;
- `eval("…")` arguments, directives (`"use strict"`), non-computed property and method keys, ES2022 string import / export names;
- the static text of tagged templates (the tag receives it), and TypeScript `enum` members, `namespace` / `declare module` blocks, type positions and `as const` values;
- licence notices: `/*! … */` blocks and comments carrying `@license`, `@preserve`, `SPDX-License-Identifier` or a copyright line.

Strings inside a template substitution (`` `${dev ? "http://…" : "https://…"}/v1` ``) are encoded like any other string.

## What the JS shield does not change

A hardened program is checked against the original by running both (`tests/fuzz-regression-js.test.ts`). To keep that true the shield holds back in a few places — know them when you judge how much a file gained:

- **Classic scripts and UMD bundles keep every top-level name.** In a `<script>` those are the page's globals; only a file that can only be a module (ESM syntax, or unguarded `require` / `module.exports`) gets its program-level bindings renamed.
- **Names the language makes observable stay:** exported and top-level function / class names (`fn.name`, `error.name`), sloppy-mode block functions, duplicate parameters, anything reachable through `with`, and a local `React` in a JSX file.
- **`&` `|` `^` rewrites keep the original operator** as the path for operands that are not Numbers (BigInt, objects), so the operator is still visible next to the arithmetic form.
- **Error messages and stack traces show the renamed identifiers**, and the runtime decoy adds one non-enumerable property to `globalThis` (`Object.keys(globalThis)` is unchanged; `Object.getOwnPropertyNames(globalThis)` shows it).
- **In a classic script the shield's own declarations are globals too.** A `<script>` has no private top level, so its decoy functions and state land on `window` beside the page's own globals: about 160 extra properties per script at `bankrupt` (they are `var`s with generated names, so two hardened scripts on one page do not collide). Code that enumerates `window` sees them; module code adds none.

## Verify honesty

`defenseScore` soft-caps JS-like targets with `self-seal-not-enabled` unless verify knows seal ran. After `bla_protect` / `bla_defend`, pass `self_seal_enabled: true` into `bla_verify` when the protect report shows `selfSeal: true` (defend/harden already forward this internally).

## Electron notes

IPC ambiguity + route mirage layers activate on JS/TS/asar/directory targets during verify. Prefer defending the packaged `.asar` or the `dist/` that ships to users, not only sources.

## Lane-independence (gates / entitlement)

Do **not** keep independent per-byte / per-lane JS check tables (`Object.freeze(parseInt hex…)`, `charCodeAt(i)` → wasm mix/seal per lane). Prefer **whole-key chained mixing**. `bla_lint_lanes` returns severity **error**; harden/defend/protect **refuse** unless `allow_lane_independent` / `--allow-lane-independent` (teaching fixtures only).

## Plaintext seal sidecars (red-blue round-2)

`bla harden` protects discovered JS/WASM/HTML artifacts — **not** adjacent `seal.json` / catalog files you copy next to the output. If a gate loads salts, expected digests, or certificate ciphertext from sibling JSON (or a WASM data-section twin), that material stays attacker-readable.

Rules of thumb:

1. Prefer **one-way** commitments (`SHA-256` / HMAC) for public `revision` / compare digests. Custom reversible ARX/Feistel “digests” invert to the key when salt+rounds are public.
2. Encrypt or omit seal sidecars in the shipped tree; or fold them under **`self_seal`** / a sealed blob bound to the entry module.
3. Dual-publish (JSON + WASM `R2SEAL` data) without encryption doubles the same exposure.

**Engine gate:** `bla_lint_seal` / CLI `bla lint-seal` flags reversible plaintext seals. At **bankrupt**, harden/protect **refuse** unless `allow_plaintext_seal` / `--allow-plaintext-seal` / `.blarc` `"allowPlaintextSeal": true` (lab fixtures only). One-way SHA-256 seals without invertible ARX params pass.

## One-way seals still need packaging (red-blue round-3)

Round-3 confirmed: SHA-256 (or HMAC) public `revision` **stops** seal-only ARX inversion. That is necessary, not sufficient:

1. Digests-only `seal.json` still triggers `plaintext-seal-sidecar` **warning** (`shouldRefuseBankrupt: false`). Prefer omit/encrypt/`self_seal`.
2. Do **not** dual-carry runtime salt/rounds/ciphertext as clear WASM data next to the seal (`R3PARM`/`R3CIPH`-class ASCII magics). Encrypt, relocate, or bind under self-seal.
3. Strip or rename stable panel helpers such as `__vaultPanelDerive_*`, and avoid leaving classic FNV primes as readable literals in HTML bundles when they back entitlement tokens.
4. For multi-artifact gates (JS + WASM + HTML + seal), turn on **`self_seal`** so siblings cannot be freely swapped/instrumented.

## Round-3 residual gates

- `bla_lint_panel_derive` / `bla lint-panel-derive` flags stable `__vaultPanelDerive_*`; maximum/bankrupt protect rewrites to `_blaPd_*` unless `allow_stable_panel_derive`.
- Multi-artifact trees: bankrupt harden reports `selfSealRecommended` — pass `self_seal: true` (auto sibling bind on harden). Single-file stays opt-in only.

## Round-4 residual gates (AES wrap + panel oracle)

AES-CTR sealed WASM param blobs without clear `PARM` magic still leak when **JS** holds a recoverable wrap key and calls `createDecipheriv` / `createCipheriv` against a fixed hdr beacon (e.g. `d17ea004`). This is **not** white-box AES.

| Gate | Surface | Default |
| :--- | :--- | :--- |
| `bla_lint_js_aes_unwrap` / `bla lint-js-aes-unwrap` | wrap-key + create*iv + fixed hdr | bankrupt **refuse** unless `allow_js_aes_unwrap` / `--allow-js-aes-unwrap` |
| `bla_lint_panel_derive` | `deriveLocal` rewrite + `panelTokenSha256` oracle | rewrite `_blaPdLocal_*`; bankrupt **refuse** oracle combo unless `allow_panel_offline_oracle` |

Prefer unwrap inside WASM; scrub plaintext panel token digests; do not ship a callable derive UI beside seal digests. Self-seal sibling SHA-256 hard-fail is separate and already on when siblings exist at protect time.
