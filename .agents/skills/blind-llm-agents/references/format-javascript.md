# Format appendix: JavaScript / TypeScript / Electron

Load this when hardening JS/TS bundles, Node modules, HTML bundles, or Electron `.asar`.

## Defaults

- JS AST weave is **always on** during protect/defend/harden (not gated by `weave_decoys`).
- Prefer `bla_harden` for a project/build dir; `bla_defend` / `bla_protect` for a named file.
- Honey source maps default **on**. MCP: `honey_source_maps` (protect). CLI: `--no-honey-maps` to disable.

## Stronger options (opt-in)

| Goal | MCP | CLI / config |
| :--- | :--- | :--- |
| Sibling-module integrity binding | `self_seal: true` | `--self-seal` / `.blarc` `"selfSeal": true` |
| Structural decoys (also helps Python in the same tree) | `weave_decoys: true` | `--weave-decoys` |
| Overwrite the input file | `in_place: true` **and** `confirm_overwrite: true` | `--in-place` |

Self-seal soft-skips in pure browser builds (digest stays 0). Pair with weave when the tree also has Python customer defs.

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

