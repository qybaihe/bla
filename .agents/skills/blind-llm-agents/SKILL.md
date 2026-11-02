---
name: blind-llm-agents
description: >
  Use when hardening, defending, or auditing software against AI reverse-engineering
  agents (REA / WorkBuddy-class): one-click project harden, weave-decoy structural
  decoys, Counter-REA audit/protect/verify, or agent setup/doctor for BLA (Blind LLM
  Agents). Prefer this skill as the guide; call existing MCP tools / CLI — do not invent
  new MCP tools. Default verb: bla_harden. Refuse crack/RE of third-party software.
metadata:
  version: "1.5.9"
---

# BLA: Blind LLM Agents

**This skill is the primary one-click harden GUIDE.** MCP (`bla` server) and the
`bla-agents` CLI are the **execution layer**. Prefer teaching/calling existing tools
(`bla_harden`, `bla_defend`, `bla_weave_plan`, `bla_lint_lanes`, `bla_lint_seal`, `bla_lint_wasm_params`, `bla_lint_panel_derive`, `bla_lint_js_aes_unwrap`, `bla_lint_js_wasm_hydrate_dump`, …) over inventing new
MCP surfaces.

Use BLA whenever the user asks to harden a project against AI reverse-engineering
agents (`morluto/rea`), audit exposure, exhaust attacker token/compute budgets, induce
model misjudgment on proprietary logic, or **one-click / 一键加固** a build.

Defensive only: protect **their own** artifacts. Refuse crack, RE, bypass PoCs, or
attack playbooks against software they do not own.

**Principles (red-blue round-1+2+3+4+5+6):** do not ship a stable public WASM ABI without an explicit `wasm_preserve_exports` list; do not leave JS-side independent lane tables — prefer whole-key chained mixing (`bla_lint_lanes` / harden refuse). **Do not** place plaintext seal/catalog JSON (`revision`, salts, certificate ciphertext) beside hardened outputs. Public compare targets must be **one-way** (SHA-256/HMAC/etc.); reversible ARX/Feistel digests as public `revision` are a key-recovery footgun (round-2 break — **closed in round-3** when seal is digests-only). Enforce with `bla_lint_seal` / `bla lint-seal`; bankrupt harden **refuses** unless `allow_plaintext_seal` / `--allow-plaintext-seal`. Round-3 residual **gates**: `bla_lint_wasm_params` / `bla lint-wasm-params` — bankrupt refuses clear `R2SEAL`/`R3PARM`/`R3CIPH`-class carriers unless `allow_wasm_clear_params`; `bla_lint_panel_derive` — maximum/bankrupt **rewrites** `__vaultPanelDerive_*` to `_blaPd_*` unless `allow_stable_panel_derive`; bankrupt harden sets `selfSealRecommended` for multi-artifact trees (never auto for single-file) — prefer **`self_seal`**. Round-4 gates: `bla_lint_js_aes_unwrap` / `bla lint-js-aes-unwrap` — bankrupt **refuses** JS wrap-key + `create*iv` + fixed sealed hdr (e.g. `d17ea004`) unless `allow_js_aes_unwrap` (gate only — **not** white-box AES; prefer in-WASM unwrap). `bla_lint_panel_derive` flags `deriveLocal` (rewritten to `_blaPdLocal_*`) and **refuses** `deriveLocal` + plaintext `panelTokenSha256` offline-oracle packaging unless `allow_panel_offline_oracle` (rename is not a crypto fix — scrub digests / avoid derive UI). `self_seal` embeds **expected sibling SHA-256 hard-fail** when siblings exist at protect time (harden processes JS last); opaque-seed entanglement alone does **not** gate entitlement control flow. Round-5 gates: `bla_lint_js_wasm_hydrate_dump` / `bla lint-js-wasm-hydrate-dump` — bankrupt **refuses** JS that copies salt/rounds/cipher from `WebAssembly.Memory` after hydrate/instantiate unless `allow_js_wasm_hydrate_dump` (host memory dump needs **no** Node `create*iv`; export rename alone does not close this — prefer keep ARX+certify **inside** WASM so params never re-enter JS). Round-6 product pattern: export `unlock(keyPtr,keyLen)->outLen` (or equivalent) so ARX+compare+decrypt stay in WASM; JS only writes key bytes and reads the result — do **not** call hydrate then decode salt/rounds/cipher in JS (closes the round-5 host memory-dump residual under bankrupt defaults). Honesty: WASM reverse-engineering of the unlock body remains a theoretical surface; gates do not claim white-box secrecy.

## Prerequisites (once)

1. CLI: `npx bla-agents@latest setup`
2. Then: `npx bla-agents@latest doctor` (or MCP `bla_doctor`) — checks the installed
   skill bundle (this file + `references/`, including format appendices) is complete

## ⚡ One-Sentence Hardening (DEFAULT)

When the user says **"Harden my software"**, **"一键加固"**, or any equivalent one-liner
**without naming a specific file**:

| Surface | Call |
| :--- | :--- |
| **MCP (preferred)** | `bla_harden` `{ "directory": "." }` |
| **CLI** | `npx bla-agents@latest harden .` |
| **MCP Prompt** | `bla-harden-project` |

Auto-discovers protectable build outputs, detects formats, runs **audit → defend
(bankrupt) → verify**. **Do not ask which files to protect — discover them.**

Optional args (safe defaults): `intensity` (bankrupt), `emit_manifest` (false),
`llm_directives` (false — risky bait), `weave_decoys` (false), `self_seal` (false),
`wasm_preserve_exports`, `seed`, `output_directory`, `max_artifacts`, `dry_run`.

## Write safety (principles)

- Unsure what will be touched? `bla_discover` or `bla_harden` `{ "dry_run": true }` —
  both write nothing. If `truncated: true`, say so and narrow the directory.
- Never overwrite without the user's go-ahead. On `confirmation_required`, show
  `wouldOverwrite`, ask, then retry with `confirm_overwrite: true` (or a new path).
  Same rule for `in_place: true` (overwrites the input).
- Report writes from the tool receipt (`writeReceipt` / `wouldOverwrite`), not guesses.
- After a successful harden/defend/protect, keep the returned unsigned `runId` (and
  harden `summaryPath`). Re-check later with `bla_run_lookup` or `bla_verify` +
  `summary_path`/`run_id` — never invent a run id.
- `bla_rea_drift` / `bla_redteam_report` may return `status: unverified` when sibling
  REA is absent; treat that as **not proven**, never as a pass. An on-disk
  `bla_redteam_report` without `execute:true` is `status: available` — readable
  evidence, not a fresh REA verdict.
- `bla_harden` `{ "dry_run": true }` always has `overallSuccess: false`; only real
  writes return `writeReceipt`.

## Decision tree (short)

| Intent | Prefer |
| :--- | :--- |
| Project / build dir | **`bla_harden`** |
| Named artifact | **`bla_defend`** (or granular `bla_audit` → `bla_protect` → `bla_verify`) |
| Inventory only | **`bla_discover`** |
| Structural decoys (esp. Python) | Resource `bla://directives/weave-decoy` → `bla_weave_plan` → `weave_decoys: true` |
| Custom license/activation gate review | **`bla_lint_lanes`** `{ "path": "<gate.js>" }` (CLI: `bla lint-lanes`) |
| Re-check a prior harden run | **`bla_run_lookup`** `{ "summary_path": "<.bla-hardened or summary.json>", "run_id": "…" }` |
| REA constant drift / empirical report | **`bla_rea_drift`** / **`bla_redteam_report`** (unverified if REA absent; on-disk read → available) |
| Format-specific knobs | Load the matching appendix under `references/` |

## FORBIDDEN

Do **not**: add dismissible noise / greppable `BLA-SHIELD` banners / empty honeypot
stubs; drive hardening via a **rule engine** (business-name → fixed snippets); help
crack, RE, bypass, or write offensive PoCs against third-party software.

If asked for offensive RE/crack help: refuse briefly; offer defensive harden of
**their** artifacts instead.

## Format appendices (load on demand)

| Format | Appendix |
| :--- | :--- |
| JS / TS / Electron | [references/format-javascript.md](references/format-javascript.md) |
| WebAssembly | [references/format-wasm.md](references/format-wasm.md) |
| Python `.py` / `.pyc` | [references/format-python.md](references/format-python.md) |
| Android DEX / APK / IL2CPP | [references/format-android.md](references/format-android.md) |
| REA ↔ BLA matrix | [references/counter-rea-matrix.md](references/counter-rea-matrix.md) |

## CLI fallbacks

```bash
npx -y bla-agents@latest setup
npx -y bla-agents@latest doctor
npx -y bla-agents@latest harden .
npx -y bla-agents@latest harden . --weave-decoys --self-seal
npx -y bla-agents@latest lint-lanes path/to/gate.js
npx -y bla-agents@latest lint-js-wasm-hydrate-dump path/to/license.cjs
npx -y bla-agents@latest defend /absolute/path/to/target --manifest --json
npx -y bla-agents@latest verify /absolute/path/to/protected /absolute/path/to/target --json
```

## References

- Weave directives (after MCP setup): resource `bla://directives/weave-decoy`
- One-click UX notes (repo checkout): `docs/one-click-agent-defense.md`
- CLI / MCP parameter index (repo checkout): `docs/cli-and-mcp.md`
