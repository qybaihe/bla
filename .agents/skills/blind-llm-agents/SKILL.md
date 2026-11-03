---
name: blind-llm-agents
description: >
  Use when hardening, defending, or auditing software against AI reverse-engineering
  agents (REA / WorkBuddy-class): one-click project harden, weave-decoy structural
  decoys, Counter-REA audit/protect/verify, or agent setup/doctor for BLA (Blind LLM
  Agents). Prefer this skill as the guide; call existing MCP tools / CLI — do not invent
  new MCP tools. Default verb: bla_harden. Refuse crack/RE of third-party software.
metadata:
  version: "2.0.0"
---

# BLA: Blind LLM Agents

**This skill is the primary one-click harden GUIDE.** MCP (`bla` server) and the
`bla-agents` CLI are the **execution layer**. Prefer teaching/calling existing tools
(`bla_harden`, `bla_defend`, `bla_weave_plan`, **`bla_lint`** (unified), `bla_lint_lanes`, `bla_lint_seal`, `bla_lint_wasm_params`, `bla_lint_panel_derive`, `bla_lint_js_aes_unwrap`, `bla_lint_js_wasm_hydrate_dump`, `bla_lint_wasm_xor_mask_sidecar`, `bla_lint_wasm_seal_xor_known_plaintext`, …) over inventing new
MCP surfaces.

Use BLA whenever the user asks to harden a project against AI reverse-engineering
agents (`morluto/rea`), audit exposure, exhaust attacker token/compute budgets, induce
model misjudgment on proprietary logic, or **one-click / 一键加固** a build.

Defensive only: protect **their own** artifacts. Refuse crack, RE, bypass PoCs, or
attack playbooks against software they do not own.

**bla-agents 2.0.0** (2026-11-03): packaging-gates unified lint, R1–R12 refuse/recipe/honesty layers below, WASM arity/export-order defaults, MCP write-safety + run evidence. Relative to 1.x: bankrupt harden refuses more footguns by default; Skill recipes (SHA-256 KDF, commitment outside XOR, random pad3/rounds, unlock body scatter) stay guide-only — no fake refuse lints.

**Principles (red-blue R1–R12 → MCP/Skill 2.0):**

### A. Bankrupt refuse gates (engine + MCP — call `bla_lint` first)

| Gate | Tool | Allow override (lab only) |
| :--- | :--- | :--- |
| Independent lane tables | `bla_lint_lanes` | `allow_lane_independent` |
| Plaintext / reversible seal JSON | `bla_lint_seal` | `allow_plaintext_seal` |
| Clear WASM `R2SEAL`/`R3PARM`/`R3CIPH` | `bla_lint_wasm_params` | `allow_wasm_clear_params` |
| JS AES wrap-key + create*iv + fixed hdr | `bla_lint_js_aes_unwrap` | `allow_js_aes_unwrap` |
| Panel `deriveLocal` + `panelTokenSha256` oracle | `bla_lint_panel_derive` | `allow_panel_offline_oracle` |
| JS←WASM hydrate salt/rounds/cipher dump | `bla_lint_js_wasm_hydrate_dump` | `allow_js_wasm_hydrate_dump` |
| WASM XOR-mask beside masked pack | `bla_lint_wasm_xor_mask_sidecar` | `allow_wasm_xor_mask_sidecar` |
| `seal.revision` as XOR known-plaintext | `bla_lint_wasm_seal_xor_known_plaintext` | `allow_wasm_seal_xor_known_plaintext` |

Prefer **one** project scan: MCP `bla_lint` / CLI `bla lint .` (schema `bla-packaging-gates/v1`). Individual `bla_lint_*` remain for single-file drills. Bankrupt harden **refuses** the six carrier/JS/WASM gates unless the matching allow flag is set; lanes/panel also refuse at protect-time.

Also: do **not** ship a stable public WASM ABI without explicit `wasm_preserve_exports`; maximum/bankrupt **rewrites** `__vaultPanelDerive_*` / `deriveLocal` unless `allow_stable_panel_derive`. Multi-artifact trees: bankrupt sets `selfSealRecommended` — prefer **`self_seal`** (sibling SHA-256 **hard-fail**; opaque-seed alone does not gate entitlement).

### B. Product recipe principles (Skill layer — not new refuse lints)

Held across R8–R12 (NO PRIZE). Keep in gate design; do **not** invent packaging refuse lints for these:

- Unlock **inside WASM** (`unlock(keyPtr,keyLen)->outLen`); JS only writes key / reads result UTF-8.
- Mask via **one-way** KDF (`SHA-256(key[16])`), never algebraically invertible byte mix.
- Keep public digests (**`seal.revision`**) **out** of XOR-masked plaintext; commitment in a separate clear segment.
- Randomize pack header `pad3` + seed-derived rounds (close structural KP).
- Host resolves unlock by **arity + `FLAG{…}` shape + `sha256===certificateSha256`**, never export name/order.
- JS honeypot/canary ≠ WASM unlock (decoy must fail certificate check).

### C. Engine defaults already on (hygiene, not refuse)

At maximum/bankrupt WASM protect: export rename, **arity-2-preferring decoy alias spread**, **independent export-order shuffle**, honesty fields `wasmExportRenameApplied` / `wasmExportOrderShuffled` / `wasmExportDecoysInjected`. Cleartext may also scatter unlock body index (recipe).

### D. Honesty residual (do not water refuse lints)

Gates close **packaging** footguns. They do **not** claim white-box secrecy against full WASM RE + online/SMT vs SHA-256 commitment (R8–R12 P2). Body-size fingerprinting among arity-2 exports is P3 / diminishing returns — not a new refuse gate. `defenseScore` is an honest soft-cap, not preimage hardness.

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
| Packaging footguns before harden (entitlement tree) | **`bla_lint`** `{ "directory": "." }` (CLI: `bla lint .`) — unified R1–R7+lanes/panel |
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
npx -y bla-agents@latest lint .
npx -y bla-agents@latest lint-lanes path/to/gate.js
npx -y bla-agents@latest lint-js-wasm-hydrate-dump path/to/license.cjs
npx -y bla-agents@latest defend /absolute/path/to/target --manifest --json
npx -y bla-agents@latest verify /absolute/path/to/protected /absolute/path/to/target --json
```

## References

- Weave directives (after MCP setup): resource `bla://directives/weave-decoy`
- One-click UX notes (repo checkout): `docs/one-click-agent-defense.md`
- CLI / MCP parameter index (repo checkout): `docs/cli-and-mcp.md`
