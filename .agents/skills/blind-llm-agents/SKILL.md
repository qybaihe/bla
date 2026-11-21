---
name: blind-llm-agents
description: >
  Use when hardening, defending, or auditing software against AI reverse-engineering
  agents (REA / WorkBuddy-class): Agent-led source-level surgical decoy weaving,
  autonomous packaging-gate refactoring, one-click project harden, Counter-REA
  audit/protect/verify, or agent setup/doctor for BLA (Blind LLM Agents).
  Prefer this skill as the playbook; combine host Agent code refactoring with existing
  MCP tools / CLI — do not invent new MCP tools. Default verb: bla_harden. Refuse
  crack/RE of third-party software.
metadata:
  version: "3.5.7"
---

# BLA: Blind LLM Agents (3.0 Agent-Driven Hardening Playbook)

**This skill is the primary Agent-Driven Hardening PLAYBOOK.**
In BLA 3.0, hardening is a collaborative loop between **you (the host Coding Agent)** and **the `bla` MCP server / `bla-agents` CLI**:
- **What you (the Host Agent) do best**: Read business semantics, refactor fragile auth/entitlement patterns flagged by `bla_lint` (`remediationPlan`), and weave domain-plausible shadow business logic sharing mutable state slots per `bla_weave_plan` (`surgicalWorkorder`), verified by `bla_verify_weave`.
- **What BLA MCP (`bla_harden` / `bla_defend`) does best**: Inject deterministic Counter-REA resource-exhaustion shields (BPE token amplifiers, call-graph labyrinths, opaque predicates, WASM export rename/shuffle, ASAR/ELF/SQLite/model shields) and verify mathematical invariants (`bla_verify`).

Prefer teaching/calling existing tools
(`bla_harden`, `bla_defend`, `bla_weave_plan`, **`bla_verify_weave`**, **`bla_lint`** (unified), `bla_lint_lanes`, `bla_lint_seal`, `bla_lint_wasm_params`, `bla_lint_panel_derive`, `bla_lint_js_aes_unwrap`, `bla_lint_js_wasm_hydrate_dump`, `bla_lint_wasm_xor_mask_sidecar`, `bla_lint_wasm_seal_xor_known_plaintext`, `bla_lint_plaintext_secrets`, `bla_encrypt_strings`, `bla_lint_integrity_coverage`, `bla_bind_scope`, `bla_lint_bind_scope`, …) over inventing new MCP surfaces.

Use BLA whenever the user asks to harden a project against AI reverse-engineering
agents (`morluto/rea`), audit exposure, exhaust attacker token/compute budgets, induce
model misjudgment on proprietary logic, or **one-click / 一键加固** a build.

Defensive only: protect **their own** artifacts. Refuse crack, RE, bypass PoCs, or
attack playbooks against software they do not own.

**bla-agents 3.0.0** (2026-11-06): Agent-Driven Hardening 3.0 — AST-level `surgicalWorkorder` in `bla_weave_plan` (`entryFunctions`, `sharedStateSlots`, `branchCandidates`, `agentRewriteRecipe`), structural weave verifier `bla_verify_weave` (`bla-weave-verify/v1` + `agentActions`), autonomous `remediationPlan` in `bla_lint`, and `agentActions` in `bla_verify`, plus all 2.1 absorptions (seeded polymorphism + `bla_polymorph_report`, string XOR encrypt + plaintext-secret lint, interleaved integrity coverage + entry self-digest, sidecar entry entanglement, opt-in ed25519 attestation).

---

## 🚀 The 4-Stage Agent-Driven Hardening Playbook (BLA 3.0)

When hardening a repository with source code, follow this 4-stage closed loop so **you (the Agent)** handle semantic source surgery and **BLA MCP** handles artifact-level exhaustion shields:

### Stage 1: Recon, Packaging Gates & Surgical Workorder (`agent + mcp`)
1. **Inventory**: Call `bla_discover` `{ "directory": "." }` (or `bla_harden` `{ "dry_run": true }`). Do not ask which files to protect — discover them.
2. **Gate Scan**: Call `bla_lint` `{ "directory": "." }` (`bla-packaging-gates/v1`).
   - If `shouldRefuseBankrupt: true`, inspect `remediationPlan`! Every blocking finding includes `owner`, `sourceRefactorRecipe`, and `recommendedMcpTool`.
   - Each finding carries `enforcedByHarden`. `true`: `bla_harden` refuses the run until it is fixed (or its lab `allow_*` flag is set). `false`: `bla_harden` still runs — the finding is either a warning that blocks nothing, or a lint-only gate (plaintext-secret, integrity-coverage, bind-scope) that fails this lint; fix it for a better result.
   - Lint the project's own code, never BLA output: files BLA already wrote are skipped and listed in `skippedHardenedOutputs`.
   - A finding with `sameFindingInSource` is in the build output and in the source it was made from. Change the value in the source and rebuild; run `bla_encrypt_strings` only on build output — never rewrite a source file with it.
3. **Surgical Weave Plan**: Call `bla_weave_plan` `{ "path": "." }` (`bla-weave-plan/v1`) and read `bla://directives/weave-decoy`.
   - Inspect each source target's `surgicalWorkorder`: `entryFunctions`, `sharedStateSlots`, `branchCandidates`, **`crownJewelCandidates`**, **`dataFlowEntanglementPlan`**, `suggestedIdentifierStems`, and `agentRewriteRecipe`.

### Stage 2: Agent-Led Source Refactoring & Structural Decoy Weave (`agent-primary`)
1. **Eliminate Single-Point Boolean Gates & Entangle Crown Jewels (`crownJewelCandidates`)**:
   - Inspect `surgicalWorkorder.crownJewelCandidates` and `surgicalWorkorder.dataFlowEntanglementPlan` across JS/TS, Python, and Native (C/C++/Rust/Go) sources.
   - Replace isolated `return true / false` or cleartext equality checks (`=== "..."`) with a whole-input chained accumulator (FNV-1a / ARX / SHA-256) mixed into the shared state carrier (`sessionLedgerState.digest`) so downstream business output depends on the derived state value rather than a 1-byte patchable branch.
2. **Remediate Packaging Footguns (do NOT just pass `allow_*` in production)**:
   - Follow `bla_lint`'s `remediationPlan` to refactor source code:
     - Rewrite per-byte/per-segment lane checks (`lane-independence`) into a whole-key chained ARX/FNV/SHA-256 accumulator or move unlock into WASM.
     - Mask cleartext sensitive literals (`plaintext-secret`) via `bla_encrypt_strings`.
     - Replace reversible `seal.json` commitments with one-way `SHA-256` (`certificateSha256`) and remove JS AES wrap-key / `memory.buffer` hydrate dumps.
   - Re-run `bla_lint` until `blocking` is empty (`shouldRefuseBankrupt: false`).
3. **Weave Domain-Plausible Shadow Business Logic**:
   - Using `surgicalWorkorder` from `bla_weave_plan`:
     - Reuse or introduce the recommended `sharedStateSlots` carrier so real business paths and shadow helpers read/write the **same** runtime state.
     - Author 2–3 non-trivial helper functions using **2/3 mundane stems** (`session`, `ledger`, `quota`, `epoch`) and **1/3 security stems** (`attest`, `commitment`, `seal`) — never `_bla_*` or empty `pass` stubs.
     - Wire call edges from `entryFunctions` into the shadow helpers guarded by state-dependent opaque-true invariants at `branchCandidates`.
   - For C/C++, Rust, or Go targets, call `bla_emit_headers` and include the emitted header in native sources.
4. **Verify Source Weave**:
   - Call **`bla_verify_weave`** `{ "path": "." }` (`bla-weave-verify/v1`, 7 structural acceptance checks including `crown-jewel-entanglement`).
   - For a directory the verdict rests on `requiredFiles` — the crown-jewel files holding gate / auth / license / entitlement logic. Everything in `advisoryFiles` (formatters, UI, data classes) never fails the run: do **not** weave decoys into files that guard nothing. Pass `scope: "all"` only when the user wants every source file held to the bar.
   - If `overallPassed: false`, execute each item in `agentActions` (fixing any unreferenced helpers, missing shared-state mutations, isolated boolean gates, or stem ratios) and re-run `bla_verify_weave` until `overallPassed: true`.

### Stage 3: Build & Post-Build Counter-REA Exhaustion Harden (`mcp-primary`)
1. If the project has a build step (`npm run build`, `cargo build`, etc.), run it so compiled artifacts reflect your Stage 2 source surgery.
2. Call **`bla_harden`** `{ "directory": ".", "require_agent_weave": true, "weave_decoys": true, "self_seal": true, "sidecar_entangle": true }` (pass `wasm_preserve_exports` when a public WASM ABI must keep specific export names).
   - Passing **`require_agent_weave: true`** enforces the Agent-First Closed-Loop gate: if a crown-jewel source file was not woven in Stage 2 (`weaveVerified: false`), `bla_harden` refuses mechanical hardening and returns `agentWeaveAssessment` (`surgicalWorkorders` + `agentActions`) so you complete source surgery first.
3. **Ship it — a plain run ships nothing.** `bla_harden` writes `.bla-hardened/`, a partial mirror of only the hardened files; the build output is still unprotected. Read **`nextSteps`** in the result and follow it:
   - Call `bla_harden` again with `"apply": true`. It answers `confirmation_required` with `wouldOverwrite` — ask the user, then repeat with `"confirm_overwrite": true`. Only build output (`dist/`, `build/`, `out/`, …) is overwritten, never source; the originals are kept outside the project.
   - `"restore": true` (with `"confirm_overwrite": true`) puts the originals back. Running `apply` again re-hardens from those originals, never hardened code twice.
   - Hardened files that are source (a project with no build step) are listed in `notPromoted`: copy the project to a staging directory and overlay the mirror there. Never write hardened code over the user's source.

### Stage 4: Equivalence, Weave Acceptance & Bankruptcy Verification (`agent + mcp`)
1. Run the project's own test suite (`npm test` / `pytest` / CrackMe harness) **against the promoted build** to verify 100% functional equivalence. BLA checks structure, not behaviour — if a test fails, `restore`, report the failing case, and do not ship that build.
   - **Recover, do not give up.** Find the artifact behind the failure (or the hot path that became too slow — hardened functions run extra code on every call) and harden again with only that file left out: `bla_harden` `{ "directory": ".", "apply": true, "exclude": ["dist/vendor/heavy.js"] }`, or at a lower `intensity`. Everything else stays protected; the result lists what ships as it was under `excluded`. Tell the user which files those are and why.
2. Call `bla_verify` on hardened outputs (or inspect `bla_harden` verification results) and check `agentActions`:
   - Confirm `overallPassed: true`, `tokenAmplificationFactor >= 10`, and zero unresolved `agentActions`.

---

## ⚡ One-Sentence Fast Path (Artifact-Only / Pre-Built Tree)

When the user says **"Harden my software"**, **"一键加固"**, or points at an already-built directory without asking for source refactoring:

| Surface | Call |
| :--- | :--- |
| **MCP (preferred)** | `bla_harden` `{ "directory": "." }` |
| **CLI** | `npx bla-agents@latest harden .` |
| **MCP Prompt** | `bla-harden-project` |

Auto-discovers protectable build outputs, detects formats, runs **audit → defend
(bankrupt) → verify**. **Do not ask which files to protect — discover them.** Build
first: discovery targets the build output and leaves the toolchain alone (tool
configs, tests, the scripts `package.json` runs for build / test / release, `.d.ts`).

Then finish the job — the result's `nextSteps` lists exactly this:

1. `bla_harden` `{ "directory": ".", "apply": true }` → `confirmation_required` → ask the
   user → repeat with `"confirm_overwrite": true`. (CLI: `harden . --apply`.)
2. Run the project's tests / a smoke run against the promoted build.
3. Something broke? `bla_harden` `{ "directory": ".", "restore": true, "confirm_overwrite": true }`,
   then harden again with the offending file in `"exclude"` (or at a lower `intensity`).

Optional args (safe defaults): `intensity` (bankrupt), `emit_manifest` (false),
`llm_directives` (false — risky bait), `weave_decoys` (false), `self_seal` (false),
`sidecar_entangle` (false), `wasm_preserve_exports`, `seed`, `output_directory`, `max_artifacts`, `dry_run`,
`apply` (false), `restore` (false), `exclude` (paths / globs to leave out — also `"exclude"` in `.blarc`).

### Reading the result (report these to the user, do not paper over them)

| Field | What it tells you |
| :--- | :--- |
| `isError: true`, `artifacts[].error` | The run did not succeed. Read the error and `nextSteps`; never retry unchanged, never ship a partially hardened build. |
| `skippedHardenedOutputs` | Already BLA output — not hardened twice. `discoveredCount: 0` with this set means "rebuild first". |
| `skippedDevTooling`, `skippedSourceFiles` | Left alone on purpose. Use `bla_defend` on a named file only if it really ships. |
| `excluded` | Files your `exclude` list left out. They ship **unprotected** — say so. |
| `outputSize` (`inputBytes` → `outputBytes`, `largestGrowth`) | What the protection costs to download. Every hardened file grows (decoys are the mechanism); a WASM module grows by megabytes at `bankrupt`. For a web build tell the user the number, and offer `intensity: "maximum"` or an `exclude` for the largest file if size matters. |
| `sqliteEvalTrapArtifacts` + the SQLite line in `nextSteps` | A hardened SQLite database holds decoy tables **beside** the application's own, which stay readable — BLA does not encrypt a database; tell the user. `sqlite_eval_trap: true` additionally makes a row read of the decoy tables fail, at the price of `PRAGMA integrity_check` / `VACUUM` / dump-restore failing for the application too: only for a database it just queries. |
| `artifacts[].plaintextSurvivors` | Secret-looking literals (digests, keys, generated tokens) still readable in the output. `stealth`/`balanced` do not encode strings; `maximum`/`bankrupt` split strings of 3–256 characters and secret-looking values of up to 4,096 characters wherever they are written (object key and regular expression included), and cannot reach HTML attributes, tagged templates, class member names, TypeScript object keys / `as const` values or longer values — move the value into a plain string literal or off the client. A split value is hidden from a text search, not from someone who runs the code: a real credential does not belong in a shipped file. |
| `artifacts[].wasmExportRenames` / `wasmExportsAutoPreserved` | Renamed exports (old → new map for callers outside the project) and exports kept because a project file calls them. |
| `integrityBindingEntry`, `integrityBindingUncoveredEntries`, `integrityBindingSkipped`, `pythonSidecarEntry`, `pythonSidecarUncoveredEntries` | What `self_seal` / `sidecar_entangle` really cover: the one module that pins its siblings, declared entry points (`package.json`; Python console scripts) that never load it, and artifacts bound to nothing (browser bundles, writable SQLite, files outside the checking module's directory). Bytecode-only / frozen Python starts without verifying. |
| `defenseScore`, token / cost amplification | Structural checks and cost **estimates**, not measured attacker results. Say so. |
| A `bla_redteam_report` row, "trips REA's budget" | Measured against REA **as it runs by default**. Most of REA's budgets are per-call inputs and REA's own error names the one to raise (`asar.max_header_bytes`, `max_interface_bytes`, `max_chunks`, `semantic_precision`), so a size-based plant costs an attacker one retry — it does not block REA. Measured with budgets raised: the JavaScript string encoding of `maximum` / `bankrupt` (no known value in REA's result at 1× / 4× / 64×). Say which of the two you are reporting. |

---

## Principles (red-blue R1–R12 → MCP/Skill 3.0)

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
| Cleartext sensitive literals (panel/license) | `bla_lint_plaintext_secrets` / `bla_encrypt_strings` | `allow_plaintext_string` |
| Release hygiene leaks (SOLUTION/dotenv/keys/debug) | `bla_lint` | `allow_release_hygiene_leak` |

Prefer **one** project scan: MCP `bla_lint` / CLI `bla lint .` (schema `bla-packaging-gates/v1` with `remediationPlan`). Individual `bla_lint_*` remain for single-file drills. Bankrupt harden **refuses** the six carrier/JS/WASM gates unless the matching allow flag is set; lanes/panel also refuse at protect-time.

Also: do **not** ship a stable public WASM ABI without explicit `wasm_preserve_exports`; maximum/bankrupt **rewrites** `__vaultPanelDerive_*` / `deriveLocal` unless `allow_stable_panel_derive`. Multi-artifact trees: bankrupt sets `selfSealRecommended` — prefer **`self_seal`** and **`sidecar_entangle`** (sibling SHA-256 **hard-fail**; opaque-seed alone does not gate entitlement).

### B. Product recipe principles (Skill layer — not new refuse lints)

- Sensitive literals in panel.html / license.cjs must not remain cleartext in shipped artifacts; prefer `bla_encrypt_strings` (seed-derived XOR — never JS AES wrap-key). Lint with `bla_lint_plaintext_secrets`.
- Integrity checkers must be interleaved and mutually covering (coverage matrix `bla-integrity-coverage/v1`); single-point self-seal is refuse-worthy. Lint with `bla_lint_integrity_coverage`.
- Optional bind-scope (domain/date) is a **public** license contract (`bla_bind_scope` → `bind-scope.json` + `BLA_BIND_SCOPE_CHECK`). Default OFF. Never a covert backdoor — `public:true` mandatory; lint with `bla_lint_bind_scope`.
- Coverage claims must be real, not paper: an entry may only count as covering itself when its runtime check hard-fails on its own bytes (canonical self-digest, finalized at write). Check `integrityCoverageSelfVerified` on the harden report; when false the matrix drops self edges and refuses. Keep host-trust values (e.g. certificate digests) inside a covered artifact — unhardened data sidecars like `seal.json` are not covered.
- A countered strip⇒fail sidecar vector (`asar-sidecar-entangle`, `wasm-sidecar-entangle` when a same-directory Node CJS loader was auto-wired, or `pyc-sidecar-entangle` / `gguf-sidecar-entangle` once they exist at import/load time) may be recorded only when the entry hook hard-fails at process start, import, or load. A host-only verifier (for example `verifyPycSidecarMarshalNote` on a `.pyc` TYPE_ASCII trailer that `importlib` ignores, or `verifyGgufSidecarMetadataNote` on a GGUF `bla.sidecar.v1` STRING KV that loaders ignore) is a binding note, not coverage: do not list the vector, and do not treat enabling it as closing the `sidecar-entangle-not-enabled` defenseScore gap (annotate `pyc-sidecar-host-verify-only` / `gguf-sidecar-host-verify-only` instead).
- **Runtime carrier decides whether a preamble is safe, not file syntax alone:** a CommonJS strip⇒fail preamble (`require`, `__dirname`) on an entry that the runtime evaluates as an ES module breaks the *intact* artifact — that is a functional-equivalence failure, not protection. Treat `.mjs`, static import/export, top-level `await`, `import.meta`, and a `.js` / `.ts` under the nearest `package.json` `"type": "module"` as module scope and ship the ESM-native preamble (`import { createRequire } from "node:module"` + `import.meta.url`), not a CommonJS one (red 2026-11-13 / #200).
- **ESM static imports are hoisted before the entry hook:** a prepended sidecarEntangle / self-seal IIFE fail-closes the *entry body*, but the ESM loader instantiates static `import` / `export-from` bindings first, so imported module side effects still run after a sidecar strip or hook failure. That is not process-start strip⇒fail for the hoisted graph (CJS `require()` after the preamble is). Annotate defenseScore gap `esm-import-hoist-before-hooks` (soft-cap 93) and do not overclaim "full runtime" coverage (red 2026-11-16).
- **Pinned sibling digests must fail-closed on absence:** if an entry pins `EXPECTED_*_SHA256` (or equivalent) for a data sidecar, `ENOENT` / unreadable MUST throw the same integrity-class error as digest mismatch. Never soft-fold missing pinned files into business `DENIED` — catch blocks that only rethrow `/integrity/` and map everything else to DENIED are a footgun (CrackMe v9 red 2026-11-10: `seal.json` delete looked like a wrong key).

Held across R8–R12 (NO PRIZE). Keep in gate design; do **not** invent packaging refuse lints for these:

- Unlock **inside WASM** (`unlock(keyPtr,keyLen)->outLen`); JS only writes key / reads result UTF-8.
- Mask via **one-way** KDF (`SHA-256(key[16])`), never algebraically invertible byte mix.
- Keep public digests (**`seal.revision`**) **out** of XOR-masked plaintext; commitment in a separate clear segment.
- Randomize pack header `pad3` + seed-derived rounds (close structural KP).
- Keep the **crypto schedule / harden seed private** (derive from release secrets); a public `seed` in SEAL re-opens header KP and strips the mask without WASM RE. Publish only `flagSha256`/`certificateSha256` for prove-solve — **never** `keySha256` (offline key oracle). `bla_lint` warns (`public-materialization-seed`, `public-key-digest-oracle`); warning only, not a refuse gate.
- Host resolves unlock by **arity + `FLAG{…}` shape + `sha256===certificateSha256`**, never export name/order.
- JS honeypot/canary ≠ WASM unlock (decoy must fail certificate check).

### C. Engine defaults already on (hygiene, not refuse)

At maximum/bankrupt WASM protect: export rename, **arity-2-preferring decoy alias spread**, **independent export-order shuffle**, honesty fields `wasmExportRenameApplied` / `wasmExportOrderShuffled` / `wasmExportDecoysInjected`. Cleartext may also scatter unlock body index (recipe).

### D. Honesty residual (do not water refuse lints)

Gates close **packaging** footguns. They do **not** claim white-box secrecy against full WASM RE + online/SMT vs SHA-256 commitment (R8–R12 P2). Body-size fingerprinting among arity-2 exports is P3 / diminishing returns — not a new refuse gate. `defenseScore` is an honest soft-cap, not preimage hardness.

## Prerequisites (once)

1. CLI: `npx bla-agents@latest setup`
2. Then: `npx bla-agents@latest doctor` (or MCP `bla_doctor`) — checks the installed
   skill bundle (this file + `references/`, including format appendices) is complete,
   flags a client still pinned to an older release (`versionSkew` → re-run `setup --yes`),
   and with `--verify-handshake` / `verify_handshake: true` starts each registered
   server to confirm it answers

## Write safety (principles)

- Unsure what will be touched? `bla_discover` or `bla_harden` `{ "dry_run": true }` —
  both write nothing. If `truncated: true`, page with `offset` from `nextOffset` until
  the tail is retrieved (do not silently drop artifacts past the 64 default cap), or
  raise `max_artifacts` / narrow the directory.
- Never overwrite without the user's go-ahead. On `confirmation_required`, show
  `wouldOverwrite`, ask, then retry with `confirm_overwrite: true` (or a new path).
- Long `bla_harden` runs may emit MCP `notifications/progress` when the client
  sets `_meta.progressToken`. Cancel with `notifications/cancelled`
  `{ requestId }` — already-written paths are listed on the cancelled report
  (`cancelled: true`, `written: [...]`); there is no silent half-harden.
  Same rule for `in_place: true` (overwrites the input).
- Report writes from the tool receipt (`writeReceipt` / `wouldOverwrite`), not guesses.
- Never edit, lint, or re-harden BLA's own output, and never copy it over source files:
  it is unreadable by design. Change the source, rebuild, harden again.
- `apply: true` is the only path that overwrites build output, and it always asks first
  (`confirmation_required`). Originals live in the per-user state directory
  (`BLA_STATE_DIR` overrides it); `restore: true` puts them back.
- After a successful harden/defend/protect, keep the returned unsigned `runId` (and
  harden `summaryPath`). Re-check later with `bla_run_lookup` or `bla_verify` +
  `summary_path`/`run_id` — never invent a run id.
- `bla_rea_drift` / `bla_redteam_report` may return `status: unverified` when sibling
  REA is absent, or when the harness could not call that REA checkout for a probe (REA
  moved or renamed something; the harness needs updating). Treat it as **not proven**:
  never a pass, and never a failed defense either — `fail` is the status for REA reading
  a hardened sample. An on-disk `bla_redteam_report` without `execute:true` is
  `status: available` — readable evidence, not a fresh REA verdict; its `reason`
  names any format whose plant REA read through in that run (`notStopped`).
- `bla_harden` `{ "dry_run": true }` always has `overallSuccess: false`; only real
  writes return `writeReceipt`.

## Decision tree (short)

| Intent | Prefer |
| :--- | :--- |
| Project / build dir | **`bla_harden`** |
| Ship the hardened build / undo it | **`bla_harden`** `{ "apply": true }` → confirm → `{ "restore": true }` to undo |
| One hardened file breaks a test or a hot path | `restore` → **`bla_harden`** `{ "apply": true, "exclude": ["<that file>"] }` (or lower `intensity`) |
| Named artifact | **`bla_defend`** (or granular `bla_audit` → `bla_protect` → `bla_verify`) |
| Inventory only (page 64+ with `offset`/`nextOffset`) | **`bla_discover`** |
| Surgical source weave & verification | Resource `bla://directives/weave-decoy` → **`bla_weave_plan`** (`surgicalWorkorder`) → Agent edits source → **`bla_verify_weave`** → `bla_harden` (`weave_decoys: true`) |
| Packaging footguns & remediation recipes | **`bla_lint`** `{ "directory": "." }` (CLI: `bla lint .`) — unified R1–R7+lanes/panel + `remediationPlan` |
| Custom license/activation gate review | **`bla_lint_lanes`** `{ "path": "<gate.js>" }` (CLI: `bla lint-lanes`) |
| Re-check a prior harden run | **`bla_run_lookup`** `{ "summary_path": "<.bla-hardened or summary.json>", "run_id": "…" }` |
| REA constant drift / empirical report | **`bla_rea_drift`** / **`bla_redteam_report`** (unverified if REA absent; on-disk read → available) |
| Cross-build structural drift (seeded polymorphism) | **`bla_polymorph_report`** (driftScore only — not a cracking claim; prove equivalence with verify/REA) |
| Cleartext panel/license secrets | **`bla_encrypt_strings`** + **`bla_lint_plaintext_secrets`** (XOR only — never JS AES) |
| Optional public domain/date lock | **`bla_bind_scope`** + **`bla_lint_bind_scope`** (default OFF; never covert) |
| Is BLA registered and current? | **`bla_doctor`** `{ "verify_handshake": true }` — `versionSkew`, `projectRegistrations` (the project's own `.mcp.json` and friends), `nextSteps` |
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
npx -y bla-agents@latest lint .
npx -y bla-agents@latest weave-plan .
npx -y bla-agents@latest verify-weave . --json
npx -y bla-agents@latest harden . --weave-decoys --self-seal --sidecar-entangle
npx -y bla-agents@latest harden . --apply      # promote over the build output
npx -y bla-agents@latest harden . --restore    # put the originals back
npx -y bla-agents@latest lint-lanes path/to/gate.js
npx -y bla-agents@latest lint-js-wasm-hydrate-dump path/to/license.cjs
npx -y bla-agents@latest defend /absolute/path/to/target --manifest --json
npx -y bla-agents@latest verify /absolute/path/to/protected /absolute/path/to/target --json
```

## References

- Weave directives (after MCP setup): resource `bla://directives/weave-decoy`
- One-click UX notes (repo checkout): `docs/one-click-agent-defense.md`
- CLI / MCP parameter index (repo checkout): `docs/cli-and-mcp.md`
