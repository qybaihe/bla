# CLI & MCP Reference (`bla-agents`)

For coding agents, the **[`blind-llm-agents` skill](../.agents/skills/blind-llm-agents/SKILL.md)** is the primary one-click harden guide; this page indexes the CLI/MCP execution surface.

## CLI Commands

| Command | Description |
| :--- | :--- |
| `npx bla-agents setup` | Auto-registers the `bla` MCP server and `blind-llm-agents` skill with Claude Code, Cursor, Codex, Windsurf, Gemini CLI, and Antigravity. |
| `npx bla-agents harden .` | **Default one-command UX**: auto-discover build outputs and run audit → protect → verify (bankrupt). Prefer over `defend` when you have a project directory. Agent guide: [`blind-llm-agents` skill](../.agents/skills/blind-llm-agents/SKILL.md). |
| `npx bla-agents lint .` | **Unified packaging-footgun scan** (`bla-packaging-gates/v1`): all R1–R7 refuse lints + lanes/panel. Exit 2 when bankrupt would refuse. `--json` prints the compact report and `--sarif` prints SARIF 2.1.0 for `upload-sarif` code scanning. Writes nothing. |
| `npx bla-agents defend <target> [--manifest] [--sign-manifest --manifest-key <pem>] [--llm-directives] [--weave-decoys]` | **5-stage pipeline** on a known path: `inspect-release` → `audit` → `protect` → `verify` → optional `.bla-manifest.json` (opt-in; unsigned unless `--sign-manifest` is set). Risky LLM directive layers stay off unless `--llm-directives`. Structural weave decoys stay off unless `--weave-decoys`. |
| `npx bla-agents harden . [--weave-decoys]` | Same as `harden` with opt-in structural weave (`weave_decoys`). |
| `npx bla-agents harden . --apply` / `--restore` | **Ship it / undo it.** `--apply` hardens and then overwrites the build output with the hardened files (originals are kept outside the project; source files are never overwritten). `--restore` puts the originals back. See [Shipping the hardened build](#shipping-the-hardened-build-apply--restore). |
| `npx bla-agents harden . --dry-run` | Lists what would be hardened and where, writing nothing. |
| `npx bla-agents harden . --exclude <a,b>` | Leaves the named paths / globs out (repeatable; also `"exclude"` in `.blarc`). For the one file that breaks or slows the program when hardened — everything else is still protected and the report lists what ships as it was. |
| `npx bla-agents harden . --sqlite-eval-trap` | SQLite only, opt-in (also `defend` / `protect`, `"sqliteEvalTrap"` in `.blarc`). The honey tables' generated columns call a function no stock connection has, so an inspector's row read of those tables fails — and so do `PRAGMA integrity_check`, `VACUUM` and a dump/restore in the application, unless it registers a function named `enclave_unseal_payload` itself. Without the flag the decoy columns are plain SQL and the database works everywhere. Either way the application's own tables are stored as before: BLA does not encrypt a database. |
| `npx bla-agents inspect-release <target>` | Read-only local scan for embedded `.map` (`sourcesContent`) and sourceMappingURL references. |
| `npx bla-agents audit <target>` | Pre-flight multi-vector REA vulnerability & token-cost audit. |
| `npx bla-agents protect <target> [-o <out>] [--weave-decoys]` | Injects BLA's Resource-Exhaustion and Model-Misjudgment shield (`stealth`, `balanced`, `maximum`, `bankrupt`). Opt-in `--weave-decoys` for structural Python customer-def weave. |
| `npx bla-agents verify <target> [original]` | Verifies Counter-REA invariants and calculates token/cost amplification. |
| `npx bla-agents benchmark` | Runs the 16-target Counter-REA Showcase Benchmark suite. |
| `npx bla-agents emit-headers --lang <c\|rust\|go>` | Emits compile-time native defense headers (`bla_shield.h`, `bla_shield.rs`, `bla_shield.go`). |
| `npx bla-agents doctor [--verify-handshake]` | Checks readiness of all BLA protection engines and agent MCP registrations — per-user client configs and the MCP config files of the project it is run in (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`, `.codex/config.toml`, `opencode.json`) — flags an entry pinned to another release (`versionSkew`), and prints what to run to repair it. `--verify-handshake` also starts each registered server and checks that it answers `initialize`. |

### Signed manifests (ed25519)

`.bla-manifest.json` is unsigned by default. To sign it:

```bash
bla defend ./dist --manifest --sign-manifest --manifest-key ./release-key.pem
```

The manifest keeps the plain JSON payload and adds a `signature` object with
`algorithm: "ed25519"`, the SPKI public key, and a base64 signature over the
payload JSON (the `signature` field is excluded). `attestationKind` is
`"unsigned"` or `"ed25519"`, so consumers can tell whether a signature exists.

Verify with the library:

```ts
import { readFileSync } from "node:fs";
import { verifyManifestSignature } from "bla-agents";

const manifest = JSON.parse(readFileSync(".bla-manifest.json", "utf8"));
// Without a pinned key this only proves the payload matches the embedded key.
verifyManifestSignature(manifest);
```

Signing fails closed: `--sign-manifest` without `--manifest-key`, a missing key
file, or a key path without `--manifest` is an error, never a silently unsigned
manifest.

## MCP Tools (`bla` Server)

### What every client gets

- **Protocol revision.** The server speaks `2024-11-05`, `2025-03-26` and `2025-06-18`. A supported `protocolVersion` is echoed, an unknown one is answered with the latest, and a client that sends none gets the oldest.
- **Instructions.** The `initialize` result carries `instructions`: a short playbook (build → `bla_harden` → follow `nextSteps` → `apply` → run the project's tests) plus the rules below. An agent that never loads the skill still gets them.
- **The guide itself.** The skill bundle is also served as MCP resources (`bla://skill/SKILL.md` and its `references/`), so a client with only the server registered can read the full guide on demand.
- **Results.** Every tool result has the JSON report in `content[0].text` and again in `structuredContent`. `isError: true` means the call did not do what was asked — a refused overwrite (`confirmation_required`), a harden with a failed artifact, a lint or weave verification that does not pass. Read `artifacts[].error`, `apply.reason` and `nextSteps` instead of retrying unchanged.
- **Size.** Reports are compacted for a model's context: an audit lists at most 8 `exposedItems` after protection (40 before), each clipped to 160 characters, with `exposedItemsTotal` / `exposedItemsTruncated` saying what was left out; the coverage contract appears once at the top level. The CLI's `--json` output is not compacted.
- **BLA's own output is not an input.** A file that still holds exactly the bytes an earlier run wrote is skipped by discovery and by the directory lints, and listed under `skippedHardenedOutputs`. Rebuild to get fresh output; name a file explicitly to lint it anyway.

Argument bounds are enforced before any tool runs: count arguments (`max_artifacts`, `max_files`, `max_total_bytes`, `max_targets`, `offset`) must be integers, and string-list arguments (`wasm_preserve_exports`, `domains`) hold at most 1024 items. A violation is a `-32602` error naming the argument, and fractional drift thresholds (`same_threshold` / `different_threshold`) stay allowed because drift scores are not counts.

- `bla_harden`: Preferred one-sentence harden of a project directory (`directory`, `intensity`, `emit_manifest` default false, `sign_manifest` / `manifest_key_path`, `llm_directives` default false, `weave_decoys` default false, `self_seal` default false, `sqlite_eval_trap` default false, `sidecar_entangle` default false, `require_agent_weave` default false, `wasm_preserve_exports`, the `allow_*` lab overrides, `seed`, `dry_run` default false, `max_artifacts` default 64, `confirm_overwrite` default false, `output_directory` optional, **`apply`** default false, **`restore`** default false, **`exclude`** — project-relative paths or globs to leave out). The report carries `dryRun`, `truncated`, `maxArtifacts`, `wouldOverwrite`, `outputDirectory`, and **`nextSteps`** — what to do next, most important first; see [Reading a harden report](#reading-a-harden-report).
- `bla_discover`: Read-only inventory using the same discovery as `bla_harden` (`directory`, `max_artifacts`, `offset`, `exclude`) → `{ directory, artifacts[{path, relativePath, format}], truncated, maxArtifacts, offset, nextOffset?, skippedDevTooling?, skippedSourceFiles?, skippedHardenedOutputs?, excluded? }`. When `truncated`, pass `nextOffset` as the next `offset` to page 64+ trees without losing the tail. Writes nothing.
- `bla_init`: Writes a starter `bla.config.json` with a fresh per-project seed (`directory`, `overwrite` default false) so zero-argument `bla defend` has a config. Writes one file only.
- `bla_defend`: Full Counter-REA pipeline on a known path (`input_path`, `output_path`, `intensity`, `emit_manifest` default false, `llm_directives` default false, `weave_decoys` default false, `self_seal` default false, `sqlite_eval_trap` default false, `wasm_preserve_exports`, `allow_lane_independent`, `allow_plaintext_seal`, `seed`, `in_place` default false, `confirm_overwrite` default false).
- `bla_audit`: Pre-flight REA exposure and token-economics audit (`path`).
- `bla_inspect_release`: Read-only local source-map and symbol exposure scan (`path`, optional `max_files`, `max_total_bytes`) — same engine as CLI `bla inspect-release`. Reports counts only; never prints embedded source or writes to the target.
- `bla_protect`: Granular shield injection (`input_path`, `output_path`, `intensity`, `seed`, `llm_directives` default false, `weave_decoys` default false, `self_seal` default false, `sqlite_eval_trap` default false, `wasm_preserve_exports`, `allow_lane_independent`, `allow_plaintext_seal`, `in_place` default false, `honey_source_maps` default true, `confirm_overwrite` default false).
- `bla_verify`: Counter-REA invariant verification (`target_path`, `original_path`, optional honesty metadata `self_seal_enabled` / `wasm_export_rename_applied` / `numeric_template_leak_known` so `defenseScore` soft-caps match what protect actually ran; optional `summary_path` / `run_id` to correlate with a prior harden summary).
- `bla_lint`: **DEFAULT** packaging-footgun project scan (`directory`, `intensity`, allow_* flags) → `bla-packaging-gates/v1` (findings + blocking + honestyNote). Prefer over calling eight separate lints. Same engines as CLI `bla lint`. Each finding says whether `bla_harden` refuses on it: **`enforcedByHarden: true`** means the run is refused until the finding is fixed; **`false`** is a warning, or a lint-only gate (plaintext-secret, integrity-coverage, bind-scope) that fails this lint — `bla_harden` still runs, and reports literals it could not hide in `artifacts[].plaintextSurvivors`. `skippedHardenedOutputs` lists BLA output that was not linted. A finding that sits both in a build-output file and in the source it was made from (`dist/license.cjs` and `src/license.cjs`) is listed once, on the file that ships, with the source in **`sameFindingInSource`**: fix the value there and rebuild — masking tools run on build output, never on a source file.
- `bla_lint_lanes`: Read-only lane-independence footgun lint (`path`) — same engine as CLI `bla lint-lanes`.
- `bla_lint_seal`: Read-only seal-commitment lint (`path`) — plaintext / reversible seal sidecars; same engine as CLI `bla lint-seal`.
- `bla_lint_wasm_params`: Read-only WASM clear param/cipher carrier lint (`path`) — `R3PARM`/`R3CIPH`/`R2SEAL`-class; same engine as CLI `bla lint-wasm-params`.
- `bla_lint_panel_derive`: Read-only panel-derive ABI lint (`path`) — stable `__vaultPanelDerive_*` / `deriveLocal` / `panelTokenSha256` oracle; same engine as CLI `bla lint-panel-derive`.
- `bla_lint_js_aes_unwrap`: Read-only JS AES wrap-key unwrap lint (`path`) — wrap-key + create*iv + fixed hdr; same engine as CLI `bla lint-js-aes-unwrap`. Gate only — not white-box AES.
- `bla_lint_js_wasm_hydrate_dump`: Read-only JS←WASM hydrate param-dump lint (`path`) — memory.buffer + salt/rounds/cipher after hydrate; same engine as CLI `bla lint-js-wasm-hydrate-dump`. Prefer in-WASM ARX+certify.
- `bla_lint_wasm_xor_mask_sidecar`: Read-only WASM XOR-mask sidecar lint (`path`) — masked entitlement pack beside plaintext 32-byte mask in WASM data; bankrupt refuses unless `allow_wasm_xor_mask_sidecar`, `allow_wasm_seal_xor_known_plaintext`.
- `bla_lint_wasm_seal_xor_known_plaintext`: Read-only seal.revision XOR known-plaintext lint (`path`, optional `seal_path`) — bankrupt refuses unless `allow_wasm_seal_xor_known_plaintext`.
- `bla_lint_integrity_coverage`: Read-only `bla-integrity-coverage/v1` matrix evaluation (`path`, optional `allow_single_point_integrity`) — discovers `integrity-coverage.json` and refuses uncovered nodes, un-covered checkers, and missing hashes at bankrupt.
- `bla_lint_plaintext_secrets`: Read-only plaintext secret lint (`path`, optional `allow_plaintext_string`) for `FLAG{...}`, high-entropy tokens, PEM headers, and derive key names in `panel.html` / `license.cjs` — same engine as `bla_encrypt_strings`' post-lint.
- `bla_run_lookup`: Read-only harden-run correlation (`summary_path`, optional `run_id`). Summaries are **unsigned**; missing/mismatched id is an error.
- `bla_rea_drift`: Thin wrapper over `npm run verify:rea` / `scripts/verify-rea-constants.mjs`. Absent sibling REA → `status: unverified` (not red-team evidence).
- `bla_redteam_report`: Read (or `execute:true` re-run) `docs/redteam/empirical-rea-validation.json`. On-disk read → `status: available` (not a live REA verdict); `execute:true` → `pass`/`fail`; missing report / unready REA → `status: unverified`. Also `unverified` when the harness could not call the REA checkout for a probe (REA renamed or moved something): nothing was measured for that format, which is the harness being out of date, not REA reading a hardened sample (`fail`).
- `bla_polymorph_report`: Compare two hardened directories (`dir_a`, `dir_b`, optional thresholds) and report structural drift (export-name Jaccard, export-order Kendall-tau, byte-diff ratio, identifier overlap, aggregate `driftScore`). Drift is a stability signal, not a cracking-resistance proof.
- `bla_benchmark`: Runs the 16-target showcase benchmark suite.
- `bla_emit_headers`: Generates C/C++, Rust, or Go defense headers (`language`, `intensity`).
- `bla_bind_scope`: Optional honest code-lock — write public `bind-scope.json` (domains / validFrom / validUntil) and inject `BLA_BIND_SCOPE_CHECK` into the license entry. Default OFF; never a covert backdoor. In-place runs require `confirm_overwrite` (see write-safety below).
- `bla_encrypt_strings`: Encrypt sensitive literals in `panel.html` / `license.cjs` with a seed-derived XOR keystream plus a runtime decrypt stub (`path`, `seed`, optional `out_dir`, `include_urls`, `dry_run`, `confirm_overwrite`). Raises static-grep cost only — not white-box AES.
- `bla_lint_bind_scope`: Read-only lint for `bla-bind-scope/v1` (refuses non-public / hidden fields / missing runtime check).
- `bla_doctor`: Diagnostics for BLA engines and agent client registrations (`home_dir`, `directory`, `verify_handshake` default false). Returns `agentClients` for the clients that are installed or registered — each with `pinnedVersion`, `versionSkew` (it launches another release than this one), `handshakeStatus`, `skillMissingFiles` / `skillModifiedFiles` (format appendices under `references/` included) — plus `projectRegistrations` (BLA entries in the MCP config files of `directory`, default the server's working directory: `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, …; `setup` never writes these, so a broken one is repaired by hand), `clientsNotDetected` (ids only), `issues`, and `nextSteps` with the command that repairs each problem. `verify_handshake: true` starts each registered server locally and checks that it answers `initialize`; a client with `versionSkew` is not probed, because the probe would start this release rather than the pinned one.
- `bla_weave_plan`: Read-only weave-decoy planner (`path`, optional `max_targets`) → `bla-weave-plan/v1` JSON (defensive theory checklist + AST `surgicalWorkorder` with `entryFunctions`, `sharedStateSlots`, `branchCandidates`, and `agentRewriteRecipe`; no crack/RE).
- `bla_verify_weave`: Read-only structural weave verifier (`path`, optional `max_targets`, `scope`, `verbose`) → `bla-weave-verify/v1` JSON (`overallPassed`, `weaveScore`, per-file 7-check verification, and actionable `agentActions` for autonomous Agent self-repair). For a directory the verdict rests on **`requiredFiles`**: with `scope: "auto"` (default) those are the crown-jewel files — the ones holding gate / auth / license / entitlement logic — and every other source file is listed in **`advisoryFiles`** and never fails the run (`scope` in the result is `crown-jewels`, or `agent-selected` when nothing is named like a gate and one woven file of the agent's choosing is enough). `scope: "all"` restores the every-file verdict. `verbose: true` includes the per-check reports of advisory files. Declarations (`.d.ts`), tool configs and tests are not verified.

### Shipping the hardened build (apply / restore)

A plain `bla_harden` / `bla harden .` writes `.bla-hardened/`, a **partial mirror** that holds only the hardened files. Nothing ships yet: the build output is unchanged, and the mirror cannot run on its own because untouched assets are not copied into it.

- **`apply: true`** (CLI `--apply`) hardens and then overwrites the build output in place, so the tree that gets packaged is the protected one. Only files inside a build-output directory (`dist/`, `build/`, `out/`, `release/`, `bin/`, `target/`, …) are overwritten — never source files; anything else that was hardened is listed in `notPromoted`. Over MCP the first call answers `confirmation_required` with `wouldOverwrite`; ask the user, then repeat with `confirm_overwrite: true`. Without an explicit `output_directory`, nothing but the promoted files is written into the project.
- The originals are backed up in a per-user state directory outside the project (`~/Library/Caches/bla-agents`, `$XDG_CACHE_HOME/bla-agents`, `%LOCALAPPDATA%\bla-agents`; override with **`BLA_STATE_DIR`**, e.g. a cached path in CI). Running `apply` again hardens from those originals — never hardened code a second time — and a rebuilt file is picked up as new input.
- **`restore: true`** (CLI `--restore`) puts the originals back and hardens nothing. Files that changed since the apply (a rebuild) are left alone and reported in `skippedModified`.
- **When the promoted build fails a test or a hot path gets too slow** (hardened functions run extra code on every call): `restore`, then run `apply` again with that one file in `exclude`, or at a lower `intensity`. A re-run always starts from the originals, so the excluded file comes back exactly as the build produced it.
- The report's `apply` object states what happened (`status`, `applied`, `added`, `backupDirectory`, and `reason` on a refusal or failure). Then run the project's own tests or a smoke run against the promoted build: BLA verifies structure, not behaviour.

### Reading a harden report

`nextSteps` is the summary an agent should act on. The fields behind it:

| Field | Meaning |
| :--- | :--- |
| `overallSuccess`, `hardenedCount`, `failedCount`, `artifacts[].error` | A run with any failed artifact is `isError: true`; do not ship a partially hardened build. |
| `skippedDevTooling`, `skippedSourceFiles` | Toolchain files (tool configs, tests, scripts `package.json` runs for build / test / release) and build inputs beside a build directory, left alone on purpose. Name a file explicitly with `bla_defend` if it really ships. `.d.ts` declarations are never hardened. |
| `skippedHardenedOutputs` | Files that are already BLA output. `discoveredCount: 0` with this set means "nothing new — rebuild first". |
| `excluded` | Files the `exclude` list left out. They ship unprotected. Pattern syntax: one with a slash is anchored at the project root and covers everything beneath a matching directory (`dist/vendor`, `dist/chunks/heavy-*.js`); one without matches any path segment (`vendor`, `*.min.js`); `*` stays inside a segment, `**` crosses segments. |
| `artifacts[].plaintextSurvivors` | Sensitive-looking literals (what `bla_lint` calls `plaintext-secret`) still readable in the hardened JS/TS/HTML, with source lines and clipped previews. `stealth` / `balanced` do not encode strings; `maximum` / `bankrupt` split string literals and template text of 3–256 characters, and a secret-looking value of up to 4,096 characters wherever it is written (string, template, object key, regular expression), but cannot reach HTML attributes, tagged templates, class member names, TypeScript object keys and `as const` values, or anything longer. Only secret-looking values (digests, keys, generated tokens, PEM headers) are listed — prose, identifiers, file names and encoding alphabets are not findings. |
| `artifacts[].wasmExportRenames` | WASM exports renamed by this run (`from` → `to`). A caller outside the project must be updated from this map, or keep the names with `wasm_preserve_exports`. |
| `artifacts[].wasmExportsAutoPreserved` | Exports kept because another file in the project refers to them (`referencedBy`). Names a host looks up by specification (`_start`, `memory`, `__wbindgen_*`, …) are never renamed and not listed. |
| `integrityBindingEntry`, `integrityBindingUncoveredEntries` | With `self_seal` / `sidecar_entangle`: the JS module that pins its hardened siblings and refuses to load when one was changed, replaced or removed — and the `package.json` entry points that never load it. When `bin` loads `main`, the check is hosted in `main` so both ways in run it. |
| `integrityBindingSkipped` | Artifacts hardened **without** the requested binding, each with the reason: a browser bundle (the binding needs `node:fs` / `node:crypto`; use server-side checks and Subresource Integrity), mutable data such as a SQLite database the application writes to, or a file the entry cannot read at load time. |
| `pythonSidecarEntry`, `pythonSidecarUncoveredEntries` | The Python module that checks the hardened files in its directory tree when it is imported (`policy.py`; else the package behind a declared console script; else a program entry), and the declared console scripts (`pyproject.toml` / `setup.cfg` / `setup.py`) that never import it — started that way nothing is verified. Files outside that module's directory are listed under `integrityBindingSkipped`. A bytecode-only tree and PyInstaller / Nuitka / cx_Freeze bundles ship no sibling sources: the module starts there without verifying anything. |
| `integrityCoveragePath`, `integrityCoverageSelfVerified` | The `bla-integrity-coverage/v1` matrix lists only the edges the hardened tree enforces. |
| `outputSize`, `artifacts[].inputBytes` / `outputBytes` | What the hardened files cost to ship. Decoys are the protection, so every file grows: roughly 50 KB (`stealth`) to 200 KB (`bankrupt`) per JS / HTML file, and megabytes per WASM module at `bankrupt` (tens of kilobytes at `maximum`). `nextSteps` flags growth of a megabyte or more and names the largest file. |
| `sqliteEvalTrapArtifacts` | SQLite databases hardened with the opt-in evaluation trap: on these, a connection that does not register `enclave_unseal_payload()` cannot read the honey tables or run `PRAGMA integrity_check`, `VACUUM`, a dump/restore. Every hardened SQLite database also gets a `nextSteps` line saying that the application's own tables are still readable, and its score is capped (`sqlite-business-data-readable`, and `sqlite-decoy-columns-evaluable` without the trap). |
| `apply`, `notPromoted` | Outcome of the promotion (see above). |
| `runId`, `summaryPath` | Unsigned correlation id and summary file for `bla_run_lookup` / `bla_verify`. |

What hardened JavaScript keeps for its callers: exported and top-level function and class names (`fn.name`, `error.name`, `instance.constructor.name`), inheritance, and the export list. Hardened TypeScript starts with `// @ts-nocheck`, so the injected code is not held to the project's `strict` settings.

### Write safety (dry-run, confirmation, receipts)

- `bla_harden` with `dry_run: true` (CLI `bla harden . --dry-run`) discovers targets and plans outputs with **zero bytes written** (no `.bla-hardened/`, no summary, no `.blarc` seed). Dry-run sets `overallSuccess: false` — it never claims a successful harden.
- Discovery is capped (`max_artifacts`, default 64); when more targets exist the result sets `truncated: true` and `nextOffset` instead of silently dropping them — page with `offset` until `truncated` is false.
- `bla_harden` / `bla_defend` / `bla_protect` / `bla_encrypt_strings` / `bla_bind_scope` refuse to overwrite an existing output file unless `confirm_overwrite: true`. A refusal is `isError: true` with `{ status: "confirmation_required", wouldOverwrite: [...], wrote: [] }`; nothing is written.
- Successful `bla_harden` / `bla_defend` / `bla_protect` / `bla_encrypt_strings` / `bla_bind_scope` writes add `writeReceipt: { status: "written", wrote, overwrote, confirmed }` (`bla_harden` dry-run and runs that write nothing omit it).
- `in_place: true` (MCP) / `--in-place` (CLI) plans the output as the input path; because that path already exists, `confirm_overwrite: true` is required on MCP or the call is refused with `confirmation_required`.

`weave_decoys: true` activates structural Python customer-def weave (shared-slot touch + opaque-false decoy calls) after the #51 tarpit; when false, Python stays warm-init-only. JS AST weave remains always-on.

Project config parity: set `"weaveDecoys": true` in `.blarc` / `bla.config.json` (schema `bla.config.v1.json`) to enable the same flag without repeating `--weave-decoys` / MCP `weave_decoys` on every invoke. CLI/MCP flags still OR with the config value.

Opt-in **self-seal** (issue #40.5): CLI `--self-seal`, MCP `self_seal`, `.blarc` `"selfSeal": true`. Injects a Node self-integrity preamble (module + optional sibling paths + env fingerprint) and folds the digest into the opaque-predicate seed for JS/Node targets.
WASM public ABI preserve list (issue #40.3 / red-blue round-1): CLI `--wasm-preserve-exports a,b`, MCP `wasm_preserve_exports`, `.blarc` `"wasmPreserveExports": ["a","b"]`. At `maximum`/`bankrupt`, **every** non-listed export is renamed by default — keeping `mix`/`seal`-style names requires an explicit list.

Heuristic **lane-independence lint** (issue #40.1 / red-blue round-1): CLI `bla lint-lanes <file>` and MCP `bla_lint_lanes` emit severity **error** when gate code looks like independent per-lane checks. Harden/defend/protect **refuse** unless CLI `--allow-lane-independent` / MCP `allow_lane_independent` / `.blarc` `"allowLaneIndependentGates": true`. Prefer whole-key chained mixing.

Heuristic **seal-commitment lint** (red-blue round-2): CLI `bla lint-seal <file>` and MCP `bla_lint_seal` flag plaintext seal/entitlement JSON and reversible public commitments (`scheduleSalt`+`rounds`+`revision` without a one-way algorithm). Severity **error** findings make **bankrupt** harden/protect **refuse** unless CLI `--allow-plaintext-seal` / MCP `allow_plaintext_seal` / `.blarc` `"allowPlaintextSeal": true`. One-way SHA-256/HMAC digests pass. Full seal-encrypt/bind remains a follow-up; refusal closes the round-2 footgun by default.

### MCP Resources

- `bla://skill/SKILL.md` — the full agent guide (the `blind-llm-agents` skill), for a client that registered the server but has no skill installed (a checked-in `.mcp.json`, for example).
- `bla://skill/references/format-javascript.md`, `…/format-wasm.md`, `…/format-python.md`, `…/format-android.md`, `…/counter-rea-matrix.md` — the skill's appendices; the relative links in the guide resolve against `bla://skill/`.
- `bla://directives/weave-decoy` — weave-decoy theory + executor checklist (Markdown).
- `bla://docs/weave-decoy-mcp` — a short pointer to the directives resource and to the repository's theory pack (the pack itself is not shipped in the npm package).

Resources are looked up by exact URI; nothing outside the bundled skill can be named.

See [`weave-decoy-mcp.md`](./weave-decoy-mcp.md).
