# One-Click Agent Defense Hardening (skill-first)

Once BLA is registered with your coding agent (`npx bla-agents@latest setup`), the
bundled **`blind-llm-agents` skill** is the primary guide for one-click hardening.
MCP tools and the CLI are the execution layer — prefer calling existing tools from
the skill rather than inventing new MCP surfaces.

Skill source: [`.agents/skills/blind-llm-agents/SKILL.md`](../.agents/skills/blind-llm-agents/SKILL.md)
(metadata.version tracks the skill guide; package version is independent).

## Default: one-sentence project harden

Tell Claude Code, Cursor, Codex, Windsurf, Gemini CLI, OpenCode, or similar:

```text
Harden my software against REA
```

(or Chinese equivalents such as `一键加固` / `一键启动防御强化`)

The agent should invoke:

| Surface | Call |
| :--- | :--- |
| **MCP (preferred)** | `bla_harden` with `{ "directory": "." }` |
| **CLI** | `npx bla-agents@latest harden .` |
| **MCP Prompt** | `bla-harden-project` |

`bla_harden` / `bla harden` **auto-discovers** protectable build outputs (`dist/`,
`build/`, `out/`, `release/`, `.asar`, native binaries, `.wasm`, `.py`/`.pyc`,
`.sqlite`, models, DEX, …) and runs **audit → defend (bankrupt) → verify**.
Agents must **not** ask which files to protect.

## From "hardened" to "shipped"

`bla_harden` writes `.bla-hardened/`, a partial mirror holding only the hardened files.
The build output is still the unprotected one. The result's **`nextSteps`** says so, and
the agent finishes the job:

1. Call `bla_harden` again with `{ "directory": ".", "apply": true }`. It answers
   `confirmation_required` and lists `wouldOverwrite`; the agent asks the user, then
   repeats with `"confirm_overwrite": true`. Only files inside a build-output directory
   are overwritten — never source — and the originals are kept outside the project.
2. Run the project's own tests or a smoke run against the promoted build.
3. `{ "directory": ".", "restore": true, "confirm_overwrite": true }` puts the originals
   back if anything is wrong. A later `apply` hardens from those originals again.
4. If one hardened file is what breaks a test (or slows a hot path), the agent hardens
   again with only that file left out — `"exclude": ["dist/vendor/heavy.js"]` — instead
   of giving up, and reports which files ship unprotected (`excluded`).

CLI: `npx bla-agents@latest harden . --apply` and `harden . --restore`.

Things an agent should not do, and the server says so in its `initialize` instructions:
edit, lint or re-harden BLA's own output (discovery lists it under
`skippedHardenedOutputs`); write hardened code over source files; retry an `isError`
result unchanged instead of reading `artifacts[].error` and `nextSteps`.

## Named single artifact

When a specific file is already known:

```bash
npx bla-agents@latest defend ./dist/app.js --manifest
```

```text
Run bla_defend on ./dist/app.js with bankrupt intensity and emit a defense manifest.
```

## Optional stronger path: Agent-driven surgical weave decoys (BLA 3.0)

For structural (non-noise) decoy entanglement — combining host Agent source refactoring with BLA's pipeline — follow the skill’s 4-stage weave path:

1. Read `bla://directives/weave-decoy` and call `bla_lint` (fixing any blocking `remediationPlan` recipes in source)
2. Call `bla_weave_plan` on the project/artifact and follow each target's `surgicalWorkorder` (`entryFunctions`, `sharedStateSlots`, `branchCandidates`) to weave domain-plausible helpers sharing mutable state
3. Call `bla_verify_weave` and resolve any `agentActions` until `overallPassed: true`
4. Run `bla_harden` / `bla_defend` / `bla_protect` with **`weave_decoys: true`** (CLI: `--weave-decoys`)

See [`weave-decoy-mcp.md`](./weave-decoy-mcp.md). Do **not** add dismissible
`_bla_*` banners, empty honeypot stubs, or rule-based name→snippet noise layers.

## What the pipeline executes

1. **Stage 1 (`inspect-release`)**: Read-only scan for accidental `.map` (`sourcesContent`) and symbol leaks.
2. **Stage 2 (`audit`)**: 16-vector REA vulnerability & Claude Opus 4 / Sonnet 4 / o3 token-cost simulation.
3. **Stage 3 (`protect --intensity bankrupt`)**: Injects both the **Resource-Exhaustion Suite** and the **Model-Misjudgment Induction Suite**.
4. **Stage 4 (`verify`)**: Verifies all Counter-REA mathematical invariants and confirms `16x–51x` token/cost bankruptcy amplification.
5. **Stage 5 (`manifest`)** (opt-in): Emits `<output>.bla-manifest.json` attesting to the hardened build.

## Related

- [CLI and MCP](./cli-and-mcp.md)
- [Counter-REA matrix](../.agents/skills/blind-llm-agents/references/counter-rea-matrix.md)


## Opt-in self-seal (#40.5)

Pass `--self-seal` / MCP `self_seal: true` / `.blarc` `"selfSeal": true` so JS/Node harden paths inject sibling-module integrity binding and entangle the opaque seed. Off by default.

The report states what the binding covers instead of implying it covers everything:
`integrityBindingEntry` is the module that pins its hardened siblings (when `bin` loads
`main`, the check is hosted in `main`, so both ways in run it);
`integrityBindingUncoveredEntries` names declared entry points that never load it; and
`integrityBindingSkipped` lists what was hardened without the binding — browser bundles
(it needs `node:fs` / `node:crypto`; use Subresource Integrity there) and mutable data
such as a SQLite database the application writes to.

A SQLite database is decorated, not hidden: BLA adds honey tables beside the application's
own, which stay readable to anyone who opens the file (the report says so, and caps the
score). By default those honey tables are plain SQL, so the database still passes
`PRAGMA integrity_check`, `VACUUM` and a dump/restore everywhere. `sqlite_eval_trap`
(CLI `--sqlite-eval-trap`) switches their generated columns to a function no stock
connection has: an inspector's row read of a honey table then fails — and so do those
maintenance commands for the application, unless it registers the function itself. Use
it only for a database the application just queries.

## WASM export rename / preserve (#40.3)

At `maximum`/`bankrupt`, BLA renames non-preserved WASM exports. Three kinds of name stay: the ones you list (`--wasm-preserve-exports main,add` / MCP `wasm_preserve_exports` / `.blarc` `"wasmPreserveExports": ["main","add"]`), the ones another file in the project refers to (reported per artifact as `wasmExportsAutoPreserved`, with the file that uses them), and the ones a host looks up by specification (`_start`, `memory`, `__wbindgen_*`, …). Everything else is renamed and the old → new map comes back in `artifacts[].wasmExportRenames` for callers outside the project. Do not leave independent JS lane tables — `bla lint-lanes` / harden refuse unless `--allow-lane-independent`.

