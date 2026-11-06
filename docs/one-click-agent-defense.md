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

## WASM export rename / preserve (#40.3)

At `maximum`/`bankrupt`, BLA renames **all** non-preserved WASM exports. Pass `--wasm-preserve-exports main,add` / MCP `wasm_preserve_exports` / `.blarc` `"wasmPreserveExports": ["main","add"]` only when the public ABI must stay; otherwise consume the rename map. Do not leave independent JS lane tables — `bla lint-lanes` / harden refuse unless `--allow-lane-independent`.

